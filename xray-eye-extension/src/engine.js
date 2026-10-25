  
               
                                                                                 
  
                                                                                  
  
                                                                                
                                                           
                                                                    
  
                
                                                                               
                                                                     
                                                                             
                                      
                                                                  
                                                                         
                                                                              
                                                                            
                                                      
                                                                           
                                                                       
  
                    
                                                                         
                                                                                  
                                                                             
                                                                  
                                                                             
                                                        
                                                                      
                                                                         
                                             
                                                                              
                                                 
                                                                             
                                                                        
   
(() => {
  "use strict";

  const VERSION = "3.2.4";
  const RELOAD_STORE_KEY = "__xrayeye_reload_capture_v1__";
  const RELOAD_CONFIG_KEY = "__xrayeye_keep_on_reload__";

                                                                          
                                                         
  try {
    const prior = window.xrayeye || window.EASYapi;
    if (prior && typeof prior.stop === "function") {
      prior.stop({ silent: true });
    } else if (typeof window.__SMART_API_DISCOVERY_CLEANUP__ === "function") {
      window.__SMART_API_DISCOVERY_CLEANUP__();
    }
  } catch (_) {}

                                                                          
                                                         
                                                                          
  const CONFIG = {
                     
    maxRequestBodyChars: 3000,
    maxResponseBodyChars: 2500,
    maxRequestBytesRead: 65536,
    maxResponseBytesRead: 16384,
                                                                                
                                                                              
    maxSpecBytes: 3145728,
    maxJsonParseChars: 262144,
    readTimeoutMs: 3000,

                   
    maxFindings: 2000,
    maxExamples: 5,
    maxWsSamples: 6,
    maxSecrets: 500,
    maxSpecEndpoints: 1500,
    maxNotes: 2500,
    maxNotesPerKind: 200,

                        
    captureResponseHeaders: true,
    trackTiming: true,
    responseHeaderAllow: [
      "www-authenticate", "access-control-allow-origin", "access-control-allow-credentials",
      "access-control-expose-headers", "access-control-allow-headers", "vary",
      "cache-control", "pragma", "age", "etag", "expires", "last-modified",
      "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after",
      "location", "set-cookie", "server", "x-powered-by", "x-aspnet-version", "x-runtime",
      "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
      "x-frame-options", "x-content-type-options", "permissions-policy", "referrer-policy",
      "x-amzn-requestid", "x-amz-cf-id", "cf-ray", "x-github-request-id", "x-request-id",
      "x-nextjs-cache", "x-matched-path", "x-now-route-matches", "x-nextjs-data"
    ],

                      
    scanJavaScript: true,
    scanForms: true,
    usePerformanceEntries: true,
    maxScripts: 80,
    maxScriptChars: 3000000,
    maxRefsPerScript: 400,
    scriptConcurrency: 3,
    scriptTimeoutMs: 15000,

                  
    followSourceMaps: true,
    maxSourceMaps: 12,
    maxMapChars: 8000000,

                           
    walkChunks: true,
    maxChunks: 150,

              
    scanSecrets: true,
    minSecretLength: 6,
    entropyBase64: 4.5,
    entropyHex: 3.0,
    entropyMinLen: 14,
    decodeBase64Blobs: true,
    maxBlobsPerScript: 40,

                                                                        
    analyzeJWTs: true,
    jwtWeakSecretTest: true,
    maxJwtFindings: 300,
    maxWeakSecretTries: 14,

                                
    sweepStorage: true,
    sweepIndexedDB: true,
    sweepCaches: true,
                                                                                    
    sweepWindowGlobals: false,
    maxStorageFindings: 500,
    maxIndexedDbRecords: 400,
    maxCacheEntries: 60,
    maxStorageValueChars: 20000,

                 
    trackOAuth: true,
    maxOAuthFlows: 120,

                                  
    detectFrameworks: true,
    frameworkCveMap: true,
    detectServerActions: true,
    maxServerActions: 200,

                      
    inspectServiceWorkers: true,

                 
    detectTabnabbing: true,
    detectPostMessageWildcard: true,

                                      
    harvestStateBlobs: true,
    harvestMetaTags: true,
    harvestLinkHints: true,
    harvestDataAttributes: true,
                                                                             
                                                                              
                                    
  harvestVisibleText: true,
                                                                               
                                                                        
  revealSecrets: true,
  maxVisibleTextChars: 300000,

                                                                             
                                                             
  scanHtmlComments: true,
  scanCredentialAttributes: true,
  scanRuntimeGlobals: true,
  decodeEncodedLiterals: true,
  reconstructStringConstants: true,
  analyzeAuthComparisons: true,
  maxDomElements: 4000,
  maxCredentialAttributes: 120,
  maxCredentialValueChars: 300,
  maxRuntimeFindings: 80,
                                                                                 
  maxRuntimeDepth: 4,
                                                                             
                                                                                
  detectEndpointCredentials: true,
                                                                      
  detectDirectoryListings: true,
  maxDirectoryEntries: 300,
                                                                    
  detectSensitivePaths: true,
  maxHtmlSourceChars: 2000000,
    scanComments: true,
    detectWebpackPublicPath: true,

          
    captureCSP: true,

                                                             
    hookStorageWrites: true,
    hookCacheOpens: true,
    hookWebRTC: true,

                  
    probeBlindSourceMaps: true,
    maxBlindMaps: 40,

                             
    harvestBodyFields: true,
    maxBodyFields: 60,

             
    live: true,
    minConfidence: "LOW",                       
    thirdParty: "tag",                   
    showRequestHeaders: true,
    showResponseBody: true,
    showSecrets: true,
    redactSensitive: true,
    livePrintBudget: 40,
    livePrintWindowMs: 2000,
    printDelayMs: 250,
    debug: false,

                                                                  
    allowActiveProbe: false,

                                                                     
                                                                         
                                                                           
                                                                            
    activeRead: false,

                                                                            
                                                                            
                                                                                
    maxTableRows: 5,
    maxTableColumns: 5,
    maxPreviewLines: 25,

                                                                        
    showPanel: true,

                                                                       
                                                                            
                                                                       
    catchJSONParse: false,
    catchConsoleDumps: false,
    catchCookieWrites: false
  };

                                                                              
                                                                               
                                                                              
                                                                             
                                                                        
  let revealOn = !!CONFIG.revealSecrets;
  try {
    Object.defineProperty(CONFIG, "revealSecrets", {
      enumerable: true,
      configurable: true,
      get: () => revealOn,
      set: next => applyReveal(!!next)
    });
  } catch (_) {}

  const CONF_RANK = { IGNORE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
                                                                             

  function matchesFinding(f, match) {
  if (match == null) return true;
  const q = String(match).toLowerCase();
  const full = ((f.host || "") + (f.normalizedPath || f.path || "")).toLowerCase();
  if (full.indexOf(q) >= 0 || String(f.url || "").toLowerCase().indexOf(q) >= 0) return true;
                                                                            
                                                           
                                                                              
                                        
  try {
  const abs = String(absoluteUrl(f) || "").toLowerCase();
  if (abs && abs.indexOf(q) >= 0) return true;
  } catch (_) {                                                     }
  return false;
  }

  function endpointDetail(match) {
    const hits = list({}).filter(f => matchesFinding(f, match));
    return hits.slice(0, 20).map(f => {
      const d = serialize(f, true);
                                                                              
                                                                    
      if (showsRawValues(f)) {
        d.valuesMasked = !CONFIG.revealSecrets;
        d.valueDisplay = CONFIG.revealSecrets
          ? "CLEARTEXT - revealSecrets is on, so values below are real. Do not share this output."
          : "MASKED - revealSecrets is off, so values below are masked but field names are real.";
      }
      if (match && hits.length === 1 && !f.observed && !f.responseBody) {
                                                                            
                                                                              
        d.knownFrom = [...f.sources].join(", ");
        d.whyNoBody = "The application never called this route while you were watching, so no request or response was captured. Its contents are unknown, not empty.";
        d.hint = "xrayeye.fetchEndpoint(" + JSON.stringify(match) + ", { confirm: 'AUTHORIZED' })";
      }
      return d;
    });
  }

                                                                               
                                                                             
                                                                    
  function observedCalls(opts) {
    const o = opts || {};
    const all = list({});
    const seen = all.filter(f => f.observed || f.requestBody || f.responseBody)
      .filter(f => !o.match || matchesFinding(f, o.match))
      .map(f => serialize(f, true));
    return {
      observed: seen,
      referencedOnly: all.filter(f => !f.observed && !f.requestBody && !f.responseBody)
        .filter(f => !o.match || matchesFinding(f, o.match))
        .map(f => ({
          url: absoluteUrl(f), method: f.method,
          sources: [...f.sources], queryParams: [...f.queryParams], thirdParty: f.thirdParty,
          why: f.reasons ? [...f.reasons] : []
        }))
    };
  }

  function reportCalls(match) {
    const r = observedCalls(match ? { match: match } : {});
    console.log("[x-ray-eye] ENDPOINT CALLS: " + r.observed.length + " observed, " + r.referencedOnly.length + " referenced only");
    if (CONFIG.revealSecrets) {
      console.log("  Values: CLEARTEXT because revealSecrets is on. Addresses and tokens below are real.");
    }
    for (const c of r.observed) {
      const status = Object.entries(c.statuses || {}).map(([k, v]) => k + "x" + v).join(" ");
      console.log("\n  " + (c.method || "?") + " " + c.url + (status ? "   -> " + status : ""));
      console.log("    seen via : " + (c.sources || []).join(", "));
      if (c.query) console.log("    query    : " + clip(String(c.query), 200));
      if (c.requestPreview) console.log("    request  : " + clip(String(c.requestPreview).replace(/\n\s*/g, " "), 400));
      if (c.responsePreview) console.log("    response : " + clip(String(c.responsePreview).replace(/\n\s*/g, " "), 600));
      else console.log("    response : (none captured)");
      if (c.responseHeaders) console.log("    headers  : " + clip(JSON.stringify(c.responseHeaders), 300));
      if (c.piiHits && c.piiHits.length) console.log("    PII      : " + c.piiHits.map(p => p.kind + " x" + (p.count || 1)).join(", "));
      if (c.auth && c.auth.sentCredentials) console.log("    auth     : sent " + c.auth.sentCredentials);
    }
    if (r.referencedOnly.length) {
      console.log("\n  REFERENCED BUT NEVER CALLED (" + r.referencedOnly.length + ") - no request or response was observed:");
      for (const c of r.referencedOnly.slice(0, 40)) {
        console.log("    " + (c.method || "?") + " " + clip(c.url, 96) + "   [" + (c.sources || []).join(",") + "]");
      }
      console.log("    (contents unknown: fetching them is the active probe path, which is refused unless you confirm)");
    }
    return api;
  }

  const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

                                                                          
                                                                           
                                                                          
  const nativeConsole = {};
  for (const m of ["log", "group", "groupCollapsed", "groupEnd", "table", "debug"]) {
    nativeConsole[m] = typeof console[m] === "function" ? console[m].bind(console) : null;
  }
  if (!nativeConsole.log) nativeConsole.log = () => {};
  if (!nativeConsole.groupCollapsed) nativeConsole.groupCollapsed = nativeConsole.group || nativeConsole.log;
  if (!nativeConsole.groupEnd) nativeConsole.groupEnd = () => {};
  if (!nativeConsole.debug) nativeConsole.debug = nativeConsole.log;

  const setT = window.setTimeout.bind(window);
  const clearT = window.clearTimeout.bind(window);
  const nativeFetch = typeof window.fetch === "function" ? window.fetch : null;
  const storageProto = typeof window.Storage !== "undefined" ? window.Storage.prototype : null;
  const nativeStorageGet = storageProto && storageProto.getItem;
  const nativeStorageSet = storageProto && storageProto.setItem;
  const nativeStorageRemove = storageProto && storageProto.removeItem;
  const hasDOM = typeof document !== "undefined" && !!document;
  const nativeAtob = typeof atob === "function" ? atob : null;

  const nowMs = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

                                                                          
          
                                                                          
  let active = true;
  let installed = false;
  let keepOnReload = true;
  let persistenceListening = false;
  let seq = 0;
  let secretSeq = 0;
  let specSeq = 0;
  const cleanups = [];
  const hooks = [];
  const installFns = [];

  const store = new Map();                                  
  const pathIndex = new Map();                             
  const secretStore = new Map();                          
  const specStore = new Map();                              
  const jwtStore = new Map();                                 
  const storageStore = new Map();                               
  const swStore = new Map();                                       
  const oauthStore = new Map();                              
  const fwStore = new Map();                                             
  const snapshots = new Map();                        
  const notes = new Map();                           
  const pending = new Map();                                            
  const pendingSecrets = new Map();
  const errors = [];
  const warned = new Set();
  const noteKindCount = new Map();

  const stats = {
    fetch: 0, xhr: 0, beacon: 0, websocket: 0, eventsource: 0, worker: 0, performance: 0,
    scripts: 0, scriptsSkipped: 0, scriptRefs: 0, sourceMaps: 0, chunks: 0,
    secrets: 0, secretsSuppressed: 0, specEndpoints: 0, graphqlFields: 0, notes: 0,
    ignored: 0, hidden: 0, skipped: 0, errors: 0, printSuppressed: 0, probes: 0,
    jwtSeen: 0, jwtWeak: 0, jwtAlgNone: 0, jwtNoExp: 0, jwtLongLived: 0, jwtEnumerableSub: 0,
    storageItems: 0, storageSecrets: 0, indexedDbRecords: 0, cacheEntries: 0,
    oauthFlows: 0, oauthRedirectUris: 0, oauthNoState: 0, oauthImplicit: 0,
    frameworks: 0, serverActions: 0, serviceWorkers: 0,
    postMessageWildcard: 0, tabnabbing: 0, bodyFields: 0, massAssignCandidates: 0,
    cacheLeaks: 0, aiEndpoints: 0, gqlDangerousArgs: 0
  };

  function fail(where, err) {
    stats.errors++;
    if (errors.length < 50) {
      errors.push({ where, message: String((err && err.message) || err), at: new Date().toISOString() });
    }
    if (CONFIG.debug) {
      try { nativeConsole.debug("[x-ray-eye] internal error in " + where, err); } catch (_) {}
    }
  }

  function warnOnce(key, message, css) {
    if (warned.has(key)) return;
    warned.add(key);
    styled("[x-ray-eye] " + message, css || STYLE.warn);
  }

                                                                          
                                     
                                                                          
  const B64_CHARSET = /^[A-Za-z0-9+/]+={0,2}$/;
  const HEX_CHARSET = /^[0-9a-fA-F]+$/;

  function shannon(s) {
    const n = s.length;
    if (!n) return 0;
    const freq = new Map();
    for (let i = 0; i < n; i++) {
      const c = s.charCodeAt(i);
      freq.set(c, (freq.get(c) || 0) + 1);
    }
    let h = 0;
    for (const count of freq.values()) {
      const p = count / n;
      h -= p * Math.log2(p);
    }
    return h;
  }

                                                                         
                                                                              
                                                   
  function entropyProfile(v) {
    if (v.length < CONFIG.entropyMinLen) return null;
    if (HEX_CHARSET.test(v)) return { bits: shannon(v), charset: "hex", threshold: CONFIG.entropyHex };
    if (B64_CHARSET.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) {
      return { bits: shannon(v), charset: "base64", threshold: CONFIG.entropyBase64 };
    }
    return null;
  }

                                                                          
              
                                                                          
                                                                             
                                                              
  const SENSITIVE_EXACT = new Set([
    "pass", "pwd", "auth", "sig", "sid", "otp", "pin", "jwt", "key",
    "session", "sessionid", "ssid", "csrf", "xsrf"
  ]);
  const SENSITIVE_PARTS = [
    "password", "passwd", "passphrase", "secret", "token", "apikey", "authorization",
    "cookie", "credential", "privatekey", "accesskey", "signature", "bearer",
    "sessionid", "verificationcode", "otpcode", "csrf", "xsrf"
  ];

  function normKey(k) {
    return String(k).toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function isSensitiveKey(k) {
    const n = normKey(k);
    if (!n) return false;
    if (NEVER_SENSITIVE.has(n)) return false;
    if (SENSITIVE_EXACT.has(n)) return true;
    for (const p of SENSITIVE_PARTS) if (n.includes(p)) return true;
    return false;
  }

                                                                           
                                                                               
  const NEVER_SENSITIVE = new Set([
    "accesscontrolallowcredentials", "accesscontrolallowheaders", "accesscontrolexposeheaders",
    "accesscontrolmaxage", "credentials", "cookiepolicy", "xcsrf_token_name"
  ]);

  const VALUE_PATTERNS = [
    [/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g, "[REDACTED_JWT]"],
    [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/gi, "$1 [REDACTED]"],
    [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
    [/\bASIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
    [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED_GOOGLE_KEY]"],
    [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[REDACTED_GITHUB_TOKEN]"],
    [/\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, "[REDACTED_GITHUB_TOKEN]"],
    [/\bglpat-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_GITLAB_TOKEN]"],
    [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED_SLACK_TOKEN]"],
    [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g, "[REDACTED_STRIPE_KEY]"],
    [/\bhooks\.slack\.com\/services\/[A-Za-z0-9_\/]+/g, "[REDACTED_SLACK_WEBHOOK]"],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"]
  ];

                                                                                  
  const KV_PATTERN = /([A-Za-z0-9_.\-]{1,64})(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&"'{}\[\]]+)/g;

  function applyValuePatterns(s) {
    let out = s;
    for (const [re, rep] of VALUE_PATTERNS) out = out.replace(re, rep);
    return out;
  }

  function redactString(s) {
    if (!CONFIG.redactSensitive) return String(s);
    let out = applyValuePatterns(String(s));
    out = out.replace(KV_PATTERN, (m, key, sep, val) => {
      if (!isSensitiveKey(key)) return m;
      return key + sep + (/^["']/.test(val) ? '"[REDACTED]"' : "[REDACTED]");
    });
    return out;
  }

  function redactValue(v, depth) {
    if (v === null || v === undefined) return v;
    if (typeof v === "string") return redactString(v);
    if (typeof v !== "object") return v;
    if (depth > 8) return "[depth limit]";
    if (Array.isArray(v)) {
      const out = v.slice(0, 50).map(x => redactValue(x, depth + 1));
      if (v.length > 50) out.push("[+" + (v.length - 50) + " more]");
      return out;
    }
    const out = Object.create(null);
    let n = 0;
    for (const k of Object.keys(v)) {
      if (++n > 100) { out["[more keys]"] = "..."; break; }
      out[k] = isSensitiveKey(k) ? "[REDACTED]" : redactValue(v[k], depth + 1);
    }
    return out;
  }

  function clip(text, max) {
    return text.length <= max ? text : text.slice(0, max) + " ... [truncated, " + text.length + " chars]";
  }

                                                                           
  function maskValue(v) {
    const s = String(v);
    if (s.length <= 4) return "*".repeat(s.length);
    return s.slice(0, 3) + "*".repeat(Math.min(s.length - 4, 24)) + s.slice(-2) + " (len " + s.length + ")";
  }

                                                                             
                                                                            
                                                                          
                                                                          
                                      
  function shownValue(masked, raw) {
    if (!CONFIG.revealSecrets) return masked;
    return typeof raw === "string" && raw ? raw : "-";
  }

                                                                         
                                                                             
                                                                              
                                                                          
  function disclosedValues(n) {
    if (CONFIG.revealSecrets) {
      const raw = n.value != null ? [n.value] : (Array.isArray(n.valuesRaw) ? n.valuesRaw : []);
      return raw.length ? raw : ["-"];
    }
    const masked = n.valueMasked != null ? [n.valueMasked] : (Array.isArray(n.values) ? n.values : []);
    return masked.length ? masked : ["-"];
  }

                                                                          
                                                                            
                                                                          
  const PII_PATTERNS = [
    ["email", /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g],
    ["ssn", /\b\d{3}-\d{2}-\d{4}\b/g],
    ["credit-card", /\b(?:\d[ -]*?){13,19}\b/g],
    ["iban", /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g],
    ["phone", /\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/g],
    ["ipv4", /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
    ["jwt", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g]
  ];

  const NON_PII_IPV4 = /^(?:0\.0\.0\.0|127\.|255\.255\.255\.255|192\.168\.0\.|10\.0\.0\.[01])$/;

  function luhn(s) {
    const d = s.replace(/[^0-9]/g, "");
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = d.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

                                                                           
                                                                          
                                                                               
function piiStandsAlone(m, idx, text) {
    const raw = m[0];
    const digits = raw.replace(/\D/g, "");
    const before = text.slice(Math.max(0, idx - 32), idx);
    const after = text.slice(idx + raw.length, idx + raw.length + 32);
                                                                                 
                                                                                 
                                                   
    if (idx > 0 && /[A-Za-z0-9]/.test(text.charAt(idx - 1))) return false;
    const nextCh = text.charAt(idx + raw.length);
    if (nextCh && /[A-Za-z0-9]/.test(nextCh)) return false;
                                                       
    if (/[?&#/]\s*$/.test(before)) return false;
                                                                        
    if (/[-_]\s*$/.test(before) && /^\s*[.\-_:)]/.test(after)) return false;
                                                                              
    if (digits.length === 13 && digits.charAt(0) === "1") return false;
    if (digits.length === 10 && digits.charAt(0) === "1") return false;
                                                                          
    if (/^\d{1,3}(?:\.\d{1,4}){2,4}$/.test(raw)) return false;
                                                                                
                                                                           
                                                         
    let s0 = idx, e0 = idx + raw.length;
    while (s0 > 0 && !/[\s"',[\]{}]/.test(text.charAt(s0 - 1))) s0--;
    while (e0 < text.length && !/[\s"',[\]{}]/.test(text.charAt(e0))) e0++;
    const tok = text.slice(s0, e0);
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tok)) return false;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{6,}$/i.test(tok)) return false;
    if (/^[0-9a-f]{24,}$/i.test(tok)) return false;
    return true;
  }

  function detectPII(text) {
    if (!text) return [];
    const hits = new Map();
    for (const [kind, re] of PII_PATTERNS) {
      const rx = new RegExp(re.source, re.flags);
      let m, seen = 0;
      while ((m = rx.exec(text)) !== null && seen < 50) {
        if (m[0].length < 4) continue;
        if (kind === "credit-card" && !luhn(m[0])) continue;
        if (kind === "email" && /\.(js|map|css|png|svg|woff2?)$/i.test(m[0])) continue;
        if (kind === "ipv4" && NON_PII_IPV4.test(m[0])) continue;
if (kind === "phone" && m[0].replace(/\D/g, "").length < 10) continue;
          if (kind === "phone" && /^(?:1\.0\.0|127\.)/.test(m[0].replace(/\D/g, ""))) continue;
                                                                  
          if ((kind === "phone" || kind === "credit-card" || kind === "national-id") &&
              !piiStandsAlone(m, m.index, text)) continue;
        seen++;
        const cur = hits.get(kind);
        if (cur) cur.count++;
                                                     
          
                                                               
                                                                              
                                                                            
                                                                        
                                                                             
                            
        else hits.set(kind, {
          kind, count: 1,
          sample: CONFIG.revealSecrets ? m[0] : maskValue(m[0]),
          masked: !CONFIG.revealSecrets,
          length: m[0].length
        });
      }
    }
    return [...hits.values()];
  }

                                                                          
                
                                                                          
  const WEB_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

  function baseURI() {
    try { return (hasDOM && document.baseURI) || location.href; } catch (_) { return location.href; }
  }

  function parseURL(input) {
    try {
      const u = new URL(String(input), baseURI());
      return WEB_PROTOCOLS.has(u.protocol) ? u : null;
    } catch (_) {
      return null;
    }
  }

  function decodeBraces(s) {
    return s.replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  }

                                                                                         
  function redactURL(u) {
    if (!CONFIG.redactSensitive) return u.href;
    const params = str => str.split("&").map(part => {
      const i = part.indexOf("=");
      if (i < 0) return part;
      const k = part.slice(0, i);
      let dk = k;
      try { dk = decodeURIComponent(k.replace(/\+/g, " ")); } catch (_) {}
      return isSensitiveKey(dk) ? k + "=[REDACTED]" : part;
    }).join("&");
                                                                   
    let out = u.protocol + "//" + u.host + decodeBraces(u.pathname);
    if (u.username) out = u.protocol + "//" +
      (CONFIG.revealSecrets ? decodeURIComponent(u.username) : maskValue(u.username)) +
      "@" + u.host + decodeBraces(u.pathname);
    if (u.search.length > 1) out += "?" + params(u.search.slice(1));
    if (u.hash.length > 1) out += "#" + (u.hash.includes("=") ? params(u.hash.slice(1)) : u.hash.slice(1));
    return applyValuePatterns(out);
  }

  function redactHref(href) {
    const u = parseURL(href);
    return u ? redactURL(u) : String(href);
  }

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const normalizeCache = new Map();

                                                                               
                                                                               
                                                                          
                                                          
  const PATH_PARAM_ID_WORDS = /^(?:id|uid|pid|oid|rid|gid)$/;
  const PATH_PARAM_ID_SUFFIX = /(?:id|uuid|guid|ref|code|key|no|num|pin|seq|oid)$/;
  const PATH_PARAM_SLUG_WORDS = /^(?:user|username|login|email|name|nickname|handle|account|org|team|project|repo|tenant|customer|client|group|channel|namespace|slug)$/;

  function normalizeSegment(seg) {
    if (!seg) return seg;
    let s = seg;
    try { s = decodeURIComponent(seg); } catch (_) {}
    if (/^\d+$/.test(s)) return "{id}";
    if (UUID_RE.test(s)) return "{uuid}";
    if (/^[0-9a-f]{16,}$/i.test(s)) return "{hex}";
    if (/^[A-Za-z0-9_-]{22,}$/.test(s) && /\d/.test(s) && /[A-Za-z]/.test(s)) return "{token}";
    if (/^\{[^}]*\}$/.test(s) || /^:[A-Za-z_]\w*$/.test(s)) {
      const flat = String(s).replace(/^[:{]+|[}]+$/g, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
      if (!flat) return "{param}";
      if (flat === "uuid" || flat === "guid") return "{uuid}";
      if (flat === "token" || flat === "access_token") return "{token}";
      if (PATH_PARAM_ID_WORDS.test(flat)) return "{id}";
      if (flat.length > 2 && PATH_PARAM_ID_SUFFIX.test(flat)) return "{id}";
      if (PATH_PARAM_SLUG_WORDS.test(flat)) return "{slug}";
      return "{param}";
    }
    return seg;
  }

  function normalizePath(p) {
    const cached = normalizeCache.get(p);
    if (cached !== undefined) return cached;
    let s = p.split("/").map(normalizeSegment).join("/");
    if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
    s = s || "/";
    if (normalizeCache.size < 20000) normalizeCache.set(p, s);
    return s;
  }

  const MULTI_TLD = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "co.in", "com.br", "com.cn", "com.mx", "com.tr", "co.za", "com.sg", "com.np", "com.pk", "com.bd"
  ]);

                                                                                
  function siteOf(hostname) {
    const h = String(hostname).toLowerCase();
    if (h.startsWith("[") || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const last2 = parts.slice(-2).join(".");
    return MULTI_TLD.has(last2) ? parts.slice(-3).join(".") : last2;
  }

                                                                               
                                         
const VENDOR_SDK_HOSTS = /(^|\.)(connect\.facebook\.net|connect\.facebook\.com|sdk\.facebook|facebook\.com|googletagmanager\.com|google-analytics\.com|analytics\.google\.com|doubleclick\.net|googleapis\.com|gstatic\.com|segment\.io|segment\.com|mixpanel\.com|hotjar\.com|fullstory\.com|intercom\.io|drift\.com|zendesk\.com)$/i;

  const NOISE_HOSTS = /(^|\.)(w3\.org|schema\.org|schemas\.microsoft\.com|ietf\.org|reactjs\.org|react\.dev|npmjs\.com|github\.com|githubusercontent\.com|gnu\.org|apache\.org|creativecommons\.org|wikipedia\.org|mozilla\.org|json-schema\.org|purl\.org|opensource\.org|fb\.me|googletagmanager\.com|google-analytics\.com|doubleclick\.net|analytics\.google\.com|connect\.facebook\.net|connect\.facebook\.com|facebook\.com\/plugins|sdk\.facebook|apis\.google\.com|gtm\.google)$/i;

                                                                         
  const INTERESTING_HOST_RE = /(^|\.)(internal|staging|stage|stg|qa|uat|preprod|pre-prod|dev|test|testing|sandbox|admin|backstage|ops|debug|preview|canary|blue|mgmt|management)(\.|$)/i;
                                                                      
  const INTERESTING_AWS_SERVICE_RE = /\.(rds|redshift|elasticache|opensearch|elasticsearch|eks|ecs|qldb|docdb|kinesis|dynamodb|elb|sqs|sns)\.[a-z0-9-]+\.amazonaws\.com$/i;
  const INTERESTING_PATH_RE = /(^|\/)(\.env($|\.)|\.git(\/|$)|phpinfo|info\.php|actuator|debug|internal|admin|backstage|_admin|wp-config|config\.(json|ya?ml)|__env|__config|swagger|openapi|graphiql|playground|v2\/api-docs|v3\/api-docs|server-status|wp-json|elmah|trace\.axd|\.well-known\/security\.txt|metrics|healthz|readyz)/i;

                                                                          
                   
                                                                   
                                                                 
                                                                        
                                                                          

                                                                              
  function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h.toString(16);
  }

  const SECRET_PATTERNS = [
                                  
    { id: "aws-key-id", name: "AWS Access Key ID", category: "cloud", severity: "HIGH", exposure: "needs-context",
      re: /\b((?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[0-9A-Z]{16})\b/g, group: 1,
      verify: "CRITICAL when a matching secret access key or session token sits in the same file." },
    { id: "aws-secret", name: "AWS Secret Access Key", category: "cloud", severity: "CRITICAL", exposure: "leak",
      re: /aws_?secret_?access_?key["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{40})/gi, group: 1 },
    { id: "aws-session-token", name: "AWS Session Token", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /aws_?session_?token["'\s]*[:=]["'\s]*([A-Za-z0-9/+=]{100,})/gi, group: 1 },
    { id: "gcp-api-key", name: "Google API Key", category: "cloud", severity: "MEDIUM", exposure: "needs-context",
      re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1,
      verify: "Safe by design for Maps/YouTube when referrer-locked. Check restrictions before reporting." },
    { id: "gcp-oauth", name: "Google OAuth Access Token", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /\b(ya29\.[A-Za-z0-9_-]{20,})/g, group: 1 },
    { id: "gcp-service-account", name: "GCP Service Account JSON", category: "cloud", severity: "CRITICAL", exposure: "leak",
      re: /("type"\s*:\s*"service_account")/g, group: 0, masked: true,
      verify: "A bundled service account is admin access to the project. private_key is usually adjacent." },
    { id: "appsync-key", name: "AWS AppSync GraphQL API Key", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /\b(da2-[a-z0-9]{26})\b/g, group: 1,
      verify: "AppSync keys are account-scoped. Confirm which schema it reaches and whether introspection is open." },
    { id: "mws-token", name: "Amazon MWS Auth Token", category: "cloud", severity: "CRITICAL", exposure: "leak",
      re: /\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/g, group: 1,
      verify: "Full seller-account access to the associated Marketplace seller ID." },
    { id: "aws-service-endpoint", name: "AWS Managed Service Endpoint", category: "internal-surface", severity: "MEDIUM", exposure: "needs-context",
      re: /((?:[a-z0-9-]+\.){1,3}(?:rds|redshift|elasticache|opensearch|elasticsearch|eks|ecs|qldb|docdb|kinesis|dynamodb)\.[a-z0-9-]+\.amazonaws\.com)/g, group: 1,
      verify: "Internal service hostnames leak account id, region and topology. Useful for pivoting and for finding exposed services." },
    { id: "firebase-database", name: "Firebase Realtime DB URL", category: "frontend-config", severity: "INFO", exposure: "by-design",
      re: /(https?:\/\/[a-z0-9-]+\.firebaseio\.com)/gi, group: 1,
      verify: "URL is public by design. Impact depends entirely on database security rules." },
    { id: "azure-storage-key", name: "Azure Storage Account Key", category: "cloud", severity: "CRITICAL", exposure: "leak",
      re: /(AccountKey\s*=\s*([A-Za-z0-9+/=]{60,}))/gi, group: 2 },
    { id: "azure-sas", name: "Azure SAS Token", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /([?&]se=[^&\s"']{10,}[^&\s"']*sig=[A-Za-z0-9%+/=]{20,})/gi, group: 1 },
    { id: "heroku", name: "Heroku API Key", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /\b(heroku_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/g, group: 1 },
    { id: "digitalocean", name: "DigitalOcean Token", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /\b(dop_v1_[a-f0-9]{64})\b/g, group: 1 },
    { id: "cloudflare-api-token", name: "Cloudflare API Token", category: "cloud", severity: "MEDIUM", exposure: "leak",
      re: /\b(cloudflare\|v1\|0-[A-Za-z0-9_-]{30,})/g, group: 1 },
    { id: "cloudflare-global-key", name: "Cloudflare Global API Key", category: "cloud", severity: "CRITICAL", exposure: "leak",
      re: /\b(cloudflare\|v1\|0-[a-f0-9]{37})\b/g, group: 1 },

                             
    { id: "github-pat", name: "GitHub Token", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\b(gh[pousr]_[A-Za-z0-9]{36,})\b/g, group: 1 },
    { id: "github-pat-fine", name: "GitHub Fine-Grained Token", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\b(github_pat_[A-Za-z0-9_]{50,})\b/g, group: 1 },
    { id: "gitlab-pat", name: "GitLab Personal Access Token", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\b(glpat-[A-Za-z0-9_-]{16,})\b/g, group: 1 },
    { id: "gitlab-runner", name: "GitLab Runner Token", category: "ci", severity: "HIGH", exposure: "leak",
      re: /\b(glrt-[A-Za-z0-9_-]{16,})\b/g, group: 1 },
    { id: "npm-token", name: "npm Token", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1 },
    { id: "pypi-token", name: "PyPI Upload Token", category: "ci", severity: "HIGH", exposure: "leak",
      re: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g, group: 1 },
    { id: "dockerhub", name: "Docker Hub PAT", category: "ci", severity: "HIGH", exposure: "leak",
      re: /\b(dckr_pat_[A-Za-z0-9_-]{20,})\b/g, group: 1 },

                    
    { id: "stripe-secret", name: "Stripe Secret Key", category: "payments", severity: "CRITICAL", exposure: "leak",
      re: /\b(sk_live_[0-9a-zA-Z]{16,})\b/g, group: 1,
      verify: "Full account access including charges and refunds. Never ship to a browser." },
    { id: "stripe-restricted", name: "Stripe Restricted Key", category: "payments", severity: "CRITICAL", exposure: "leak",
      re: /\b(rk_live_[0-9a-zA-Z]{16,})\b/g, group: 1 },
    { id: "stripe-webhook-secret", name: "Stripe Webhook Signing Secret", category: "payments", severity: "CRITICAL", exposure: "leak",
      re: /\b(whsec_[0-9a-zA-Z]{16,})\b/g, group: 1 },
    { id: "stripe-publishable", name: "Stripe Publishable Key", category: "payments", severity: "INFO", exposure: "by-design",
      re: /\b(pk_live_[0-9a-zA-Z]{16,})\b/g, group: 1,
      verify: "Designed to be public. Confirm domain restriction before treating as a finding." },
    { id: "square-token", name: "Square Access Token", category: "payments", severity: "CRITICAL", exposure: "leak",
      re: /\b(sq0atp-[0-9A-Za-z_-]{22})\b/g, group: 1 },
    { id: "square-secret", name: "Square OAuth Secret", category: "payments", severity: "CRITICAL", exposure: "leak",
      re: /\b(sq0csp-[0-9A-Za-z_-]{43})\b/g, group: 1 },
    { id: "braintree", name: "Braintree Access Token", category: "payments", severity: "HIGH", exposure: "leak",
      re: /(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})/g, group: 1 },
    { id: "paypal-secret", name: "PayPal / Braintree Secret", category: "payments", severity: "HIGH", exposure: "leak",
      re: /(paypal[_-]?(?:secret|client[_-]?secret)["'\s]*[:=]["'\s]*([A-Za-z0-9_-]{20,}))/gi, group: 2 },

                                     
    { id: "slack-token", name: "Slack Token", category: "messaging", severity: "CRITICAL", exposure: "leak",
      re: /\b(xox[abporsu]-[A-Za-z0-9-]{10,})\b/g, group: 1 },
    { id: "slack-app-token", name: "Slack App-Level Token", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /\b(xapp-[0-9A-Za-z-]{10,})\b/g, group: 1 },
    { id: "slack-webhook", name: "Slack Incoming Webhook", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /(https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/-]{20,})/g, group: 1,
      verify: "Anyone holding it can post into the channel. Low noise, high signal." },
    { id: "discord-webhook", name: "Discord Webhook", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,})/g, group: 1 },
    { id: "discord-token", name: "Discord Bot Token", category: "messaging", severity: "CRITICAL", exposure: "leak",
      re: /(discord[_-]?(?:bot[_-]?)?token["'\s]*[:=]["'\s]*([A-Za-z0-9_-]{24}))/gi, group: 2 },
    { id: "telegram-bot", name: "Telegram Bot Token", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b/g, group: 1 },
    { id: "sendgrid", name: "SendGrid API Key", category: "messaging", severity: "CRITICAL", exposure: "leak",
      re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, group: 1 },
    { id: "mailgun", name: "Mailgun API Key", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /\b(key-[0-9a-zA-Z]{32})\b/g, group: 1 },
    { id: "mailchimp", name: "Mailchimp API Key", category: "messaging", severity: "HIGH", exposure: "leak",
      re: /\b([0-9a-f]{32}-us[0-9]{1,2})\b/g, group: 1 },
    { id: "twilio-key", name: "Twilio API Key SID", category: "messaging", severity: "HIGH", exposure: "needs-context",
      re: /\b(SK[0-9a-fA-F]{32})\b/g, group: 1,
      verify: "The SID is half a credential. It is critical when the paired 32-char secret is also present." },
    { id: "twilio-sid", name: "Twilio Account SID", category: "messaging", severity: "INFO", exposure: "by-design",
      re: /\b(AC[0-9a-f]{32})\b/g, group: 1 },

                              
    { id: "openai", name: "OpenAI API Key", category: "saas", severity: "CRITICAL", exposure: "leak",
      re: /\b(sk-proj-[A-Za-z0-9_-]{20,})\b/g, group: 1 },
    { id: "anthropic", name: "Anthropic API Key", category: "saas", severity: "CRITICAL", exposure: "leak",
      re: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/g, group: 1 },
    { id: "openai-legacy", name: "OpenAI API Key", category: "saas", severity: "CRITICAL", exposure: "leak",
      re: /\b(sk-[A-Za-z0-9]{32,})\b/g, group: 1 },
    { id: "linear", name: "Linear API Key", category: "saas", severity: "CRITICAL", exposure: "leak",
      re: /\b(lin_api_[A-Za-z0-9]{32,})\b/g, group: 1 },
    { id: "notion", name: "Notion Integration Token", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b((?:ntn_|secret_)[A-Za-z0-9]{40,})\b/g, group: 1 },
    { id: "huggingface", name: "Hugging Face Token", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b(hf_[A-Za-z0-9]{34,})\b/g, group: 1 },
    { id: "postman", name: "Postman API Key", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b(PAK[a-f0-9]{24}-[a-f0-9]{34}-[a-f0-9]{34})\b/g, group: 1 },
    { id: "airtable", name: "Airtable API Key", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b(key[a-zA-Z0-9]{14})\b(?=[^]{0,40}pat[a-zA-Z0-9]{24}\.)/g, group: 1 },
    { id: "algolia-admin", name: "Algolia Admin Key", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b((?:admin|api)-[a-f0-9]{32})\b/g, group: 1 },
    { id: "facebook-token", name: "Facebook Access Token", category: "saas", severity: "CRITICAL", exposure: "leak",
      re: /\b(EAACEdEose0cBA[A-Za-z0-9]{20,})\b/g, group: 1 },
    { id: "google-client-secret", name: "Google OAuth Client Secret", category: "saas", severity: "HIGH", exposure: "leak",
      re: /\b(GOCSPX-[A-Za-z0-9_-]{20,})\b/g, group: 1,
      verify: "Client secrets have no legitimate place in a browser bundle." },
    { id: "recaptcha-secret", name: "reCAPTCHA Secret Key", category: "saas", severity: "MEDIUM", exposure: "leak",
      re: /\b(6L[A-Za-z0-9_-]{38})\b/g, group: 1 },
    { id: "supabase-url", name: "Supabase Project URL", category: "frontend-config", severity: "INFO", exposure: "by-design",
      re: /(https?:\/\/[a-z0-9]{20}\.supabase\.co)/g, group: 1,
      verify: "Public by design. The anon key is only safe while row level security is enforced." },

                                 
    { id: "private-key", name: "Private Key Block", category: "keys", severity: "CRITICAL", exposure: "leak",
      re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g, group: 1, masked: true,
      verify: "Check whether this is documentation sample material or a real key. A real key in a bundle is critical; sample keys are noise." },
    { id: "certificate", name: "X.509 Certificate", category: "keys", severity: "INFO", exposure: "by-design",
      re: /(-----BEGIN CERTIFICATE-----)/g, group: 1, masked: true },

                                                               
    { id: "url-userinfo", name: "Credentials in URL", category: "auth", severity: "HIGH", exposure: "leak",
      re: /\b(https?:\/\/[^\/\s:@"'\\]{1,64}:[^\/\s@"'\\]{1,64}@[^\/\s"'\\]+)/g, group: 1,
      verify: "Basic auth in a URL leaks through logs, referrers and browser history." },
    { id: "mongodb-uri", name: "MongoDB Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b(mongodb(?:\+srv)?:\/\/[^\/\s:@"']{1,64}:[^\/\s@"']{1,64}@[^\/\s"']+)/g, group: 1 },
    { id: "db-dsn", name: "Database Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b((?:postgres(?:ql)?|mysql|mariadb|amqps?|redis|rediss|clickhouse|cockroachdb|mssql):\/\/[^\/\s:@"'\\]{1,64}:[^\/\s@"'\\]{1,64}@[^\/\s"'\\]+)/g, group: 1 },
    { id: "jdbc-uri", name: "JDBC Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b(jdbc:[a-z0-9]+:\/\/[^\/\s:@"']{1,64}:[^\/\s@"']{1,64}@[^\/\s"']+)/g, group: 1 },

                         
    { id: "jwt-literal", name: "Hardcoded JWT", category: "auth", severity: "MEDIUM", exposure: "needs-context",
      re: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})/g, group: 1,
      verify: "Check exp and whether it is a long-lived service token rather than a short-lived user token." },
    { id: "bearer-literal", name: "Hardcoded Authorization Header", category: "auth", severity: "HIGH", exposure: "leak",
      re: /(["']authorization["']\s*[:=]\s*["'](?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,})/gi, group: 1 },
    { id: "basic-literal", name: "Hardcoded Basic Auth Header", category: "auth", severity: "HIGH", exposure: "leak",
      re: /(["']authorization["']\s*[:=]\s*["']Basic\s+[A-Za-z0-9+/=]{12,})/gi, group: 1 },

                         
    { id: "sentry-token", name: "Sentry Auth Token", category: "observability", severity: "CRITICAL", exposure: "leak",
      re: /\b(sntrys_[A-Za-z0-9_-]{20,})\b/g, group: 1 },
    { id: "sentry-dsn", name: "Sentry DSN", category: "observability", severity: "INFO", exposure: "by-design",
      re: /(https:\/\/[a-f0-9]{16,}@[A-Za-z0-9.-]+\/[0-9]+)/g, group: 1,
      verify: "DSNs ship by design. Severity comes from the project permissions, not the DSN." },

                                                             
                                                                              
    { id: "pg-uri", name: "PostgreSQL URI with password", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b(postgres(?:ql)?:\/\/[^\s:@/]+:([^\s:@/]{3,120})@)/gi, group: 2,
      verify: "Group 1 is the whole URI. The password is group 2; the host is usually not a secret." },
    { id: "mysql-uri", name: "MySQL/MariaDB URI with password", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\bmysql:\/\/[^\s:@/]+:([^\s:@/]{3,120})@/gi, group: 1 },
    { id: "mongo-uri", name: "MongoDB URI with password", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\bmongodb(?:\+srv)?:\/\/[^\s:@/]+:([^\s:@/,]{3,120})@/gi, group: 1 },
    { id: "amqp-uri", name: "AMQP/RabbitMQ URI with password", category: "database", severity: "HIGH", exposure: "leak",
      re: /\bamqps?:\/\/[^\s:@/]+:([^\s:@/]{3,120})@/gi, group: 1 },
    { id: "redis-uri", name: "Redis URI with password", category: "database", severity: "HIGH", exposure: "leak",
      re: /\bredis(?:s)?:\/\/(?:[^\s:@/]*:)?([^\s:@/]{3,120})@/gi, group: 1 },
    { id: "ftp-uri", name: "FTP/SFTP URI with password", category: "misc", severity: "HIGH", exposure: "leak",
      re: /\bftps?:\/\/[^\s:@/]+:([^\s:@/]{3,120})@/gi, group: 1 },
    { id: "smtp-creds", name: "SMTP credentials", category: "misc", severity: "HIGH", exposure: "leak",
      re: /\bsmtp(?:s)?_?pass(?:word)?["'\s]*[:=]\s*["']?([^\s"',;}]{4,120})/gi, group: 1 },

                                            
    { id: "telegram-bot", name: "Telegram Bot Token", category: "messaging", severity: "CRITICAL", exposure: "leak",
      re: /\b(\d{6,12}:AA[A-Za-z0-9_-]{32,})\b/g, group: 1,
      verify: "A bot token is a complete control channel for that bot." },
                                                                                   
                                                                               
    { id: "pypi-token", name: "PyPI Upload Token", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g },
    { id: "bitbucket-pat", name: "Bitbucket App Password", category: "ci", severity: "CRITICAL", exposure: "leak",
      re: /\b(ATB[A-Za-z0-9]{30,})\b/g, group: 1 },
    { id: "artifactory-token", name: "Artifactory Token", category: "ci", severity: "HIGH", exposure: "leak",
      re: /\b(AP[0-9A-Za-z]{14}\d{4}AKit[A-Za-z0-9_-]{10,})\b/g, group: 1 },
    { id: "newrelic-key", name: "New Relic License/User Key", category: "observability", severity: "HIGH", exposure: "leak",
      re: /\b(NRAK-[A-Z0-9]{27}|NRJS-[a-f0-9]{19})\b/g },
    { id: "newrelic-insert", name: "New Relic Browser Insert Key", category: "observability", severity: "LOW", exposure: "leak",
      re: /\b(NRJS-[a-f0-9]{19})\b/g },
                                                                                   
                                                                   
    { id: "dynatrace-token", name: "Dynatrace API Token", category: "observability", severity: "HIGH", exposure: "leak",
      re: /\b(dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{60,})/g, group: 1 },
    { id: "mailgun-key", name: "Mailgun API Key", category: "messaging", severity: "CRITICAL", exposure: "leak",
      re: /\b(key-[0-9a-f]{32})\b/g, group: 1 },
    { id: "vault-token", name: "HashiCorp Vault Token", category: "devops", severity: "CRITICAL", exposure: "leak",
                                                                                
                                                                        
      re: /\b(hvs\.[A-Za-z0-9_-]{24,}|s\.[A-Za-z0-9]{24,})(?=[^A-Za-z0-9]|$)/g,
      postFilter: v => /hvs\./.test(v) || (/[A-Z]/.test(v) && /\d/.test(v)) },
    { id: "terraform-token", name: "Terraform Cloud Token", category: "devops", severity: "CRITICAL", exposure: "leak",
      re: /\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b/g, group: 1 },
    { id: "doppler-token", name: "Doppler API Token", category: "devops", severity: "CRITICAL", exposure: "leak",
      re: /\b(dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,})\b/g, group: 1 },
    { id: "azure-sas", name: "Azure SAS Token", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /([?&]sig=[A-Za-z0-9%+/=]{20,})/g, group: 1,
      verify: "A shared access signature grants access without any session. Report the sig value, not the URL around it." },
    { id: "gcp-signed-url", name: "Google Cloud Signed URL", category: "cloud", severity: "HIGH", exposure: "leak",
      re: /([?&]X-Goog-Signature=[A-Za-z0-9%+/=]{20,})/g, group: 1 },
    { id: "firebase-db-key", name: "Firebase Realtime Database URL", category: "cloud", severity: "MEDIUM", exposure: "needs-context",
      re: /(https:\/\/[a-z0-9-]+\.firebaseio\.com)/g, group: 1,
      verify: "The URL alone is not a credential. Report it when the database rules allow unauthenticated reads." }
  ];

                                                                               
                                                                  
  const GENERIC_SECRET_RE =
    /(?:key|api|token|secret|client|passwd|password|pass|pauth|auth|authorization|access|user|username|user_?name|email|mail|login|credential|creds|session|jwt|bearer)(?:[0-9a-z\-_\t .]{0,20})(?:\s|'|"){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|"|\s|=|\x60){0,5}([0-9a-z\-_.=@+]{6,150})(?:['"\n\r\s\x60;,)\]}]|$)/gi;

                                                                            
                                                                               
  const SECRET_NOISE_RE = new RegExp([
    "\\bAKIAIOSFODNN7EXAMPLE\\b", "\\bASIAIOSFODNN7EXAMPLE\\b", "\\bAIzaSyDOCAbC1234567890\\b",
    "\\bEXAMPLE\\b", "\\bPLACEHOLDER\\b", "\\bYOUR_?KEY\\b", "\\bREPLACE_?ME\\b", "\\bCHANGE_?ME\\b", "\\bTODO\\b",
    "\\bx{5,}\\b", "\\*{4,}", "\\b0123456789\\b", "\\babcdef123456\\b", "\\b123456789\\b",
    "\\bdummy\\b", "\\bsample\\b", "\\bredacted\\b", "\\bchangethis\\b", "\\byour-?domain\\b", "\\bexample\\.com\\b",
    "\\btest[-_]?only\\b", "\\blorem\\b", "\\bipsum\\b", "\\bfoo\\b", "\\bbar\\b", "\\bundefined\\b", "\\bnull\\b"
  ].join("|"), "i");

                                                                    
  function shapeOf(v) {
    const s = String(v);
                                                                              
                                                                                  
    if (s.length > 24) return "blob";
    if (/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(s)) return "email";
    if (/^https?:\/\//i.test(s)) return "url";
    if (/^wss?:\/\//i.test(s)) return "ws-url";
    if (/^\/[\w\-./{}:]*$/.test(s)) return "path";
    if (/^\d+(\.\d+)?$/.test(s)) return "number";
    if (/^(true|false|null|undefined|none|nil)$/i.test(s)) return "literal";
    if (/^[a-z][a-z0-9]*$/i.test(s)) return "identifier";
    if (/^[A-Z0-9_]+$/.test(s)) return "constant";
    return "blob";
  }

                                                                              
                                                                            
                                                                    
  function looksLikeCodeIdentifier(v) {
    const s = String(v || "");
    if (!s) return false;
    if (/^[A-Z][A-Z0-9_]{3,}$/.test(s)) return CODE_CONSTANT_WORD_RE.test(s);
    return /[a-z][A-Z]/.test(s) || /[A-Z][a-z]/.test(s);
  }

  function isNoise(v, extra) {
    if (!v) return true;
    if (v.length < CONFIG.minSecretLength) return true;
    if (SECRET_NOISE_RE.test(v)) return true;
                                                                              
    if (/(?:ABCDEFGHIJKLMNOPQRSTUVWXYZ|abcdefghijklmnopqrstuvwxyz|0123456789abcdef|0123456789ABCDEF)/.test(v)) return true;
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(v)) return true;
    if (/^(?:[A-Za-z]|\$|_){2,}$/.test(v)) return true;
    if (extra && SECRET_NOISE_RE.test(extra)) return true;
    return false;
  }

                                                                              
  function lineIndex(text) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    return starts;
  }

  function locate(starts, offset) {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo] + 1 };
  }

                                                                              
                                                                           
                                                                         
  function hardRedact(s) {
    let out = String(s);
    for (const pat of SECRET_PATTERNS) {
      if (pat.severity === "INFO") continue;
      let re;
      try { re = new RegExp(pat.re.source, pat.re.flags.replace("g", "")); } catch (_) { continue; }
      out = out.replace(re, "[" + pat.id + " REDACTED]");
    }
    return out;
  }

                                                                  
  function contextSnippet(text, offset, length, mask) {
    const from = Math.max(0, offset - 60);
    const to = Math.min(text.length, offset + length + 60);
    let s = text.slice(from, to);
    if (CONFIG.redactSensitive && !CONFIG.revealSecrets) {
      try { s = mask(s); } catch (_) {}
                                                                            
                                                                            
                                                          
      s = maskDisclosedPhrases(s);
    }
    s = s.replace(/\s+/g, " ").replace(/[\r\n\t]+/g, " ");
    return (from > 0 ? "..." : "") + clip(s, 220) + (to < text.length ? "..." : "");
  }

  function scanSecrets(text, file, depth) {
    const found = [];
    if (!CONFIG.scanSecrets || !text) return found;
    let starts;
    try { starts = lineIndex(text); } catch (_) { return found; }
    const l1Hashes = new Set();

                               
    for (const pat of SECRET_PATTERNS) {
      let m;
      const re = new RegExp(pat.re.source, pat.re.flags.replace("g", "") + "g");
      let guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 200) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        const raw = pat.group ? m[pat.group] : m[0];
        if (!pat.masked) {
          if (!raw || isNoise(raw)) continue;
                                                                           
          if (pat.postFilter) { try { if (!pat.postFilter(raw)) continue; } catch (_) { continue; } }
                                                                      
          if (l1Hashes.has(fnv1a(raw))) continue;
          l1Hashes.add(fnv1a(raw));
        }
        const at = locate(starts, m.index);
        found.push({
          id: pat.id, name: pat.name, category: pat.category,
          severity: pat.severity, exposure: pat.exposure,
          raw: pat.masked ? pat.name : raw,
          masked: pat.masked === true, length: m[0].length,
          shape: pat.masked ? "material" : shapeOf(raw),
          entropy: pat.masked ? null : entropyProfile(raw),
          file, line: at.line, column: at.column,
          context: contextSnippet(text, m.index, m[0].length, s => s.split(raw).join(maskValue(raw))),
          verify: pat.verify || null,
          layer: 1
        });
      }
    }

                                                               
    let m;
    let guard = 0;
    const gen = new RegExp(GENERIC_SECRET_RE.source, GENERIC_SECRET_RE.flags);
    while ((m = gen.exec(text)) !== null && guard++ < 400) {
      if (m[0].length === 0) { gen.lastIndex++; continue; }
      const value = m[1];
      if (!value) continue;
      if (l1Hashes.has(fnv1a(value))) continue;                                         
      if (isNoise(value, m[0].slice(0, m[0].length - value.length))) continue;

      const shape = shapeOf(value);
      let severity = "LOW";
      let exposure = "needs-context";
      let entropy = null;
                                                                              
                                                                             
      if ((shape === "identifier" || shape === "constant") && looksLikeCodeIdentifier(value)) continue;

      if (shape === "email" || shape === "identifier" || shape === "url" || shape === "path") {
                                                                             
        severity = "LOW";
        exposure = "needs-context";
      } else if (shape === "blob" || shape === "constant") {
        entropy = entropyProfile(value);
        if (!entropy || entropy.bits < entropy.threshold) continue;           
        severity = entropy.bits >= 5 ? "HIGH" : "MEDIUM";
        exposure = "leak";
      } else {
        continue;                                          
      }

      const at = locate(starts, m.index);
      found.push({
        id: "generic-secret", name: "Hardcoded " + shape + " in source",
        category: "generic", severity, exposure,
        raw: value, masked: false, length: value.length, shape, entropy,
        file, line: at.line, column: at.column,
        context: contextSnippet(text, m.index, m[0].length, s => s.split(value).join(maskValue(value))),
        verify: "Confirm the value is a live credential and reachable from outside the app before reporting.",
        layer: 2
      });
    }

                                                                          
    if (CONFIG.decodeBase64Blobs && (!depth || depth < 2)) {
      const seenBlobs = new Set();
      const blobs = [];
      const b64 = /[A-Za-z0-9+/]{40,}={0,2}/g;
      let bg = 0;
      while ((bg = b64.exec(text)) !== null && blobs.length < CONFIG.maxBlobsPerScript) {
        const v = bg[0];
        if (seenBlobs.has(v)) continue;
        seenBlobs.add(v);
        blobs.push({ v, at: bg.index });
      }
      const atobLit = /atob\(\s*["'`]([A-Za-z0-9+/=]{16,})["'`]\s*\)/g;
      while ((bg = atobLit.exec(text)) !== null && blobs.length < CONFIG.maxBlobsPerScript) {
        const v = bg[1];
        if (seenBlobs.has(v)) continue;
        seenBlobs.add(v);
        blobs.push({ v, at: bg.index });
      }

      for (const b of blobs) {
        let decoded = null;
        try {
          if (!nativeAtob) continue;
          const raw = nativeAtob(b.v);
          if (!raw || raw.length < 8 || raw.length > 20000) continue;
                                                               
          let printable = 0;
          for (let i = 0; i < raw.length; i++) {
            const c = raw.charCodeAt(i);
            if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
          }
          if (printable / raw.length < 0.92) continue;
          decoded = raw;
        } catch (_) { continue; }
        if (!decoded) continue;

        const inner = scanSecrets(decoded, file + " (base64 @" + b.at + ")", (depth || 0) + 1);
        for (const s of inner) {
          s.decodedFrom = "base64";
          s.context = "decoded from a base64 literal in " + file;
          found.push(s);
        }
        if (found.length > 400) break;
      }
    }

    return found;
  }

                                                                          
                                                                             
                                                                        
                                                                          
  function addNote(key, note) {
    if (notes.has(key)) return notes.get(key);
    if (notes.size >= CONFIG.maxNotes) return null;
                                                                              
                                                  
    const k = note.kind || "note";
    const n = (noteKindCount.get(k) || 0) + 1;
    if (n > CONFIG.maxNotesPerKind) {
      noteKindCount.set(k, n);
      return null;
    }
    noteKindCount.set(k, n);
                                                                             
                                                                          
    note.noteId = ++seq;
    notes.set(key, note);
    stats.notes++;
    return note;
  }

                                                                          
                                                                    
                                                                          
  const IDOR_PARAM_RE = /^(?:id|ids|uid|uuid|guid|user_?id|user_?name|account_?id|order_?id|customer_?id|client_?id|invoice_?id|bill_?id|report_?id|project_?id|issue_?id|merge_?request_?id|group_?id|team_?id|workspace_?id|org_?id|organization_?id|file_?id|attachment_?id|media_?code|message_?id|comment_?id|post_?id|article_?id|note_?id|node_?id|item_?id|parent_?id|ticket_?id|transaction_?id|payment_?id|subscription_?id|invoice_?number|board_?id|column_?id|card_?id|photo_?ids?|member_?id|responder_?user_?id|application_?id|external_?status_?check_?id|issue_?ids|label_?ids|ref|reference|resource_?id|object_?id|key|token_?id)$/i;

  function classifyIdValue(v) {
    const s = String(v);
    if (/^\d{1,10}$/.test(s)) return "sequential-int";
    if (/^\d{15,20}$/.test(s)) return "steamid";
    if (UUID_RE.test(s)) return "uuid";
    if (/^file:\d+/.test(s)) return "file-ref";
    if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(s)) {
      try {
        if (nativeAtob) {
          const d = nativeAtob(s);
          if (/^[a-z]+:\/\//i.test(d)) return "decoded-url-gid";
          if (/^\d/.test(d)) return "decoded-numeric-gid";
        }
      } catch (_) {}
      return "base64-gid";
    }
    if (/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(s)) return "email-ref";
    if (/^[a-z0-9][a-z0-9_.-]{2,39}$/i.test(s)) return "slug-or-username";
    if (/^[A-Za-z0-9_-]{20,}$/.test(s)) return "opaque-token";
    return "other";
  }

  const ENUMERABLE_SHAPES = new Set([
    "sequential-int", "steamid", "uuid", "decoded-url-gid", "decoded-numeric-gid",
    "base64-gid", "email-ref", "slug-or-username"
  ]);

                                                                              
                                                                             
  function safeIdValue(v, kind) {
    const s = String(v);
    if (!CONFIG.redactSensitive) return s;
    if (kind === "email-ref" || looksLikeJWT(s) || s.length > 32) return maskValue(s);
    const e = entropyProfile(s);
    if (e && e.bits >= 4.2) return maskValue(s);
    return s;
  }

  function addIdorCandidates(f, names, pairs, source) {
    if (!f) return;
                                                                                
                                                                               
    const byName = new Map();
    for (const p of (pairs || [])) {
      if (!p || p.length < 2) continue;
      const n = String(p[0]);
      if (!byName.has(n)) byName.set(n, []);
      byName.get(n).push(p[1]);
    }
    for (const name of names) {
      if (!IDOR_PARAM_RE.test(String(name))) continue;
      const shaped = [];
      for (const v of (byName.get(String(name)) || []).slice(0, 5)) {
        if (v === undefined || v === null) continue;
        if (looksLikeJWT(v)) continue;                               
        const kind = classifyIdValue(v);
        if (!kind) continue;
        shaped.push({ kind, value: safeIdValue(v, kind) });
        if (shaped.length >= 5) break;
      }
      if (!f.idorCandidates) f.idorCandidates = [];
      if (f.idorCandidates.some(c => c.name === name)) continue;
      f.idorCandidates.push({ name, shapes: shaped, enumerable: shaped.some(s => ENUMERABLE_SHAPES.has(s.kind)), via: source });
    }
  }

                                                                          
                                                                  
                                                                        
                                                                          
  const GQL_DOC = /^\s*(?:#[^\n]*\n\s*)*(?:(query|mutation|subscription)\b\s*([A-Za-z_]\w*)?\s*(?:\([^)]*\))?\s*\{|\{)/;
  const DID_YOU_MEAN_RE = /Did you mean ['"`]?([A-Za-z_][A-Za-z0-9_]*)['"`]?/g;
  const FIELD_MISSING_RE = /["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]? does not exist on type ["'`]?([A-Za-z_][A-Za-z0-9_]*)/g;

  function detectGraphQL(u, json, path) {
    const ops = [];
    const items = Array.isArray(json) ? json.slice(0, 20) : (json && typeof json === "object" ? [json] : []);
    for (const it of items) {
      if (!it || typeof it !== "object") continue;
      const q = typeof it.query === "string" ? it.query : null;
      const opName = typeof it.operationName === "string" ? it.operationName : null;
      if (q !== null) {
        const m = GQL_DOC.exec(q);
        if (m) ops.push({ type: m[1] || "query", operation: m[2] || opName });
      } else if (it.extensions && typeof it.extensions === "object" && it.extensions.persistedQuery) {
        ops.push({ type: "persisted", operation: opName });
      }
    }
    if (!ops.length) {
      const q = u.searchParams.get("query");
      if (q) {
        const m = GQL_DOC.exec(q);
        if (m) ops.push({ type: m[1] || "query", operation: m[2] || u.searchParams.get("operationName") });
      }
    }
    if (!ops.length && /(^|\/)(graphql|gql)(\/|$)/i.test(path)) ops.push({ type: "unknown", operation: null });
    return ops.length ? { operations: ops.slice(0, 10), batched: ops.length > 1 } : null;
  }

                                                                                 
  function maybeGraphQL(u, json, path, requestContentType, responseContentType) {
    const p = String(path || "");
    if (GQL_PATH_RE.test(p)) return true;
    if (GQL_CT_RE.test(String(requestContentType || "")) || GQL_CT_RE.test(String(responseContentType || ""))) return true;
    if (u && u.searchParams.has("query")) return true;
    if (!json || typeof json !== "object") return false;
    return Array.isArray(json)
      ? json.some(x => x && typeof x === "object" && ("query" in x || "__schema" in x || (x.data && x.data.__schema)))
      : ("query" in json || "__schema" in json || !!(json.data && json.data.__schema) || "operationName" in json);
  }

  const GQL_PATH_RE = /graphql|(^|\/)gql(\/|$)|graphiql|playground/i;
  const GQL_CT_RE = /graphql/i;

function harvestGraphQLSuggestions(text, source) {
if (!text || text.length > 200000) return 0;
                                                                               
                                                                           
                                                                            
                                                         
const norm = text.replace(/\\(["'`])/g, "$1");
let n = 0;
let m;
const re1 = new RegExp(DID_YOU_MEAN_RE.source, "g");
while ((m = re1.exec(norm)) !== null && n < 60) {
n++; stats.graphqlFields++;
addNote("gql-suggest:" + m[1], { kind: "graphql-suggestion", field: m[1], via: "did-you-mean", source });
}
const re2 = new RegExp(FIELD_MISSING_RE.source, "g");
while ((m = re2.exec(norm)) !== null && n < 120) {
n++; stats.graphqlFields++;
addNote("gql-field:" + m[2] + "." + m[1], { kind: "graphql-field", type: m[2], field: m[1], via: "error-message", source });
}
                                                                            
                                                                               
const re3 = /Cannot query field\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?\s+on type\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)/g;
while ((m = re3.exec(norm)) !== null && n < 180) {
n++; stats.graphqlFields++;
addNote("gql-field:" + m[2] + "." + m[1], { kind: "graphql-field", type: m[2], field: m[1], via: "error-message", source });
}
return n;
}

                                                                          
                                                                        
                                                                          
  const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
  const SPEC_PATH_RE = /(^|\/)(?:openapi|swagger|api-docs|api-docs\.json|spec|v[23]\/api-docs)(?:\.(?:json|ya?ml))?$|(^|\/)graphql?$|(^|\/)graphiql$|(^|\/)playground$/i;

  function looksLikeSpecURL(path) {
    return SPEC_PATH_RE.test(String(path || ""));
  }

  function ingestSpecBody(json, specUrl) {
    if (!json || typeof json !== "object") return false;
    try {
      if ((json.openapi || json.swagger) && json.paths && typeof json.paths === "object") {
        return ingestOpenAPI(json, specUrl);
      }
      if (json.data && json.data.__schema) return ingestIntrospection(json.data.__schema, specUrl, "introspection");
      if (json.__schema) return ingestIntrospection(json.__schema, specUrl, "introspection");
      if (json.info && Array.isArray(json.item)) return ingestPostman(json, specUrl);
    } catch (e) {
      fail("ingestSpec", e);
    }
    return false;
  }

  function specBaseURLs(doc, specU) {
    const out = [];
                                                                                
                                                              
    const push = s => {
      if (!s) return;
      const v = String(s).replace(/\/+$/, "");
      if (v && out.indexOf(v) < 0 && out.length < 4) out.push(v);
    };
    try {
      if (Array.isArray(doc.servers)) {
        for (const s of doc.servers) if (s && s.url) push(new URL(s.url, specU.href).href);
      }
      if (doc.host) push(specU.protocol + "//" + doc.host + (doc.basePath || ""));
      push(specU.origin + (doc.basePath || ""));
    } catch (_) {
      push(specU.origin);
    }
    if (!out.length) push(specU.origin);
    return out;
  }

  function ingestOpenAPI(doc, specUrl) {
    const specU = parseURL(specUrl);
    if (!specU) return false;
    const bases = specBaseURLs(doc, specU);
    const version = doc.openapi ? "OpenAPI " + doc.openapi : "Swagger " + (doc.swagger || "");
    const hasSecurity = !!(doc.security || doc.components && doc.components.securitySchemes);
    const hasGlobalAuth = Array.isArray(doc.security) && doc.security.length > 0;

    let count = 0;
    for (const p of Object.keys(doc.paths || {})) {
      const ops = doc.paths[p];
      if (!ops || typeof ops !== "object") continue;
      if (count >= CONFIG.maxSpecEndpoints) break;
      const shared = Array.isArray(ops.parameters) ? ops.parameters : [];
      for (const method of Object.keys(ops)) {
        const M = method.toUpperCase();
        if (!HTTP_METHODS.has(M)) continue;
        if (count >= CONFIG.maxSpecEndpoints) break;
        const op = ops[method] || {};
        const params = [], required = [];
        for (const prm of shared.concat(Array.isArray(op.parameters) ? op.parameters : [])) {
          if (!prm || !prm.name) continue;
          const nm = isSensitiveKey(prm.name) ? prm.name + "=[REDACTED]" : String(prm.name);
          if (params.indexOf(nm) < 0) params.push(nm);
          if (prm.required && required.indexOf(nm) < 0) required.push(nm);
          if (prm.schema && Array.isArray(prm.schema.enum)) {
            const e = nm + "=" + prm.schema.enum.slice(0, 8).join("|");
            if (params.indexOf(e) < 0) params.push(e);
          }
        }
        const opSec = op.security;
        const secMissing = opSec !== undefined ? !(Array.isArray(opSec) && opSec.length) : !hasGlobalAuth;
        for (const base of bases) {
          record({
            source: "spec", observed: false, authoritative: true,
            url: base + p, method: M, specKind: "openapi",
            specOrigin: specUrl, specDeclared: true,
            params, required,
            scoreBonus: 60,
            reasons: ["declared in " + version + " spec", "operation: " + (op.operationId || "(unnamed)")],
            tags: Array.isArray(op.tags) ? op.tags.slice(0, 4) : [],
            deprecated: !!op.deprecated,
            noAuthDeclared: secMissing,
            queryString: op.parameters && op.parameters.some(x => x && x.in === "query")
          });
          count++;
        }
      }
    }

    specStore.set(specUrl, {
      id: ++specSeq, kind: "openapi", title: (doc.info && doc.info.title) || specUrl,
      version, specUrl, bases, endpoints: count, noAuth: !hasGlobalAuth,
      note: !hasGlobalAuth ? "No global security requirement declared. Endpoints may be unauthenticated." : null,
      at: new Date().toISOString()
    });

    stats.specEndpoints += count;
    styled("[x-ray-eye] Parsed " + version + " spec at " + specU.host + specU.pathname + " -> " + count + " declared endpoints.", STYLE.ok);
    return true;
  }

  function ingestIntrospection(schema, specUrl, kind) {
    if (!schema || !Array.isArray(schema.types)) return false;
    const specU = parseURL(specUrl);
    if (!specU) return false;
    const roots = {};
    if (schema.queryType) roots.query = schema.queryType.name;
    if (schema.mutationType) roots.mutation = schema.mutationType.name;
    if (schema.subscriptionType) roots.subscription = schema.subscriptionType.name;

    let fields = 0;
    const rootOps = [];
    for (const t of schema.types) {
      if (!t || !t.name || !Array.isArray(t.fields)) continue;
      if (/^__/.test(t.name)) continue;
      const isRoot = roots.query === t.name || roots.mutation === t.name || roots.subscription === t.name;

                                                                                
                                                                                 
      if (t.name === "Node" || (Array.isArray(t.fields) && t.fields.some(x => x && x.name === "nodes"))) {
        addNote("gql-nodes:" + t.name, {
          kind: "graphql-relay-nodes", type: t.name,
          note: "A Relay-style 'nodes' field is exposed on this type. On connections it can return records the UI never renders. Verify authz on every nodes traversal."
        });
      }

      for (const f of t.fields) {
        if (!f || !f.name) continue;
        fields++; stats.graphqlFields++;
        const role = roots.query === t.name ? "query" : roots.mutation === t.name ? "mutation" : roots.subscription === t.name ? "subscription" : "type";
        const argNames = Array.isArray(f.args) ? f.args.map(a => a && a.name).filter(Boolean) : [];
        addNote("gql:" + t.name + "." + f.name, {
          kind: "graphql-field", type: t.name, field: f.name, role,
          args: argNames,
          idFields: argNames.filter(n => IDOR_PARAM_RE.test(n)),
          specUrl
        });
                                                                     
                                                                              
        for (const a of (f.args || [])) {
          const an = a && a.name ? String(a.name) : "";
          if (!an) continue;
          if (!/^(filter|where|\$where|orderby|order_by|sort|search|query|q|expr|expression|condition|criteria|predicate|match|rules)$/i.test(normKey(an))) continue;
          stats.gqlDangerousArgs++;
          addNote("gql-danger:" + t.name + "." + f.name + ":" + an, {
            kind: "graphql-dangerous-arg", type: t.name, field: f.name, arg: an,
            argType: a.type && a.type.name ? a.type.name : null,
            note: "Free-form argument reaching a query builder. Historically the vector for code execution when a library compiles the value (sift $where -> new Function, HackerOne 3782701, $12,000). Active test only, use probe()."
          });
        }
        if (isRoot) rootOps.push({ op: f.name, role, args: argNames });
      }
    }

    specStore.set(specUrl, {
      id: ++specSeq, kind: "graphql", title: "GraphQL " + kind, version: "",
      specUrl, bases: [specU.origin + specU.pathname], endpoints: rootOps.length,
      noAuth: null, types: schema.types.length, fields,
      note: "Introspection is enabled. The full schema, including fields the UI never calls, is public.",
      at: new Date().toISOString()
    });

    for (const r of rootOps.slice(0, CONFIG.maxSpecEndpoints)) {
      record({
        source: "spec", observed: false, authoritative: true,
        url: specU.origin + specU.pathname, method: r.role === "mutation" ? "POST" : "POST",
        specKind: "graphql", specOrigin: specUrl, specDeclared: true,
        params: r.args, required: [],
        scoreBonus: 55,
        reasons: ["GraphQL " + r.role + " field", "operation: " + r.op],
        graphql: { operations: [{ type: r.role, operation: r.op }], batched: false }
      });
    }
    stats.specEndpoints += rootOps.length;
    styled("[x-ray-eye] Parsed GraphQL " + kind + " at " + specU.host + specU.pathname + " -> " + fields + " fields, " + rootOps.length + " root operations.", STYLE.ok);
    return true;
  }

  function ingestPostman(doc, specUrl) {
    const specU = parseURL(specUrl);
    if (!specU) return false;
    let count = 0;
    const walk = items => {
      for (const it of items || []) {
        if (!it) continue;
        if (Array.isArray(it.item)) { walk(it.item); continue; }
        const req = it.request;
        if (!req || !req.url) continue;
        let raw = typeof req.url === "string" ? req.url : req.url.raw;
        if (!raw) continue;
        raw = raw.replace(/\{\{[^}]*\}\}/g, "{param}");
        const m = /^\{?([A-Za-z0-9_]+)\}?(?::([A-Za-z0-9_]+))?$/.exec(raw);
        const pathPart = m ? "/" + (m[2] || m[1]) : raw;
        record({
          source: "spec", observed: false, authoritative: true,
          url: specU.origin + pathPart, method: String(req.method || "GET").toUpperCase(),
          specKind: "postman", specOrigin: specUrl, specDeclared: true,
          scoreBonus: 45, reasons: ["declared in Postman collection"],
          queryParams: Array.isArray(req.url && req.url.query) ? req.url.query.map(q => q && q.key).filter(Boolean) : []
        });
        count++;
      }
    };
    walk(doc.item);
    specStore.set(specUrl, {
      id: ++specSeq, kind: "postman", title: (doc.info && doc.info.name) || "Postman collection",
      version: "", specUrl, bases: [specU.origin], endpoints: count, at: new Date().toISOString()
    });
    stats.specEndpoints += count;
    if (count) styled("[x-ray-eye] Imported " + count + " requests from a public Postman collection.", STYLE.ok);
    return count > 0;
  }












                                                               
                                                             
                                                                  
  
                                                           
  
                                                                              
                                                                           
                                                                          
                                              
  
                                                                              
                   
  
                                                                    
                                                                            
                                                                  
  
                                                                        
                                            
                                                                 
                                                                        
                                                                      
                          
                                                                      
  
                                                                        
                                                                             
                                                                            
                                                                             
                              
   

                                                                        
                 
                                                                        

const SEC_MAX = 400;                                                   

function secFinding(out, kind, id, severity, title, detail, where, evidence, how, basis) {
  if (out.length >= SEC_MAX) return null;
  const f = {
    id, kind, severity, title, detail: detail || "",
    where: where || "", evidence: evidence == null ? "" : String(evidence).slice(0, 300),
    how: how || "", basis: basis || "OBSERVED",
    at: new Date().toISOString()
  };
  out.push(f);
                                                                         
                                                                           
  addNote("sec:" + kind + ":" + id, {
    kind: "security-posture", label: kind, severity, title,
    where: f.where, note: detail, how, value: f.evidence, basis: f.basis
  });
  return f;
}

                                                                       
function hdr(headers, name) {
  if (!headers) return null;
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (String(k).toLowerCase() === want) return String(headers[k]);
  }
  return null;
}

                                                                        
                                                     
                                                                        

                                                                        
                                                                             
                                                
  
                                              
                                                                        
                                                                            
                                                                         
                                                                             
function splitSetCookie(raw) {
  const out = [];
  if (!raw) return out;
  const parts = String(raw)
    .split(/\s\|\s/)
    .flatMap(chunk => chunk.split(/,\s*(?=[A-Za-z0-9_\-.!#$%&'*+^_`|~]+=)/));
  for (const p of parts) {
    const s = p.trim();
    if (s) out.push(s);
  }
  return out;
}

function parseSetCookie(raw) {
  const first = String(raw || "").split(";")[0] || "";
  const eq = first.indexOf("=");
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();
  const rest = String(raw).toLowerCase();
  const isSession = !/;\s*expires\s*=/.test(rest) && !/;\s*max-age\s*=/.test(rest);
  const attr = /\b(samesite)\s*=\s*([a-z]+)/.exec(rest);
  const domain = /;\s*domain\s*=\s*([^;]+)/.exec(rest);
  return {
    name,
                                                                        
                                                             
    hasValue: value.length > 0,
    valueLength: value.length,
    secure: /;\s*secure\b/.test(rest),
    httpOnly: /;\s*httponly\b/.test(rest),
    sameSite: attr ? attr[2] : null,
    domain: domain ? domain[1].trim() : null,
    isSession
  };
}

                                                                             
                                              
const SESSION_COOKIE_RE =
  /^(?:sess(?:ion)?(?:id)?|sid|jsessionid|phpsessid|asp\.net(?:[._]sessionid)?|connect\.sid|csrf(?:token)?|xsrf|auth|__session|__secure-.*|remember_me|laravel_session|connect\.session)$/i;

                                                                               
  
                                                                      
                                                                       
                                                                            
                                                                               
                                           
function looksAbsent(f) {
  if (!f || !f.statuses || typeof f.statuses.forEach !== "function") return false;
  let seen = 0;
  let absent = true;
  f.statuses.forEach((_, status) => {
    seen++;
    if (status !== 404 && status !== 410) absent = false;
  });
  return seen > 0 && absent;
}

                                                                              
                                                                              
                                                                               
                        
function looksPersonal(text) {
  if (!text || typeof text !== "string") return false;
  return /"(?:email|phone|ssn|dob|date_of_birth|address|full_name|first_name|last_name)"\s*:|@[\w.-]+\.[a-z]{2,}|\b\d{3}-\d{2}-\d{4}\b/i
    .test(text.slice(0, 4000));
}

function analyzeSecurityHeaders() {
  const out = [];
  const seen = new Set();
  const origins = new Set();

  for (const f of store.values()) {
    if (!f.responseHeaders) continue;
                                                                             
                                                                             
                                                                                
                                                       
    if (looksAbsent(f)) continue;
    const where = f.method + " " + (f.host || "") + (f.normalizedPath || f.path || "");
    origins.add(f.host || "");
    const H = f.responseHeaders;

                                                                           
    for (const raw of splitSetCookie(hdr(H, "set-cookie"))) {
      const c = parseSetCookie(raw);
      if (!c || !c.name) continue;
                                                                                     
                                                                             
const id = "cookie-flag:" + f.host + (f.normalizedPath || f.path) + ":" + c.name;
      if (seen.has(id)) continue;
      seen.add(id);

      const looksSession = c.isSession || SESSION_COOKIE_RE.test(c.name);

      if (looksSession && !c.secure) {
        secFinding(out, "cookie-flag", id + ":no-secure",
          f.host && /^http:/i.test(f.host || "") ? "HIGH" : "MEDIUM",
          "session cookie without Secure: " + c.name,
          "The cookie is set without Secure, so it will be sent over plain http. " +
          "Any network position between the user and the host reads it.",
          where, c.name + "  (session=" + c.isSession + ")", null, "OBSERVED");
      }
      if (looksSession && !c.httpOnly) {
        secFinding(out, "cookie-flag", id + ":no-httponly", "MEDIUM",
          "session cookie without HttpOnly: " + c.name,
          "document.cookie can read this cookie, so any script on the page - " +
          "including anything injected through a DOM sink - can exfiltrate it.",
          where, c.name, null, "OBSERVED");
      }
      if (c.sameSite && c.sameSite !== "none" && c.sameSite !== "lax" && c.sameSite !== "strict") {
        secFinding(out, "cookie-flag", id + ":samesite", "LOW",
          "unrecognised SameSite value: " + c.name + "=" + c.sameSite,
          "An unrecognised SameSite value is treated as absent by browsers, which " +
          "silently removes the cross-site protection.",
          where, c.name, null, "OBSERVED");
      }
      if (c.sameSite === "none" && !c.secure) {
        secFinding(out, "cookie-flag", id + ":samesite-none", "HIGH",
          "SameSite=None without Secure: " + c.name,
          "SameSite=None opts the cookie into every cross-site context, and " +
          "without Secure it can travel over plain http.",
          where, c.name, null, "OBSERVED");
      }
      if (c.domain && c.domain.charAt(0) === ".") {
        secFinding(out, "cookie-flag", id + ":domain", "LOW",
          "cookie scoped to every subdomain: " + c.name,
          "A leading dot shares the cookie with all subdomains, so a takeover or " +
          "XSS on any sibling subdomain reads it.",
          where, "Domain=" + c.domain, null, "OBSERVED");
      }
    }

                                                                          
    if (!hdr(H, "strict-transport-security")) {
      secFinding(out, "header", "hsts:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
        "no HSTS on " + (f.normalizedPath || f.path || "/"),
        "Without Strict-Transport-Security a first request is still made over http " +
        "and can be downgraded before the redirect happens.",
        where, null, null, "OBSERVED");
    }

    const csp = hdr(H, "content-security-policy");
    if (!csp) {
      secFinding(out, "header", "csp:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
        "no Content-Security-Policy on " + (f.normalizedPath || f.path || "/"),
        "No CSP means any script that reaches an HTML sink runs unrestricted.",
        where, null, null, "OBSERVED");
    } else {
      if (/unsafe-inline/i.test(csp)) {
        secFinding(out, "header", "csp-unsafe-inline:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
          "CSP allows unsafe-inline",
          "unsafe-inline removes the main protection CSP provides against injected " +
          "script. It is the most common reason a CSP that looks present is not one.",
          where, clip(csp, 200), null, "OBSERVED");
      }
      if (/unsafe-eval/i.test(csp)) {
        secFinding(out, "header", "csp-unsafe-eval:" + f.host + (f.normalizedPath || f.path), "LOW",
          "CSP allows unsafe-eval",
          "unsafe-eval permits string-to-code conversion, which widens the gadget " +
          "surface available to any injected script.",
          where, clip(csp, 200), null, "OBSERVED");
      }
      if (/default-src\s+[^;]*\*/i.test(csp) || /script-src\s+[^;]*\*/i.test(csp)) {
        secFinding(out, "header", "csp-wildcard:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
          "CSP allows a wildcard script source",
          "A wildcard script-src allows script from anywhere, which is close to no CSP at all.",
          where, clip(csp, 200), null, "OBSERVED");
      }
    }

    if (!hdr(H, "x-frame-options") && !(csp && /frame-ancestors/i.test(csp))) {
      secFinding(out, "header", "xfo:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
        "nothing forbids framing " + (f.normalizedPath || f.path || "/"),
        "No X-Frame-Options and no CSP frame-ancestors: any site can frame this page, " +
        "which enables clickjacking and framing-based UI redress.",
        where, null, null, "OBSERVED");
    }

    if (!hdr(H, "referrer-policy")) {
      secFinding(out, "header", "referrer:" + f.host + (f.normalizedPath || f.path), "LOW",
        "no Referrer-Policy on " + (f.normalizedPath || f.path || "/"),
        "Full referrers leak to third parties and can carry identifiers out of the app.",
        where, null, null, "OBSERVED");
    }

                                                                            
    if (!hdr(H, "x-content-type-options")) {
      secFinding(out, "header", "xcto:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
        "no X-Content-Type-Options",
        "Without nosniff a browser may ignore the declared Content-Type and execute " +
        "a response that was meant to be inert data.",
        where, null, null, "OBSERVED");
    } else if (!/nosniff/i.test(String(hdr(H, "x-content-type-options")))) {
      secFinding(out, "header", "xcto-bad:" + f.host + (f.normalizedPath || f.path), "LOW",
        "X-Content-Type-Options is not set to nosniff",
        "The header is present with a value that does nothing.",
        where, hdr(H, "x-content-type-options"), null, "OBSERVED");
    }

    if (!hdr(H, "permissions-policy")) {
      secFinding(out, "header", "perms:" + f.host + (f.normalizedPath || f.path), "LOW",
        "no Permissions-Policy",
        "Powerful features - camera, microphone, geolocation, payment - stay available " +
        "to embedded third parties unless this restricts them.",
        where, null, null, "OBSERVED");
    }

    if (!hdr(H, "cross-origin-opener-policy")) {
      secFinding(out, "header", "coop:" + f.host + (f.normalizedPath || f.path), "LOW",
        "no Cross-Origin-Opener-Policy",
        "The window is shareable with cross-origin documents, which keeps tabnabbing " +
        "and cross-origin opener abuse available.",
        where, null, null, "OBSERVED");
    }

                                    
    const ver = [];
    const serverHdr = String(hdr(H, "server") || "");
    const poweredBy = String(hdr(H, "x-powered-by") || "");
    if (/\d+\.\d+/.test(serverHdr)) ver.push("Server: " + serverHdr);
    if (/\d+\.\d+/.test(poweredBy)) ver.push("X-Powered-By: " + poweredBy);
    if (ver.length) {
      secFinding(out, "header", "version:" + f.host + (f.normalizedPath || f.path), "LOW",
        "exact server version disclosed",
        "A precise version turns a vulnerability lookup into a shortlist and tells an " +
        "attacker which CVEs apply without a single probe.",
        where, ver.join(" | "),
        "Remove the banner, or at minimum the patch level.", "OBSERVED");
    }

                                                      
    const cc = String(hdr(H, "cache-control") || "").toLowerCase();
    const publiclyCached = /\bpublic\b/.test(cc) || (!/\bno-store\b|\bprivate\b/.test(cc) && /\bmax-age=\d+/.test(cc));
    if (publiclyCached && f.responseBody && looksPersonal(f.responseBody)) {
      secFinding(out, "header", "cache-sensitive:" + f.host + (f.normalizedPath || f.path),
        "MEDIUM",
        "personal data in a publicly cacheable response",
        "The response carries data that identifies people and is cacheable by shared " +
        "caches. Any intermediary - and often any user of the same network - can read " +
        "it after it was meant to be gone.",
        where, "Cache-Control: " + (hdr(H, "cache-control") || "(absent)"),
        "Return Cache-Control: no-store on responses carrying personal data.",
        "OBSERVED");
    }

    if (f.host && /^http:/i.test(f.host) && f.observed) {
      secFinding(out, "transport", "http:" + f.host + (f.normalizedPath || f.path), "HIGH",
        "API observed over plain http",
        "Credentials and personal data cross the network in the clear. On anything " +
        "past a login this is a finding on its own.",
        where, null, null, "OBSERVED");
    }

                                                                           
                                                                      
                                                                            
                                                                           
                                                                           
                     
    const acao = String(hdr(H, "access-control-allow-origin") || "").trim();
    const acac = String(hdr(H, "access-control-allow-credentials") || "").toLowerCase();
    if (acao && acao !== "*" && acao.toLowerCase() !== "null") {
      secFinding(out, "cors", "cors-reflect:" + f.host + (f.normalizedPath || f.path || ""),
        acac === "true" ? "HIGH" : "LOW",
        "a specific CORS origin is allowed: " + acao,
        acac === "true"
          ? "The response names a specific allowed origin AND allows credentials. " +
            "A browser will therefore attach cookies when " + acao + " calls this, " +
            "so that site can read the response as a logged-in user. Confirm whether " +
            "the origin is attacker-controlled or reachable via a redirect."
          : "Only " + acao + " may read this. Harmless while that origin is trusted; " +
            "it becomes a cross-origin read the moment that host is compromised or " +
            "used as an open redirect.",
        where, acao, null, "OBSERVED");
      if (!/vary/i.test(String(hdr(H, "vary") || ""))) {
        secFinding(out, "cors", "cors-no-vary:" + f.host + (f.normalizedPath || f.path || ""),
          "MEDIUM",
          "CORS varies by origin but sends no Vary: Origin",
          "A shared cache that keys only on the URL will serve one origin's response " +
          "to another. The result is both an information leak and a cache poisoning " +
          "opportunity.",
          where, "Vary: " + (hdr(H, "vary") || "(absent)"), null, "OBSERVED");
      }
    }
    const exposed = String(hdr(H, "access-control-expose-headers") || "");
    if (exposed && /\b(?:x-[a-z-]*token|x-[a-z-]*key|x-[a-z-]*secret|x-internal|x-debug|authorization)\b/i.test(exposed)) {
      secFinding(out, "cors", "cors-expose:" + f.host + (f.normalizedPath || f.path || ""),
        "MEDIUM",
        "CORS exposes internal headers to other origins",
        "Access-Control-Expose-Headers names headers that were presumably meant to " +
        "stay server-side. Any origin allowed to read this response can read them too.",
        where, exposed, null, "OBSERVED");
    }
    for (const c of (f.cors || [])) {
      if (c === "wildcard-origin-with-credentials") {
        secFinding(out, "cors", "cors-wc:" + f.host + (f.normalizedPath || f.path), "HIGH",
          "wildcard CORS origin WITH credentials",
          "Access-Control-Allow-Origin: * together with " +
          "Access-Control-Allow-Credentials: true is the combination that makes a " +
          "response readable by any site. Browsers reject the pairing at the fetch " +
          "layer, so if it works the origin is very likely reflecting instead of " +
          "literally echoing the wildcard.",
          where, clip(hdr(H, "access-control-allow-origin") || "*", 120), null, "OBSERVED");
      } else if (c === "wildcard-origin") {
        secFinding(out, "cors", "cors-wild:" + f.host + (f.normalizedPath || f.path), "LOW",
          "wildcard CORS origin",
          "Any origin may read this response. Low on its own; it matters when the " +
          "response also carries personal data or is otherwise not meant to be public.",
          where, "*", null, "OBSERVED");
      } else if (c === "null-origin-allowed") {
                                                                          
                                                                              
                                                                            
        secFinding(out, "cors", "cors-null:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
          "CORS reflects the null origin",
          "A null origin comes from sandboxed iframes and data: URLs, including " +
          "cross-origin opener abuse. Reflecting it widens who can read the response.",
          where, clip(hdr(H, "access-control-allow-origin") || "", 120), null, "OBSERVED");
      }
    }

                                                                            
    if (f.observed && !looksAbsent(f) && !f.challenge && !f.authSeen && /admin|manage|internal|system|console|settings|config|debug|actuator/i.test(String(f.normalizedPath || f.path || ""))) {
      secFinding(out, "authz", "unauth-privileged:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
        "privileged-looking route with no auth challenge",
        "The route name suggests an administrative surface and the response carried " +
        "no WWW-Authenticate and the app sent no credentials to it. That is a " +
        "hypothesis about authorization, not a confirmed gap - the check may live " +
        "in a cookie or a token the browser attached without the app setting it.",
        where, null,
        "Confirm with two accounts of different privilege. See authz.hypotheses.",
        "HYPOTHESIS");
    }
  }

  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

                                                                        
                                                                    
                                                                        

                                                                             
                                                                              
                                
                                                                        
  
                                                                           
                                                                             
                                                                              
                                                                              
                                                                              
const LEAK_SIGNATURES = [
  { id: "java-stacktrace", re: /\bat\s+[\w.$/]+\([\w./$]+\.java:\d+\)/, weight: 90,
    title: "Java stack trace in the response",
    detail: "A Java stack trace names internal classes, packages and often a framework version. It is a map of the server's internals." },
  { id: "dotnet-stacktrace", re: /System\.(?:NullReferenceException|InvalidOperationException|ArgumentException)|\bat\s+[A-Z]\w+\.[\w.]+\([\w.]+\.cs:line\s+\d+\)/,
    weight: 90, title: ".NET stack trace in the response",
    detail: "Names namespaces, assemblies and source files of the server." },
  { id: "python-traceback", re: /Traceback \(most recent call last\)[\s\S]{0,400}?File "[^"]+", line \d+/,
    weight: 90, title: "Python traceback in the response",
    detail: "Reveals file paths and library versions." },
                                                                        
                                                                     
                                                                          
                                                                           
                                                                     
  { id: "php-error", re: /Warning:|Fatal error|Parse error|Uncaught\s+\w*(?:Error|Exception)|\b(?:PDOException|ErrorException)\b/i,
    weight: 70, title: "PHP error output in the response",
    detail: "PHP errors leak file paths and occasionally query text." },
  { id: "ruby-error", re: /ActionController::\w+Exception|ActiveRecord::\w+Exception|\.rb:\d+:in/,
    weight: 85, title: "Ruby/Rails exception in the response",
    detail: "Names the controller, the model and the migration context." },
  { id: "node-error", re: /\bat\s+\/[^\s:]+\.js:\d+:\d+|node_modules\/[\w@/.-]+/,
    weight: 70, title: "Node stack trace or module path in the response",
    detail: "Reveals the install layout and dependency versions." },
                                                                                
                                                                              
                                                                           
                                                                           
  { id: "sql-error", re: /SQLSTATE\[|ORA-\d{5}|pg_query\(\)|You have an error in your SQL syntax|mysql_fetch|valid MySQL result|mysqli_sql_exception|valid MariaDB result/i,
    weight: 90, title: "database error text in the response",
    detail: "A database error names the engine and often echoes part of the statement. It is the classic route from an error page to a blind SQL injection." },
  { id: "ignition", re: /Whoops!|Ignition\\+(?:\x2f)?\w*|laravel\.com\x2fdocs\x2f\d|Whoops\\?\w*Exception/i,
    weight: 85, title: "debug exception page",
    detail: "A development-mode error page. These routinely include environment variables and source excerpts." },
                                                                                
                                                                          
                                                                              
                                                                           
                         
  { id: "debug-flag", re: /["']?(?:APP_DEBUG|DEBUG)["']?\s*[=:]\s*["']?(?:true|1)\b/i,
    weight: 75, title: "debug mode flag in the response",
    detail: "A debug flag returned to the browser means the application is running with diagnostics on." },
  { id: "env-dump", re: /["']?\b(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|DB_PASSWORD|REDIS_URL|STRIPE_SECRET|SECRET_KEY|GITHUB_TOKEN)["']?\s*[=:]\s*["'][^"']{6,}/i,
    weight: 100, title: "environment secret in the response",
    detail: "A configuration value that names a provider credential is in the response body. Treat every one of these as disclosed until proven otherwise." },
  { id: "env-names", re: /(?:process\.env\.|os\.environ\[|getenv\()/,
    weight: 55, title: "environment access shown in the response",
    detail: "The application is printing or serialising its environment." },
  { id: "webroot", re: /\/(?:var\/www|home\/[\w-]+\/|usr\/share\/nginx|inetpub\/wwwroot|srv\/http)|[A-Z]:\\(?:inetpub|xampp|wamp)/i,
    weight: 75, title: "absolute server path in the response",
    detail: "An absolute path names the deployment layout and the web root." },
  { id: "config-dump", re: /["']\b(?:DATABASE_URL|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD|REDIS_URL)["']\s*:\s*["'][^"']{8,}/,
    weight: 95, title: "serialised configuration in the response",
    detail: "A configuration object returned to the browser carries server-side settings the page never needs." },
  { id: "internal-host", re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
    weight: 45, title: "private address in the response",
    detail: "RFC1918 addresses in a response describe internal topology." },
  { id: "internal-hostname", re: /\b[a-z0-9-]+\.(?:internal|local|corp|intranet|lan|private)\b/i,
    weight: 60, title: "internal hostname in the response",
    detail: "An internal-only name in a public response gives away naming conventions and often the service layout." },

                                                                               
  { id: "git-config", re: /\[(?:core|remote "origin")\][\s\S]{0,400}?\[remote[^\]]*\]\s*url\s*=\s*\S+/i,
    weight: 100, title: "a .git/config in the response",
    detail: "A served .git/config exposes the repository layout and, when the remote carries a token, working credentials for it." },
  { id: "git-credentials", re: /\[credential\][\s\S]{0,200}?(?:helper|username|password)\s*=/i,
    weight: 100, title: "a .git/credentials file in the response",
    detail: "Credential helper configuration, sometimes with the credential itself." },
  { id: "phpinfo", re: /phpinfo\(\)|\bPHP Version\b[\s\S]{0,80}\d+\.\d+[\s\S]{0,200}?Configuration File \(php\.ini\) Path/i,
    weight: 85, title: "a phpinfo() page",
    detail: "phpinfo discloses the PHP build, every loaded module, configuration paths and often environment variables." },
  { id: "private-key", re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
    weight: 100, title: "a private key in the response",
    detail: "A PEM private key. Treat the key as compromised and rotate it - a key that reached a client cannot be un-leaked." },
  { id: "aws-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    weight: 95, title: "an AWS access key id",
    detail: "A long-lived AWS access key id. Without its secret it is half a credential, but it identifies the account and pairs with any secret found nearby." },
  { id: "sendgrid", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
    weight: 95, title: "a SendGrid API key",
    detail: "A SendGrid key can send mail as the domain, which is a phishing channel in its own right." },
  { id: "twilio", re: /\bAC[0-9a-fA-F]{32}\b/,
    weight: 80, title: "a Twilio account SID",
    detail: "The account identifier half of Twilio credentials." },
  { id: "mailgun", re: /\bkey-[0-9a-f]{32}\b/,
    weight: 90, title: "a Mailgun API key",
    detail: "A Mailgun private API key allows sending mail through the domain." },
  { id: "slack", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    weight: 95, title: "a Slack token",
    detail: "A Slack token for posting or reading as the app or the user it was issued to." },
  { id: "firebase", re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/,
    weight: 85, title: "a Firebase database key",
    detail: "A Firebase realtime-database URL with its key. The key is often a grant to read the whole database." },
  { id: "jwt-secret", re: /\b(?:JWT_SECRET|SECRET_KEY_BASE|token_secret)\s*[=:]\s*["']?[A-Za-z0-9_\-]{12,}/i,
    weight: 100, title: "a token-signing secret",
    detail: "The secret used to sign sessions or tokens. With it, tokens can be forged outright." },
  { id: "sql-dump", re: /INSERT\s+INTO\s+`?[\w.]+`?\s*\([^)]*(?:password|passwd|token|secret)[^)]*\)\s*VALUES/i,
    weight: 95, title: "an SQL dump with credential columns",
    detail: "A database export served to the browser, including password hashes or tokens." },
  { id: "cms-version", re: /<meta[^>]+name=["']generator["'][^>]+content=["'](?:WordPress|Joomla|Drupal|Magento|OpenCart|TYPO3)[\s\S]{0,20}?\d+\.\d+/i,
    weight: 60, title: "a CMS and version in the markup",
    detail: "A generator tag naming a CMS and version, which turns a vulnerability lookup into a shortlist." },
  { id: "x-generator", re: /\bx-(?:generator|powered-by)\b\s*:\s*(?:Drupal|Joomla|WordPress|Magento|TYPO3)\s*\d/i,
    weight: 60, title: "a CMS version in a response header",
    detail: "The same disclosure as a generator tag, delivered in a header." },
  { id: "backup-file", re: /\b(?:database|db|dump|backup)[\w.-]*\.(?:sql|bak|old|sql\.gz|tar\.gz)\b/i,
    weight: 80, title: "a backup or dump filename in the response",
    detail: "A reference to a database backup, often as a download link or a left-behone path." },
  { id: "internal-error-url", re: /https?:\/\/(?:[\w.-]+\.)?(?:internal|intranet|corp|local)[\w.-]*\/[\w./-]*/i,
    weight: 50, title: "an internal service URL in the response",
    detail: "An absolute URL pointing inside the network, which maps the trust boundary for a caller." }
];

                                                                              
  
                                                                            
                                                                          
                                                                            
                                                                    
                                                                             
                                                                         
                                                                       
                                                                      
function matchLeakSignatures(text) {
  const hits = [];
  if (!text || typeof text !== "string" || text.length < 12) return hits;
  for (const s of LEAK_SIGNATURES) {
    const m = s.re.exec(text);
    if (!m) continue;
    const at = m.index;
    const excerpt = clip(text.slice(Math.max(0, at - 60), at + 200), 240);
    hits.push({
      sig: s,
      excerpt: CONFIG.revealSecrets ? excerpt : maskDisclosedPhrases(excerpt)
    });
  }
  return hits;
}

                                                                          
function noteLeaks(meta) {
  const hits = matchLeakSignatures(meta.responseText);
  const host = "";
  let u = null;
  try { u = parseURL(meta.url); } catch (_) { u = null; }
  const where = (u ? String(u.host || host) : "") + (u ? String(u.pathname || "/") : "");
  for (const h of hits) {
    addNote("leak:" + h.sig.id + ":" + String(meta.method || "GET") + "|" + where, {
      kind: "leak", label: "leak", channel: CH_NETWORK,
      severity: h.sig.weight >= 90 ? "HIGH" : h.sig.weight >= 70 ? "MEDIUM" : "LOW",
      sig: h.sig.id, weight: h.sig.weight,
      title: h.sig.title, detail: h.sig.detail,
      where: String(meta.method || "GET") + " " + where,
      value: h.excerpt
    });
  }
  return hits.length;
}

                                                                          
                                                                            
                                                                  
function scanLeakText(text, where, idPrefix, labelIn) {
  const out = [];
  for (const h of matchLeakSignatures(text)) {
    secFinding(out, "leak", "leak:" + h.sig.id + ":" + idPrefix,
      h.sig.weight >= 90 ? "HIGH" : h.sig.weight >= 70 ? "MEDIUM" : "LOW",
      h.sig.title + " - " + labelIn,
      h.sig.detail, where, h.excerpt,
      "Reproduce with a request that produces the same error. If the response is " +
      "cached, purge it; errors in a CDN cache outlive the deploy that caused them.",
      "OBSERVED");
  }
  return out;
}

function analyzeResponseLeaks() {
  const out = [];
                                                                                
                                                                          
                                                                        
                
  for (const n of notes.values()) {
    if (n.kind !== "leak") continue;
    secFinding(out, "leak", "leak:" + n.sig + ":" + n.noteId, n.severity,
      n.title, n.detail, n.where, n.value,
      "Reproduce with a request that produces the same error. If the response " +
      "is cached, purge it; errors in a CDN cache outlive the deploy that " +
      "caused them.", "OBSERVED");
  }
  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

                       
  
                                                                            
                                                                              
                                                                             
                                                                            
                                                                          
                                                                           
                                                                    
  
                                                                          
                                                               
function analyzeDocumentLeaks() {
  if (typeof hasDOM === "undefined" || !hasDOM) return [];
  let src = "";
  try { src = htmlSourceSnapshot(); } catch (_) { return []; }
  if (!src) return [];
  let url = "";
  try { url = String(location.href || ""); } catch (_) { url = ""; }
  return scanLeakText(src, "document " + url, "document:" + url, "the page itself");
}

                                                                        
                          
  
                                                                             
                                                                            
                                                                        
                                                                       
                                                                 
                                                                        

                                                                      
                                                                             
const REFLECTABLE = /^[A-Za-z0-9@!#$%^&*().\-_+=]{6,}$/;

function sinkOf(body, at, valueLen) {
  const before = body.slice(Math.max(0, at - 120), at);
  const after = body.slice(at + valueLen, at + valueLen + 120);
  if (/<script[\s>][\s\S]{0,200}$/i.test(before) || /on\w+\s*=\s*["'][^"']{0,80}$/i.test(before)) {
    return { sink: "script", detail: "the value lands inside a script block or an event-handler attribute" };
  }
                                                                             
                                                                       
                                                                              
  if (/(?:href|src|action|formaction|data)\s*=\s*["'][^"']*$/i.test(before)) {
    return { sink: "url", detail: "the value lands in a URL attribute, which is the javascript: vector" };
  }
  if (/jsonp|callback\s*[:=]/i.test(before)) {
    return { sink: "jsonp", detail: "the value lands in a JSONP callback name" };
  }
                                                                  
                                                                               
                                                                             
    
                                                                           
                                                                            
                                                                           
                                     
  const win = before.slice(-60) + "@@" + after.slice(0, 60);
  if (/typeof\s+[A-Za-z_$@][\w$@]*\s*===?\s*['"]function['"]/.test(win)) {
    return { sink: "jsonp", detail: "the value is used as a JSONP callback name in a script response" };
  }
  if (/<(?:textarea|title|style|noscript)[\s>][^>]*$/i.test(before)) {
    return { sink: "markup", detail: "the value lands inside a raw-text element, where markup is not escaped" };
  }
  if (/<[^>]*$/.test(before) && /^[^>]*>/.test(after)) {
    return { sink: "html", detail: "the value lands unescaped inside an HTML tag" };
  }
  return { sink: "text", detail: "the value is reflected into the page text; escaping is not observable from the response alone" };
}

                                                                              
                                                                              
                                                                              
                                                                    
                         
const SSRF_PARAMS = /^(?:url|uri|dest|destination|target|proxy|fetch|site|host|domain|endpoint|feed|webhook|redirect_uri|image|img|file|path|src|resource|out|view|next)$/i;
const CMDI_PARAMS = /^(?:cmd|command|exec|execute|shell|ping|ip|addr|host|ns|lookup|dig|trace|target_file|file_?path|dir|user_?agent|agent)$/i;
const REDIRECT_PARAMS = /^(?:redirect|redirect_uri|return|return_url|returnurl|next|returnto|goto|target|rurl|dest|continue|to)$/i;
const NOSQL_PARAMS = /^(?:user|username|login|email|account|password|pass|q|query|search|filter|where|id)$/i;

                                                                        
                    
  
                                                                         
                                                                         
                                                                   
                                                                          
                                      
  
                                                                           
                                                                          
                                                                         
                                                                             
                     
  
                                    
  
                                                                           
                                                                            
                                                                    
                                    
                                                                         
                                                                        
                                                                    
                                                                  
                                                                       
                                                                   
                                                                     
                                      
  
                                                                         
                                                                           
                                                         
                                                                        

                                                                         
                                               
const TEMPLATE_ENGINES = [
  { id: "jinja2", label: "Jinja2 (Python)",
    errors: [/jinja2\.exceptions\.[A-Za-z]+/, /\bUndefinedError\b/, /\bTemplateSyntaxError\b/,
      /Undefined template variable/i, /jinja2\.[A-Za-z]/],
    marks: [/jinja2/i, /\.jinja2?\b/i, /\.html\.jinja\b/i],
    spans: ["mustache", "jinja-stmt", "jinja-comment"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "twig", label: "Twig (PHP)",
    errors: [/Twig_Error/, /Twig\\Error/, /UnparsedExpressionException/, /Twig\\Template/],
    marks: [/twig/i, /\.twig\b/i],
    spans: ["mustache", "jinja-stmt", "jinja-comment"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "nunjucks", label: "Nunjucks (JavaScript)",
    errors: [/nunjucks/i, /Template render error/],
    marks: [/nunjucks/i],
    spans: ["mustache", "jinja-stmt"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "blade", label: "Blade (Laravel)",
    errors: [/BladeCompilerException/, /Illuminate\\View/],
    marks: [/blade/i, /illuminate/i],
    spans: ["mustache", "jinja-stmt", "blade-raw"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "handlebars", label: "Handlebars",
    errors: [/Handlebars\.Exception/, /\bHandlebars\b/],
    marks: [/handlebars/i],
    spans: ["mustache", "handlebars-raw"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "freemarker", label: "FreeMarker (Java)",
    errors: [/freemarker\.core\.[A-Za-z]+/, /InvalidReferenceException/, /FreeMarker Template Error/],
    marks: [/freemarker/i],
    spans: ["java-el", "freemarker-dir"],
    probe: "${7*7}", probeResult: "49" },
  { id: "velocity", label: "Velocity (Java)",
    errors: [/org\.apache\.velocity/, /ParseErrorException/],
    marks: [/velocity/i],
    spans: ["java-el", "velocity-dir"],
    probe: "${7*7}", probeResult: "49" },
  { id: "thymeleaf", label: "Thymeleaf (Java)",
    errors: [/TemplateInputException/, /thymeleaf/i],
    marks: [/thymeleaf/i],
    spans: ["thymeleaf-expr"],
    probe: "[[${7*7}]]", probeResult: "49" },
  { id: "spring", label: "Spring Expression Language",
    errors: [/SpelEvaluationException/, /EL\d{4}E/, /org\.springframework\.expression/],
    marks: [/springframework/i],
    spans: ["java-el"],
    probe: "${7*7}", probeResult: "49" },
  { id: "erb", label: "ERB (Ruby)",
                                                                          
                                                                           
                                                                             
                                                                           
    errors: [/ActionView::Template::Error/, /SyntaxError in template/, /erb\.rb:\d+/,
      /ERB::|erb_exceptions|ActionView::Template::Error/],
    marks: [/\.erb\b/i, /erb\.rb/i],
    spans: ["erb"],
    probe: "<%= 7*7 %>", probeResult: "49" },
  { id: "ejs", label: "EJS (JavaScript)",
    errors: [/EJS\.Error/],
    marks: [/\bejs\b/i, /\.ejs\b/i],
    spans: ["erb"],
    probe: "<%= 7*7 %>", probeResult: "49" },
  { id: "smarty", label: "Smarty (PHP)",
    errors: [/SmartyCompilerException/, /Smarty error/],
    marks: [/smarty/i],
    spans: ["smarty"],
    probe: "{7*7}", probeResult: "49" },
  { id: "mako", label: "Mako (Python)",
    errors: [/mako\.exceptions/, /\bmako\b/],
    marks: [/\bmako\b/i, /\.mako\b/i],
    spans: ["java-el", "php-tag"],
    probe: "${7*7}", probeResult: "49" },
  { id: "razor", label: "Razor (ASP.NET)",
    errors: [/RazorParseException/, /Razor/],
    marks: [/razor/i],
    spans: [],
    probe: "@(7*7)", probeResult: "49" },
  { id: "typo3", label: "TYPO3 Fluid",
    errors: [/typo3/i, /fluid/i],
    marks: [/typo3/i, /fluid/i],
    spans: ["fluid"],
    probe: "{7*7}", probeResult: "49" },
  { id: "play", label: "Play Framework (Twirl)",
    errors: [/playframework/i, /twirl/i],
    marks: [/playframework/i, /twirl/i],
    spans: [],
    probe: "@(7*7)", probeResult: "49" },
  { id: "jsp", label: "JSP / GSP",
    errors: [/javax\.servlet\.jsp/, /org\.apache\.jasper/],
    marks: [/jsp/i, /jasper/i],
    spans: ["jsp-expr", "jsp-decl"],
    probe: "${7*7}", probeResult: "49" },
  { id: "django", label: "Django",
    errors: [/django\.template/, /TemplateSyntaxError/],
    marks: [/django/i],
    spans: ["mustache", "jinja-stmt"],
    probe: "{{7*7}}", probeResult: "49" },
  { id: "php-native", label: "PHP (native, not a template engine)",
    errors: [/Fatal error: Uncaught (?:Error|Exception)/, /Parse error: syntax error/],
    marks: [],
    spans: ["php-tag"],
    probe: null, probeResult: null }
];

                                                                          
                                                                         
                                         
  
                                                                       
                                                                           
                                    
const TEMPLATE_SPANS = [
  { id: "handlebars-raw", re: /\{\{\{[\s\S]{0,400}?\}\}\}/g, engines: ["handlebars"] },
  { id: "blade-raw", re: /\{!![\s\S]{0,400}?!!\}/g, engines: ["blade"] },
  { id: "jinja-comment", re: /\{#[\s\S]{0,400}?#\}/g, engines: ["jinja2", "twig", "nunjucks"] },
  { id: "jinja-stmt", re: /\{%[\s\S]{0,400}?%\}/g, engines: ["jinja2", "twig", "nunjucks", "blade"] },
  { id: "mustache", re: /\{\{[\s\S]{0,400}?\}\}/g, engines: ["jinja2", "twig", "nunjucks", "blade", "handlebars", "django"] },
  { id: "php-tag", re: /<\?(?!xml)[\s\S]{0,400}?\?>/g, engines: ["mako", "php-native"] },
  { id: "erb", re: /<%=?[\s\S]{0,400}?%>/g, engines: ["erb", "ejs"] },
  { id: "freemarker-dir", re: /<#[\s\S]{0,400}?>/g, engines: ["freemarker"] },
  { id: "velocity-dir", re: /#[A-Za-z]+[\s\S]{0,400}?#[\s\S]{0,400}?#end\b/g, engines: ["velocity"] },
  { id: "thymeleaf-expr", re: /\[\[[\s\S]{0,400}?\]\]/g, engines: ["thymeleaf"] },
  { id: "fluid", re: /<f:[\s\S]{0,200}?>/g, engines: ["typo3"] },
  { id: "jsp-expr", re: /\$\{[\s\S]{0,200}?\}/g, engines: ["spring", "freemarker", "velocity", "jsp", "mako"] },
  { id: "jsp-decl", re: /<%@[\s\S]{0,400}?%>/g, engines: ["jsp"] },
                                                                              
                                                                             
                                                               
  { id: "smarty", re: /\{\$[A-Za-z_][\w.\[\]'"]*\}|\{(?:if|else|elseif|foreach|for|while|section|include|assign|capture|strip|ldelim|rdelim|foreachelse|forelse)\b[\s\S]{0,300}?\}/g,
    engines: ["smarty", "typo3"] }
];

                                                                
function findTemplateSpans(text) {
  const out = [];
  if (!text) return out;
  for (const s of TEMPLATE_SPANS) {
    const re = new RegExp(s.re.source, "g");
    let m;
    while ((m = re.exec(text)) !== null) {
      out.push({
        kind: s.id,
        at: m.index,
        end: m.index + m[0].length,
        text: m[0].slice(0, 200),
        engines: s.engines
      });
      if (out.length > 400) return out;
    }
  }
  return out;
}

                                                         
  
                                                                           
                                                                           
                                                                         
                                                                          
                                                                      
                                      
function identifyTemplateEngine(text, spans) {
  const t = String(text || "");
  const errors = [];
  for (const e of TEMPLATE_ENGINES) {
    for (const re of e.errors) {
      const m = re.exec(t);
      if (m) {
        errors.push({ engine: e, at: m.index, match: m[0].slice(0, 120) });
        break;
      }
    }
  }
  if (errors.length) {
                                                                  
    const first = errors[0];
    return {
      id: first.engine.id,
      label: first.engine.label,
      confidence: "error",
      evidence: first.match,
      errors: errors,
      probe: first.engine.probe,
      probeResult: first.engine.probeResult
    };
  }

  for (const e of TEMPLATE_ENGINES) {
    if (!e.marks.length) continue;
    for (const re of e.marks) {
      const m = re.exec(t);
      if (m) {
        return {
          id: e.id, label: e.label, confidence: "fingerprint",
          evidence: m[0].slice(0, 120), errors: [],
          probe: e.probe, probeResult: e.probeResult
        };
      }
    }
  }

                                                                      
  if (spans && spans.length) {
    const kinds = [...new Set(spans.map(s => s.kind))];
    const families = [...new Set(spans.flatMap(s => s.engines))];
    return {
      id: "unknown",
      label: "an unidentified template engine (" + kinds.join(", ") + " syntax)",
      confidence: "delimiters",
      evidence: kinds.join(", "),
      errors: [],
      family: families,
      probe: null, probeResult: null
    };
  }
  return null;
}

                                                                     
  
                                                                          
                                                                         
                                                                            
                                                                       
                                                                       
function endpointForNote(note) {
  const where = String(note.where || "");
  const sp = where.indexOf(" ");
  if (sp < 0) return null;
  const method = where.slice(0, sp);
  const rest = where.slice(sp + 1);
  let best = null;
  for (const f of store.values()) {
    if (f.method !== method) continue;
    if (!rest.startsWith(String(f.host || ""))) continue;
    const p = rest.slice(String(f.host || "").length);
    if (f.normalizedPath === p || f.path === p) { best = f; break; }
    if (!best && f.responseBody && note.value &&
        String(f.responseBody).indexOf(String(note.value)) >= 0) best = f;
  }
  return best;
}

                                                                           
const tplCache = new Map();
function tplFor(note) {
  const key = note.noteId;
  if (tplCache.has(key)) return tplCache.get(key);
  let out = null;
  const f = endpointForNote(note);
  if (f && f.responseBody) {
    const body = String(f.responseBody);
    const spans = findTemplateSpans(body);
    const engine = identifyTemplateEngine(body, spans);
    const context = templateContextOf(spans, note.value, body);
    out = { engine: engine, context: context, spans: spans, body: body, endpoint: f };
  }
  tplCache.set(key, out);
  return out;
}

                                          
  
                                                                              
                                                                         
                                                                            
  
                                                                            
                                                                      
                                                                           
                                                                       
                                                                           
                                           
function evalArithmetic(src) {
  const s = String(src == null ? "" : src).trim();
  if (!s || s.length > 40) return null;
  if (!/^[\d\s+\-*/().]+$/.test(s)) return null;
  if (!/[+\-*/]/.test(s)) return null;
  let i = 0;
  const peek = () => s.charAt(i);
  const skipSpace = () => { while (i < s.length && s.charAt(i) === " ") i++; };

  function expr() {
    let v = term();
    if (v === null) return null;
    for (;;) {
      skipSpace();
      const op = peek();
      if (op !== "+" && op !== "-") return v;
      i++;
      const r = term();
      if (r === null) return null;
      v = op === "+" ? v + r : v - r;
    }
  }
  function term() {
    let v = factor();
    if (v === null) return null;
    for (;;) {
      skipSpace();
      const op = peek();
      if (op !== "*" && op !== "/") return v;
      i++;
      const r = factor();
      if (r === null) return null;
      if (op === "*") { v = v * r; }
      else { if (r === 0) return null; v = v / r; }
    }
  }
  function factor() {
    skipSpace();
    if (peek() === "(") {
      i++;
      const v = expr();
      skipSpace();
      if (peek() !== ")") return null;
      i++;
      return v;
    }
    const m = /^\d+(?:\.\d+)?/.exec(s.slice(i));
    if (!m) return null;
    i += m[0].length;
    return parseFloat(m[0]);
  }

  const out = expr();
  skipSpace();
  if (i !== s.length) return null;                                         
  if (out === null || !isFinite(out)) return null;
  return out;
}


                                                       
                                                                       
                                                                           
                                                                    
function templateContextOf(spans, value, body) {
  if (!spans || !spans.length || !value) return null;
  const v = String(value);
  if (v.length < 2) return null;
  const at = String(body || "").indexOf(v);
  if (at < 0) return null;
  for (const s of spans) {
    if (at >= s.at && at + v.length <= s.end) return { span: s, at: at, value: v };
  }
  return null;
}

                                        
    
                                                                            
                                                                      
                                                                        
                                                                           
                                                                          
                                                          
    
                                                                           
                                                                         
                                                                            
                                                    
  const THIRD_PARTY = new Map();
  function noteThirdParty(kind, url, extra) {
    const u = parseURL(url);
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return;
    let host = "";
    try { host = new URL(u.href).host; } catch (_) { return; }
    if (!host) return;
                                                
    try { if (new URL(u.href).origin === location.origin) return; } catch (_) {}
    const key = kind + "|" + u.origin + u.pathname;
    if (THIRD_PARTY.has(key)) return;
    const row = Object.assign({
      kind: kind,
      url: u.href,
      origin: u.origin,
      host: host,
      at: new Date().toISOString()
    }, extra || {});
    THIRD_PARTY.set(key, row);
    addNote("thirdparty:" + key, {
      kind: "third-party",
      label: kind,
      severity: "INFO",
      where: kind + " " + u.origin,
      value: u.href,
      note: "This page loads " + kind + " code from " + u.origin + ", which is a " +
        "different origin. The code there was NOT analysed: the browser does not " +
        "let a page read a cross-origin frame, and a cross-origin script cannot " +
        "be fetched by the page's own requests. It can be fetched by the " +
        "extension - use the Third-party code panel to have it read."
    });
  }

  function analyzeThirdParty() {
    const rows = [];
    for (const r of THIRD_PARTY.values()) rows.push(r);
    rows.sort((a, b) => (a.kind === b.kind ? a.host.localeCompare(b.host) : a.kind < b.kind ? -1 : 1));
    return rows;
  }

  function analyzeInjection() {
  const out = [];

                                                          
    
                                                                               
                                                                           
                                                                            
                                                                      
  for (const n of notes.values()) {
    if (n.kind !== "reflection" || n.sink !== "jsonp") continue;
    secFinding(out, "injection", "jsonp:" + n.noteId + ":" + n.param, "HIGH",
      "the response is JSONP and the callback is caller-supplied: " + n.param,
      "The application builds a script response by calling a function named by " +
      "the caller. The callback name reaches the same origin as the script, and " +
      "older parsers have been known to accept a name containing an expression - " +
      "which is script execution, not script injection.",
      n.where, n.evidence,
      "Request with a callback that is not an identifier and see whether the " +
      "server rejects it. Not sent by this tool.", "CANDIDATE");
  }

                                                                
    
                                                                         
                                                                             
                                                                     
    
                                                                          
                                                                      
                                                                         
                                                                            
                            
    
                                                                       
                                                                             
                                                                            
                                                                           
                                             
  for (const n of notes.values()) {
    if (n.kind !== "value-evaluated") continue;
    secFinding(out, "injection", "ssti:evaluated:" + n.noteId + ":" + n.param,
      "HIGH",
      "the submitted value was EVALUATED by the template engine: " +
        n.value + " came back as " + n.result,
      "The submitted value " + n.value + " does not appear in the response, " +
      "and its arithmetic result (" + n.result + ") does. A template engine " +
      "that evaluates an expression taken from the request is doing server-side " +
      "template injection, and what it evaluates next is not bounded by what was " +
      "asked. A coincidental match is possible - the result is a short string " +
      "and could appear by chance - so confirm with a second, different " +
      "expression before reporting it as confirmed.",
      n.where, n.evidence,
      "Confirm by submitting a second, different expression in the same " +
      "parameter and checking that its result comes back too. Not sent by " +
      "this tool.",
      "OBSERVED");
  }

                                                                
    
                                                                           
                                                                             
                                                                            
                                                                            
                                            
  for (const n of notes.values()) {
    if (n.kind !== "reflection") continue;
    const name = String(n.param || "");
    const where = n.where || "";

    if (SSRF_PARAMS.test(name)) {
      secFinding(out, "injection", "ssrf:" + n.noteId + ":" + name, "MEDIUM",
        "parameter named like a fetch target, and reflected: " + name,
        "A parameter called " + name + " is commonly handed to an outbound request. " +
        "If the server fetches whatever it is given, an attacker chooses the " +
        "destination - including 127.0.0.1 and the cloud metadata endpoint.",
        where, n.evidence,
        "Confirm with a callback URL of your own, or a request for " +
        "http://127.0.0.1/. Not sent by this tool.", "CANDIDATE");
    }
    if (CMDI_PARAMS.test(name)) {
      secFinding(out, "injection", "cmdi:" + n.noteId + ":" + name, "MEDIUM",
        "parameter named like a command argument, and reflected: " + name,
        "A parameter called " + name + " is commonly passed to a shell or to a " +
        "network utility. Where it is, command injection becomes reachable.",
        where, n.evidence,
        "Confirm with a harmless argument that has an observable effect. Not sent " +
        "by this tool.", "CANDIDATE");
    }
    if (REDIRECT_PARAMS.test(name)) {
      secFinding(out, "injection", "openredirect:" + n.noteId + ":" + name, "MEDIUM",
        "redirect-shaped parameter, and reflected: " + name,
        "A parameter called " + name + " that the application redirects to is the " +
        "standard open-redirect shape. It matters because it lends your domain's " +
        "reputation to a phishing page and defeats redirect allowlists.",
        where, n.evidence,
        "Request this with next=https://example.invalid/ and confirm the browser " +
        "is sent there. Not sent by this tool.", "CANDIDATE");
    }
                                                                       
                                                                             
                                                          
    if (/\[\$?(?:ne|gt|lt|gte|lte|regex|exists|or|and|in|nin|all)\]/i.test(name)) {
      secFinding(out, "injection", "nosql:" + n.noteId + ":" + name, "MEDIUM",
        "a query operator was submitted as a parameter name: " + name,
        "The application accepted a Mongo-style operator key. If the driver binds " +
        "the object rather than the value, this is how authentication is bypassed " +
        "without any credential.",
        where, n.evidence,
        "Confirm whether the operator changed the result set. Not sent by this tool.",
        "CANDIDATE");
    }
    if (/xml/i.test(String(n.contentType || "")) || /xml/i.test(where) || /<\?xml/i.test(String(n.evidence || ""))) {
      secFinding(out, "injection", "xxe:" + n.noteId + ":" + name, "MEDIUM",
        "XML response reflecting a parameter: " + name,
        "The response is XML and it echoed the submitted value. If the request side " +
        "is parsed with external entities enabled, this is XXE - the response type " +
        "only shows that the application is speaking XML here.",
        where, n.evidence,
        "Confirm on the request side, not the response. Not sent by this tool.",
        "CANDIDATE");
    }
  }

                                                                     
  for (const n of notes.values()) {
    if (n.kind !== "reflection") continue;
    if (["script", "url", "html", "markup", "jsonp"].indexOf(String(n.sink)) >= 0) continue;
    if (n.sqlError || n.templateEcho) continue;
    secFinding(out, "injection", "html:" + n.noteId + ":" + n.param, "LOW",
      "parameter reflected into the markup: " + n.param,
      "The value comes back inside the page. It is not in a script or URL context " +
      "as far as the response shows, so this is markup injection rather than " +
      "script execution - still useful for phishing and page defacement.",
      n.where, n.evidence, null, "CANDIDATE");
  }

                                                                        
  for (const n of notes.values()) {
    if (n.kind !== "url-credential") continue;
    if (!/redirect/i.test(String(n.label || ""))) continue;
    secFinding(out, "injection", "openredirect-hdr:" + n.noteId, "MEDIUM",
      "the response redirects to an absolute URL the caller supplied",
      "The Location header holds an absolute URL that came from the request. If " +
      "the parameter is unrestricted, that is an open redirect.",
      n.where, n.value, "Allow-list the destinations, or use relative paths.",
      "CANDIDATE");
  }
                                                                              
                                                                                
                                                                               
                                                                
  for (const n of notes.values()) {
    if (n.kind !== "reflection") continue;
    const sink = n.sink || "text";
    const sqlError = !!n.sqlError;
    const templateEcho = !!n.templateEcho;

    if (sqlError) {
      secFinding(out, "injection", "sqli:" + n.noteId + ":" + n.param,
        "HIGH",
        "parameter reflected into a database error: " + n.param,
        "The response carries a database error and the submitted value appears in " +
        "the body. Error-based SQL injection is the first thing to rule out, and it " +
        "is testable with a single quote.",
        n.where, n.evidence,
        "Send " + n.param + "=<single quote>. This tool does not send payloads; " +
        "confirm manually on a system you are authorized to test.",
        "CANDIDATE");
    } else if (templateEcho) {
                                                                              
        
                                                                          
                                                                             
                                                                           
                                                                          
                  
      const tpl = tplFor(n);
      const engineLabel = tpl && tpl.engine ? tpl.engine.label : "a template engine";
      const inTemplate = tpl && tpl.context;
      const probe = tpl && tpl.engine && tpl.engine.probe;
      secFinding(out, "injection", "ssti:" + n.noteId + ":" + n.param,
        "MEDIUM",
        inTemplate
          ? "parameter reflected inside a template expression: " + n.param
          : "parameter reflected beside template syntax: " + n.param,
        inTemplate
          ? "The submitted value appears inside a " + (tpl.context.span.kind) +
            " template expression in a response rendered by " + engineLabel + ". " +
            "Two readings, and they point in opposite directions. Either the " +
            "engine PRINTED the expression rather than running it - the safe " +
            "case, and what a template source shown on a page looks like - or " +
            "the value reached the template compiler as source, which is the " +
            "vulnerable case. This response cannot tell them apart. What " +
            "tells them apart is whether an arithmetic expression submitted in " +
            "this parameter comes back as its result."
          : "The response contains template syntax and the submitted value, " +
            "rendered by " + engineLabel + ". The two are not in the same place " +
            "in the response, so this is the weaker of the two shapes: it says " +
            "the page has a template engine and echoes the input, not that the " +
            "two are related.",
        n.where, tpl && tpl.context ? tpl.context.span.text : n.evidence,
        "Send " + n.param + "=" + (probe || "{{7*7}}") +
          (probe ? " (the probe for " + engineLabel + ")" : "") +
          ". Not sent by this tool.",
        "CANDIDATE");
    } else if (sink === "script" || sink === "url" || sink === "html" || sink === "markup") {
      secFinding(out, "injection", "xss:" + n.noteId + ":" + n.param,
        sink === "url" ? "HIGH" : "MEDIUM",
        "parameter reflected into a " + sink + " sink: " + n.param,
        "The application put " + n.param + " back into its own response and " + (n.sinkDetail || "") +
        ". A value that reaches a script context unescaped is reflected XSS.",
        n.where, n.evidence,
        "Confirm the sink executes. Not sent by this tool.",
        "CANDIDATE");
    } else {
      secFinding(out, "injection", "reflect:" + n.noteId + ":" + n.param,
        "INFO",
        "parameter reflected into the response: " + n.param,
        "The application echoes " + n.param + ". Reflection on its own is not a " +
        "vulnerability; it matters only if the value reaches an executable or " +
        "parsing context, which the response body alone cannot fully settle.",
        n.where, n.evidence, null, "CANDIDATE");
    }
  }

                                                       
    
                                                                      
    
                                                                         
                                                                         
                                                                          
                                                                          
                                                                          
                                                                           
                   
    
                                                                             
                                                                      
                                                
  for (const f of store.values()) {
    if (looksAbsent(f)) continue;
    const body = f.responseBody;
    if (!body || !String(body)) continue;
    const text = String(body);
    if (!/\{[{%#]|<[%?]?|\$\{|\[\[|<f:/.test(text)) continue;

    const where = f.method + " " + f.host + (f.normalizedPath || f.path || "");
    const spans = findTemplateSpans(text);
    const engine = identifyTemplateEngine(text, spans);
    if (!engine) continue;

    if (engine.errors && engine.errors.length) {
      const first = engine.errors[0];
      secFinding(out, "injection", "ssti:engine-error:" + f.host + (f.normalizedPath || f.path || ""),
        "HIGH",
        "the template engine threw while rendering this response: " + engine.label,
        "The response contains an exception from " + engine.label + " (" +
        first.match + "). A template engine that throws has evaluated " +
        "something it was given, and a template engine that evaluates what " +
        "it is given will evaluate what an attacker gives it. This is " +
        "evidence of a reachable template engine, not of an exploit - whether " +
        "the expression can be used to read a file or run a command is a " +
        "separate question that one request settles.",
        where, clip(text.slice(Math.max(0, first.at - 90), first.at + 170), 260),
        "Reproduce with the same input that produced this error. If the error " +
        "mentions the submitted value, the value reached the engine. Not sent " +
        "by this tool.",
        "OBSERVED");
      continue;
    }

                                                                        
                                                                     
                 
      
                                                                         
                                                                           
                                                                           
                                                                       
                                                                            
                                               
    const names = [...new Set(spans.map(s => s.kind))];
    const identified = engine.id !== "unknown";
    secFinding(out, "injection", "ssti:engine:" + f.host + (f.normalizedPath || f.path || ""),
      "MEDIUM",
      identified
        ? "this response is rendered by " + engine.label
        : "this response contains " + names.join(", ") + " template syntax",
      identified
        ? "The response names " + engine.label + ", so the page is built by a " +
          "template engine. Any input that reaches that engine is evaluated " +
          "rather than escaped. Whether any input does reach it is not " +
          "established here - this says where to look, not that something is wrong."
        : "The response contains template expressions (" + names.join(", ") +
          " syntax) but nothing that says which engine produced them. Input " +
          "that reaches a template engine is evaluated rather than escaped, so " +
          "this is where to look - but note that a template source DISPLAYED " +
          "in a page looks exactly the same, and is the opposite of " +
          "vulnerable. Nothing here says the expressions were evaluated.",
      where, clip(spans[0].text, 200),
      "Test the parameters that are reflected into this response with " +
      (engine.probe || "{{7*7}}") + ". Not sent by this tool.",
      "OBSERVED");
  }

  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

                                                                             
                                                                              
                                                                          
                                                                    
const URL_CREDENTIAL_RE = /[?&](token|access_token|auth|jwt|session|sid|api_key|apikey|secret|password|pwd|sessionid)=([^&\s#]{8,})/i;

function noteUrlCredentials(meta) {
  const u = parseURL(meta.url);
  if (!u) return 0;
  const search = String(u.search || "");
  if (!search) return 0;
  const m = URL_CREDENTIAL_RE.exec(search);
  if (!m) return 0;
  addNote("urlcred:" + String(meta.method || "GET") + "|" + String(u.host || "") + String(u.pathname || "/") + "|" + m[1], {
    kind: "url-credential", label: "credential in a URL",
    severity: "HIGH", channel: CH_NETWORK,
    param: m[1],
    where: String(meta.method || "GET") + " " + String(u.host || "") + String(u.pathname || ""),
                                                                            
                                                       
    value: m[1] + "=[value withheld]",
    note: "A credential was passed in the query string. It lands in browser history, " +
      "in the Referer sent to every third-party resource, and in every proxy log " +
      "between here and the server."
  });
  return 1;
}

                                                                              
                                                                              
  
                                                                      
                                                                               
                                                                             
                                                                               
                                        
function noteReflections(meta) {
  const text = meta.responseText;
  if (!text || typeof text !== "string") return 0;
  const u = parseURL(meta.url);
  if (!u) return 0;
  const host = String(u.host || "");
  const path = String(u.pathname || "/");
  const method = String(meta.method || "GET");

                                                                         
                                                                             
                                                        
  const location = hdr(meta.responseHeaders, "location") || "";
  if (location && /^https?:\/\//i.test(location)) {
    addNote("or:" + method + "|" + host + path, {
      kind: "url-credential", label: "reflected into Location",
      severity: "MEDIUM", channel: CH_NETWORK,
      where: method + " " + host + path,
      value: location,
      note: "The response redirects to an absolute URL supplied by the caller."
    });
  }

  const probes = [];
  const q = String(u.search || "").replace(/^\?/, "");
  for (const pair of q.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    let name = "", value = "";
    try {
      name = decodeURIComponent(pair.slice(0, eq));
      value = decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, " "));
    } catch (_) { continue; }
    if (REFLECTABLE.test(value) && value.length <= 80) probes.push({ name, value });
  }
  if (meta.requestBody && typeof meta.requestBody === "string") {
    for (const mm of meta.requestBody.matchAll(/"([A-Za-z0-9_.\-]{2,40})"\s*:\s*"([^"\\]{6,80})"/g)) {
      probes.push({ name: mm[1], value: mm[2] });
    }
  }
  if (!probes.length) return 0;

  const sqlError = /SQLSTATE\[|ORA-\d{5}|pg_query\(\)|You have an error in your SQL syntax/i.test(text);
  const templateEcho = /\{\{|\$\{|\{%|<%=/.test(text);
  const seen = new Set();
  let found = 0;

  for (const p of probes) {
    if (seen.has(p.name)) continue;
    seen.add(p.name);
    const at = text.indexOf(p.value);
    if (at < 0) continue;
    found++;
    const s = sinkOf(text, at, p.value.length);
    const n = addNote("reflect:" + method + "|" + host + path + "|" + p.name, {
      kind: "reflection", label: "parameter reflected",
      severity: "INFO", channel: CH_NETWORK,
      where: method + " " + host + path,
      param: p.name, sink: s.sink, sinkDetail: s.detail,
                                                                            
                                                                            
                                                                          
                                                                             
      contentType: String(meta.responseContentType || ""),
      sqlError, templateEcho,
                                                                        
                                                                    
      value: p.value,
      evidence: clip(text.slice(Math.max(0, at - 80), at + 160), 220),
      note: "The application reflected the submitted value " + p.name +
        " into its own response (" + s.sink + " context)."
    });
    void n;
  }

                                                            
    
                                                                       
                                                                          
                                                                         
                                                                            
    
                                                                           
                                                                        
                                                                          
            
    
                                                                         
                                                                       
                                                                            
                                         
    
                                                                           
                                                                      
                                                                             
                                          
  const evaluatedSeen = new Set();
  for (const p of probes) {
    if (evaluatedSeen.has(p.name)) continue;
    const r = evalArithmetic(p.value);
    if (r === null) continue;
    const result = String(r);
    if (result === String(p.value)) continue;
    if (text.indexOf(p.value) >= 0) continue;                             
    const at = text.indexOf(result);
    if (at < 0) continue;                                                          
    evaluatedSeen.add(p.name);
    addNote("evaluated:" + method + "|" + host + path + "|" + p.name, {
      kind: "value-evaluated", label: "submitted value was evaluated",
      severity: "HIGH", channel: CH_NETWORK,
      where: method + " " + host + path,
      param: p.name,
      value: p.value,
      result: result,
      evidence: clip(text.slice(Math.max(0, at - 110), at + 110), 240),
      note: "The submitted value " + p.value + " does not appear in the " +
        "response and its arithmetic result (" + result + ") does. A template " +
        "engine that evaluates an expression taken from the request is doing " +
        "server-side template injection."
    });
  }
  return found;
}

                                                                        
                                  
  
                                                                              
                                                                            
                                                                          
                                                                            
                                   
                                                                        

const PRIVILEGED_ROUTE_RE =
  /\/(?:admin|administrator|manage[^\/]*|internal|system|console|back-?office|billing|impersonat\w*|su|root|superuser|debug|actuator|metrics|graphql|schema|sys\/|v1\/admin)(?:[\/?]|$)/i;
const ROLE_CHECK_RE =
  /\b(?:isAdmin|isSuperUser|canAccess|hasPermission|hasRole|checkRole|role\s*===?\s*["'](?:admin|super|root|owner)["']|["']?(?:admin|superuser)["']?\s*===?\s*\w+\.role|\.includes\(["']admin["']\))\b/i;

function analyzeFunctionAuthz() {
  const out = [];

                                                                             
  for (const f of store.values()) {
    const path = String(f.normalizedPath || f.path || "");
    if (!PRIVILEGED_ROUTE_RE.test(path)) continue;
                                                                            
                                                                           
                                                                              
                                
    if (looksAbsent(f)) continue;
    const where = f.method + " " + (f.host || "") + path;

    const evidence = [];
    if (f.challenge) evidence.push("challenges with " + String(f.challenge).slice(0, 60));
    if (f.authSeen) evidence.push("the app sent credentials to it");
    if (f.specDeclared && f.noAuthDeclared) evidence.push("the spec declares no auth for it");
    if (!f.observed) evidence.push("never actually called by the page");

    if (!evidence.length) {
      secFinding(out, "authz", "bfla-noauth:" + f.host + path, "HIGH",
        "privileged route with no authentication signal: " + path,
        "The path reads as an administrative surface and nothing about the exchange " +
        "suggested it was protected: no challenge, no credentials sent, no spec " +
        "declaration of auth. The check may still be in a cookie the browser attached " +
        "automatically, so this is a hypothesis, not a finding.",
        where, null,
        "Replay the request with the cookies removed. If it answers 200 unchanged, the " +
        "route is unauthenticated. That is an active test and is not performed here.",
        "HYPOTHESIS");
    } else if (f.specDeclared && f.noAuthDeclared) {
      secFinding(out, "authz", "bfla-specauth:" + f.host + path, "MEDIUM",
        "spec declares no auth on a privileged route: " + path,
        "The application's own API description marks this privileged route as " +
        "unauthenticated. Documentation and behaviour disagree often enough to be worth " +
        "checking.",
        where, "noAuthDeclared in " + (f.specOrigin || "the spec"),
        "Call it with no credentials and with a low-privilege account.",
        "HYPOTHESIS");
    }

                                                                             
                                        
    if (!f.observed) continue;
    const base = path.replace(PRIVILEGED_ROUTE_RE, "/").replace(/\/+$/, "") || "/";
    for (const g of store.values()) {
      if (g === f) continue;
      const gp = String(g.normalizedPath || g.path || "");
      if ((g.normalizedPath || g.path || "") === base && g.observed) {
        secFinding(out, "authz", "bfla-parity:" + f.host + path + "|" + gp, "MEDIUM",
          "same resource at two privilege levels: " + base + " and " + gp,
          "The application exposes this resource both plainly and under an " +
          "administrative prefix. That is the shape of a function-level gap: the " +
          "plain route may or may not enforce the same check.",
          f.method + " " + (f.host || "") + gp + "  /  " + f.method + " " + (f.host || "") + path,
          null,
          "Compare the two responses with a low-privilege account. Identical bodies " +
          "means the admin prefix adds nothing.",
          "HYPOTHESIS");
      }
    }
  }

                                                                            
                                                                               
                                                                               
                                          
  const hasPrivileged = out.length > 0;
  if (hasPrivileged) {
    let checks = 0;
    const samples = [];
    for (const f of store.values()) {
      if (!f.sources) continue;
                                                                                
      void f;
    }
                                                        
    for (const n of notes.values()) {
      if (n.kind !== "role-check") continue;
      checks++;
      if (samples.length < 6) samples.push(n.where + (n.note ? "  " + clip(n.note, 120) : ""));
    }
    if (checks) {
      secFinding(out, "authz", "bfla-clientrole:" + checks, "MEDIUM",
        "role enforcement appears to live in the client: " + checks + " check(s)",
        "The bundle decides who may see or call something. Anything the browser " +
        "enforces is not enforced at all - the same routes are still callable. " +
        "Client-side gating is a usability decision, not a control.",
        samples[0] || "", samples.join(" | "),
        "Call the underlying endpoint directly with a low-privilege account.",
        "HYPOTHESIS");
    }
  }

                                                                   
    
                                                                         
                                                                      
                                                                         
                                                                             
  for (const f of store.values()) {
    if (!f.observed || looksAbsent(f)) continue;
    const method = String(f.method || "").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) continue;
    if (f.challenge || f.authSeen) continue;
    const path = f.normalizedPath || f.path || "/";
    secFinding(out, "authz", "authz-write-noauth:" + method + ":" + f.host + path, "MEDIUM",
      "state-changing " + method + " with no authentication signal: " + path,
      "The application issued a " + method + " that changed or can change state, " +
      "and nothing about the exchange suggested protection: no challenge, and no " +
      "credentials sent. A cookie the browser attached automatically would not " +
      "show up here, so this is a hypothesis rather than a finding.",
      method + " " + f.host + path,
      f.requestContentType ? "content-type: " + f.requestContentType : null,
      "Replay with the cookie removed. If it still answers 2xx, the route is " +
      "unauthenticated. That is an active test and is not performed here.",
      "HYPOTHESIS");
  }

                                                   
  for (const f of store.values()) {
    const body = f.responseBody;
    if (!body || !/"__schema"\s*:|"__type"\s*:/.test(String(body))) continue;
    if (looksAbsent(f)) continue;
    const path = f.normalizedPath || f.path || "/";
    secFinding(out, "authz", "gql-introspection:" + f.host + path,
      f.authSeen || f.challenge ? "INFO" : "MEDIUM",
      "GraphQL introspection answered" + (f.authSeen || f.challenge ? " for an authenticated caller" : " with no auth signal"),
      "Introspection hands over the entire schema - every type, every field, every " +
      "argument - which is a complete map of the API to anyone who asks. It is " +
      "usually disabled in production for exactly that reason.",
      f.method + " " + f.host + path, "types: " +
      (String(body).match(/"name"\s*:\s*"[^"]+"/g) || []).slice(0, 5).join(", "),
      "Disable introspection in production, or gate it behind authentication.",
      f.authSeen || f.challenge ? "OBSERVED" : "HYPOTHESIS");
  }

                                                                            
    
                                                                            
                                               
    
                                                      
    
                                                                        
                                                                       
                                             
    
                                                                         
                                                                    
                                                                          
                                                                         
                                        
    
                                                                          
                                                                         
                                    
  let formHtml = "";
  try { formHtml = htmlSourceSnapshot(); } catch (_) { formHtml = ""; }
  if (formHtml) {
    const forms = formHtml.match(/<form\b[^>]*>[\s\S]{0,4000}?<\/form>/gi) || [];
    let privilegeSeen = 0;
    for (let fi = 0; fi < forms.length && fi < 12; fi++) {
      const f = forms[fi];
      const openTag = /<form\b[^>]*>/i.exec(f);
      if (!openTag) continue;
      const body = f.slice(openTag[0].length);
      const method = (/method\s*=\s*["']?([a-z]+)/i.exec(openTag[0]) || [])[1] || "get";
      const action = (/action\s*=\s*["']([^"']*)["']/i.exec(openTag[0]) || [])[1] || "";
      const hasToken = /csrf|xsrf|_token|authenticity|__requestverificationtoken/i.test(f);
      const fields = (body.match(/(?:name|id)\s*=\s*["']([^"']+)["']/gi) || [])
        .map(x => (x.match(/["']([^"']+)["']/) || [])[1]).filter(Boolean);
      const privilege = fields.some(n => /^(role|admin|is_?admin|permission|group|owner|uid|user_?role|is_?super_?user)$/i.test(n));
      const password = fields.some(n => /^(pass(word)?|pwd|otp|pin|secret)$/i.test(n));

      if (privilege && !hasToken) {
        privilegeSeen++;
        secFinding(out, "authz", "csrf-missing:document", "MEDIUM",
          "a form sets a privilege field with no CSRF token",
          "The form posts a role or ownership field and carries nothing that " +
          "identifies the session as the one that loaded it. Any page can make a " +
          "browser submit it.",
          "document " + (typeof location !== "undefined" ? location.href : ""),
          fields.slice(0, 5).join(", "),
          "Add a per-session token to the form and verify it server-side.",
          "HYPOTHESIS");
        continue;
      }

                                                                        
        
                                                                         
                                                                         
                                                                       
                                                 
      if (!hasToken && /^(?:post|put|patch|delete)$/i.test(method) &&
          (password || /logout|delete|remove|update|change|transfer|pay/i.test(action))) {
        secFinding(out, "authz", "csrf-missing:form:" + fi, "LOW",
          "a form posts to the application with no CSRF token",
          "This form changes something and carries nothing that ties the " +
          "submission to the session that loaded it. " +
          (password
            ? "It is a login form, so the shape is a login CSRF: a page can " +
              "make the victim sign in as an account the attacker controls, " +
              "and anything they type afterwards goes to it."
            : "Any page can make a browser submit it."),
          "document " + (typeof location !== "undefined" ? location.href : ""),
          (action ? "action=" + action + "  " : "") + "method=" + method +
            "  fields: " + fields.slice(0, 5).join(", "),
          "Add a per-session token to the form and verify it server-side. For " +
          "a login form, a SameSite cookie on the session is the usual answer.",
          "HYPOTHESIS");
      }
    }
  }

                                                                            
  for (const j of jwtStore.values()) {
    const adminish = (j.signals || []).some(s => s.id === "admin-claim" || s.id === "privilege-claim");
    if (!adminish) continue;
                                                                               
                                                                           
                                     
    secFinding(out, "authz", "jwt-role-claim:" + fnv1a(String(j.sub || "") + String(j.iss || "")),
      "MEDIUM",
      "token carries an administrative claim",
      "A token in the browser carries a role or admin claim. Role claims are " +
      "attacker-editable only if the signature check is weak, so check the token " +
      "before assuming the claim decides anything server-side.",
      "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"),
                                                                            
                                                                        
                                                                         
                                                                       
                                        
      j.token || j.masked || "", null, "OBSERVED");
  }

  return out.sort((a, z) => sevRank(z.severity) - sevRank(a.severity));
}

                                                                               
function noteRoleChecks(text, file) {
  if (!text || !ROLE_CHECK_RE.test(text)) return 0;
  let n = 0;
  const re = new RegExp(ROLE_CHECK_RE.source, "g");
  let m;
  while ((m = re.exec(text)) !== null && n < 4) {
    addNote("rolecheck:" + file + ":" + m.index, {
      kind: "role-check", label: "client-side role check",
      file, severity: "LOW", channel: CH_STATIC,
      value: clip(m[0], 80),
      note: "A role check in shipped JavaScript. It gates the UI only; the endpoint " +
        "it protects is still callable."
    });
    n++;
  }
  return n;
}

                                                                        
                      
                                                                        

function analyzeSessions() {
  const out = [];

                                                                             
  const byArea = {};
  for (const s of storageStore.values()) {
    const key = String(s.area || "?");
    byArea[key] = (byArea[key] || 0) + 1;
    if (s.hasJwt) {
      secFinding(out, "session", "token-localstorage:" + s.name, "MEDIUM",
        "token held in " + s.area + ": " + s.name,
        "Web storage is readable by every script on the origin and survives the tab " +
        "closing. A token here is exposed to any XSS and persists indefinitely.",
        s.area + " / " + s.name,
                                                    
          
                                                                          
                                                                                 
                                                                            
                                                                         
                                                                       
                                                                            
                                                                   
        s.raw || s.masked || "(withheld)",
        "If this is a session token, move it to a Secure, HttpOnly cookie. " +
        "If it is a refresh token, accept the exposure and keep it short-lived.",
        "OBSERVED");
    }
  }

                                                    
    
                                                                          
                                                                            
                                                                              
                                         
  const now = Math.floor(Date.now() / 1000);
  for (const j of jwtStore.values()) {
    const signals = j.signals || [];
    if (signals.some(s => s.id === "alg-none")) {
      secFinding(out, "session", "alg-none:" + fnv1a(String(j.sub || "") + String(j.iss || "")),
        "HIGH", "an unsigned token (alg: none)",
        "The token carries alg:none, so there is no signature for a server to " +
        "verify. If the server accepts it, anyone can mint a token for any user - " +
        "privilege escalation by construction rather than by exploitation.",
        "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"), j.token || j.masked || "",
        "Replay a token with a forged role against a low-privilege endpoint. " +
        "That is an active test and is not performed here.", "OBSERVED");
    }
    const weak = signals.find(s => s.id === "weak-secret");
    if (weak) {
      secFinding(out, "session", "jwt-weak-secret:" + fnv1a(String(j.sub || "") + String(j.iss || "")),
        "HIGH", "a token signed with a guessable secret",
        "The signing secret was recovered from a small dictionary of common " +
        "values. Anyone holding the same secret can mint a valid token for any user.",
        "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"), weak.detail || "",
        "Rotate it, and use a long random value.", "OBSERVED");
    }
    if (!j.exp || !j.iat) continue;
    const ttlDays = (j.exp - j.iat) / 86400;
    if (ttlDays > 30) {
      secFinding(out, "session", "token-ttl:" + fnv1a(String(j.sub || "") + String(j.iss || "")), "MEDIUM",
        "token valid for " + Math.round(ttlDays) + " days",
        "A token with a long lifetime cannot be recalled. Rotating a leaked " +
        "credential does nothing until this expires, so the blast radius of a leak " +
        "is the whole TTL.",
        "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"),
        "iat " + new Date(j.iat * 1000).toISOString() + " -> exp " + new Date(j.exp * 1000).toISOString(),
        null, "OBSERVED");
    }
  }

                                                                             
                                                                             
                                                                            
                             
  const logoutSignals = [...notes.values()].filter(n => n.kind === "logout-signal");
  if (logoutSignals.length) {
    secFinding(out, "session", "logout", "INFO",
      "logout behaviour observed: " + logoutSignals.length + " signal(s)",
      "The application performed a client-side logout step. Whether the session is " +
      "actually revoked is server-side and invisible from here - a cleared localStorage " +
      "with a still-valid token is the common failure.",
      logoutSignals[0].file || "", logoutSignals.map(s => clip(s.note || "", 80)).slice(0, 3).join(" | "),
      "Reuse the token after logout. If it still works, revocation is missing.",
      "HYPOTHESIS");
  }

                                                                            
  if (byArea.cookie) {
    secFinding(out, "session", "cookies-present", "INFO",
      byArea.cookie + " cookie(s) readable from JavaScript",
      "These are the cookies document.cookie can see, which excludes every " +
      "HttpOnly cookie. Anything not listed here may still be set with HttpOnly - " +
      "absence is not evidence of absence.",
      "document.cookie", null, null, "OBSERVED");
  }

                                                            
    
                                                                             
                                                                            
                                                                              
  for (const f of store.values()) {
    if (!f.responseHeaders || looksAbsent(f)) continue;
    const path = f.normalizedPath || f.path || "/";
    for (const raw of splitSetCookie(hdr(f.responseHeaders, "set-cookie"))) {
      const c = parseSetCookie(raw);
      if (!c || !c.name) continue;
      const id = "cookie-flag:" + f.host + path + ":" + c.name;
      const rest = String(raw).toLowerCase();

      if (!c.isSession && /;\s*max-age=(\d+)/.test(rest)) {
        const secs = parseInt(/\;\s*max-age=(\d+)/.exec(rest)[1], 10);
        if (secs > 86400 * 30) {
          secFinding(out, "session", "cookie-longlife:" + f.host + path + ":" + c.name, "MEDIUM",
            "cookie persists for " + Math.round(secs / 86400) + " days: " + c.name,
            "A credential that lives for a year cannot be recalled. Clearing " +
            "browser data is the only reliable revocation the user has, and most " +
            "will not think to do it after a shared machine or a lost laptop.",
            "cookie " + c.name, "Max-Age=" + secs,
            "Give it a short life and re-issue it, so a leak stops mattering quickly.",
            "OBSERVED");
        }
      }

      if (SESSION_COOKIE_RE.test(c.name) && c.isSession && !/;\s*path\s*=/i.test(rest)) {
        secFinding(out, "session", "cookie-no-expiry:" + f.host + path + ":" + c.name, "LOW",
          "session cookie with no Expires, no Max-Age and no Path: " + c.name,
          "Without an explicit Path the cookie is scoped by the server's directory, " +
          "so the same name can appear several times with different scopes. That " +
          "makes it hard to reason about which one a request actually carries.",
          "cookie " + c.name, raw, null, "OBSERVED");
      }
    }
  }

                                                                  
                                                                             
  for (const n of notes.values()) {
    if (n.kind !== "url-credential") continue;
    secFinding(out, "session", "token-in-url:" + n.noteId + ":" + n.param, "HIGH",
      "a credential is passed in the URL: " + n.param,
      "A token in the query string is written to browser history, sent in the " +
      "Referer header to every third-party resource the page loads, and logged by " +
      "every proxy in between. It should be a header or a cookie, never a parameter.",
      n.where, n.value, "Move the credential to an Authorization header.", "OBSERVED");
  }

  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

                                                                        
                                 
                                                                        

                                                                            
                                                                             
                                                                          
                                                                            
                                                                            
  
                                                                             
                                                                      
                                                                             
                                                                          
const headerBackup = new Map();
const HEADER_BACKUP_CAP = 500;

function rememberHeaderRow(row) {
  if (!row || !row.url || !row.headers) return;
  const headers = {};
  for (const [k, v] of Object.entries(row.headers)) {
    if (v == null) continue;
    headers[String(k).toLowerCase()] = String(v);
  }
  if (!Object.keys(headers).length) return;
  headerBackup.set(String(row.url), {
    url: String(row.url),
    method: String(row.method || "GET").toUpperCase(),
    status: typeof row.status === "number" ? row.status : undefined,
    headers,
    source: row.source || "headers",
    at: Date.now()
  });
  if (headerBackup.size > HEADER_BACKUP_CAP) {
    const drop = headerBackup.size - HEADER_BACKUP_CAP;
    let n = 0;
    for (const k of headerBackup.keys()) {
      headerBackup.delete(k);
      if (++n >= drop) break;
    }
  }
}

function setExternalHeaders(list) {
  let n = 0;
  for (const e of (list || [])) {
    if (!e || !e.url || !e.headers) continue;
    try {
      rememberHeaderRow({
        url: e.url, method: e.method, status: e.status,
        headers: e.headers, source: "webRequest"
      });
                                                                           
                                                                            
                                                                            
                                                                 
      record({
        source: "webRequest",
        url: e.url,
        method: e.method || "GET",
        observed: true,
        status: typeof e.status === "number" ? e.status : undefined,
        responseHeaders: e.headers,
                                                                              
                                                                         
                                               
        scoreBonus: 30
      });
      n++;
    } catch (err) { fail("setExternalHeaders", err); }
  }
  return n;
}

                                                                        
                         
  
                                                                          
                                                                            
                                                                            
                                                                              
  
                                                         
                                                                         
                                                                                
                                                                             
                                                
                                                       
                                                                        

const PARAM_CATEGORIES = [
                                       
  { cat: "idor", re: /^(?:[iu]id|guid|uuid|[a-z]{2,20}_?id|.*_?ids)$/i,
    strict: /^(?:id|uid|uuid|guid|user_?id|account_?id|tenant_?id|org_?id|organisation_?id|customer_?id|client_?id|order_?id|invoice_?id|project_?id|member_?id|role_?id|group_?id|session_?id|parent_?id|owner_?id|file_?id|doc_?id)$/i,
    next: "Fetch the same object with an account that should not own it and compare the responses.",
    why: "identifies another object's record, which is what object-level authorization is checked against" },

                                   
  { cat: "ssrf", re: /^(?:url|uri|url_?s|link|href|src|site|host|hostname|ip|ip_?addr|domain|target|dest|destination|endpoint|callback|callback_?url|webhook|webhook_?url|notify_?url|hook|feed|proxy|gateway|remote|remote_?url|resource|img|image|avatar|og_?url|page_?url|return_?url|referrer|referer|continue_?url)$/i,
    strict: /^(?:url|uri|url_?s|link|site|host|hostname|domain|endpoint|callback|callback_?url|webhook|webhook_?url|notify_?url|feed|proxy|remote_?url|img|image|og_?url|page_?url)$/i,
    next: "Point it at a callback you control, or at 169.254.169.254, and see whether the server makes the request.",
    why: "a value the server may fetch, which makes it a server-side request forgery target" },

                                       
  { cat: "file", re: /^(?:file|filename|file_?name|filepath|file_?path|path|dir|directory|upload|upload_?file|attachment|document|doc|archive|temp|template|import|export|bulk|csv|folder|image_?path|avatar|save_?as|destination|output|input)$/i,
    strict: /^(?:file|filename|file_?name|filepath|file_?path|path|dir|directory|upload|attachment|document|archive|template|import|export|folder|save_?as|output|input)$/i,
    next: "Try a path traversal sequence and an unexpected extension. Confirm nothing is written and nothing executes.",
    why: "handles a filename or path, which is where traversal, overwrite and upload issues live" },

                    
  { cat: "redirect", re: /^(?:next|next_?url|return|return_?url|returnurl|returnto|return_?to|redirect|redirect_?url|redirect_?uri|redirectto|continue|continue_?url|goto|go|dest|target|rurl|to|uri|path|continue_?path|back)$/i,
    strict: /^(?:next|next_?url|return|return_?url|returnurl|redirect|redirect_?url|redirect_?uri|continue|goto|rurl|continue_?path|back)$/i,
    next: "Request it with an external destination such as https://example.invalid/ and see whether the browser is sent there.",
    why: "a value the application redirects to, which is the standard open-redirect shape" },

                              
  { cat: "auth", re: /^(?:login|log_?in|signin|sign_?in|username|user|email|password|passwd|pwd|pass|otp|code|mfa|2fa|token|access_?token|refresh_?token|id_?token|auth|authorization|otp_?code|verification|captcha|reset|forgot|new_?password|sso|saml|oauth|oauth_?code|callback|state|nonce|api_?key|apikey|secret|session)$/i,
    strict: /^(?:login|signin|username|password|passwd|otp|code|mfa|2fa|token|access_?token|refresh_?token|auth|captcha|reset|forgot|sso|saml|oauth|oauth_?code|api_?key|secret|session)$/i,
    next: "Walk the flow with a throwaway account and note each step that changes state without proving who asked.",
    why: "belongs to an authentication or session flow, where state transitions are the question" },

                                             
  { cat: "business", re: /^(?:price|amount|total|subtotal|cost|fee|discount|discount_?pct|coupon|promo|quantity|qty|units|balance|credit|transfer|payment|plan|tier|role|status|state|owner|ownership|approved|approval|verified|active|enabled|locked|banned|workflow|stage|step)$/i,
    strict: /^(?:price|amount|total|subtotal|discount|quantity|qty|balance|credit|transfer|role|status|owner|approved|verified|active|plan|tier)$/i,
    next: "Change one field by one step and check the server still validates it rather than trusting the client.",
    why: "a field the client proposes and the server is supposed to decide, which is where price and role logic breaks" },

                                          
  { cat: "massassign", re: /^(?:role|roles|is_?admin|admin|is_?staff|is_?super|permission|permissions|scope|scopes|group|groups|verified|approved|active|status|balance|credit|price|owner_?id|tenant_?id|account_?id|plan|tier|subscription|email|username|user_?id|created_?by|internal)$/i,
    strict: /^(?:role|roles|is_?admin|admin|is_?super|permission|permissions|scope|verified|approved|balance|price|owner_?id|tenant_?id|plan|tier|internal)$/i,
    next: "Send the field in the request body and see whether the server accepts it or ignores it.",
    why: "a property the client can propose that a server should be the only authority for" },

                       
  { cat: "sqli", re: /^(?:id|order|orderby|order_?by|sort|sortby|group|groupby|filter|where|q|query|search|find|keyword|limit|offset|page|per_?page|fields|select|column|table)$/i,
    strict: /^(?:order|orderby|sort|sortby|groupby|filter|q|query|search|keyword|limit|offset|per_?page|fields|select)$/i,
    next: "Send a single quote and compare the response with a clean one.",
    why: "shapes a query, which is where a value reaching the query layer matters" },

                                                       
  { cat: "client-sink", re: /^(?:message|msg|comment|note|notes|content|body|text|title|description|label|search|q|name|display|html|markdown)$/i,
    strict: /^(?:message|msg|comment|note|content|body|text|title|description|html)$/i,
    next: "Confirm the value is escaped in every context it lands in, not just the one you tested.",
    why: "free text the application may place into a document" }
];

const GRAPHQL_PARAM_RE = /^(?:operationName|operation|variables|query|mutation|subscription|field|fragment)$/i;

                                                                             
                                                                             
                                               
function noteParameters(meta) {
  const u = parseURL(meta.url);
  if (!u) return 0;
  const host = String(u.host || "");
  const path = String(u.pathname || "/");
  const method = String(meta.method || "GET");
  const where = method + " " + host + path;
  let n = 0;

  const emit = (name, source, value) => {
    if (!name || name.length > 64) return;
    const id = method + "|" + host + path + "|" + source + "|" + name;
    const cats = [];
    for (const r of PARAM_CATEGORIES) {
      if (r.strict.test(name)) { cats.push(r.cat); }
      else if (r.re.test(name)) { cats.push(r.cat); }
    }
    if (GRAPHQL_PARAM_RE.test(name)) cats.push("graphql");
    addNote("param:" + id, {
      kind: "param", label: "parameter",
      channel: CH_NETWORK,
      param: name, source, method, where,
      host, path,
                                                                         
                                                          
      reflected: !!value && String(meta.responseText || "").indexOf(String(value)) >= 0,
      isInt: /^\s*-?\d+\s*$/.test(String(value || "")),
      isUrl: /^https?:\/\//i.test(String(value || "")),
      isBool: /^(?:true|false|0|1)$/i.test(String(value || "")),
      categories: cats,
                                                                              
                                                                               
      shape: String(value == null ? "" : value).slice(0, 40),
      value: CONFIG.revealSecrets ? String(value).slice(0, 80)
        : (String(value).slice(0, 8) + "...")
    });
    n++;
  };

                 
  const search = String(u.search || "").replace(/^\?/, "");
  if (search) {
    for (const pair of search.split("&")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      const rawName = eq < 0 ? pair : pair.slice(0, eq);
      const rawVal = eq < 0 ? "" : pair.slice(eq + 1);
      let name = rawName, value = rawVal;
      try { name = decodeURIComponent(rawName); } catch (_) {}
      try { value = decodeURIComponent(rawVal.replace(/\+/g, " ")); } catch (_) {}
      emit(name, /^\[|^\$/.test(rawName) ? "operator" : "query", value);
    }
  }

         
  const body = String(meta.requestBody || "");
  if (body) {
    const json = safeParse(body);
    const walk = (obj, prefix, depth) => {
      if (!obj || typeof obj !== "object" || depth > 4) return;
      for (const k of Object.keys(obj).slice(0, 40)) {
        const v = obj[k];
        const name = prefix ? prefix + "." + k : k;
        if (v && typeof v === "object" && !Array.isArray(v)) { walk(v, name, depth + 1); continue; }
        emit(name, Array.isArray(v) ? "body" : "body",
          typeof v === "object" ? JSON.stringify(v).slice(0, 40) : String(v));
      }
    };
    if (json && typeof json === "object") walk(json, "", 0);
    else {
      for (const pair of body.split(/[&;]/)) {
        if (!pair) continue;
        const eq = pair.indexOf("=");
        if (eq <= 0) continue;
        let name = pair.slice(0, eq), value = pair.slice(eq + 1);
        try { name = decodeURIComponent(name); } catch (_) {}
        try { value = decodeURIComponent(value.replace(/\+/g, " ")); } catch (_) {}
        emit(name, "form", value);
      }
    }
  }

                                                                            
                                                               
  const q = /(?:[?&]query=|\"query\"\s*:\s\")([^&\"]+)/i.exec(search + " " + body);
  if (q) {
    const vars = /variables\s*[:=]\s*(\{[^}]*\})/i.exec(decodeURIComponent(q[1] || "") + " " + body);
    if (vars) {
      try {
        walk2(vars[1]);
      } catch (_) {}
    }
  }
  function walk2(text) {
    for (const m of String(text).matchAll(/"([A-Za-z_$][\w$]*)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)/g)) {
      let v = m[2];
      if (/^"/.test(v)) { try { v = JSON.parse(v); } catch (_) {} }
      emit(m[1], "graphql-var", String(v));
    }
  }

  return n;
}

                                                                        
                   
  
                                                                          
                                                                    
                                                                       
                                               
                                                                        

const CAT_META = {
  idor:        { label: "IDOR / BOLA",        group: "authz" },
  ssrf:        { label: "SSRF",               group: "injection" },
  file:        { label: "file handling",      group: "injection" },
  redirect:    { label: "redirect",           group: "injection" },
  auth:        { label: "authentication",     group: "session" },
  business:    { label: "business logic",     group: "authz" },
  massassign:  { label: "mass assignment",    group: "authz" },
  sqli:        { label: "query shaping",      group: "injection" },
  "client-sink": { label: "untrusted output", group: "injection" },
  graphql:     { label: "GraphQL",            group: "injection" }
};

function paramType(n) {
  if (n.isUrl) return "url";
  if (n.isInt) return "integer";
  if (n.isBool) return "boolean";
  return "string";
}

function analyzePotentialPoints() {
  const out = [];
  for (const n of notes.values()) {
    if (n.kind !== "param") continue;

                                                                               
                                                                          
                           
    if (!n.categories || !n.categories.length) {
      secFinding(out, "param", "param:" + n.param, "INFO",
        "parameter " + n.param + " (" + paramType(n) + ", " + n.source + ")",
        "Recorded as an entry point. No category rule matched this name, which is " +
        "not evidence that it is harmless - most names match nothing.",
        n.where, n.shape, null, "OBSERVED");
      continue;
    }

    const dangerous = /dangerous|unsafe|script|onerror|javascript:/i.test(String(n.sink || ""));
    const erred = /sql|template|php-error|traceback/i.test(String(n.errorClass || ""));

    for (const cat of n.categories) {
      const rule = PARAM_CATEGORIES.find(r => r.cat === cat);
      const meta = CAT_META[cat] || { label: cat, group: "injection" };

                                                     
      let confidence = "low";
      const why = ["the parameter is named like a " + meta.label.toLowerCase() + " target"];
      if (n.reflected) {
        confidence = "medium";
        why.push("the submitted value came back in the response, so the application handles it");
      }
      if (dangerous) {
        confidence = "high";
        why.push("it was reflected into an unsafe output context");
      }
      if (erred) {
        confidence = "high";
        why.push("the response carried a matching error");
      }

                                                                                   
                                                                             
                                                                               
                                              
secFinding(out, "param", "pp:" + cat + ":" + n.param,
        confidence === "high" ? "MEDIUM" : confidence === "medium" ? "LOW" : "INFO",
        meta.label + " candidate: " + n.param,
        rule ? rule.why : meta.label + " candidate.",
        n.where, n.shape,
        rule ? rule.next : "Review this parameter.",
        confidence === "high" ? "CANDIDATE" : "HYPOTHESIS");
    }
  }
  return out;
}

                                                                        
                       
  
                                                           
                                                                            
                                                                         
                                                                        
function analyzeAttackSurface() {
  const hosts = new Map();
  for (const f of store.values()) {
    const host = f.host || "?";
    if (!hosts.has(host)) {
      hosts.set(host, {
        host,
        scripts: new Set(), endpoints: [], parameters: 0,
        auth: new Set(), firstParty: false, thirdParty: !!f.thirdParty
      });
    }
    const h = hosts.get(host);
    for (const s of (f.sources || [])) if (s === "javascript") h.scripts.add(f.path);
    if (f.auth && f.auth.challenge) h.auth.add(f.auth.challenge);
    if (f.auth && f.auth.sentCredentials) h.auth.add("credentials sent");
    if (f.cors && f.cors.length) h.auth.add("CORS: " + f.cors.join(", "));
    h.endpoints.push({
      method: f.method, path: f.path, observed: !!f.observed,
      status: f.lastStatus === undefined ? null : f.lastStatus,
      confidence: f.confidence, score: f.score,
      spec: !!f.specDeclared, sources: [...(f.sources || [])]
    });
  }
  let params = 0;
  for (const n of notes.values()) if (n.kind === "param") params++;
  for (const h of hosts.values()) {
    h.scripts = [...h.scripts];
    h.auth = [...h.auth];
  }
  return {
    generatedAt: new Date().toISOString(),
    hosts: [...hosts.values()],
    totals: {
      hosts: hosts.size,
      endpoints: store.size,
      parameters: params,
      scripts: [...hosts.values()].reduce((a, h) => a + h.scripts.length, 0)
    }
  };
}

                                                                        
                        
  
                                                                           
                                                                           
                                                          
                                                                        
function inferSchema(text) {
  const j = safeParse(text);
  const shape = (v, depth) => {
    if (depth > 4) return "any";
    if (v === null) return "null";
    if (Array.isArray(v)) return v.length ? [shape(v[0], depth + 1)] : [];
    if (typeof v === "object") {
      const o = {};
      for (const k of Object.keys(v).slice(0, 60)) o[k] = shape(v[k], depth + 1);
      return o;
    }
    return typeof v;
  };
  return j === null ? null : shape(j, 0);
}

function flattenSchema(shape, prefix, out) {
  out = out || {};
  prefix = prefix || "";
  if (shape === null || typeof shape !== "object") { out[prefix || "value"] = shape; return out; }
  if (Array.isArray(shape)) { out[prefix + "[]"] = shape.length ? flattenSchema(shape[0], prefix + "[]", {})[prefix + "[]"] : "empty"; return out; }
  for (const k of Object.keys(shape)) flattenSchema(shape[k], prefix ? prefix + "." + k : k, out);
  return out;
}

function analyzeSchema() {
  const routes = [];
  for (const f of store.values()) {
    if (!f.responseBody || !/json|xml/i.test(String(f.responseContentType || ""))) continue;
    const flat = flattenSchema(inferSchema(f.responseBody));
    routes.push({
      method: f.method,
      path: f.normalizedPath || f.path,
      specDeclared: !!f.specDeclared,
      fields: Object.keys(flat).sort()
    });
  }

  const specFields = new Set();
  for (const s of specStore.values()) {
    try { collectSpecFields(s, specFields); } catch (_) {}
  }
  const undocumented = [];
  const seen = new Set();
  for (const r of routes) {
    for (const field of r.fields) {
      if (!specFields.size || field.indexOf("[") >= 0) continue;
      const key = r.method + " " + r.path + " " + field;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!specFields.has(field)) undocumented.push({ method: r.method, path: r.path, field });
    }
  }
  return { routes, undocumented: undocumented.slice(0, 200), specFieldCount: specFields.size };
}

function collectSpecFields(spec, out) {
  if (!spec || typeof spec !== "object") return;
  const visit = (node, path) => {
    if (!node || typeof node !== "object") return;
    for (const k of Object.keys(node)) {
      if (path === "properties" || path === "definitions" || path === "schemas") {
        out.add(k);
        visit(node[k], "properties");
      } else {
        visit(node[k], k);
      }
    }
  };
  visit(spec, "");
  if (spec.schema) visit(spec.schema, "");
  if (spec.definitions) for (const k of Object.keys(spec.definitions)) { out.add(k); visit(spec.definitions[k], "properties"); }
  if (spec.components && spec.components.schemas) for (const k of Object.keys(spec.components.schemas)) { out.add(k); visit(spec.components.schemas[k], "properties"); }
}

                                                                        
                                      
  
                                                                     
  
                                                                             
                                                                            
                                                                              
                                                                              
                                                                           
                                                                               
                   
                                                                        

                                                                              
                                                                                  
                                                                           
                                                                              
                                                    
const TECH_DISCLOSURES = [
                                                                
                                                  
    
                                                                           
                                                                          
                                                                           
                                                                          
  { product: "PHP", re: /PHP\/([\d.]+)/i, from: "X-Powered-By", hint: "php" },
  { product: "Apache", re: /Apache\/([\d.]+)/i, from: "Server", hint: "apache" },
  { product: "nginx", re: /nginx\/([\d.]+)/i, from: "Server", hint: "nginx" },
  { product: "IIS", re: /Microsoft-IIS\/([\d.]+)/i, from: "Server", hint: "microsoft-iis|iis" },
  { product: "ASP.NET", re: /^([\d.]+)$/, from: "X-AspNet-Version" },
  { product: "Node/Express", re: /Express\/([\d.]+)/i, from: "X-Powered-By", hint: "express" },
  { product: "WordPress", re: /WordPress\s+([\d.]+)/i, from: "meta generator" },
  { product: "Joomla", re: /Joomla\s+([\d.]+)/i, from: "meta generator" },
  { product: "Drupal", re: /Drupal\s+([\d.]+)/i, from: "meta generator" },
  { product: "Magento", re: /Magento\s+([\d.]+)/i, from: "meta generator" },
  { product: "TYPO3", re: /TYPO3\s+([\d.]+)/i, from: "meta generator" },
  { product: "OpenCart", re: /OpenCart\s+([\d.]+)/i, from: "meta generator" },
  { product: "Next.js", re: /Next(?:js)?[\s/-]?([\d]+\.[\d]+\.[\d]+)/i, from: "bundle or header", hint: "next" },
  { product: "OpenResty", re: /OpenResty\/([\d.]+)/i, from: "Server", hint: "openresty" },
  { product: "LiteSpeed", re: /LiteSpeed\/([\d.]+)/i, from: "Server", hint: "litespeed" },
  { product: "Caddy", re: /Caddy\/([\d.]+)/i, from: "Server", hint: "caddy" },
  { product: "Kestrel", re: /Kestrel/i, from: "Server", hint: "kestrel" },
  { product: "WordPress", re: /WordPress\s*([\d.]+)?/i, from: "X-Generator", hint: "wordpress" },
  { product: "Drupal", re: /Drupal\s*([\d.]+)?/i, from: "X-Generator", hint: "drupal" }
];

                                                                              
                                                                              
                                                                             
                                                                              
const PLATFORM_SIGS = [
  { product: "Meta web platform", headers: ["x-stack", "x-fb-debug", "x-fb-connection-quality"], from: "X-Stack" },
  { product: "Cloudflare", headers: ["cf-ray", "cf-cache-status"], server: /cloudflare/i, from: "CF-Ray" },
  { product: "Vercel", headers: ["x-vercel-id", "x-vercel-cache"], server: /vercel/i, from: "X-Vercel-Id" },
  { product: "Fastly", headers: ["x-fastly-request-id", "x-served-by"], from: "X-Fastly-Request-Id" },
  { product: "Amazon CloudFront", headers: ["x-amz-cf-id", "x-amz-cf-pop"], from: "X-Amz-Cf-Id" },
  { product: "Akamai", headers: ["akamai-grn", "x-akamai-transformed"], from: "Akamai-GRN" },
  { product: "Azure Front Door", headers: ["x-azure-ref", "x-fd-int-roxy-purgeid"], from: "X-Azure-Ref" },
  { product: "Envoy proxy", headers: ["x-envoy-upstream-service-time"], server: /envoy/i, from: "X-Envoy-Upstream-Service-Time" },
  { product: "Google frontend", headers: ["x-cloud-trace-context"], server: /\bgws\b|google frontend/i, from: "X-Cloud-Trace-Context" },
  { product: "Netlify", headers: ["x-nf-request-id", "x-nf-render-mode"], from: "X-Nf-Request-Id" },
  { product: "Shopify", headers: ["x-shopid", "x-shopify-stage"], from: "X-ShopId" },
  { product: "Next.js edge", headers: ["x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time"], from: "X-Nextjs-Cache" }
];

                                                                              
                                                                              
                                                                           
                                                                        
                                                  
function readGeneratorClaims(text) {
  const out = [];
  if (!text) return out;
  const re = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(text)) !== null) out.push(m[1].slice(0, 200));
  return out;
}

                                                                            
                            
  
                                                                           
                                                                          
                                                                            
                                                                          
                                                                         
                                                                             
            
  
                                                                            
                        
function versionIsComparable(v) {
  return /^\d+\.\d+(\.\d+)?([-+].*)?$/.test(String(v || "").trim());
}

                                                                        
                                                          
  
                                                                          
                                                                    
                                                                          
                                                            
  
                                                                           
                 
                                                                        
const STACK_ADVISORIES = [
  { product: "PHP", lt: "8.0.0", ids: ["EOL-PHP-5"], title: "PHP 5 and 7 are end of life and receive no security fixes",
    severity: "HIGH", why: "An end-of-life runtime gets no patches at all, so every CVE found after it was published stays open." },
  { product: "PHP", lt: "8.3.0", ids: ["CVE-2024-4577"], title: "argument injection in some CGI configurations",
    severity: "MEDIUM", why: "Only affects CGI mode with a particular configuration; check whether the app runs as CGI." },
  { product: "Apache", lt: "2.4.49", ids: ["CVE-2021-41773"], title: "path traversal and file disclosure",
    severity: "HIGH", why: "A crafted request can read files outside the document root on a default configuration." },
  { product: "Apache", lt: "2.4.51", ids: ["CVE-2021-42013"], title: "path traversal that bypasses the 2.4.49 fix",
    severity: "HIGH", why: "The incomplete fix for CVE-2021-41773, and it is exploitable by default." },
  { product: "nginx", lt: "1.21.1", ids: ["CVE-2021-23017"], title: "off-by-one in the DNS resolver",
    severity: "MEDIUM", why: "Only matters if nginx resolves names for a location block; otherwise it is not reachable." },
  { product: "nginx", lt: "1.25.3", ids: ["CVE-2024-24989", "CVE-2024-24990"], title: "HTTP/3 memory disclosure and null pointer dereference",
    severity: "MEDIUM", why: "Only the HTTP/3 module is affected, and only with QUIC enabled." },
  { product: "jQuery", lt: "3.5.0", ids: ["CVE-2020-11022", "CVE-2020-11023"], title: "cross-site scripting through HTML that is passed to DOM manipulation methods",
    severity: "HIGH", why: "Any code that puts attacker-controlled HTML into jQuery is exploitable, including code that looks safe." },
  { product: "jQuery", lt: "3.0.0", ids: ["CVE-2015-9251"], title: "cross-site scripting in the selector engine",
    severity: "HIGH", why: "The classic selector-based XSS; the fix is in every later major version." },
  { product: "jQuery", lt: "3.4.0", ids: ["CVE-2019-11358"], title: "prototype pollution through $.extend",
    severity: "MEDIUM", why: "Deep extends with a crafted object can pollute Object.prototype." },
  { product: "AngularJS", lt: "1.8.0", ids: ["CVE-2020-7676"], title: "cross-site scripting through the sandbox",
    severity: "HIGH", why: "The sandbox could be escaped, which is script execution in the page's origin." },
  { product: "Bootstrap", lt: "3.4.1", ids: ["CVE-2019-8331"], title: "cross-site scripting in the tooltip and popover",
    severity: "MEDIUM", why: "Exploitable where user content is placed in a tooltip or a popover." },
  { product: "Bootstrap", lt: "4.3.1", ids: ["CVE-2019-8331"], title: "cross-site scripting in the tooltip and popover",
    severity: "MEDIUM", why: "Exploitable where user content is placed in a tooltip or a popover." },
  { product: "lodash", lt: "4.17.19", ids: ["CVE-2020-8203"], title: "prototype pollution in deep merge and deep set",
    severity: "MEDIUM", why: "Reachable through a merge of attacker-shaped JSON." },
  { product: "axios", lt: "0.21.1", ids: ["CVE-2021-3749"], title: "regular expression denial of service",
    severity: "MEDIUM", why: "A crafted parameter makes the browser hang on the regex." },
  { product: "moment", lt: "2.29.4", ids: ["CVE-2022-31129"], title: "regular expression denial of service in date parsing",
    severity: "MEDIUM", why: "A long date string makes the parser hang." },
  { product: "Express", lt: "4.21.2", ids: ["CVE-2024-43796"], title: "cross-site scripting through the response location header",
    severity: "MEDIUM", why: "A redirect to an attacker-controlled host can carry script." },
  { product: "Django", lt: "4.1.9", ids: ["CVE-2023-46604"], title: "denial of service in the multipart parser",
    severity: "MEDIUM", why: "A crafted multipart upload can exhaust memory." },
  { product: "Django", lt: "3.2.25", ids: ["CVE-2023-46604"], title: "denial of service in the multipart parser",
    severity: "MEDIUM", why: "A crafted multipart upload can exhaust memory." },
  { product: "WordPress", lt: "6.4.3", ids: ["CVE-2024-31210"], title: "remote code execution through a POP chain",
    severity: "CRITICAL", why: "Unauthenticated remote code execution on some configurations." },
  { product: "React Router", lt: "6.22.3", ids: ["CVE-2024-28849"], title: "open redirect and possible token leakage",
    severity: "MEDIUM", why: "A redirect to an external host can carry data with it." },
  { product: "Vue", lt: "2.6.14", ids: ["CVE-2024-9506"], title: "cross-site scripting through a compiled template",
    severity: "MEDIUM", why: "Only affects an application that compiles templates at runtime." },
  { product: "Handlebars", lt: "4.7.8", ids: ["CVE-2021-23369", "CVE-2021-23383"], title: "remote code execution through a crafted template",
    severity: "CRITICAL", why: "Arbitrary code execution when the template is compiled with user input." },
  { product: "Express", lt: "4.19.2", ids: ["CVE-2024-29041"], title: "open redirect through malformed URLs",
    severity: "MEDIUM", why: "A malformed path is treated as a protocol-relative URL." },
  { product: "jQuery UI", lt: "1.13.0", ids: ["CVE-2022-31160"], title: "cross-site scripting in the datepicker",
    severity: "MEDIUM", why: "Exploitable where a date is rendered from user input." }
];

                                                          
function stackIsAffected(product, version) {
  const v = String(version || "");
  if (!v) return null;
  const pa = v.split(/[.\-+]/).map(x => parseInt(x, 10) || 0);
  for (const a of STACK_ADVISORIES) {
    if (a.product.toLowerCase() !== String(product).toLowerCase()) continue;
    const pb = a.lt.split(/[.\-+]/).map(x => parseInt(x, 10) || 0);
    let less = false;
    for (let i = 0; i < 3; i++) {
      const x = pa[i] || 0, y = pb[i] || 0;
      if (x !== y) { less = x < y; break; }
    }
    if (less) return a;
  }
  return null;
}

function analyzeTechnology() {
  const out = [];
  const seen = new Set();

  const claim = (product, version, source, where, raw) => {
    const key = product + "@" + (version || "?") + "@" + source;
    if (seen.has(key)) return;
    seen.add(key);
                                                                              
                                                                             
                                                                
    const evidence = source && raw ? source + ": " + raw : raw;
    if (version) {
      secFinding(out, "tech", "tech:" + product + ":" + version, "INFO",
        product + " " + version + " (version stated)",
        "The application states this version itself, in " + source + ". That is " +
        "what makes an advisory list applicable rather than decorative.",
        where, evidence, null, "OBSERVED");
    } else {
      secFinding(out, "tech", "tech:" + product + ":unknown", "INFO",
        product + " (version not stated)",
        "The product is disclosed but no version is. No advisory is matched: a " +
        "CVE list attached to an unversioned fingerprint is a guess that reads " +
        "like a result.",
        where, evidence, "Find the version in the assets, a package manifest or the " +
        "source map before trusting any advisory.", "OBSERVED");
    }
  };

  const headerSources = [];
  for (const f of store.values()) {
    if (looksAbsent(f) || f.thirdParty) continue;
    const where = f.method + " " + f.host + (f.normalizedPath || f.path || "");
    if (f.responseHeaders) headerSources.push({ where, headers: f.responseHeaders });
    if (f.responseBody) {
      for (const g of readGeneratorClaims(f.responseBody)) {
        for (const d of TECH_DISCLOSURES) {
          if (d.from !== "meta generator") continue;
          const m = d.re.exec(g);
          if (m) claim(d.product, m[1], "meta generator", where, g);
        }
      }
    }
  }

                                                                             
                                                                          
                                                                             
  for (const r of headerBackup.values()) {
    if (r.status && (r.status < 200 || r.status >= 400)) continue;
    const u = parseURL(r.url);
    if (!u) continue;
    if (siteOf(u.hostname) !== siteOf(location.hostname)) continue;
    headerSources.push({
      where: r.method + " " + u.host + (u.pathname || "/"),
      headers: r.headers
    });
  }

  for (const src of headerSources) {
    const where = src.where;
    const H = src.headers;
    for (const [header, value] of Object.entries(H)) {
      for (const d of TECH_DISCLOSURES) {
        if (d.from.toLowerCase() !== header.toLowerCase()) continue;
        const m = d.re.exec(String(value));
        if (m) {
          claim(d.product, m[1], d.from, where, value);
        } else if (!d.hint || new RegExp(d.hint, "i").test(String(value))) {
          claim(d.product, null, d.from, where, value);
        }
      }
    }

    for (const p of PLATFORM_SIGS) {
      let hit = null;
      for (const name of p.headers) {
        const v = hdr(H, name);
        if (v) { hit = name + ": " + v; break; }
      }
      if (!hit && p.server) {
        const sv = hdr(H, "server");
        if (sv && p.server.test(sv)) hit = "Server: " + sv;
      }
      if (!hit) continue;
      const id = "platform:" + p.product;
      if (seen.has(id)) continue;
      seen.add(id);
      secFinding(out, "tech", id, "INFO",
        p.product + " (platform inferred from response headers)",
        "The response carries headers this platform adds. That identifies the edge " +
        "or hosting layer, not necessarily the application server behind it. No " +
        "version is claimed unless the platform states one.",
        where, hit, null, "OBSERVED");
    }
  }

                                                                             
                                                                             
                                                                      
                              
  try {
    const docText = (typeof document !== "undefined" && document.documentElement)
      ? String(document.documentElement.outerHTML || "") : "";
    if (docText) {
      const where = "document " + ((typeof location !== "undefined" && location.href) || "");
      try { detectFrameworksIn(docText); } catch (_) {}
      for (const g of readGeneratorClaims(docText)) {
        for (const d of TECH_DISCLOSURES) {
          if (d.from !== "meta generator") continue;
          const m = d.re.exec(g);
          if (m) claim(d.product, m[1], "meta generator", where, g);
        }
      }
    }
  } catch (_) {                                                                    }

                                                                                  
                                                                              
                                                                        
  try {
    const urls = [];
    if (typeof performance !== "undefined" && typeof performance.getEntriesByType === "function") {
      for (const e of performance.getEntriesByType("resource") || []) {
        if (e && e.name) urls.push(e.name);
        if (urls.length >= 400) break;
      }
    }
    if (typeof document !== "undefined" && document.querySelectorAll) {
      for (const s of document.querySelectorAll("script[src]")) {
        if (s && s.src) urls.push(s.src);
        if (urls.length >= 500) break;
      }
    }
    if (urls.length) detectFrameworksIn(urls.join("\n"));
  } catch (_) {}

  try { detectRuntimeFrameworks(); } catch (_) {}

                                                         
  for (const rec of fwStore.values()) {
    const versions = [...(rec.versions || [])].filter(Boolean);
    const key = "fw:" + rec.name;
                                                                                
                                                                            
                                                                            
    if (seen.has(key)) continue;
    seen.add(key);
    if (!versions.length) {
      secFinding(out, "tech", "tech:" + rec.name + ":unknown", "INFO",
        rec.name + " fingerprint (no version found)",
        "The library was identified in a shipped bundle but no version could be " +
        "read from the code. Advisories are withheld rather than guessed.",
        "bundles", null, "Check the bundle's source map, a package manifest, or " +
        "/_next/static asset names for the build.", "OBSERVED");
      continue;
    }
    for (const v of versions) {
      const coarse = !versionIsComparable(v);
      secFinding(out, "tech", "tech:" + rec.name + ":" + v, "INFO",
        rec.name + " " + v + (coarse ? " (version too coarse to compare)" : " (version read from a shipped bundle)"),
        coarse
          ? "The code names the product and a version, but not a release: " + v +
            " is a major line, and every release inside it may or may not be " +
            "affected. No advisory is matched against it."
          : "A version string was present in the code the browser downloaded.",
        "bundles", v, coarse
          ? "Find the exact release in the package manifest, the lockfile or the " +
            "source map before any advisory is applied."
          : null, "OBSERVED");
    }
  }

                                                         
    
                                                                             
                                                                             
                                                                            
  for (const f of out) {
    if (f.kind !== "tech") continue;
    const m = /^tech:(.+?):(.+)$/.exec(f.id);
    if (!m) continue;
    const product = m[1], version = m[2];
    if (/unknown|coarse/.test(version)) continue;
    const adv = stackIsAffected(product, version);
    if (!adv) continue;
    secFinding(out, "tech", "tech-cve:" + adv.ids.join(",") + ":" + product + ":" + version,
      adv.severity || "MEDIUM",
      product + " " + version + " is affected by " + adv.ids.join(", ") +
        (adv.title ? " - " + adv.title : ""),
      (adv.why || "The observed version is older than the release that fixed this.") +
      " The version was read out of what the server or the bundle stated, so it " +
      "is what the server CLAIMS. A patched build behind a stale banner is " +
      "common - confirm before reporting.",
      f.where, f.evidence,
      "Confirm the deployed build is the version that answered. If the banner is " +
      "stale, the finding does not apply. Not sent by this tool.",
      "CANDIDATE");
  }

                                           
    
                                                                             
                                                                   
    
                                                                              
                                                                           
                                                                            
                                                                             
                                                                    
                                                                           
                                                                            
                                                         
    
                                                                            
                                                                        
  for (const rec of fwStore.values()) {
    const list = FRAMEWORK_CVES[rec.name] || [];
    if (!list.length) continue;
    const versions = [...(rec.versions || [])].filter(Boolean);
    for (const v of versions) {
                                                                
                                                                               
      if (!versionIsComparable(v)) continue;
      for (const entry of list) {
        if (!verLessThan(v, entry.lt)) continue;
        for (let i = 0; i < entry.ids.length; i++) {
          const id = entry.ids[i];
          const title = (entry.titles || [])[i] || "";
          secFinding(out, "tech", "cve:" + rec.name + ":" + id + ":" + v, "MEDIUM",
            rec.name + " " + v + " is below " + entry.lt + " - " + id,
            title || "The observed version is in the affected range of this advisory.",
            "fingerprinted in a shipped bundle",
            "affected: < " + entry.lt + "   observed: " + v,
            entry.how || null,
                                                                                
                                                                                
                                                                        
            "HYPOTHESIS");
        }
      }
    }
  }

                                                                   
    
                                                                              
                                                                              
                                                                          
                                                                             
                                                                           
                                                                           
                                                                          
    
                                                              
  const advisoryRows = out.filter(r => /^cve:/.test(String(r.id || "")));
  for (const r of advisoryRows) {
    if (!/\d+\.\d+/.test(String(r.title || ""))) {
      secFinding(out, "tech", "tech-check:" + r.id, "INFO",
        "version evidence required before advisories",
        "An advisory was raised without a version to check it against. Withheld " +
        "from the advisory list - it is recorded here so the gap is visible " +
        "rather than silent.",
        r.where, r.evidence, null, "OBSERVED");
    }
  }

  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

                                                                        
                        
  
                                                                             
                                                                           
                                                                          
                                                                              
                               
                                                                        

const DF_SOURCES = [
  { id: "location.hash",      re: /\blocation\.hash\b/,                   what: "the fragment, which never reaches the server" },
  { id: "location.search",    re: /\blocation\.search\b/,                 what: "the query string" },
  { id: "location.href",      re: /\blocation\.href\b/,                   what: "the full URL, query and fragment included" },
  { id: "document.URL",       re: /\bdocument\.(?:URL|documentURI)\b/,     what: "the current document URL" },
  { id: "document.referrer",  re: /\bdocument\.referrer\b/,               what: "the referring URL, which the previous page chose" },
  { id: "window.name",        re: /\bwindow\.name\b/,                     what: "window.name, which persists across navigations" },
  { id: "postMessage",        re: /\bpostMessage\b|\.(?:onmessage|addEventListener\(\s*["']message["'])/, what: "a message from another origin" },
  { id: "document.cookie",    re: /\bdocument\.cookie\b/,                 what: "a cookie, which any script on the origin can read" },
  { id: "input value",        re: /\.(?:value|innerText|textContent)\b(?=\s*(?:\)|\}|;|$))/ , what: "a value a user typed" }
];

const DF_SINKS = [
  { id: "innerHTML",        re: /\.innerHTML\s*=(?!=)/,            cls: "script", why: "assigning a string to innerHTML parses it as markup" },
  { id: "outerHTML",        re: /\.outerHTML\s*=(?!=)/,            cls: "script", why: "the same, one node out" },
  { id: "insertAdjacentHTML", re: /\.insertAdjacentHTML\s*\(/,   cls: "script", why: "parses the argument as markup" },
  { id: "document.write",   re: /document\.write(?:ln)?\s*\(/,   cls: "script", why: "parses the argument as markup" },
  { id: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/, cls: "script", why: "React's explicit innerHTML equivalent" },
  { id: "eval",             re: /\beval\s*\(/,                    cls: "script", why: "evaluates the argument as code" },
  { id: "new Function",      re: /new\s+Function\s*\(/,            cls: "script", why: "compiles the argument as code" },
  { id: "setTimeout(string)", re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/, cls: "script", why: "a string argument is evaluated as code" },
  { id: "location assignment", re: /\blocation(?:\.href|\.hash)?\s*=\s*(?!\=)/, cls: "url", why: "navigates to the value, which can also carry a javascript: URL" },
  { id: "window.open",      re: /\bwindow\.open\s*\(/,             cls: "url", why: "opens the value as a URL" },
  { id: "srcdoc",           re: /\.srcdoc\s*=/,                    cls: "url", why: "loads the value as a document" },
  { id: "postMessage out",  re: /\b(?:window\.)?parent\.postMessage\b|\b(?:window\.)?opener\.postMessage\b|\btop\.postMessage\b/, cls: "url", why: "hands the value to another window, possibly cross-origin" }
];

                                                                              
function dfSourceVars(text) {
  const out = [];
  for (const s of DF_SOURCES) {
    const re = new RegExp(
      "(?:(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*)?" +
      "(?:(?:var|let|const)\\s*\\{[^}]*\\b" + s.re.source + "\\b[^}]*\\})?" +
      s.re.source, "g");
    let m;
    while ((m = re.exec(text)) !== null && out.length < 60) {
      out.push({ source: s, var: m[1] || null, at: m.index });
    }
                                                                            
    if (!re.lastIndex) continue;
  }
  return out;
}

function dfChainVars(text, name) {
                                                                             
  const vars = new Set();
  if (name) vars.add(name);
  const re = new RegExp("(?:(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*)([^;\\n]{0,200})", "g");
  let m;
  let guard = 0;
  while ((m = re.exec(text)) !== null && guard++ < 400) {
    const target = m[1], expr = m[2];
    for (const v of [...vars]) {
      if (new RegExp("\\b" + v.replace(/\$/g, "\\$") + "\\b").test(expr)) { vars.add(target); break; }
    }
  }
  return vars;
}

function analyzeDataFlow() {
  const out = [];
  let scanned = 0, pairs = 0;

                                                                           
                                                                            
  const texts = [];
  for (const f of store.values()) {
    if (f.sources && Array.prototype.indexOf.call(f.sources, "javascript") >= 0 && f.bodyCaptured) {
                                                                              
                                                      
    }
  }
  try {
                                                                             
    const inline = [];
    for (const el of document.querySelectorAll("script")) {
      const t = el.textContent || "";
      if (t) inline.push({ label: "inline script", text: t });
    }
    const docText = (typeof document !== "undefined" && document.documentElement)
      ? String(document.documentElement.outerHTML || "") : "";
    if (docText) inline.push({ label: "page source", text: docText });
    texts.push(...inline);
  } catch (_) {                                                                   }

  for (const item of texts) {
    const text = item.text;
    if (!text || text.length > 3000000) continue;
    scanned++;

    const srcs = dfSourceVars(text);
    if (!srcs.length) continue;
    const sinks = [];
    for (const s of DF_SINKS) {
      const re = new RegExp(s.re.source, "g");
      let m;
      while ((m = re.exec(text)) !== null && sinks.length < 200) {
        sinks.push({ sink: s, at: m.index, match: m[0] });
      }
    }
    if (!sinks.length) continue;

    for (const sv of srcs) {
      const tainted = dfChainVars(text, sv.var);
      for (const sk of sinks) {
        pairs++;
                                                                            
                                                                         
                                                           
        const window = text.slice(Math.max(0, sk.at - 220), sk.at + 120);
        const links = [...tainted].filter(v =>
          new RegExp("\\b" + v.replace(/\$/g, "\\$") + "\\b").test(window));
        if (!links.length) continue;

        secFinding(out, "flow", "flow:" + sv.source.id + ">" + sk.sink.id + ":" +
          Math.round(sk.at / 500), "MEDIUM",
          sv.source.id + " reaches " + sk.sink.id,
          sv.source.id + " is " + sv.source.what + ", and " + sk.sink.id + " is " +
          sk.sink.why + ". The tainted variable (" + links.join(", ") + ") is read " +
          "inside the same assignment. This is a source-to-sink path, which is a " +
          "stronger signal than either side alone - but whether it executes " +
          "depends on whether the value can contain markup, which static reading " +
          "cannot settle.",
          item.label,
          clip(text.slice(Math.max(0, sk.at - 160), sk.at + 90), 240),
          "Craft a value for " + sv.source.id + " containing markup and see " +
          "whether it reaches " + sk.sink.id + " intact. Not sent by this tool.",
          "CANDIDATE");
      }
    }
  }

                                                                            
                                                                               
                                                            
  if (!scanned) {
    secFinding(out, "flow", "flow:none", "INFO",
      "no script text was available to analyse",
      "Client-side data flow needs the source. Only inline scripts and the " +
      "serialized page source are in hand here - external bundle files are read " +
      "for credentials but their bodies are not retained, so flows that live " +
      "inside a downloaded bundle are not covered by this pass.",
      "document", null, null, "OBSERVED");
  }
  return out;
}

                                                                        
                 
                                                                        

                                                                           
                                                                         
                                                           
const ANALYZER_BUILD = "security-3";

                                                     
  
                                                                               
                                                                            
                                                                             
                                                                            
                                                                              
                                           
function analyzerDiagnostics() {
  let docChars = 0, docErr = null, docPreview = "", docMatches = [];
  try {
    if (typeof hasDOM === "undefined" || !hasDOM) docErr = "no DOM in this context";
    else {
      const src = htmlSourceSnapshot();
      docChars = src ? src.length : 0;
      docPreview = src ? clip(src.replace(/\s+/g, " "), 600) : "";
                                                                              
                                                                               
                                                                           
                                                      
      if (src) {
        for (const s of LEAK_SIGNATURES) if (s.re.test(src)) docMatches.push(s.id);
      }
    }
  } catch (e) { docErr = String((e && e.message) || e); }

  const groups = {
    headers: 0, leaks: 0, injection: 0, authz: 0, session: 0
  };
  let analysisErr = null;
                                                                              
                                                                       
                                                                         
  const findings = [];
  try {
    const a = securityAnalysis();
    for (const g of Object.keys(groups)) {
      groups[g] = a[g].length;
      for (const f of a[g].slice(0, 8)) {
        findings.push({
          group: g, id: f.id, severity: f.severity, basis: f.basis,
          title: f.title, where: f.where, evidence: f.evidence
        });
      }
    }
  } catch (e) { analysisErr = String((e && e.message) || e); }

  return {
    analyzerBuild: ANALYZER_BUILD,
    version: typeof VERSION === "string" ? VERSION : null,
    active: typeof active !== "undefined" ? !!active : null,
    hasDOM: typeof hasDOM !== "undefined" ? !!hasDOM : null,
    readyState: (typeof document !== "undefined" && document && document.readyState) || null,
    documentChars: docChars,
    documentPreview: docPreview,
    documentMatches: docMatches,
    documentError: docErr,
    storeSize: typeof store !== "undefined" ? store.size : null,
    jwtCount: typeof jwtStore !== "undefined" ? jwtStore.size : null,
    notesCount: typeof notes !== "undefined" ? notes.size : null,
    storageCount: typeof storageStore !== "undefined" ? storageStore.size : null,
    counts: groups,
    findings: findings,
    analysisError: analysisErr,
    hookErrors: (typeof errors !== "undefined" ? errors : []).slice(0, 8),
    installedHooks: typeof hooks !== "undefined" ? hooks.slice() : null,
    url: (typeof location !== "undefined" && location && location.href) || null
  };
}

function securityAnalysis() {
  const headers = analyzeSecurityHeaders();
                                                                          
  const leaks = [...analyzeResponseLeaks(), ...analyzeDocumentLeaks()].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const injection = analyzeInjection();
  const authz = analyzeFunctionAuthz();
  const session = analyzeSessions();
  const params = analyzePotentialPoints();
  const tech = analyzeTechnology();
  const flow = analyzeDataFlow();
  const surface = analyzeAttackSurface();
  const schema = analyzeSchema();
                                                                              
                                                                          
                                                                             
                             
  const stamp = (rows, group) => rows.map(r => { r.group = group; return r; });
  stamp(headers, "headers"); stamp(leaks, "leaks"); stamp(injection, "injection");
  stamp(authz, "authz"); stamp(session, "session"); stamp(params, "params");
  stamp(tech, "tech"); stamp(flow, "flow");

                                                                               
                                                                         
                                                                        
                                              
  const confRank = { high: 3, medium: 2, low: 1 };
  for (const r of params) {
    r.confidence = /it was reflected|matching error/.test(r.how || "") ? "high"
      : /came back in the response/.test(r.detail || "") ? "medium" : "low";
    r.status = "unverified";
    r.endpoint = r.where;
    r.category = (CAT_META[r.cat] || { label: r.cat }).label;
  }

                                                                         
                                                                   
  const merged = new Map();
  for (const r of params) {
    const key = (r.group || "") + "|" + r.title;
    const prev = merged.get(key);
    if (!prev) { merged.set(key, r); continue; }
    prev.where = prev.where === r.where ? prev.where : prev.where + ", " + r.where;
    if ((confRank[r.confidence] || 0) > (confRank[prev.confidence] || 0)) prev.confidence = r.confidence;
  }
  const deduped = [...merged.values()].sort((a, b) => {
    const g = (confRank[b.confidence] || 0) - (confRank[a.confidence] || 0);
    if (g) return g;
    return sevRank(b.severity) - sevRank(a.severity);
  });
  for (const r of deduped) r.deduped = merged.get((r.group || "") + "|" + r.title) && merged.size > 1 ? true : false;

  const prioritized = deduped.map((r, i) => {
    r.rank = i + 1;
    r.score = (confRank[r.confidence] || 0) * 10 + sevRank(r.severity);
    return r;
  });

                                                                            
                                                                          
                                  
  let bodies = 0, responses = 0;
  for (const f of store.values()) {
    if (f.responseHeaders) responses++;
    if (f.responseBody) bodies++;
  }
  const coverage = { endpoints: store.size, responses, bodies };
                                                                         
                                                                              
                                                     
  coverage.documentChars = (function () {
    try { if (typeof hasDOM === "undefined" || !hasDOM) return 0; return htmlSourceSnapshot().length; }
    catch (_) { return 0; }
  })();
  coverage.scannerErrors = (typeof errors !== "undefined" ? errors.length : 0);
  const limits = [
    "No payload is ever sent. Injection findings are read out of responses " +
    "the application already produced.",
    "An injection finding is a CANDIDATE - a reflection the analyzer saw and " +
    "one request would settle. Two are OBSERVED instead, because what they " +
    "report was read out of the response: a template engine that threw, and " +
    "a submitted value that came back as its arithmetic result.",
    "BFLA findings are HYPOTHESES. Confirming them needs two accounts of " +
    "different privilege making real requests.",
    "HttpOnly is unreadable from JavaScript. Cookie flags are read from " +
    "Set-Cookie on responses, so a cookie never set over the network is invisible.",
    "The page's own HTML is scanned too, so a server-rendered error is reported " +
    "even when the page makes no API calls at all."
  ];
  if (!responses) {
    limits.push("No captured API response carried headers, so the header and " +
      "cookie checks had nothing to read. Press Start before browsing, then " +
      "revisit the endpoints you care about.");
  }
  if (!bodies) {
    limits.push("No captured response body was available, so the verbose-error " +
      "and config-leak checks only ran against the page's own HTML.");
  }
                                                                           
                                                                            
                                                     
  let assessed = 0, allAbsent = 0;
  for (const f of store.values()) {
    if (!f.responseHeaders) continue;
    if (looksAbsent(f)) allAbsent++; else assessed++;
  }
  if (assessed === 0 && allAbsent > 0) {
    limits.push("Every captured response was a 404 or 410, so the header and " +
      "cookie checks had nothing real to read. Open a page that actually loads " +
      "application content and run the scan again.");
  }
  if (!coverage.documentChars) {
    limits.push("The page's own HTML could not be read at all (" +
      "documentChars = 0). Every document-level check - stack traces, SQL " +
      "errors, config leaks - is therefore blind. Copy diagnostics from the " +
      "Settings tab.");
  }

  return {
    headers, leaks, injection, authz, session,
                                                                           
                                                                      
                                               
    params: prioritized,
    tech, flow,
    surface,
    schema,
                                                                       
                                                                           
                                                                         
                                                              
    thirdParty: analyzeThirdParty(),
    counts: {
      headers: headers.length, leaks: leaks.length, injection: injection.length,
      authz: authz.length, session: session.length, params: prioritized.length,
      tech: tech.length, flow: flow.length
    },
    coverage,
    limits
  };
}
                        

                                                         
                                                       
                                                                  
  
                                                                  
  
                                                                               
                                                                       
                                                                            
                                                                   
  
                     
                     
                                                                      
                                           
  
                                               
                                                                       
                                                                      
  
                                                                          
                                                                          
                                                                         
  
                                                     
                                                                          
                                                                          
          
  
                            
                            
                                                                           
                                                                         
                                                                           
                                                                        
                                                                      
  
                                                                  
                                                                           
                                    
  
                                                                            
                                                                       
                                                                             
                                                                          
                                                                             
   
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
                  
                                                                          
                                
                                                                          
  const TEXTUAL = /json|graphql|xml|text|javascript|x-www-form-urlencoded|html|csv|protobuf/i;
  const RAW_CAP = 65536;

  function describeText(text, maxChars) {
    let json;
    if (text.length <= CONFIG.maxJsonParseChars && /^\s*[\[{]/.test(text)) {
      try { json = JSON.parse(text); } catch (_) {}
    }
    let display;
    if (json !== undefined) {
      display = JSON.stringify(CONFIG.redactSensitive ? redactValue(json, 0) : json);
    } else {
      display = redactString(text.length > RAW_CAP ? text.slice(0, RAW_CAP) : text);
    }
    return { display: clip(display || "", maxChars), json };
  }

  function describeEntries(entries, max) {
    const obj = Object.create(null);
    for (const [k, v] of entries) {
      const val = (typeof File !== "undefined" && v instanceof File)
        ? "[File " + v.name + ", " + v.size + " bytes]"
        : String(v);
      obj[k] = k in obj ? [].concat(obj[k], val) : val;
    }
    const shown = CONFIG.redactSensitive ? redactValue(obj, 0) : obj;
    return { display: clip(JSON.stringify(shown), max), json: obj };
  }

  function describeBody(body) {
    if (body === undefined || body === null) return null;
    const max = CONFIG.maxRequestBodyChars;
    try {
      if (typeof body === "string") return describeText(body, max);
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return describeEntries(body.entries(), max);
      if (typeof FormData !== "undefined" && body instanceof FormData) return describeEntries(body.entries(), max);
      if (typeof Blob !== "undefined" && body instanceof Blob) return { display: "[Blob " + (body.type || "unknown type") + ", " + body.size + " bytes]" };
      if (typeof ArrayBuffer !== "undefined" && (body instanceof ArrayBuffer || ArrayBuffer.isView(body))) return { display: "[binary, " + body.byteLength + " bytes]" };
      if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) return { display: "[ReadableStream]" };
      return describeText(String(body), max);
    } catch (e) {
      fail("describeBody", e);
      return null;
    }
  }

  function putHeader(obj, name, value) {
    const key = String(name).toLowerCase();
    if (key === "__proto__") return;
    obj[key] = CONFIG.redactSensitive && isSensitiveKey(key) ? "[REDACTED]" : redactString(String(value));
  }

  function headersToObject(h) {
    const out = {};
    if (!h) return out;
    try {
      if (typeof Headers !== "undefined" && h instanceof Headers) {
        h.forEach((v, k) => putHeader(out, k, v));
      } else if (Array.isArray(h)) {
        for (const pair of h) if (pair && pair.length >= 2) putHeader(out, pair[0], pair[1]);
      } else if (typeof h === "object") {
        for (const k of Object.keys(h)) putHeader(out, k, h[k]);
      }
    } catch (e) {
      fail("headers", e);
    }
    return out;
  }

                                                                               
                                                       
  function headerAllowed(name) {
    const allow = CONFIG.responseHeaderAllow;
    const lk = name.toLowerCase();
    if (allow instanceof Set) return allow.has(lk);
    if (Array.isArray(allow)) {
      for (const a of allow) if (String(a).toLowerCase() === lk) return true;
      return false;
    }
    return false;
  }

  function storeResponseHeader(out, name, value) {
    const lk = String(name).toLowerCase();
    if (!headerAllowed(lk)) return;
    if (lk === "set-cookie") {
      out[lk] = out[lk] ? out[lk] + " | " : "";
                                                                            
                                                                              
                                                          
        
                                                                         
                                              
                                                                            
                                                                         
                                                                          
                                                                           
      const parts = String(value).split(";");
      const head = parts.shift() || "";
      const eq = head.indexOf("=");
      const nm = (eq >= 0 ? head.slice(0, eq) : head).trim();
      const masked = nm && /^[\w.-]+$/.test(nm) ? nm + "=[REDACTED]" : head.trim();
                                                                               
                                                                             
                                                                
      const attrs = parts.map(p => {
        const t = p.trim();
        return t.length > 120 ? t.slice(0, 120) + "..." : t;
      }).filter(Boolean);
      out[lk] += [masked].concat(attrs).join("; ");
      return;
    }
    if (isSensitiveKey(lk)) { out[lk] = "[REDACTED]"; return; }
    out[lk] = clip(redactString(String(value)), 300);
  }

  function collectResponseHeaders(h) {
    const out = {};
    if (!CONFIG.captureResponseHeaders || !h) return out;
    try {
      if (typeof h.forEach === "function") h.forEach((v, k) => storeResponseHeader(out, k, v));
      else if (Array.isArray(h)) for (const p of h) if (p && p.length >= 2) storeResponseHeader(out, p[0], p[1]);
    } catch (e) {
      fail("respHeaders", e);
    }
    return out;
  }

                                                                 
  function parseRawHeaderString(s) {
    const all = {};
    if (!s) return all;
    const rows = String(s).split(/\r?\n/);
    for (const line of rows) {
      const i = line.indexOf(":");
      if (i < 1) continue;
      const k = line.slice(0, i).trim().toLowerCase();
      const v = line.slice(i + 1).trim();
      if (!k) continue;
      all[k] = k in all ? all[k] + ", " + v : v;
    }
    const out = {};
    for (const k of Object.keys(all)) storeResponseHeader(out, k, all[k]);
    return out;
  }

  function corsPosture(h) {
    const acao = String(h["access-control-allow-origin"] || "").toLowerCase();
    const acac = String(h["access-control-allow-credentials"] || "").toLowerCase();
    const flags = [];
    if (acao === "*") flags.push(acac === "true" ? "wildcard-origin-with-credentials" : "wildcard-origin");
    else if (acao === "null") flags.push("null-origin-allowed");
    else if (acao && acao !== "*") flags.push("explicit-origin:" + clip(acao, 60));
    if (acac === "true") flags.push("credentials-allowed");
    return flags;
  }

  function authChallenge(h) {
    const wa = h["www-authenticate"];
    if (!wa) return null;
    const m = /^\s*([A-Za-z]+)/.exec(String(wa));
    return m ? m[1].toLowerCase() : "present";
  }

  function hasAuthHeader(reqHeaders) {
    if (!reqHeaders) return false;
    for (const k of Object.keys(reqHeaders)) {
      if (k === "authorization" || k === "x-api-key" || k === "x-auth-token" || k === "proxy-authorization") return true;
      if (/^x-.*(?:auth|token|key|jwt|session)/.test(k)) return true;
    }
    return false;
  }

                                                                          
                                                                           
                                                                           
  function safeCancel(body) {
    try {
      if (body && typeof body.cancel === "function") {
        const p = body.cancel();
        if (p && typeof p.catch === "function") p.catch(() => {});
      }
    } catch (_) {}
  }

                                                                                              
  function withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
      const t = setT(() => reject(new Error("timeout")), ms);
      promise.then(v => { clearT(t); resolve(v); }, e => { clearT(t); reject(e); });
    });
  }

  async function readPreview(body, maxBytes) {
    if (!body || typeof body.getReader !== "function") return { text: "", truncated: false };
    const reader = body.getReader();
    const decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { fatal: false }) : null;
    let received = 0;
    let text = "";
    let truncated = false;
    try {
      while (true) {
        if (received >= maxBytes) { truncated = true; break; }
        const { done, value } = await withTimeout(reader.read(), CONFIG.readTimeoutMs);
        if (done) break;
        received += value.byteLength;
        text += decoder ? decoder.decode(value, { stream: true }) : "";
      }
    } catch (_) {
      truncated = true;
    } finally {
      try { reader.cancel().catch(() => {}); } catch (_) {}
    }
    return { text, truncated };
  }

  function noteInterestingSurface(u, path) {
    if (!u) return;
    const host = u.hostname.toLowerCase();
    const reasons = [];
    if (INTERESTING_HOST_RE.test(host)) reasons.push("non-production hostname");
    if (INTERESTING_AWS_SERVICE_RE.test(host)) reasons.push("AWS managed service hostname");
    if (INTERESTING_PATH_RE.test(path)) reasons.push("admin/debug/config path");
    if (reasons.length) {
      addNote("surface:" + u.origin + path, {
        kind: "surface", host, path, reasons, url: redactURL(u)
      });
    }
  }

                                                                          
            
                                                                          
  const RESOURCE_WORDS = new Set([
    "users", "user", "accounts", "account", "profiles", "profile", "auth", "login", "logout",
    "register", "session", "token", "customers", "customer", "products", "product", "orders",
    "order", "payments", "payment", "invoices", "invoice", "bookings", "booking", "files",
    "file", "upload", "download", "messages", "message", "notifications", "notification",
    "settings", "config", "configuration", "admin", "search", "reports", "report",
    "analytics", "health", "status"
  ]);
  const API_SEGMENT = /^(?:api|apis|graphql|gql|rest|rpc|jsonrpc|odata|trpc)(?:[-_]?v?\d+)?$/;
  const SPEC_SEGMENT = /^(?:swagger|openapi|api-docs|wp-json|admin-ajax\.php|swagger\.json|openapi\.json)$/;
  const STATIC_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip|wasm)$/i;

  function scoreFinding(i) {
    let score = 0;
    const why = [];
    const add = (pts, reason) => { score += pts; if (reason) why.push(reason); };
    const p = i.path.toLowerCase();
    const segs = p.split("/").filter(Boolean);

    if (i.specDeclared) add(60, "declared in API spec");
    if (segs.some(s => API_SEGMENT.test(s))) add(35, "API path segment");
    if (segs.some(s => SPEC_SEGMENT.test(s))) add(40, "API spec or framework");
    if (segs.some(s => /^v\d+(?:\.\d+)?$/.test(s))) add(18, "versioned path");
    if (/(^|[.-])(api|apis|backend|gateway|graphql|rest|svc|services?)([.-]|$)/.test(i.hostname)) add(25, "API-like hostname");
    if (INTERESTING_HOST_RE.test(i.hostname)) add(20, "non-production hostname");
    if (INTERESTING_AWS_SERVICE_RE.test(i.hostname)) add(15, "AWS managed service hostname");
                                                                             
                                                                                  
    if (INTERESTING_PATH_RE.test(p)) add(28, "admin, debug or config path");

    const hits = p.split(/[\/_.\-]+/).filter(t => RESOURCE_WORDS.has(t));
    if (hits.length) add(Math.min(new Set(hits).size * 6, 24), "resource:" + [...new Set(hits)].slice(0, 4).join(","));

    if (["POST", "PUT", "PATCH", "DELETE"].includes(i.method)) add(15, i.method);
    if (i.hasBody) add(8, "request body");
    if (/json|graphql|xml|form/i.test(i.requestContentType || "")) add(10, "structured request");
    if (/json|graphql|xml/i.test(i.responseContentType || "")) add(15, "structured response");
    if (/html/i.test(i.responseContentType || "") && i.status >= 200 && i.status < 300) add(-15, "html response");
    if (i.graphql) add(35, "GraphQL");
    if (i.method === "WEBSOCKET") add(35, "WebSocket");
    if (["fetch", "xhr", "beacon", "websocket", "eventsource", "probe"].includes(i.source)) add(12, "runtime request");
    if ([401, 403, 405, 429].includes(i.status)) add(12, "HTTP " + i.status);
    if (i.status >= 200 && i.status < 300 && /json|graphql/i.test(i.responseContentType || "")) add(20, "successful JSON response");
    if (i.source === "javascript") add(8, "referenced in code");
    if (i.source === "performance") add(5, "resource timing");
                                                                       
                                                                         
                                                                            
                                                                             
                                                                          
    if (i.hasResponseBody) add(25, "response body captured");
                                                                    
                                                                           
                                                                             
                                                                         
    if (i.source === "form") add(24, "form posts to this endpoint");
    if (i.source === "dom-attr") add(22, "declared on a data-* attribute");
    if (i.challenge) add(12, "auth challenge: " + i.challenge);
    if (i.cors && i.cors.length) add(10, "CORS " + i.cors.join(", "));
    if (i.noAuthDeclared) add(12, "spec declares no authentication");
    if (i.deprecated) add(4, "marked deprecated");
    if (i.idorCandidates && i.idorCandidates.some(c => c.enumerable)) add(12, "IDOR candidate parameter");
    if (i.specDeclared && i.noAuthDeclared && ["POST", "PUT", "PATCH", "DELETE"].includes(i.method)) add(8, "state-changing and declared unauthenticated");

    if (STATIC_EXT.test(p)) add(-30, null);
    else if (/\.html?$/.test(p)) add(-15, null);

    score += i.scoreBonus || 0;
    return { score: Math.max(0, score), reasons: why };
  }

                                                                                
                                                        
  function confidenceFrom(score, observed, authoritative) {
    let c = score >= 75 ? "HIGH" : score >= 45 ? "MEDIUM" : score >= 22 ? "LOW" : "IGNORE";
    if (!observed && !authoritative && c === "HIGH") c = "MEDIUM";
    return c;
  }

                                                                          
                 
                                                                               
                                                                          
  function b64urlDecode(s) {
    if (!nativeAtob) return null;
    try {
      let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
      while (t.length % 4) t += "=";
      return nativeAtob(t);
    } catch (_) {
      return null;
    }
  }

  const utf8Bytes = s => {
    try {
      if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(String(s));
    } catch (_) {}
    const out = [];
    for (let i = 0; i < String(s).length; i++) out.push(String(s).charCodeAt(i) & 0xff);
    return new Uint8Array(out);
  };

  function bytesToB64url(bytes) {
    try {
      if (typeof btoa !== "function") return null;
      let bin = "";
      const b = new Uint8Array(bytes);
      for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    } catch (_) {
      return null;
    }
  }

                                                                           
                                                                               
  async function hmacVerify(secret, signingInput, sigB64url, hash) {
    try {
      const subtle = (typeof crypto !== "undefined" && crypto.subtle) || null;
      if (!subtle || typeof TextEncoder === "undefined") return false;
      const key = await subtle.importKey("raw", utf8Bytes(secret), { name: "HMAC", hash: hash || "SHA-256" }, false, ["sign"]);
      const sig = await subtle.sign("HMAC", key, utf8Bytes(signingInput));
      const got = bytesToB64url(sig);
      return !!got && got.length === sigB64url.length &&
        got.split("").every((c, i) => c === sigB64url[i]);
    } catch (_) {
      return false;
    }
  }

                                                                
  const WEAK_JWT_SECRETS = [
    "secret", "password", "supersecret", "changeme", "jwt-secret", "jwt_secret", "jwtsecret",
    "your-256-bit-secret", "your-secret-key", "shhhhh", "mysecret", "secretkey", "secret_key",
    "key", "token", "admin", "test", "qwerty", "123456", "abc123", "letmein", "default",
    "private", "passw0rd", "auth", "hs256-secret", "node_env", "development"
  ];

  const SENSITIVE_CLAIMS = ["role", "roles", "isadmin", "is_admin", "admin", "is_superuser",
    "superuser", "is_staff", "staff", "permissions", "permission", "scopes", "scope",
    "groups", "groups_id", "entitlements", "plan", "tier", "is_verified", "verified"];
  const ADMIN_ROLE_RE = /^(admin|administrator|superuser|root|owner|staff|moderator|editor|system)$/i;

  const JWT_QUERY_KEYS = ["access_token", "id_token", "refresh_token", "token", "jwt", "auth",
    "authorization", "assertion", "bearer", "code"];

  function looksLikeJWT(s) {
    const t = String(s || "").trim().replace(/^Bearer\s+/i, "");
    if (t.length < 20 || t.length > 8192) return false;
    if (t.indexOf(".") < 1) return false;
    const parts = t.split(".");
    if (parts.length !== 3) return false;
    return /^[A-Za-z0-9_-]+$/.test(parts[0]) && /^[A-Za-z0-9_-]+$/.test(parts[1]);
  }

                                                                          
                                                                   
  const JWT_SUBSTR_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/;

  function analyzeJWT(token, source) {
    if (!CONFIG.analyzeJWTs) return null;
    const raw = String(token == null ? "" : token).trim().replace(/^Bearer\s+/i, "");
    let rec = decodeAndAnalyzeJWT(raw, source);
    if (!rec) {
      const m = JWT_SUBSTR_RE.exec(raw);
      if (m && m[0] !== raw) rec = decodeAndAnalyzeJWT(m[0], source);
    }
    return rec;
  }

  function decodeAndAnalyzeJWT(raw, source) {
    if (!looksLikeJWT(raw)) return null;
    const parts = raw.split(".");
    const headerJson = b64urlDecode(parts[0]);
    const payloadJson = b64urlDecode(parts[1]);
    if (!headerJson || !payloadJson) return null;
    let header = null, payload = null;
    try { header = JSON.parse(headerJson); } catch (_) {}
    try { payload = JSON.parse(payloadJson); } catch (_) {}
    if (!header || !payload) return null;

    stats.jwtSeen++;
    const signals = [];
    const add = (id, label, severity, detail) => signals.push({ id, label, severity, detail });

    const alg = String(header.alg || "");
    const key = "jwt:" + fnv1a(raw);

    if (/^none$/i.test(alg)) {
      stats.jwtAlgNone++;
      add("alg-none", "alg:none", "CRITICAL",
        "Unsigned token. If the server accepts it, signature verification is skipped entirely. Confirming this needs an active replay test.");
    }
    if (/^HS/i.test(alg)) add("hmac", "HMAC-signed (" + alg + ")", "INFO",
      "Verifiable with a symmetric secret, so a leaked or guessable secret means forgery.");
    if (header.kid) add("kid", "kid header present", "INFO",
      "kid is attacker-influenced in some libraries and can enable key injection or path traversal. Active test required.");

    const now = Math.floor(Date.now() / 1000);
    const exp = typeof payload.exp === "number" ? payload.exp : null;
    const iat = typeof payload.iat === "number" ? payload.iat : null;
    if (exp === null) {
      stats.jwtNoExp++;
      add("no-exp", "no exp claim", "HIGH", "Token never expires on its own.");
    } else if (exp < now) {
      add("expired", "expired", "INFO", "Already expired (exp=" + exp + ").");
    } else if (iat && exp - iat > 7 * 86400) {
      stats.jwtLongLived++;
      add("long-ttl", "long-lived token", "MEDIUM",
        "Lifetime is " + Math.round((exp - iat) / 86400) + " days. Session tokens should be minutes.");
    }
    if (exp !== null && exp > now + 365 * 86400) {
      add("absurd-ttl", "multi-year lifetime", "HIGH", "exp is more than a year out.");
    }

    const sub = payload.sub;
    if (typeof sub === "string" && sub) {
      if (!UUID_RE.test(sub) && /^[\w.@:-]+$/.test(sub)) {
        stats.jwtEnumerableSub++;
        add("sub-enumerable", "enumerable sub claim", "MEDIUM",
          "sub='" + clip(sub, 40) + "' is human-readable and sequential-looking, which supports account enumeration.");
      }
    }
    if (!payload.aud) add("no-aud", "no aud claim", "LOW", "No audience restriction observed.");
    if (!payload.iss) add("no-iss", "no iss claim", "LOW", "No issuer restriction observed.");

    const roleish = [];
    for (const k of Object.keys(payload)) {
      const nk = normKey(k);
      if (!SENSITIVE_CLAIMS.includes(nk)) continue;
      const v = payload[k];
      const isAdmin = typeof v === "string" ? ADMIN_ROLE_RE.test(v)
        : Array.isArray(v) && v.some(x => typeof x === "string" && ADMIN_ROLE_RE.test(x));
      roleish.push(k + "=" + clip(typeof v === "object" ? JSON.stringify(v) : String(v), 30));
      if (isAdmin) {
        add("admin-claim", "admin-shaped privilege claim", "HIGH",
          "Claim '" + k + "' carries an administrator value. If the signature can be forged or the claim is trusted from the client, this is privilege escalation.");
      }
    }
    if (roleish.length && !signals.some(s => s.id === "admin-claim")) {
      add("privilege-claim", "privilege claim present", "MEDIUM",
        "Claims: " + roleish.join(", ") + ". Confirm the server never trusts these from the client.");
    }

    let severity = "INFO";
    for (const s of signals) if ((SEV_RANK[s.severity] || 0) > (SEV_RANK[severity] || 0)) severity = s.severity;

    if (!jwtStore.has(key)) {
      const f = {
        id: ++jwtSeq, key, alg, typ: header.typ || "", kid: header.kid || null,
        sub: typeof sub === "string" ? clip(sub, 80) : null,
        iss: payload.iss ? clip(String(payload.iss), 120) : null,
        aud: payload.aud ? clip(JSON.stringify(payload.aud), 120) : null,
        exp, iat, claims: Object.keys(payload).slice(0, 30),
        signals, severity, masked: maskValue(raw),
                                                                         
                                                                           
        token: CONFIG.revealSecrets ? raw : null,
        sources: [source], weakSecret: null, firstSeen: Date.now()
      };
      jwtStore.set(key, f);
    } else {
                                                                                
                                                                       
      const prev = jwtStore.get(key);
      if (prev.sources.indexOf(source) < 0 && prev.sources.length < 16) prev.sources.push(source);
                                                                            
                              
      if (CONFIG.revealSecrets && prev.token == null) prev.token = raw;
    }

    const rec = jwtStore.get(key);
                                                                 
    if (CONFIG.jwtWeakSecretTest && /^HS/i.test(alg) && rec.weakSecret === null && !rec.weakTested) {
      rec.weakTested = true;
      testWeakSecret(rec, raw, alg, header);
    }
    return rec;
  }

  let jwtSecretTestsInFlight = 0;

  async function testWeakSecret(rec, raw, alg, header) {
    if (jwtSecretTestsInFlight > 4) return;
    jwtSecretTestsInFlight++;
    try {
      const hash = /384/.test(alg) ? "SHA-384" : /512/.test(alg) ? "SHA-512" : "SHA-256";
      const signingInput = raw.split(".").slice(0, 2).join(".");
      const sig = raw.split(".")[2];
      const tries = WEAK_JWT_SECRETS.slice(0, CONFIG.maxWeakSecretTries);
      for (const s of tries) {
        if (!active) return;
        if (await hmacVerify(s, signingInput, sig, hash)) {
          stats.jwtWeak++;
          rec.weakSecret = CONFIG.revealSecrets ? s : maskValue(s);
          rec.signals.push({
            id: "weak-hmac-secret", label: "weak HMAC secret recovered", severity: "CRITICAL",
            detail: "The signature verifies against a trivially guessable secret (" +
              (CONFIG.revealSecrets ? s : maskValue(s)) + "). Anyone can forge tokens with arbitrary claims. Verified locally, no requests sent."
          });
          rec.severity = "CRITICAL";
          addNote("jwt-weak:" + rec.key, {
            kind: "jwt-weak-secret", alg, source: rec.sources[0],
            detail: "token forgeable with a guessable secret"
          });
          return;
        }
      }
    } catch (e) {
      fail("jwtWeakSecret", e);
    } finally {
      jwtSecretTestsInFlight--;
    }
  }

  let jwtSeq = 0;

                                                                          
  function analyzeJWTsInURL(u, source) {
    if (!CONFIG.analyzeJWTs) return;
    try {
      for (const k of u.searchParams.keys()) {
        if (JWT_QUERY_KEYS.indexOf(String(k).toLowerCase()) < 0) continue;
        const v = u.searchParams.get(k);
        analyzeJWT(v, source + " url:" + k);
      }
      if (u.hash && u.hash.length > 2) {
        const frag = u.hash.slice(1);
        const asParams = new URLSearchParams(frag);
        for (const [k, v] of asParams.entries()) {
          if (JWT_QUERY_KEYS.indexOf(String(k).toLowerCase()) >= 0) analyzeJWT(v, source + " fragment:" + k);
        }
        if (asParams.size === 0) analyzeJWT(frag, source + " fragment");
      }
    } catch (_) {}
  }

                                                                            
                                                                              
  function analyzeJWTsInJSON(json, source) {
    if (!CONFIG.analyzeJWTs || !json || typeof json !== "object") return;
    const stack = [json];
    let guard = 0;
    while (stack.length && guard++ < 600) {
      const cur = stack.pop();
      if (Array.isArray(cur)) { for (const x of cur.slice(0, 20)) if (x && typeof x === "object") stack.push(x); continue; }
      if (!cur || typeof cur !== "object") continue;
      for (const k of Object.keys(cur).slice(0, 60)) {
        const v = cur[k];
        if (typeof v === "string") {
          if (looksLikeJWT(v)) analyzeJWT(v, source + " json:" + k);
          else if (JWT_QUERY_KEYS.indexOf(normKey(k)) >= 0 && v.length > 20) analyzeJWT(v, source + " json:" + k);
        } else if (v && typeof v === "object") stack.push(v);
      }
    }
  }

  function analyzeJWTsInHeaders(headers, source) {
    if (!CONFIG.analyzeJWTs || !headers) return;
    for (const k of Object.keys(headers)) {
      if (k === "authorization" || /^(x-)?(api-?key|auth-?token|access-?token|id-?token|jwt)$/.test(k)) {
        const v = String(headers[k] || "");
        if (v && v !== "[REDACTED]") analyzeJWT(v, source + " header:" + k);
      }
    }
  }

                                                                          
                              
                                                            
                                                                          
  function storageFinding(area, key, value, extra) {
    if (storageStore.size >= CONFIG.maxStorageFindings) return null;
    const sk = area + "|" + key;
    const text = String(value == null ? "" : value).slice(0, CONFIG.maxStorageValueChars);
    if (storageStore.has(sk)) {
      const prev = storageStore.get(sk);
      if (String(prev.rawLength) === String(String(value).length)) {
                                                                            
                                                                         
        if (CONFIG.revealSecrets) {
          if (prev.raw == null) prev.raw = text;
                                                                               
                                                                     
          analyzeJWT(text, "storage:" + area);
        }
        return prev;
      }
    }
    stats.storageItems++;
    const secrets = analyzeJWT(text, "storage:" + area) ? 1 : 0;
    const rec = {
      id: ++storageSeq, key: sk, area, name: key,
      masked: maskValue(text), rawLength: String(text).length,
      raw: CONFIG.revealSecrets ? text : null,
      hasJwt: !!secrets, secrets: secrets,
      pii: detectPII(text),
      classified: isSensitiveKey(key),
      note: null, at: new Date().toISOString(),
      ...(extra || {})
    };
    if (!rec) return null;
    storageStore.set(sk, rec);
    return rec;
  }

  let storageSeq = 0;

  function sweepKeyValueStore(area, storeObj) {
    if (!storeObj) return;
    try {
      const n = Number(storeObj.length) || 0;
      for (let i = 0; i < n; i++) {
        const k = storeObj.key(i);
        if (k === null || k === RELOAD_STORE_KEY || k === RELOAD_CONFIG_KEY) continue;
        let v;
        try { v = storeObj.getItem(k); } catch (_) { continue; }
        const rec = storageFinding(area, k, v);
        if (rec && rec.classified) stats.storageSecrets++;
                                                               
        if (CONFIG.scanSecrets && typeof v === "string" && v.length > 8) {
          const hits = scanSecrets(v.slice(0, CONFIG.maxStorageValueChars), "storage:" + area + ":" + k);
          for (const h of hits) if (h.exposure === "leak") stats.storageSecrets++;
        }
      }
    } catch (e) {
      fail("sweep:" + area, e);
    }
  }

  function sweepCookies() {
    if (!hasDOM || !document.cookie) return;
    try {
      for (const part of String(document.cookie).split(";")) {
        const i = part.indexOf("=");
        if (i < 1) continue;
        const name = part.slice(0, i).trim();
        const value = part.slice(i + 1).trim();
        if (!name) continue;
        const rec = storageFinding("cookie", name, value, { httpOnly: "unknown (not readable from JS)" });
        if (rec && rec.classified) stats.storageSecrets++;
        if (CONFIG.analyzeJWTs) analyzeJWT(value, "storage:cookie:" + name);
      }
    } catch (e) {
      fail("sweep:cookie", e);
    }
  }

                                                                           
                               
  const GLOBAL_NAME_RE = /(config|env|settings|api|token|key|secret|flag|feature|auth|client|runtime|options|props|store|state|creds?|credential|password|endpoint|base_?url)/i;

  function sweepWindowGlobals() {
    if (!CONFIG.sweepWindowGlobals) return;
    try {
      let names = [];
      try { names = Object.getOwnPropertyNames(window); } catch (_) { return; }
      let seen = 0;
      for (const name of names) {
        if (seen > 400) break;
        if (!GLOBAL_NAME_RE.test(name)) continue;
        let v;
        try { v = window[name]; } catch (_) { continue; }
        if (v === null || v === undefined) continue;
        const t = typeof v;
        if (t === "function") continue;
        let text;
        try { text = t === "object" ? JSON.stringify(v) : String(v); } catch (_) { continue; }
        if (!text || text.length > CONFIG.maxStorageValueChars) continue;
        if (text === "[object Object]" || text === "undefined" || text === "null") continue;
        seen++;
        storageFinding("window", name, text);
        if (CONFIG.analyzeJWTs) analyzeJWT(text, "storage:window:" + name);
      }
    } catch (e) {
      fail("sweep:window", e);
    }
  }

                                                                           
                                                                            
                                                                          
    let idbRetryLeft = 0;
    function scheduleIndexedDbRetry() {
      if (!CONFIG.sweepIndexedDB || idbRetryLeft <= 0) return;
      idbRetryLeft--;
      const delay = idbRetryLeft >= 2 ? 1200 : 4000;
      setTimeout(() => {
        sweepIndexedDB().then(() => {
          if (stats.indexedDbRecords > 0) { idbRetryLeft = 0; return; }
          scheduleIndexedDbRetry();
        }).catch(e => fail("sweepIndexedDB.retry", e));
      }, delay);
    }
    function armIndexedDbRetries() { idbRetryLeft = 3; scheduleIndexedDbRetry(); }

    async function sweepIndexedDB() {
    if (!CONFIG.sweepIndexedDB || typeof indexedDB === "undefined" || !indexedDB) return;
    try {
      let dbs = [];
      if (typeof indexedDB.databases === "function") dbs = await indexedDB.databases();
      else {
                                                                          
        const open = indexedDB.open("");
        dbs = [await new Promise(res => { open.onsuccess = () => res({ name: open.result.name, version: open.result.version }); open.onerror = () => res(null); })];
      }
      for (const d of (dbs || []).slice(0, 20)) {
        if (!d || !d.name) continue;
        let db;
        try {
          db = await new Promise((res, rej) => {
            const req = indexedDB.open(d.name);
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
            req.onblocked = () => rej(new Error("blocked"));
          });
        } catch (_) { continue; }
        let stores = [];
        try { stores = Array.prototype.slice.call(db.objectStoreNames || []); } catch (_) {}
        for (const s of stores.slice(0, 12)) {
          try {
            const tx = db.transaction(s, "readonly");
            const os = tx.objectStore(s);
            const req = os.getAll();
            const vals = await new Promise(res => { req.onsuccess = () => res(req.result || []); req.onerror = () => res([]); });
for (const v of (vals || []).slice(0, CONFIG.maxIndexedDbRecords)) {
                let text;
                try { text = typeof v === "string" ? v : JSON.stringify(v); } catch (_) { continue; }
                if (!text) continue;
                stats.indexedDbRecords++;
                                                                                 
                                                                               
                                                                            
                                                                            
                let recKey = "";
                if (v && typeof v === "object") {
                  const k = v.key != null ? v.key : (v.name != null ? v.name : (v.id != null ? v.id : null));
                  if (k != null) recKey = " " + String(k).slice(0, 120);
                }
                storageFinding("indexeddb", d.name + "/" + s + recKey, text);
                if (CONFIG.analyzeJWTs) analyzeJWT(text, "storage:indexeddb:" + d.name + "/" + s);
              }
          } catch (_) {}
        }
        try { db.close(); } catch (_) {}
      }
    } catch (e) {
      fail("sweep:indexeddb", e);
    }
  }

  async function sweepCaches() {
    if (!CONFIG.sweepCaches || typeof caches === "undefined" || !caches) return;
    try {
      const keys = await caches.keys();
      for (const k of keys.slice(0, 12)) {
        let cache = null;
        try { cache = await caches.open(k); } catch (_) { continue; }
        let reqs = [];
        try { reqs = await cache.keys(); } catch (_) {}
        for (const req of (reqs || []).slice(0, CONFIG.maxCacheEntries)) {
          stats.cacheEntries++;
          const u = parseURL(req && req.url);
          if (u) {
            addNote("cache:" + u.href, {
              kind: "cache-entry", cache: k, url: redactURL(u),
              note: "response held in Cache Storage for offline use"
            });
          }
          try {
            const res = await cache.match(req);
            if (!res) continue;
            const ct = (res.headers && res.headers.get("content-type")) || "";
            if (!/json|text|xml/i.test(ct)) continue;
            const text = await res.clone().text();
            safeCancel(res.body);
            if (text.length > 200000) continue;
            const label = "cache:" + k + (u ? " " + u.pathname : "");
            analyzeJWTsInJSON(safeParse(text), label);
                                                                              
                                                                                
            storageFinding("cache", (u ? u.pathname : String(req.url)).slice(0, 200), text.slice(0, 400), {
              cache: k, url: u ? redactURL(u) : String(req.url)
            });
            if (CONFIG.scanSecrets) {
              const hits = scanSecrets(text.slice(0, 60000), label);
              for (const h of hits) if (h.exposure === "leak") stats.storageSecrets++;
              if (hits.length) ingestSecrets(hits, label, CH_STORAGE);
            }
            const pii = detectPII(text);
            if (pii.length) {
              addNote("cache-pii:" + u + ":" + pii.map(p => p.kind).join(","), {
                kind: "cache-pii", cache: k, url: u ? redactURL(u) : String(req.url),
                pii: pii.map(p => p.kind + " x" + p.count),
                note: "sensitive data is persisted in Cache Storage and readable by any script on this origin"
              });
            }
          } catch (_) {}
        }
      }
    } catch (e) {
      fail("sweep:caches", e);
    }
  }

  function sweepStorage() {
    if (!CONFIG.sweepStorage) return;
    sweepKeyValueStore("localStorage", (() => { try { return window.localStorage; } catch (_) { return null; } })());
    sweepKeyValueStore("sessionStorage", (() => { try { return window.sessionStorage; } catch (_) { return null; } })());
    sweepCookies();
    sweepWindowGlobals();
                                                    
    sweepIndexedDB().catch(e => fail("sweepIndexedDB", e));
    sweepCaches().catch(e => fail("sweepCaches", e));
  }

                                                                            
                                                                                 
                                                                        
  const GQL_ALIAS_RE = /(^|[\s{,])([A-Za-z_]\w*)\s*:\s*[A-Za-z_]\w*\s*[({]/g;

  function noteGraphQLComplexity(json, bodyText, u) {
    if (!json && !bodyText) return;
    const aliasHits = [];
    const batches = [];
    const consider = q => {
      if (typeof q !== "string") return;
      const rx = new RegExp(GQL_ALIAS_RE.source, "g");
      let m, guard = 0;
      while ((m = rx.exec(q)) !== null && guard++ < 60) {
        if (/^__/.test(m[2])) continue;
        aliasHits.push(m[2]);
      }
    };
    if (Array.isArray(json)) {
      batches.push(json.length);
      for (const it of json.slice(0, 20)) if (it && typeof it === "object") consider(it.query);
    } else if (json && typeof json === "object") {
      consider(json.query);
    }
    if (!aliasHits.length && bodyText) {
      let m;
      const rx2 = /(?:^|[\s{,])([A-Za-z_]\w*)\s*:\s*[A-Za-z_]\w*\s*[({]/g;
      let guard = 0;
      while ((m = rx2.exec(String(bodyText))) !== null && guard++ < 60) {
        if (!/^__/.test(m[1])) aliasHits.push(m[1]);
      }
    }

    const uniq = [...new Set(aliasHits)];
    if (!uniq.length && !batches.length) return;
    const maxBatch = batches.length ? Math.max(...batches) : 0;

    if (maxBatch >= 2) {
      addNote("gql-batch:" + u.origin + u.pathname + ":" + maxBatch, {
        kind: "graphql-batch-observed", aliases: uniq.slice(0, 12), maxOperations: maxBatch,
        note: "The app itself sent a batched GraphQL request with " + maxBatch + " operations. Batching and aliasing are used for amplification DoS (HackerOne 3287208, $12,500). OBSERVED ONLY, never generated by this tool."
      });
    }
    if (uniq.length >= 2) {
      addNote("gql-alias:" + u.origin + u.pathname + ":" + uniq.join(","), {
        kind: "graphql-alias-observed", aliases: uniq.slice(0, 12),
        note: "Aliased fields observed in app traffic: " + uniq.slice(0, 8).join(", ") + ". Replication is an ACTIVE test. HackerOne tightened its DoS policy in October 2025, so confirm scope before raising it."
      });
    }
  }

                                                                          
                                  
                                                                              
                                                                    
                                                                          
  const OAUTH_PATH_RE = /(\/oauth2?(\/|$)|\/oauth(\/|$)|\/authorize(\/|$)|\/token(\/|$)|\/login\/oauth|\/signin\/oauth|\/auth\/callback|\/callback(\/|$)|\/openid\/connect|\/\.well-known\/openid-configuration|\/userpool|\/realms?\/[^/]+\/protocol\/openid-connect)/i;
  const OAUTH_STEP_RE = /(\/authorize|\/oauth\/authorize|\/oauth2\/authorize|\/token|\/oauth\/token|\/oauth2\/token|\/userinfo|\/revoke|\/introspect|\/openid-configuration)/i;

                                                                              
                                                 
  function stateLooksWeak(s) {
    const v = String(s || "");
    if (!v) return true;
    if (/^\d{1,13}$/.test(v)) return true;                                        
    if (v.length < 12) return true;
    if (/^(state|nonce|csrf|xsrf)[-_=]/i.test(v)) return true;
    if (/^(test|dummy|abc123|12345|state)/i.test(v)) return true;
    return false;
  }

  function analyzeOAuth(u, meta) {
    if (!CONFIG.trackOAuth || !u) return null;
    const p = u.pathname;
    const isDiscovery = /openid-configuration/.test(p);
    const isStep = OAUTH_STEP_RE.test(p);
    if (!isDiscovery && !isStep) return null;

    const findings = [];
    const q = u.searchParams;
    const flow = isDiscovery ? "discovery" : (/token/i.test(p) ? "token" : (/authorize|login|signin/i.test(p) ? "authorize" : "other"));

    const clientId = q.get("client_id") || q.get("clientId") || "";
    const redirectUris = [];
    for (const k of ["redirect_uri", "redirectUrl", "redirect_url", "returnTo", "return_to", "continue", "callback"]) {
      const v = q.get(k);
      if (v) redirectUris.push({ param: k, value: v });
    }
    if (redirectUris.length) stats.oauthRedirectUris += redirectUris.length;

    const state = q.get("state");
    const responseType = q.get("response_type") || "";
    const scope = q.get("scope") || "";
    const pkce = q.get("code_challenge") ? true : false;

    if (flow === "authorize") {
      if (!state) { stats.oauthNoState++; findings.push({ id: "no-state", label: "no state parameter", severity: "HIGH", detail: "No CSRF state on the authorization request. Combined with a lax callback this enables login CSRF and account linking." }); }
      else if (stateLooksWeak(state)) findings.push({ id: "weak-state", label: "guessable state", severity: "MEDIUM", detail: "state appears predictable, weakening CSRF protection." });
      if (/token/i.test(responseType)) {
        stats.oauthImplicit++;
        findings.push({ id: "implicit-flow", label: "implicit flow", severity: "MEDIUM", detail: "response_type includes token, so an access token lands in the URL fragment and is exposed to referrers, history and any script on the page." });
      }
      if (scope) findings.push({ id: "scopes", label: "scopes requested", severity: "INFO", detail: "scope=" + clip(scope, 200) });
      if (!pkce) findings.push({ id: "no-pkce", label: "no PKCE", severity: "MEDIUM", detail: "No code_challenge. An intercepted authorization code is directly redeemable." });
    }

    for (const param of ["access_token", "id_token", "refresh_token", "code"]) {
      if (q.get(param)) {
        findings.push({
          id: "token-in-url", label: param + " in URL query", severity: "HIGH",
          detail: "Credential in a URL is written to server logs, proxy logs, browser history and Referer headers."
        });
      }
    }

                                                                                 
    const bodyText = meta && meta.requestBody ? String(meta.requestBody) : "";
    if (bodyText && /client_secret["'\s]*[:=]/.test(bodyText)) {
      findings.push({ id: "client-secret-body", label: "client_secret in request body", severity: "HIGH", detail: "A confidential client secret is being sent from the browser. If it is a real secret it must not ship to a client at all." });
    }
    if (bodyText && /grant_type["'\s]*[:=]\s*["']?client_credentials/.test(bodyText)) {
      findings.push({ id: "client-credentials-grant", label: "client_credentials grant", severity: "MEDIUM", detail: "A client_credentials exchange implies a confidential secret is present in the browser." });
    }

    const fk = flow + "|" + u.origin + u.pathname;
    const rec = {
      id: ++oauthSeq, key: fk, flow, url: redactURL(u), host: u.host,
      clientId: clientId ? clip(clientId, 80) : null,
      issuer: null, jwksUri: null,
      redirectUris: redirectUris.map(r => ({ param: r.param, value: clip(r.value, 300) })),
      responseType: responseType || null, scope: scope || null, pkce,
      findings, at: new Date().toISOString()
    };
    if (!oauthStore.has(fk)) { oauthStore.set(fk, rec); stats.oauthFlows++; }

    if (redirectUris.length) {
      for (const r of redirectUris) {
        const notes = [];
        try {
          const ru = new URL(r.value, u.href);
          if (siteOf(ru.hostname) !== siteOf(u.hostname)) notes.push("points at a different registrable domain");
          if (ru.protocol === "http:") notes.push("plain http");
          if (/localhost|127\.0\.0\.1|\[::1\]/i.test(ru.hostname)) notes.push("loopback host");
          if (ru.search) notes.push("contains a query string");
          if (/[?&](?:code|token|state)=/.test(ru.search)) notes.push("already carries a credential-shaped parameter");
        } catch (_) { notes.push("not an absolute URL"); }
        addNote("redir:" + r.value, {
          kind: "oauth-redirect-uri", flow, client: rec.clientId,
          value: clip(r.value, 300), notes,
          via: flow === "authorize" ? "observed in an authorization request" : "observed in a token request"
        });
      }
    }

    if (isDiscovery) {
      const j = meta && meta.responseJson;
      if (j && typeof j === "object") {
        rec.issuer = j.issuer ? String(j.issuer).slice(0, 160) : null;
        rec.jwksUri = j.jwks_uri ? String(j.jwks_uri).slice(0, 200) : null;
        oauthStore.set(fk, rec);
        addNote("oidc:" + u.origin, {
          kind: "oidc-discovery", issuer: rec.issuer, jwksUri: rec.jwksUri,
          endpoints: Object.keys(j).filter(x => /_endpoint$/.test(x)).slice(0, 12),
          note: "authorization server metadata is public, which pins the tenant and the full auth endpoint set"
        });
      }
    }
    return rec;
  }

  let oauthSeq = 0;

                                                                          
                                               
                                                                      
                                                                          
  const FRAMEWORK_SIGS = [
    { name: "next.js", kind: "lib", tests: [/__NEXT_DATA__/, /\/_next\/static\//, /self\.__next_f/], ver: [/__NEXT_DATA__[\s\S]{0,400}?"version"\s*:\s*"([^"]+)"/, /"version"\s*:\s*"(\d+\.\d+\.\d+)"/] },
    { name: "react", kind: "lib", tests: [/React\.version\s*=\s*"([^"]+)"/, /react-dom(-|\/)/, /ReactDOM(?:\.classic|-prod\.classic|CompatibilityLayer)/, /["']React\.classic["']/, /data-reactroot/, /id=["']react-root["']/, /__REACT_DEVTOOLS_GLOBAL_HOOK__/], ver: [/React\.version\s*=\s*"([^"]+)"/, /"react"\s*:\s*"?(\d+\.\d+\.\d+)/] },
    { name: "vue", kind: "lib", tests: [/Vue\.version\s*=\s*"([^"]+)"/, /data-v-[0-9a-f]{8}/, /__VUE__/, /data-v-app/], ver: [/Vue\.version\s*=\s*"([^"]+)"/] },
    { name: "angular", kind: "lib", tests: [/ng-version[=:]\s*["']?([\d.]+)/, /\bAngular\b.*\bversion\b/i], ver: [/ng-version[=:]\s*["']?([\d.]+)/] },
    { name: "angularjs", kind: "lib", tests: [/angular\.version\s*=\s*\{/, /ng-controller=/, /ng-app[=\s>]/], ver: [/angular\.version\s*=\s*\{[^}]*full\s*:\s*"([^"]+)"/] },
    { name: "svelte", kind: "lib", tests: [/svelte-[a-z0-9]{6}/, /SvelteComponent/, /data-svelte-h=/], ver: [/svelte@(\d+\.\d+\.\d+)/] },
    { name: "remix", kind: "lib", tests: [/@remix-run\//, /__remixContext/], ver: [/@remix-run\/[^"'\s]*@?(\d+\.\d+\.\d+)/] },
    { name: "nuxt", kind: "lib", tests: [/__NUXT__/, /nuxt-link/, /\/_nuxt\//], ver: [/nuxt@(\d+\.\d+\.\d+)/, /"nuxt"\s*:\s*"?(\d+\.\d+\.\d+)/] },
    { name: "gatsby", kind: "lib", tests: [/___gatsby/, /gatsby-chunk/], ver: [] },
    { name: "astro", kind: "lib", tests: [/astro-island/, /data-astro-cid/], ver: [] },
    { name: "ember", kind: "lib", tests: [/Ember\.VERSION/, /data-ember-action/], ver: [/Ember\.VERSION\s*=\s*"([^"]+)"/] },
    { name: "htmx", kind: "lib", tests: [/hx-get=/, /hx-post=/, /htmx\.org/], ver: [/htmx(?:\.min)?\.js\?v=([\d.]+)/, /htmx@([\d.]+)/] },
    { name: "vite", kind: "build", tests: [/@vite\/client/, /__vite\w*MapDeps/, /import\.meta\.url/], ver: [/@vite\/client\?v=(\d+)/] },
    { name: "webpack", kind: "build", tests: [/webpackChunk\w*\s*=/, /__webpack_require__/, /webpackJsonp/], ver: [] },
    { name: "Meta Spin", kind: "build", tests: [/"__spin_b"\s*:/, /__spin_r["']?\s*:\s*\d+/, /bootloader-hash/, /__d_stub/, /requireLazy\s*=/], ver: [] },
    { name: "jQuery", kind: "lib", tests: [/jQuery\.fn\.jquery\s*=\s*"([^"]+)"/, /\$\.fn\.jquery\s*=\s*"([^"]+)"/], ver: [/jquery\s*=\s*"(\d+\.\d+\.\d+)/, /jquery@(\d+\.\d+\.\d+)/] },
    { name: "axios", kind: "lib", tests: [/axios[\s\S]{0,60}?VERSION\s*=\s*"([^"]+)"/], ver: [/axios@(\d+\.\d+\.\d+)/] },
    { name: "sentry", kind: "lib", tests: [/Sentry\.init\(/, /sentry\.io\/api/], ver: [/@sentry\/browser@(\d+\.\d+\.\d+)/] }
  ];

                                                                              
  const FRAMEWORK_CVES = {
    "next.js": [
      { lt: "15.5.16", ids: ["CVE-2026-44575", "CVE-2026-44574"],
        titles: ["App Router middleware/proxy bypass via .rsc and segment-prefetch transport variants (7.5)",
                 "Middleware bypass via dynamic route parameter injection (8.1)"],
        how: "Request the same page as <path>.rsc or /segments/*.segment.rsc. These resolve to the same content but did not match the compiled middleware matcher." },
      { lt: "15.5.21", ids: ["CVE-2026-64649"], titles: ["SSRF in Server Actions via Host-associated headers (8.3)"],
        how: "Applies to custom servers or deployments that do not pin the Host header. Managed hosting is not affected." },
      { lt: "15.5.27", ids: ["CVE-2026-94483"], titles: ["Response cache key too broad, cross-user content substitution (6.5)"],
        how: "Root-level catch-all plus SSG/ISR routes sharing an insufficiently scoped cache key." }
    ],
    "vite": [
      { lt: "5.4.20", ids: ["CVE-2025-30208"], titles: ["fs.deny bypass exposing server files in dev server (7.5)"],
        how: "Dev-server only. Applies to ?raw??url= and ?import&raw= style requests against the dev server." }
    ]
  };

  function verLessThan(a, b) {
    const pa = String(a || "0").split(".").map(x => parseInt(x, 10) || 0);
    const pb = String(b || "0").split(".").map(x => parseInt(x, 10) || 0);
    for (let i = 0; i < 3; i++) {
      const x = pa[i] || 0, y = pb[i] || 0;
      if (x !== y) return x < y;
    }
    return false;
  }

  function detectFrameworksIn(text) {
    if (!CONFIG.detectFrameworks || !text || text.length > 4000000) return;
    for (const sig of FRAMEWORK_SIGS) {
      let matched = false;
      for (const t of sig.tests) {
        if (t.test(text)) { matched = true; break; }
      }
      if (!matched) continue;
      let version = null;
      for (const v of sig.ver) {
        const m = v.exec(text);
        if (m && m[1]) { version = m[1]; break; }
      }
      recordFramework(sig.name, version, sig.kind);
    }
  }

  function recordFramework(name, version, kind) {
    let rec = fwStore.get(name);
    if (!rec) {
      rec = {
        name, versions: new Set(), cves: [], kind: kind || "lib",
        firstSeen: new Date().toISOString()
      };
      fwStore.set(name, rec);
      stats.frameworks++;
    }
    if (kind) rec.kind = kind;
    if (version && !rec.versions.has(version)) {
      rec.versions.add(version);
      rec.version = version;
      if (CONFIG.frameworkCveMap) rec.cves = matchCVEs(name, version);
      addNote("fw:" + name, {
        kind: "framework", name, version,
        otherVersions: [...rec.versions],
        cves: rec.cves,
        note: rec.cves.length ? "version matches known advisories, see the CVE notes" : "fingerprint only"
      });
    }
  }

                                                                              
                                                                              
                                                                            
                                                                            
                                                                          
  function safeVersion(v) {
    const s = typeof v === "string" ? v.trim() : (typeof v === "number" ? String(v) : "");
    return /^\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?$/.test(s) ? s : null;
  }

  function detectRuntimeFrameworks() {
    if (!CONFIG.detectFrameworks || typeof window === "undefined" ||
        typeof document === "undefined") return;

    const g = name => {
      try { return window[name]; } catch (_) { return undefined; }
    };
    const domHas = sel => {
      try { return !!document.querySelector(sel); } catch (_) { return false; }
    };
    const firstNodeWith = (props, count) => {
      try {
        const nodes = document.querySelectorAll("body *");
        const n = Math.min(nodes.length, count || 400);
        for (let i = 0; i < n; i++) {
          const el = nodes[i];
          if (!el) continue;
          const keys = Object.keys(el);
          for (const k of keys) {
            if (props(k)) return true;
          }
        }
      } catch (_) {}
      return false;
    };

    let reactVersion = null;
    try {
      const R = g("React");
      if (R) reactVersion = safeVersion(R.version);
      if (!reactVersion) {
        const RD = g("ReactDOM");
        if (RD) reactVersion = safeVersion(RD.version);
      }
      if (!reactVersion) {
        const hook = g("__REACT_DEVTOOLS_GLOBAL_HOOK__");
        if (hook && hook.renderers && typeof hook.renderers.values === "function") {
          for (const r of hook.renderers.values()) {
            const v = safeVersion(r && r.version);
            if (v) { reactVersion = v; break; }
          }
        }
      }
    } catch (_) {}
    const isReact = !!g("React") || !!g("ReactDOM") ||
      domHas("[data-reactroot],#react-root,[id^='react-root'],[data-reactid]") ||
      firstNodeWith(k => k.indexOf("__reactFiber$") === 0 ||
        k.indexOf("__reactContainer$") === 0 ||
        k.indexOf("__reactProps$") === 0 || k === "_reactRootContainer");
    if (isReact) recordFramework("react", reactVersion, "lib");

    let vueVersion = null;
    try {
      const V = g("Vue");
      if (V) vueVersion = safeVersion(V.version);
      if (!vueVersion) {
        const V3 = g("__VUE__");
        if (V3) vueVersion = safeVersion(V3.version);
      }
    } catch (_) {}
    const isVue = !!g("Vue") || !!g("__VUE__") || domHas("[data-v-app]") ||
      firstNodeWith(k => k === "__vue__" || k === "__vueParentComponent" ||
        k === "__vue_app__");
    if (isVue) recordFramework("vue", vueVersion, "lib");

    let ngVersion = null;
    try {
      const angular = g("angular");
      if (angular && angular.version) {
        ngVersion = safeVersion(angular.version.full || angular.version);
      }
      if (!ngVersion) {
        const ng = g("ng");
        if (ng && ng.VERSION) ngVersion = safeVersion(ng.VERSION.full);
      }
    } catch (_) {}
    if (!ngVersion) {
      try {
        const el = document.querySelector("[ng-version]");
        if (el) ngVersion = safeVersion(el.getAttribute("ng-version"));
      } catch (_) {}
    }
    const isAngularJs = !!g("angular") || domHas("[ng-app],[ng-controller]");
    const isModernAngular = !!g("ng") || domHas("[ng-version]");
    if (isAngularJs) recordFramework("angularjs", ngVersion, "lib");
    if (isModernAngular) recordFramework("angular", ngVersion, "lib");

    let jq = null;
    try { jq = g("jQuery") || g("$"); } catch (_) {}
    if (jq && jq.fn && jq.fn.jquery) {
      recordFramework("jQuery", safeVersion(jq.fn.jquery), "lib");
    }

    const isSvelte = !!g("__svelte") || domHas("[class*='svelte-']") ||
      domHas("[data-svelte-h]");
    if (isSvelte) recordFramework("svelte", null, "lib");

    try {
      const Ember = g("Ember");
      if (Ember) recordFramework("ember", safeVersion(Ember.VERSION), "lib");
      const Backbone = g("Backbone");
      if (Backbone) recordFramework("backbone", safeVersion(Backbone.VERSION), "lib");
      const Alpine = g("Alpine");
      if (Alpine) recordFramework("alpinejs", safeVersion(Alpine.version), "lib");
      const htmx = g("htmx");
      if (htmx) recordFramework("htmx", safeVersion(htmx.version), "lib");
      if (g("Turbo")) recordFramework("turbo", null, "lib");
      if (g("Stimulus")) recordFramework("stimulus", null, "lib");
      if (g("__PREACT_DEVTOOLS__")) recordFramework("preact", null, "lib");
      if (g("__NEXT_DATA__") || g("next")) recordFramework("next.js", null, "lib");
      if (g("__NUXT__")) recordFramework("nuxt", null, "lib");
      if (g("___gatsby")) recordFramework("gatsby", null, "lib");
      if (g("__remixContext")) recordFramework("remix", null, "lib");
    } catch (_) {}

    let webpack = !!g("__webpack_require__");
    if (!webpack) {
      try {
        for (const k of Object.keys(window)) {
          if (/^(?:webpackChunk|webpackJsonp)/.test(k)) { webpack = true; break; }
        }
      } catch (_) {}
    }
    if (webpack) recordFramework("webpack", null, "build");

    if (g("__vite__mapDeps") || g("__vite_ssr_import__")) {
      recordFramework("vite", null, "build");
    }
    if (g("parcelRequire")) recordFramework("parcel", null, "build");
    if (g("__rspack_require__")) recordFramework("rspack", null, "build");
    try {
      const sys = g("System");
      if (sys && sys.constructor && /SystemJS/.test(String(sys.constructor.name || ""))) {
        recordFramework("systemjs", null, "build");
      }
      const rjs = g("requirejs");
      if (rjs) recordFramework("requirejs", safeVersion(rjs.version), "build");
    } catch (_) {}

                                                                              
                                                                           
    try {
      if (g("__spin_r") || g("__spin_b") ||
          typeof g("requireLazy") === "function" ||
          typeof g("__d") === "function" ||
          domHas("link[data-bootloader-hash]")) {
        recordFramework("Meta Spin", null, "build");
      }
    } catch (_) {}
  }

  function matchCVEs(name, version) {
    const list = FRAMEWORK_CVES[name] || [];
    const out = [];
    for (const e of list) {
      if (version && verLessThan(version, e.lt)) {
        out.push({ fixedIn: e.lt, ids: e.ids, titles: e.titles, how: e.how });
        for (const id of e.ids) {
          addNote("cve:" + name + ":" + id, {
            kind: "cve-candidate", framework: name, version, cve: id,
            fixedIn: e.lt, titles: e.titles, how: e.how,
            note: "passive version match, not proof of exploitability. Confirm the exact version and test before reporting."
          });
        }
      }
    }
    return out;
  }

                                                                          
                                                          
                                                                           
                                                              
                                                                          
  const SERVER_ACTION_RES = [
    /createServerReference\)\(\s*"([0-9a-f]{40})"/g,
    /createServerReference\(\s*"([0-9a-f]{40})"/g,
    /\b([0-9a-f]{40})\b(?=[^"'`]*?(?:use server|Server Action))/g
  ];
  const RSC_CT_RE = /text\/x-component/i;
  const RSC_URL_RE = /([?&]_rsc=)|(\.rsc$)|(\.segments?\/[^/]+\.segment\.rsc$)/i;

  function detectServerActions(text, file) {
    if (!CONFIG.detectServerActions || !text) return;
    if (text.indexOf("createServerReference") < 0 && text.indexOf("use server") < 0) return;
    const found = new Set();
    for (const re of SERVER_ACTION_RES) {
      const rx = new RegExp(re.source, re.flags);
      let m;
      while ((m = rx.exec(text)) !== null && found.size < CONFIG.maxServerActions) {
        found.add(m[1]);
        if (m[0].length === 0) rx.lastIndex++;
      }
      if (found.size >= CONFIG.maxServerActions) break;
    }
    for (const id of found) {
      stats.serverActions++;
      addNote("sa:" + id, {
        kind: "server-action", id, file: String(file).split("/").pop(),
        note: "Server Action ID present in a public client chunk. Its endpoints are callable without auth when middleware does not cover them."
      });
    }
  }

  const PROTECTED_PATH_RE = /(admin|account|billing|settings|profile|security|subscription|payment|invoice|dashboard|internal|org\/|workspace|user\/?$)/i;

  function noteRSC(u, meta) {
    const ct = meta && meta.responseContentType ? String(meta.responseContentType) : "";
    const isRSC = RSC_CT_RE.test(ct) || RSC_URL_RE.test(u.pathname + u.search);
    if (!isRSC) return false;
    stats.rsc = (stats.rsc || 0) + 1;
    addNote("rsc:" + u.origin + u.pathname, {
      kind: "rsc-request", url: redactURL(u), contentType: ct || "(rsc transport variant)",
      note: "App Router transport variant. These have historically resolved to the same page without matching middleware matchers."
    });
                                                                       
    const fw = fwStore.get("next.js");
    if (fw && PROTECTED_PATH_RE.test(u.pathname)) {
      addNote("rsc-bypass-candidate:" + u.pathname, {
        kind: "rsc-bypass-candidate", path: u.pathname,
        url: redactURL(u), cves: ["CVE-2026-44575", "CVE-2026-44574"],
        note: "Next.js is in use and this protected-looking path was served over an .rsc/prefetch transport. Reproducing the bypass is an ACTIVE test, use probe().",
        how: "Request the canonical path as <path>.rsc and compare. Never fire this from a passive run."
      });
    }
    return true;
  }

                                                                          
                    
                                                                          
  async function inspectServiceWorkers() {
    if (!CONFIG.inspectServiceWorkers || typeof navigator === "undefined" || !navigator.serviceWorker) return;
    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const r of regs.slice(0, 20)) {
        const scope = r.scope || "";
        const script = r.active && r.active.scriptURL ? r.active.scriptURL : (r.installing && r.installing.scriptURL) || "";
        if (swStore.has(scope)) continue;
        stats.serviceWorkers++;
        const rec = { scope, script, state: r.active ? "active" : (r.installing ? "installing" : "waiting"), at: new Date().toISOString() };
        swStore.set(scope, rec);

                                                                             
                                                            
        let broad = false;
        try {
          const s = new URL(scope, location.href);
          const here = new URL(location.pathname, location.href);
          if (s.origin !== location.origin) broad = true;
          else if (s.pathname === "/") broad = true;
          else if (here.pathname.indexOf(s.pathname) !== 0) broad = true;
        } catch (_) {}
        rec.broadScope = broad;

        addNote("sw:" + scope, {
          kind: "service-worker", scope: redactHref(scope), script: redactHref(script), state: rec.state,
          broadScope: broad,
          note: broad
            ? "Scope is broader than the current path, so this worker can intercept requests the developer may not have considered. Verify the routing is intended."
            : "registered service worker; its script is scanned like any other asset"
        });

                                                                  
        if (script && /^https?:/i.test(script)) enqueueScript(script);
      }
    } catch (e) {
      fail("inspectServiceWorkers", e);
    }
  }

  function installServiceWorkerHook() {
    if (typeof navigator === "undefined" || !navigator.serviceWorker ||
        typeof navigator.serviceWorker.register !== "function" || typeof Proxy === "undefined") return;
    const swProto = Object.getPrototypeOf(navigator.serviceWorker);
    const original = swProto.register;
    if (typeof original !== "function") return;
    const wrapper = function register(scriptURL, options) {
      if (active) {
        try {
          addNote("swreg:" + String(scriptURL), {
            kind: "service-worker", scope: options && options.scope ? redactHref(options.scope) : "(default)",
            script: redactHref(String(scriptURL)), state: "registering",
            note: "service worker registered by the page"
          });
          stats.serviceWorkers++;
                                                                             
          Promise.resolve(Reflect.apply(original, this, arguments))
            .then(() => { inspectServiceWorkers().catch(() => {}); })
            .catch(() => {});
          return;
        } catch (e) { fail("sw.register", e); }
      }
      return Reflect.apply(original, this, arguments);
    };
    try { swProto.register = wrapper; } catch (_) { return; }
    cleanups.push(() => { try { if (swProto.register === wrapper) swProto.register = original; } catch (_) {} });
    hooks.push("service-worker");
  }

                                                                          
                                                      
                                                                          
  function installPostMessageHook() {
    if (!CONFIG.detectPostMessageWildcard || typeof window.postMessage !== "function") return;
    const original = window.postMessage;
    const wrapper = function postMessage(message, targetOrigin, transfer) {
      if (active) {
        try {
                                                                             
                                                                                   
          const origin = targetOrigin === undefined ? "(omitted)" : String(targetOrigin);
          if (targetOrigin === "*" || targetOrigin === undefined || targetOrigin === null) {
            stats.postMessageWildcard++;
            const shape = (() => {
              try {
                if (typeof message === "string") return "string";
                if (message && typeof message === "object") return "object:" + Object.keys(message).slice(0, 6).join(",");
                return typeof message;
              } catch (_) { return "unknown"; }
            })();
            addNote("pm:" + shape + ":" + origin, {
              kind: "postmessage-wildcard", targetOrigin: origin, shape,
              note: "postMessage sent without a target origin. Any listening frame, including a cross-origin or opened one, can read it. Relevant to CSWSH and to token hand-off flows."
            });
          }
        } catch (e) { fail("postMessage", e); }
      }
      return Reflect.apply(original, this, arguments);
    };
    try { window.postMessage = wrapper; } catch (_) { return; }
    cleanups.push(() => { try { if (window.postMessage === wrapper) window.postMessage = original; } catch (_) {} });
    hooks.push("postmessage");
  }

  let tabnabbingSeen = 0;

  function scanTabnabbing() {
    if (!CONFIG.detectTabnabbing || !hasDOM) return;
    try {
      const links = document.querySelectorAll('a[target="_blank"]');
      for (const a of links) {
        if (a.__xrayTabSeen) continue;
        a.__xrayTabSeen = 1;
        if (tabnabbingSeen >= CONFIG.maxNotesPerKind) return;
        const rel = String(a.getAttribute("rel") || "");
        if (/(^|\s)noopener(\s|$)/i.test(rel)) continue;
        tabnabbingSeen++;
        stats.tabnabbing++;
        addNote("tab:" + (a.getAttribute("href") || "").slice(0, 200), {
          kind: "tabnabbing", href: redactHref(a.getAttribute("href") || ""),
          rel: rel || "(none)", text: clip(String(a.textContent || "").trim(), 60),
          note: "target=_blank without rel=noopener. The opened page can navigate this one via window.opener (reverse tabnabbing and phishing)."
        });
      }
    } catch (e) {
      fail("tabnabbing", e);
    }
  }

                                                                          
                                                                    
                                                                          
  const MASS_ASSIGN_FIELDS = ["role", "roles", "isadmin", "is_admin", "admin", "permissions",
    "permission", "verified", "is_verified", "email_verified", "price", "amount", "balance",
    "credits", "plan", "tier", "subscription", "account_type", "user_type", "owner_id",
    "tenant_id", "org_id", "email", "username"];

  function harvestBodyFields(json) {
    if (!CONFIG.harvestBodyFields || !json || typeof json !== "object") return null;
    const names = new Map();
    const stack = [json];
    let guard = 0;
    while (stack.length && guard++ < 500 && names.size < CONFIG.maxBodyFields) {
      const cur = stack.pop();
      if (Array.isArray(cur)) { for (const x of cur.slice(0, 20)) if (x && typeof x === "object") stack.push(x); continue; }
      if (!cur || typeof cur !== "object") continue;
      for (const k of Object.keys(cur).slice(0, 60)) {
        if (!names.has(k)) names.set(k, { name: k, idor: IDOR_PARAM_RE.test(k), massAssign: MASS_ASSIGN_FIELDS.indexOf(normKey(k)) >= 0 });
        const v = cur[k];
        if (v && typeof v === "object") stack.push(v);
      }
    }
    if (!names.size) return null;
    stats.bodyFields += names.size;
    const mass = [...names.values()].filter(f => f.massAssign);
    if (mass.length) {
      stats.massAssignCandidates += mass.length;
      addNote("massassign:" + [...names.keys()].sort().join(",").slice(0, 200), {
        kind: "mass-assignment-candidate",
        fields: mass.map(f => f.name).slice(0, 20),
        note: "Response contains privilege-shaped fields. On a writable endpoint these are the fields to test for mass assignment. Active test, use probe()."
      });
    }
    return [...names.values()];
  }

                                                                          
                                
                                                                          
  const AI_ENDPOINT_RE = /(\/v1\/chat\/completions|\/v1\/messages|\/v1\/completions|\/v1\/embeddings|\/v1\/responses|\/api\/chat|\/api\/completions|\/generate|\/infer|\/api\/predict|api\.openai\.com|api\.anthropic\.com|api\.cohere\.(?:ai|com)|api\.groq\.com|api\.together\.xyz|api\.replicate\.com|api\.mistral\.ai|api-inference\.huggingface\.co|openai\.azure\.com|api\.fireworks\.ai|generativelanguage\.googleapis\.com|api\.perplexity\.ai|\/ollama|\/vllm)/i;

  function noteAIEndpoint(u) {
    if (!u) return;
    const hit = String(u.href).match(AI_ENDPOINT_RE);
    if (!hit) return;
    stats.aiEndpoints++;
    addNote("ai:" + u.origin + u.pathname, {
      kind: "ai-endpoint", match: hit[0], url: redactURL(u), host: u.host,
      note: "Browser is calling an LLM provider or local inference endpoint directly. Any bundled key for it is billable by anyone who loads the page."
    });
  }

                                                                                
                                                                       
                                                               
  function analyzeCachePosture(f) {
    if (!f || !f.responseHeaders) return;
    const h = f.responseHeaders;
    const cc = String(h["cache-control"] || "").toLowerCase();
    const vary = String(h["vary"] || "").toLowerCase();
    if (!cc) return;
    const publiclyCacheable = /\bpublic\b/.test(cc) || (/\bmax-age=/.test(cc) && !/\bprivate\b|\bno-store\b/.test(cc));
    const hasSetCookie = !!h["set-cookie"];
    const pii = f.piiHits || [];
    const signals = [];

    if (publiclyCacheable && hasSetCookie) {
      signals.push({
        id: "cacheable-set-cookie", label: "cacheable response carrying Set-Cookie", severity: "HIGH",
        detail: "A shared cache may store this response including the session cookie and serve it to other users. Same class as CVE-2024-26144 (Active Storage, $4,323 bounty)."
      });
    }
    if (publiclyCacheable && pii.length) {
      signals.push({
        id: "cacheable-pii", label: "publicly cacheable response containing PII", severity: "HIGH",
        detail: "PII (" + pii.map(p => p.kind).join(",") + ") is in a response marked publicly cacheable, so it can be retained and served beyond the session."
      });
    }
    if (publiclyCacheable && f.authSeen && !/cookie|authorization/i.test(vary)) {
      signals.push({
        id: "cache-missing-vary", label: "authenticated response cached without Vary", severity: "MEDIUM",
        detail: "Response depends on the request credentials but Vary does not include Cookie or Authorization, so a shared cache can serve one user's response to another."
      });
    }
    if (!signals.length) return;
    stats.cacheLeaks += signals.length;
    f.cacheRisk = signals;
    const worst = signals.reduce((a, s) => ((SEV_RANK[s.severity] || 0) > (SEV_RANK[a.severity] || 0) ? s : a), signals[0]);
    if ((SEV_RANK[worst.severity] || 0) > (SEV_RANK[f.confidence] || 0)) {
      f.confidence = f.confidence === "HIGH" ? "HIGH" : "HIGH";
    }
    addNote("cache-leak:" + f.key, {
      kind: "cache-leak", method: f.method, host: f.host, path: f.normalizedPath,
      cacheControl: h["cache-control"] || null, vary: h["vary"] || null,
      setCookie: hasSetCookie, pii: pii.map(p => p.kind),
      signals,
      note: "cache posture derived from observed response headers. Confirm with a real shared-cache test before reporting."
    });
  }

                                                                          
                                                 
                                                                         
                                                                        
                                                                          

  const STATE_GLOBALS = [
    { name: "__NEXT_DATA__", vendor: "next.js" },
    { name: "__NUXT__", vendor: "nuxt" },
    { name: "__INITIAL_STATE__", vendor: "redux" },
    { name: "__APOLLO_STATE__", vendor: "apollo" },
    { name: "__remixContext", vendor: "remix" },
    { name: "__INITIAL_PAYLOAD__", vendor: "remix" },
    { name: "__PRELOADED_STATE__", vendor: "generic" },
    { name: "__REDUX_DEVTOOLS_EXTENSION__", vendor: "generic" }
  ];
  const CONFIGISH_KEY_RE = /^(?:base_?url|api_?url|api_?base|baseurl|apibase|endpoint|endpoints|api_?endpoint|api_?host|host|origin|gateway|graphql_?url|ws_?url|service_?url|server_?url|cdn|assets_?url|public_?url|auth_?url|upload_?url|socket_?url|proxy)$/i;

                                                                               
                                                     
  function ingestStateTree(node, source, keyPath, depth, state) {
                                                                           
                                                                            
    const st = state || { urls: 0, configs: 0 };
    if (depth > 9 || !node || typeof node !== "object") return st;
    for (const k of Object.keys(node).slice(0, 80)) {
      const v = node[k];
      const p = keyPath ? keyPath + "." + k : k;
      if (typeof v === "string") {
        if (/^(?:https?|wss?):\/\//i.test(v) && v.length < 500) {
          if (CONFIGISH_KEY_RE.test(k)) {
            st.configs++;
            addNote("cfg:" + p + ":" + fnv1a(v), {
              kind: "state-config", key: p, value: clip(v, 200), vendor: source,
              note: "API base or endpoint declared in a client state blob. These are the real backends, including ones the UI never calls."
            });
          }
          if (st.urls < 200) {
            st.urls++;
            record({ source: "state", url: v, method: "?", observed: false });
          }
          analyzeJWT(v, "state:" + p);
        } else if (/^\/[A-Za-z0-9_\-./{}$?=&%:-]{2,}$/.test(v) && st.urls < 200) {
          st.urls++;
          record({ source: "state", url: v, method: "?", observed: false });
        }
      } else if (v && typeof v === "object") {
        if (CONFIGISH_KEY_RE.test(k) && (v.href || v.url || v.origin || v.host)) {
          st.configs++;
          addNote("cfg:" + p, {
            kind: "state-config", key: p, value: clip(JSON.stringify(v), 200), vendor: source,
            note: "API configuration object found in client state."
          });
        }
        ingestStateTree(v, source, p, depth + 1, st);
      }
    }
    return st;
  }

                                                                              
                                                                             
                                                      
  function ingestStateBlob(label, vendor, text, origin, channel) {
    if (!text) return null;
    const key = "state:" + label + ":" + fnv1a(String(text).slice(0, 4000));
    if (notes.has(key)) return null;
    let json = null;
    try { json = safeParse(text); } catch (_) {}
    try { recordRefs(text, "state"); } catch (_) {}
    try { ingestSecrets(scanSecrets(text, origin), origin, channel || CH_DOM); } catch (_) {}
    try { detectFrameworksIn(text); } catch (_) {}
    if (json && typeof json === "object") {
      try { analyzeJWTsInJSON(json, origin); } catch (_) {}
      try { harvestBodyFields(json); } catch (_) {}
    }
    const st = ingestStateTree(json, vendor, "", 0, { urls: 0, configs: 0 });
    addNote(key, {
      kind: "framework-state", label, vendor, size: String(text).length,
      parsed: !!json, urls: st.urls, configs: st.configs,
      note: "Client state blob read from " + origin + ". Contains API responses and configuration. Zero requests were sent to obtain it."
    });
    return json;
  }

  function harvestFrameworkState() {
    for (const g of STATE_GLOBALS) {
      let v;
      try { v = window[g.name]; } catch (_) { continue; }
      if (v === undefined || v === null) continue;
      let text = null;
      try { text = typeof v === "string" ? v : JSON.stringify(v); } catch (_) {}
      if (!text || text.length > 2000000) continue;
      try { ingestStateBlob(g.name, g.vendor, text, "window." + g.name, CH_RUNTIME); } catch (e) { fail("state:" + g.name, e); }
    }
    if (!hasDOM) return;
    try {
      const tags = document.querySelectorAll('script#__NEXT_DATA__, script#__NUXT_DATA__, script[type="application/json"], script[data-state="true"]');
      for (const t of tags) {
        if (!t || t.__xrayStateSeen) continue;
        t.__xrayStateSeen = 1;
                                                                               
                                                   
        let id = "";
        try { id = (typeof t.getAttribute === "function" ? t.getAttribute("id") : "") || t.id || ""; } catch (_) { id = ""; }
        let type = "";
        try { type = (typeof t.getAttribute === "function" ? t.getAttribute("type") : "") || ""; } catch (_) {}
        const txt = String(t.textContent || "").slice(0, 2000000);
        if (!txt) continue;
        const label = id || type || "application/json";
        const vendor = /NEXT_DATA/.test(label) ? "next.js" : (/NUXT/.test(label) ? "nuxt" : "generic");
        try { ingestStateBlob(label, vendor, txt, "script#" + label, CH_DOM); } catch (e) { fail("stateTag", e); }
      }
    } catch (e) {
      fail("stateTags", e);
    }
  }

                                                                         
  function parseCSP(value) {
    const out = { connect: [], script: [], img: [], frame: [], default: [], other: [], reportOnly: false, raw: null };
    if (!value) return out;
    out.raw = String(value).slice(0, 4000);
    if (/report-only/i.test(out.raw)) out.reportOnly = true;
    for (const part of out.raw.split(";")) {
      const s = part.trim();
      if (!s) continue;
      const sp = s.search(/\s/);
      if (sp < 0) continue;
      const dir = s.slice(0, sp).toLowerCase();
      for (const v of s.slice(sp + 1).trim().split(/\s+/)) {
        if (!v) continue;
        if (v === "'none'") continue;
        if (/^'[a-z-]+'$/i.test(v)) continue;                  
        if (v === "*") { if (dir === "connect-src" || dir === "default-src") out.connect.push("*"); continue; }
        if (/^[a-z]+:/i.test(v) || v.indexOf(".") > 0 || v === "localhost") {
          const host = v.replace(/^[a-z]+:\/\//i, "").split("/")[0].split(":")[0];
          if (host) {
            const bucket = dir === "connect-src" ? out.connect
              : dir === "script-src" ? out.script
                : dir === "img-src" ? out.img
                  : dir === "frame-src" ? out.frame
                    : dir === "default-src" ? out.default : out.other;
            if (bucket.indexOf(host) < 0) bucket.push(host);
          }
        }
      }
    }
    return out;
  }

  function noteCSP(csp, source) {
    if (!csp || !csp.raw) return;
    const connect = [...new Set(csp.connect)];
    const key = "csp:" + fnv1a(csp.raw);
    if (notes.has(key)) return;
    addNote(key, {
      kind: "csp", source, reportOnly: csp.reportOnly,
      connectSrc: connect, scriptSrc: csp.script, defaultSrc: csp.default,
      note: csp.reportOnly
        ? "Content-Security-Policy-Report-Only. Not enforced, so it is not a protection."
        : "connect-src is an authoritative whitelist of hosts the application is allowed to call."
    });
    if (!connect.length) return;
                                                                                 
    for (const host of connect) {
      if (host === "*") {
        addNote("csp-wildcard:" + source, {
          kind: "csp-gap", source, wildcard: true,
          note: "connect-src is '*'. The browser will allow requests to any origin, which removes the same-origin protection CSP would otherwise give."
        });
        continue;
      }
      addNote("csp-host:" + host, {
        kind: "csp-declared-host", host, source, reportOnly: csp.reportOnly,
        note: "API host declared in CSP connect-src" + (csp.reportOnly ? " (report-only)" : "") + ". Authoritative, not inferred."
      });
      record({ source: "csp", url: "https://" + host + "/", method: "?", observed: false });
    }
  }

                                                                       
                                                                       
  function crossCheckCSP() {
    const out = { declared: [], observed: [], undeclared: [], unused: [], wildcard: false, enforced: false };
    for (const n of notes.values()) {
      if (n.kind === "csp-declared-host") { out.declared.push(n.host); if (!n.reportOnly) out.enforced = true; }
      if (n.kind === "csp-gap" && n.wildcard) out.wildcard = true;
    }
    out.declared = [...new Set(out.declared)];
    if (out.wildcard) return out;
    if (!out.declared.length) {
      if ([...notes.values()].some(n => n.kind === "csp")) {
        addNote("csp-gap:none", {
          kind: "csp-gap", note: "No connect-src directive was observed. Cross-origin API calls are not restricted by CSP."
        });
      }
      return out;
    }
    const cspHosts = new Set(out.declared.filter(h => out.enforced || true));
    const observed = new Set();
    for (const f of store.values()) {
      if ([...f.sources].some(s => ["csp", "state", "spec", "comment", "dom-attr", "webpack", "robots", "sitemap"].indexOf(s) >= 0)) continue;
      if (!/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|WEBSOCKET)$/.test(f.method)) continue;
      if (f.observed) observed.add(f.host.toLowerCase().split(":")[0]);
    }
    out.observed = [...observed];
    out.undeclared = [...observed].filter(h => h && !cspHosts.has(h));
    out.unused = out.declared.filter(h => !observed.has(h));
    if (out.undeclared.length) {
      addNote("csp-gap:undeclared", {
        kind: "csp-gap", hosts: out.undeclared.slice(0, 40),
        note: "These hosts were called but are absent from connect-src, so they are reached outside the declared policy. Either the policy is stale or something is being fetched dynamically."
      });
    }
    if (out.unused.length) {
      addNote("csp-gap:unused", {
        kind: "csp-declared-unused", hosts: out.unused.slice(0, 40),
        note: "Declared in connect-src but not observed during this session. May be an unused, decommissioned or differently-routed backend."
      });
    }
    return out;
  }

                                                                                           
  function harvestMetaTags() {
    if (!hasDOM) return;
    try {
      const metas = document.querySelectorAll("meta");
      for (const m of metas) {
        if (!m || m.__xrayMetaSeen) continue;
        m.__xrayMetaSeen = 1;
        const equiv = String(m.getAttribute("http-equiv") || "").toLowerCase();
        const name = String(m.getAttribute("name") || "").toLowerCase();
        const content = String(m.getAttribute("content") || "").slice(0, 8000);
        if (!content) continue;
        if (equiv === "content-security-policy" || equiv === "content-security-policy-report-only") {
          const csp = parseCSP(content);
          if (equiv.indexOf("report-only") < 0) csp.reportOnly = false;
          noteCSP(csp, "meta[http-equiv]");
          continue;
        }
        if (/^(?:og|og:|twitter|twitter:)/.test(name) || equiv) {
          addNote("meta:" + name + ":" + fnv1a(content), {
            kind: "meta-tag", name: name || equiv, value: clip(content, 300),
            note: "Metadata tag. og:image and og:url frequently leak internal or non-production hostnames."
          });
          const u = parseURL(content);
          if (u) noteInterestingSurface(u, u.pathname);
        }
      }
    } catch (e) {
      fail("metaTags", e);
    }
  }

  function harvestLinkHints() {
    if (!hasDOM) return;
    try {
      const links = document.querySelectorAll('link[rel], link[href]');
      for (const l of links) {
        if (!l || l.__xrayLinkSeen) continue;
        l.__xrayLinkSeen = 1;
        const rel = String(l.getAttribute("rel") || "").toLowerCase();
        const href = String(l.getAttribute("href") || "");
        if (!href) continue;
        if (/(?:^|\s)(?:preconnect|dns-prefetch|prefetch|preload|modulepreload|prerender)(?:\s|$)/.test(rel)) {
          const u = parseURL(href);
          if (u) {
            noteInterestingSurface(u, u.pathname);
            addNote("linkhint:" + rel + ":" + u.origin, {
              kind: "link-hint", rel, origin: u.origin, url: redactURL(u),
              note: "Declared as a connection hint, so the browser contacts it early. Often an API or asset host the UI barely uses."
            });
            if (/\.(?:m?js)$/i.test(u.pathname)) enqueueScript(u.href);
          }
        }
      }
    } catch (e) {
      fail("linkHints", e);
    }
  }

                                                                          
                                          
                                                                            
                                                                           
                                                                          
                                                                          
                                                                     
                                                                        
const VISIBLE_SKIP_TAGS = /^(?:SCRIPT|STYLE|NOSCRIPT|TEMPLATE|TEXTAREA|OPTION|SELECT)$/;
const disclosedSeen = new Set();
const CRED_SEP = "(?:is(?:\\s+set)?(?:\\s+to)?|will\\s+be|are|=|:|\\u2013|-|\\u2192|->)";
const PWD_PHRASE_RE = new RegExp(
  "((?:pass(?:word|wd|code)?|pwd|passphrase|secret|api[\\s_-]?key|auth[\\s_-]?token|access[\\s_-]?token|private[\\s_-]?key))" +
  "[^\\n]{0,24}?" + CRED_SEP + "\\s*[`'\\\"\u2018\u201c]?([^\\s`'\",;.<>()\\[\\]{}\u2019\u201d]{3,64})", "gi");
const USER_PHRASE_RE = new RegExp(
                                                                               
                                                                                
                                                     
  "((?i:user(?:[\\s_-]?name|[\\s_-]?id)?|login|log[\\s_-]?in|email[\\s_-]?id|e-?mail|account|student[\\s_-]?id|employee[\\s_-]?id|operator[\\s_-]?id|admin[\\s_-]?id))" +
  "[^\\n]{0,24}?" + CRED_SEP + "\\s*[`'\\\"\u2018\u201c]?([A-Za-z0-9._%+-]{2,40}(?:\\s+[A-Z][A-Za-z]{1,19})?)", "g");
                                                                              
                                                                                
                                                     
const PHRASE_SCRUB_RES = [PWD_PHRASE_RE, USER_PHRASE_RE].map(
  re => new RegExp(re.source, re.flags.replace("g", "") + "g"));
                                                          
const CRED_STOPWORDS = /^(?:is|are|was|were|the|a|an|and|or|not|no|none|null|nil|empty|blank|required|optional|needed|must|should|will|be|set|here|below|above|this|that|it|they|same|as|your|our|their|hidden|disabled|shown|given|provided|default|custom|enter|type|input|field|form|login|signin|sign-in|check|reset|change|update|confirm|again|new|old|correct|wrong|true|false|yes|no\.?|n\/a|tbd|todo|xxx+|xxx+|secret|password|passwd|admin|user|username)$/i;

function visibleTextSnapshot() {
  const root = document.body || document.documentElement;
  if (!root) return { text: "" };
                                                                              
                                                                       
                                
  if (typeof document.createTreeWalker !== "function" || typeof NodeFilter === "undefined") return { text: "" };
  let out = "";
  let walker = null;
  try {
    walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  } catch (_) {
    return { text: "" };
  }
  let n, nodes = 0;
  while (nodes < 40000) {
    try { n = walker.nextNode(); } catch (_) { break; }
    if (!n) break;
    if (out.length >= CONFIG.maxVisibleTextChars) break;
    const v = n.nodeValue;
    if (!v || !/\S/.test(v)) continue;
    const p = n.parentElement || n.parentNode;
    if (p) {
      const tag = String(p.nodeName || "").toUpperCase();
      if (VISIBLE_SKIP_TAGS.test(tag)) continue;
      try {
                                                                        
                                                                  
        if (p.closest && p.closest('[aria-hidden="true"]')) continue;
      } catch (_) {}
    }
    nodes++;
    out += (out ? " " : "") + v.replace(/\s+/g, " ");
  }
  return { text: out };
}

function looksLikeRealPassword(v) {
  if (!v || v.length < 6) return false;
                                                                            
                                 
  const hasUpper = /[A-Z]/.test(v), hasLower = /[a-z]/.test(v);
  const hasDigit = /\d/.test(v), hasSym = /[^A-Za-z0-9]/.test(v);
  if (hasDigit && (hasSym || hasUpper)) return true;
  if (hasSym && hasUpper && hasLower) return true;
  return v.length >= 12 && hasDigit && hasUpper;
}

function harvestVisibleText() {
  if (!CONFIG.harvestVisibleText || !hasDOM) return;
  let snap;
  try { snap = visibleTextSnapshot(); } catch (e) { fail("visibleText", e); return; }
  const text = snap && snap.text ? snap.text : "";
  if (!text || text.length < 8) return;

  let found = 0;
  const seenKeys = new Set();

                                                                          
                                                          
  const pw = new RegExp(PWD_PHRASE_RE.source, "gi");
  let m;
  while ((m = pw.exec(text)) !== null && found < 40) {
    const label = String(m[1] || "").toLowerCase();
    const value = String(m[2] || "").replace(/[.,;:]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
    if (!looksLikeRealPassword(value)) continue;
    const key = "pwd:" + value;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    found++;
    const at = text.indexOf(value, Math.max(0, m.index - 40));
    recordDisclosedCredential(label, value, "rendered in page text", "visible text",
      text.slice(Math.max(0, at - 60), at + value.length + 20), { channel: CH_DOM });
  }

                                                                             
                                                                  
  const us = new RegExp(USER_PHRASE_RE.source, "gi");
  const users = [];
  while ((m = us.exec(text)) !== null && users.length < 12) {
    const value = String(m[2] || "").replace(/[.,;:]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
                                                                      
                                                                         
                                                                     
if (String(value).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
    if (/^(?:https?|www\.)/i.test(value)) continue;
                                                                      
                                                                             
    if (String(value).indexOf("@") >= 0) continue;
    users.push(value);
  }
  if (users.length) {
                                                                           
    const maskedUsers = users.slice(0, 6).map(u => maskValue(u));
                                                                             
                                                                              
                                         
    const rawUsers = CONFIG.revealSecrets ? users.slice(0, 6) : null;
    const listedUsers = CONFIG.revealSecrets ? null : maskedUsers;
    const uNote = notes.get("visiblecred:users");
    if (uNote) {
      uNote.values = listedUsers;
      uNote.valuesRaw = rawUsers;
    } else {
      addNote("visiblecred:users", {
        kind: "disclosed-credential", label: "username", exposure: "rendered in page text",
        values: listedUsers, valuesRaw: rawUsers,
        severity: "HIGH", where: "visible text",
        note: "A username is spelled out in page text. Paired with the password disclosure above this is a working login for any reader."
      });
    }
  }
  if (found) stats.hidden = stats.hidden;

                                                                            
                                                                              
                                                                                
                                                                           
                          
  try {
    scanCredentialPairsInText(text, "visible text", CH_DOM, null, false);
  } catch (e) { fail("visibleText.pairs", e); }
}

                                                                         
                                                                           
                                                                               
                                                                       
                                                                             
                                                                           
                                                             
  
                                                                             
                                                                            
                                  
function maskDisclosedPhrases(text) {
                                                                              
                                                                        
  if (CONFIG.revealSecrets) return String(text);
  let out = String(text);
  for (const re of PHRASE_SCRUB_RES) {
    out = out.replace(re, (m, label, value) =>
      (label && value ? m.split(value).join(maskValue(value)) : m));
  }
  if (CONFIG.redactSensitive) out = hardRedact(redactString(out));
  return out;
}

                                                                               
                                                                            
                                                                              
                                                                       
                                                                            
function recordDisclosedCredential(label, value, where, file, snippetText, opts) {
  const o = opts || {};
  const key = label + "|" + fnv1a(value);
                                                                           
                                                                          
  const verdictInfo = o.classification || (o.verdict ? { verdict: o.verdict } : classifyValue(value, label));
  const verdict = verdictInfo.verdict;
  if (verdict === "arbitrary") return false;
                                                                            
                                                                            
  if (nonValueReason(value)) return false;
  if (!CRED_VALUE_RE.test(value) && !looksLikeRealPassword(value)) return false;
                                                                                
                                                                
  const severity = severityForVerdict(verdict, verdictInfo.weakKey ? "MEDIUM" : o.severity);
  const confidence = verdictInfo.confidence || (o.severity === "CRITICAL" ? "high" : "medium");
  const noteKey = "disclosed:" + key;
  const masked = maskValue(value);
                                                                             
                                                                              
                                                         
  const snippet = snippetText
    ? clip(CONFIG.revealSecrets ? String(snippetText) : maskDisclosedPhrases(String(snippetText).split(value).join(masked)), 240)
    : null;
  const exact = o.lineExact === undefined ? lineOffsetExact : !!o.lineExact;
  const existing = notes.get(noteKey);
  if (existing) {
                                                                            
                                                                             
    if (CONFIG.revealSecrets) {
      existing.value = value;
      existing.valueMasked = null;
      existing.snippet = snippet;
    }
                                                                             
                                                                              
                                                        
    if (o.line != null && exact && existing.lineExact === false) {
      existing.line = absLine(o.line);
      existing.column = o.column == null ? null : o.column;
      existing.lineExact = true;
    }
  } else {
    addNote(noteKey, {
      kind: "disclosed-credential", label: String(label || "credential").toLowerCase(),
      exposure: where, valueMasked: CONFIG.revealSecrets ? null : masked, length: value.length,
      value: CONFIG.revealSecrets ? value : null,
      severity, verdict, confidence: confidence || null, fixture: verdict === "fixture", channel: o.channel || null,
      line: absLine(o.line), column: o.column == null ? null : o.column,
      lineExact: exact,
      container: o.container || null, decodedFrom: o.decodedFrom || null,
      reconstructedFrom: o.reconstructedFrom || null,
      where, file: file || null,
      snippet,
      note: where === "rendered in page text"
        ? "A credential is spelled out in text the user can read. Anyone who opens the page, or any screenshot, bug report or training material copied from it, learns the login. Remove the note and rotate the value."
        : "A credential is hardcoded as prose inside shipped JavaScript. It is readable in the bundle, in any saved copy of the page, and it survives forever in caches and archives. Remove it and rotate the value."
    });
  }
  disclosedSeen.add(key);
                                                                             
                                                                             
                       
  try {
    ingestSecrets([{
      id: o.typeId || "credential-disclosure", name: (o.name || (label || "credential") + " (hardcoded)"),
      category: "credential", severity, exposure: where,
      raw: value, length: value.length, shape: o.shape || "prose-disclosure", file: file || "script",
                                                                             
                                                                      
      line: o.line == null ? null : o.line, column: o.column == null ? null : o.column,
      lineExact: exact,
      channel: o.channel || null, verdict, confidence: confidence || null, fixture: verdict === "fixture",
                                                                               
                                                                          
                                                                  
      verdictReason: verdictInfo.reason || null,
      decodedFrom: o.decodedFrom || null, reconstructedFrom: o.reconstructedFrom || null
    }], file || "script");
  } catch (e) { fail("disclosed.secret", e); }
  indexValue(value, o.channel, (file || "script") + (o.line == null ? "" : ":" + o.line), verdict);
  return !existing;
}

                                                                        
                    
                                                                            
                                                                            
                                                                             
                                                                               
                                                                        
                                                    
                                                                        
const CH_STATIC = "static-source";
const CH_DOM = "dom";
const CH_RUNTIME = "runtime";
const CH_STORAGE = "storage";
const CH_NETWORK = "network";
const CHANNELS = [CH_STATIC, CH_DOM, CH_RUNTIME, CH_STORAGE, CH_NETWORK];
const channelSeen = { "static-source": 0, dom: 0, runtime: 0, storage: 0, network: 0 };

                                                                             
                                                                            
                                                                             
                                                         
const LOGOUT_PATH_RE = /\/(?:logout|log-out|signout|sign-out|session\/(?:end|terminate|destroy|revoke)|deauth(?:enticate)?|revoke)(?:[\/?]|$)/i;

                                                                            
                                                                               
                                                                         
const FIXTURE_RE = /(?:^|[^a-z0-9])(?:fake|faux|dummy|demo|decoy|example|sample|placeholder|mock|not[\s_-]*a?[\s_-]*real|notreal|changeme|change_?me|redacted|sandbox|training|test|testing|todo|stub|xxx+)(?:[^a-z0-9]|$)/i;

                                                                                
                                                                               
                                                                          
                                                 
function fixtureMarker(s) {
  const t = String(s == null ? "" : s);
  if (FIXTURE_RE.test(t)) return true;
  return FIXTURE_RE.test(t.replace(/([a-z0-9])([A-Z])/g, "$1 $2"));
}

                                                                              
                                                      
const CRED_VALUE_RE = /^[A-Za-z0-9._%+\-:!@#$^&*~?]{4,120}$/;

                                                                                
                                                                                
                                                        
const JS_ROOTS_RE = /^(?:document|window|console|self|top|parent|globalThis|Math|JSON|Object|Array|String|Number|Boolean|Date|RegExp|Error|Promise|Map|Set|WeakMap|Symbol|BigInt|navigator|location|history|localStorage|sessionStorage|indexedDB|caches|process|require|module|exports|this)(?:[.[(]|$)/;
const JS_METHODS_RE = /^(?:getElementById|querySelector|querySelectorAll|getAttribute|setAttribute|removeAttribute|createElement|appendChild|removeChild|addEventListener|removeEventListener|value|textContent|innerHTML|innerText|className|classList|length|toString|trim|trimStart|trimEnd|split|join|concat|slice|substring|replace|replaceAll|match|test|map|filter|reduce|forEach|find|some|every|sort|reverse|push|pop|shift|unshift|keys|values|entries|now|random|floor|ceil|round|abs|min|max|log|warn|error|debug|info|fetch|then|catch|resolve|reject|get|set|has|add|delete|clear|size|count|parse|stringify|resolve)$/;

                                                                            
                                                                              
const CRED_KEYISH_RE = /(?:pass|pwd|passwd|secret|token|cred|auth|user|login|api|key|pin|otp|mfa|code|session|cookie|hash|salt|sign|cert|private|nonce|backup|vault|client|licen[sc]e|csalt|iv_?key|bearer)/i;

                                                                      
const ID_KEYISH_RE = /(?:^|[_\-.])(?:id|ids|code|no|num|number|ref|index|idx|year|count|size|port)(?:$|[_\-.])|(?:Id|ID|PIN|Code|Code|Flag|Port|Number|Version|Index|Count|Year|Ref)$/;
                                                               
const NUMERIC_SECRET_RE = /(?:pin|otp|passcode|pwd|pass|secret|token|key|combos?)/i;

                                                                           
                                                                            
                                  
const UI_COPY_WORD_RE = /^(?:password|passwords|passwd|passcode|passcodes|passphrase|passphrases|pass|user|users|username|usernames|login|logins|log-in|signin|sign-in|signup|sign-up|logout|signout|sign-out|email|emails|e-mail|account|accounts|remember|forgot|reset|change|update|confirm|submit|cancel|continue|save|close|open|next|previous|back|mobile|phone|number|numbers|verification|verify|security|question|questions|answer|answers|balance|deposit|withdraw|withdrawal|payment|payments|recharge|transaction|transactions|history|details|detail|information|create|binding|bind|level|remark|title|label|name|code|codes|old|new|current|my|your|our|the|a|an|in|on|of|to|and|or|with|for|enter|input|field|form|text|message|error|success|loading|senha|senhas|sandi|kata|clave|contraseña|contrasena|usuario|cuenta|passwort|kennwort|benutzer|konto|mot|passe|utilisateur|compte|parola|şifre|sifre|kullanıcı|kullanici|пароль|密码|密碼|mật|khẩu|mat|khau|पासवर्ड|रहस्य)$/i;

const CODE_IDENTIFIER_TOKEN_RE = /(?:Info|Error|Message|Msg|Title|Label|Name|Key|Config|Value|Type|List|Item|Map|Data|Api|String|Number|Object|Array|Deposit|Transfer|Translate|Login|Password|Email|Mail|Link|Icon|Form|Field|Input|Button|Btn|Container|Wrapper|Modal|Dialog|Page|View|Component|Provider|Handler|Callback|Event|Action|Reducer|Store|State|Props|Param|Query|Route|Path|Url|Host|Port|Token|Code|Flag|Status|Count|Index)/;

const CODE_CONSTANT_WORD_RE = /(?:SEND|MAIL|PASS|PWD|PAY|FEEDBACK|FEED|BACK|TRANS|PAYMENT|LOG|EMAIL|RISK|TOKEN|KEY|SECRET|ACCOUNT|BALANCE|REWARD|CENTER|CEN|REW|MAN|PLAY|RESP|PERS|CODE|FLAG|TITLE|LABEL|NAME|INFO|CONFIG|VALUE|TYPE|LIST|ITEM|ERROR|MSG|BUTTON|BTN|INPUT|FIELD|FORM|ICON|LINK)/;

const UI_CLASS_TOKEN_RE = /(?:^|[-_])(?:form|icon|btn|button|input|field|label|wrapper|container|row|col|text|title|name|email|pass|pwd|main|content|card|item|list|nav|header|footer|modal|dialog|tab|panel|box|grid|flex|err|error|msg|message|link|avatar|image|logo|menu|toggle|checkbox|radio|select|option|placeholder|hint)(?:$|[-_\d])/i;

function nonValueReason(s) {
  if (/[{}<>]|;|=>|<\/?[A-Za-z]/.test(s)) return "markup or code, not a value";
  if (/^https?:\/\//i.test(s)) return "a URL";
  if (/^\/[^\s]*$/.test(s)) return "a path";
  if (/^#[0-9a-f]{3,8}$/i.test(s)) return "a colour";
  if (/^(?:get|post|put|delete|patch|head|options|true|false|null|undefined|none|nan)$/i.test(s)) return "a keyword";
  if (s.trim().split(/\s+/).length >= 3) return "a sentence";
                                                                         
                                                                         
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) return "a timestamp, not a credential";
                                                                          
  if (/(?:ABCDEFGHIJKLMNOPQRSTUVWXYZ|abcdefghijklmnopqrstuvwxyz|0123456789abcdef|0123456789ABCDEF)/.test(s)) {
    return "a character table or alphabet, not a credential";
  }
                                                                         
                                                                        
                                                                     
  {
    const prose = s.trim().replace(/[?!.,;:]+$/, "");
    const words = prose.split(/[\s\/]+/)
      .map(w => w.replace(/[^A-Za-z0-9'’_-]/g, "")).filter(Boolean);
    if (words.length === 1 && UI_COPY_WORD_RE.test(words[0])) return "UI copy, not a credential";
    if (words.length >= 2 && words.length <= 8 && words.every(w => UI_COPY_WORD_RE.test(w))) {
      return "UI copy, not a credential";
    }
    if (words.length >= 2 && words.length <= 6 && /[\s\/]/.test(prose) &&
        words.every(w => /^[A-Za-z][A-Za-z'’.-]{0,24}$/.test(w))) {
      return "prose text, not a credential";
    }
  }
                                                               
                                                                      
  if (/^[A-Z][A-Z0-9_]{4,}$/.test(s) && CODE_CONSTANT_WORD_RE.test(s)) {
    return "an uppercase constant name, not a credential";
  }
                                                                          
                                                                         
  if (/^[a-z][a-z0-9]*(?:[-_][a-z0-9]+){1,8}$/.test(s) && UI_CLASS_TOKEN_RE.test(s)) {
    return "a class or element identifier, not a credential";
  }
                                                                        
  if (/^[a-z][A-Za-z0-9]*$/.test(s) && /[A-Z]/.test(s) && CODE_IDENTIFIER_TOKEN_RE.test(s)) {
    return "a camelCase identifier, not a credential";
  }
                                                                             
                                                                               
                                                                        
                                                                          
  if (JS_ROOTS_RE.test(s) && !/[^\w$.,()"'\s]/.test(s) && /[.[(]/.test(s)) {
    return "a code reference, not a value";
  }
                                                                                 
                                                                               
                                                    
  if (/^(?:null|undefined|none|nan|true|false|void|empty)-/i.test(s)) return "opens with a literal keyword";
                                                                              
                                                                              
                                                                     
  if (/^[A-Za-z_$]{1,2}(?:\.[A-Za-z_$][\w$]*)+(?:[+*/%\-|&]|<<|>>)?$/.test(s)) return "a minified property path, not a value";
                                                                               
                                                         
  if (/[A-Za-z0-9_$]\s*=\s*[A-Za-z_$]/.test(s)) return "an assignment expression, not a value";
                                                                              
                                    
  if (/^[A-Za-z0-9_.-]+\.(?:m?js|cjs|css|map|json|wasm|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip)$/i.test(s)) return "an asset filename";
                                                                              
                                                             
  if (/^[a-z]+(?:-[a-z]+)+$/.test(s)) return "a kebab-case label, not a value";
                                                                              
                                                                              
                                                                            
                                                      
  if (/^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(s)) return "a snake_case label, not a value";
                                                                            
                                                                             
                                                                        
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(s)) return "a SCREAMING_SNAKE constant, not a value";
                                                                           
                                                                                
                                                                          
  if (/^X-[A-Za-z-]+$/.test(s) || /^(?:accept|accept-charset|accept-encoding|accept-language|authorization|cache-control|connection|content-disposition|content-length|content-type|cookie|dnt|etag|expect|forwarded|from|host|if-match|if-modified-since|if-none-match|if-range|if-unmodified-since|keep-alive|max-forwards|origin|pragma|proxy-authorization|range|referer|te|trailer|transfer-encoding|upgrade|user-agent|vary|via|warning|www-authenticate|x-csrf-token|x-xsrf-token|content-security-policy|x-frame-options|x-requested-with)$/i.test(s)) {
    return "an HTTP header name, not a credential";
  }
  if (/^(?:function|return|const|let|var|new|this|typeof|instanceof|void|String|Number|Boolean|Object|Array|Promise|Symbol|Math|JSON|Error|Date|RegExp|Map|Set|undefined|null|true|false)$/.test(s)) return "a keyword or builtin";
  if (/^-?\d+(?:\.\d+)?%?$/.test(s)) return "a number, not a credential";
  if (/^\d{1,3}(?:\.\d{1,4}){1,4}$/.test(s)) return "a version number, not a credential";
  if (/&&|\|\||\?\?|=>|!==|===/.test(s)) return "a code expression, not a value";
  if (/[A-Za-z_$][\w$]*\s*\(|\)\s*[.,;]|\(\)/.test(s)) return "a call expression, not a value";
                                                                     
  if (/^(?:use[A-Z][A-Za-z0-9]*|set[A-Z][A-Za-z0-9]*)$/.test(s)) return "a hook or setter name, not a value";
                                                              
  if (/^[.#][A-Za-z][\w-]*(?:[.#][\w-]+)*$/.test(s)) return "a CSS selector, not a value";
                                                                              
  if (/^(?:auto|text|initial|inherit|unset|block|inline|inline-block|flex|grid|center|left|right|justify|bold|normal|italic|solid|dashed|none|hidden|visible|absolute|relative|static|fixed)$/i.test(s)) return "a CSS keyword, not a value";
                                                                         
                                                                             
                                                               
  if (/[^\x20-\x7E]/.test(s)) return "non-ASCII text, not a credential";
                                                                             
  if (/\\[uxnrt"'\\]/.test(s)) return "an escaped string, not a value";
                                                                         
                                                                            
  if (/^\$[A-Za-z_][\w]*$/.test(s)) return "a template placeholder, not a value";
                                                                             
                                                        
  if (/%[0-9A-Fa-f]{2}/.test(s) && /(?:%[0-9A-Fa-f]{2}){3,}/.test(s)) return "a percent-encoded string, not a value";
                                                           
  if (/^https?:\/\/\S{8,}$/i.test(s) && /[?&=]/.test(s)) return "a URL, not a value";
  return null;
}

                                                                       
                                                                               
                                                                
  function isGeneratedValue(s) {
    const t = String(s == null ? "" : s);
    if (t.length < 12 || t.length > 200) return false;
                                                                               
                                                                           
                                                         
    if (!/[A-Za-z]/.test(t) || !/\d/.test(t)) return false;
    return shannon(t) >= 3.2;
  }
                                                                         
  const STRONG_LABEL_RE = /(?:pass|pwd|passphrase|secret|token|apikey|api[_-]?key|access[_-]?key|access[_-]?token|auth|private[_-]?key|client[_-]?secret|credential|passcode|pin|otp|user|login|account|e-?mail)/i;
                                                           
                                                                             
                                                                
                                                                                 
                                                                              
                                                                              
                                                   
  const IDENTITY_LABEL_RE = /(?:^|[^a-zA-Z])(?:username|user|login|e-?mail|account)(?:name|id)?(?:$|[^a-zA-Z])/i;
  const SECRET_WORD_RE = /(?:pass|pwd|passphrase|secret|token|apikey|api[_-]?key|access[_-]?key|access[_-]?token|auth|private[_-]?key|client[_-]?secret|credential|passcode|pin|otp)/i;
  function isStrongLabel(k) { return SECRET_WORD_RE.test(k) || IDENTITY_LABEL_RE.test(k); }
                                                                              
                                                                         
  const WEAK_LABEL_RE = /^(?:[a-z0-9_-]*)?(?:key|keys|value|values|name|nametype|names|type|types|label|labels|title|text|ref|var|desc|description|msg|message|path|file|files|icon|class|style|variant|count|index|group|kind|state|status|source|target|action|event|code|suffix|prefix|display|position|color|size|width|height|margin|padding|font|weight|family|selector|attr|props?)$/i;
                                                                             
                                                                            
                                                                     
  const IDENTIFIER_LABEL_RE = /(?:Id|ID)$|(?:^|[_-])ids?$|^id$|^oid$|^(?:uuid|guid|ulid)$|^\d+id$/i;

                                                                                
                                                                                
                   
                                                                                
                        
  const REVISION_LABEL_RE = /(?:revision|commit|commithash|githead|buildsha|buildid|buildnumber|checksum|version|versioncode|buildversion|sourcemapref|appversion)/i;

  function classifyValue(value, label) {
  const raw = String(value == null ? "" : value);
  let key = String(label == null ? "" : label);
  if (!raw) return { verdict: "arbitrary", reason: "empty" };
  if (raw.length > 300) return { verdict: "arbitrary", reason: "too long to be one value" };
                                                                               
                                                                                 
                                                                                
  let s = raw;
  const kv = /^([A-Za-z_][\w.\-]{0,60})\s*[=:]\s*(\S.{0,200})$/.exec(raw);
  if (kv && !/\s/.test(kv[1])) { key = kv[1]; s = kv[2]; }
                                                                           
                                                                              
                                           
  const leaf = String(key).split(/[.[\]]/).filter(Boolean).pop() || key;
                                                                    
                                                                          
                                                                        
  if (leaf && String(leaf).length >= 3 && s.toLowerCase() === String(leaf).toLowerCase()) {
    return { verdict: "arbitrary", reason: "the value repeats the field name (" + leaf + ")" };
  }
                                                                 
                                                                                 
  if (/^(?:session|bearer|basic|digest|hmac|jwt|oauth|oauth2|none|default|required|optional|anonymous|guest)$/i.test(s)) {
    return { verdict: "arbitrary", reason: "an authentication-scheme name, not a credential" };
  }
const nonValue = nonValueReason(s);
if (nonValue) return { verdict: "arbitrary", reason: nonValue };
                                                                               
                                                                              
                                                                         
                                                                               
                                                   
    
                                                                             
                                                                          
                                                                    
  const looksDigest = t =>
    /^[0-9a-f]{32}$/i.test(t) || /^[0-9a-f]{40}$/i.test(t) ||
    /^[0-9a-f]{64}$/i.test(t) || /^[0-9a-f]{128}$/i.test(t) ||
    (/^[0-9a-f]{7,10}$/i.test(t) && /[a-f]/i.test(t));
  if (looksDigest(s) && !isStrongLabel(leaf)) {
    return { verdict: "arbitrary", reason: "a hash digest (query hash or build revision), not a credential" };
  }
                                                                           
                                                                              
                                                    
  if (REVISION_LABEL_RE.test(leaf)) {
    return { verdict: "arbitrary", reason: "a build/revision field (" + leaf + "), not a credential" };
  }
                                           
  if (/^\d{3,}$/.test(s) && ID_KEYISH_RE.test(key) && !NUMERIC_SECRET_RE.test(key)) {
    return { verdict: "arbitrary", reason: "a numeric identifier under " + key };
  }
                                                                           
                                                               
  if (IDENTIFIER_LABEL_RE.test(leaf)) {
    return { verdict: "arbitrary", reason: "an identifier field (" + leaf + "), not a credential" };
  }
                                                                      
                                                                            
                                                      
  if (WEAK_LABEL_RE.test(leaf) && !STRONG_LABEL_RE.test(leaf) && !isGeneratedValue(s)) {
    return { verdict: "arbitrary", reason: "a generic key (" + leaf + ") with a value that does not look like a credential" };
  }
                                                                       
                                                                              
  if (!isStrongLabel(leaf) && !isGeneratedValue(s)) {
    return { verdict: "arbitrary", reason: "the key (" + leaf + ") does not name a secret and the value is not credential-shaped" };
  }
                                                                              
                                                                  
  if (/^\d{3,}$/.test(s) && !CRED_KEYISH_RE.test(key) && !NUMERIC_SECRET_RE.test(key)) {
    return { verdict: "arbitrary", reason: "a numeric identifier under the non-secret key " + key };
  }
                                                                          
                                                                               
                                                                             
                                                         
  const weakKey = !CRED_KEYISH_RE.test(key);
  if (weakKey && !/\d/.test(s) && /^[A-Za-z][A-Za-z-]{1,24}$/.test(s)) {
    return { verdict: "arbitrary", reason: "a plain word under the non-secret key " + key };
  }
  if (fixtureMarker(s)) return { verdict: "fixture", reason: "the value names itself as test material" };
  if (fixtureMarker(key)) return { verdict: "fixture", reason: "the key names it as test material (" + key + ")" };
  return {
    verdict: "real",
    weakKey,
    confidence: weakKey ? "medium" : "high",
    reason: weakKey
      ? "credential-shaped value, but the key " + key + " does not name a secret"
      : "no fixture marker in the value or its key"
  };
}

function severityForVerdict(verdict, base) {
  if (verdict === "real") return base || "HIGH";
  if (verdict === "fixture") return "LOW";
  return "INFO";
}

const escRe = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

                                                                          
                                                                 
const lineTableCache = new Map();
function lineTableOf(text) {
  const hit = lineTableCache.get(text);
  if (hit) return hit;
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  if (lineTableCache.size > 40) lineTableCache.clear();
  lineTableCache.set(text, starts);
  return starts;
}

                                                                       
function lineColAt(text, offset) {
  if (typeof text !== "string" || offset == null || offset < 0) return null;
  try { return locate(lineTableOf(text), Math.min(offset, text.length)); } catch (_) { return null; }
}

function decodePrintableRatio(s) {
  if (!s) return 0;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ok++;
  }
  return ok / s.length;
}

                                                                               
                                                                            
                                                                               
                                                                       
const DECODED_MEANING_RE = /[_\-.:=@\\\/]|\b(?:pass|pwd|user|key|token|secret|admin|root|login|auth|api)\b/i;
const B64_TOKEN_RE = /^[A-Za-z0-9+/_-]{16,512}={0,2}$/;
const HEX_TOKEN_RE = /^(?:[0-9a-fA-F]{2}){8,256}$/;

function tryDecodeBase64(token) {
  if (!B64_TOKEN_RE.test(token)) return null;
  const body = token.replace(/=+$/, "");
                                                           
  if (body.length % 4 === 1) return null;
  let padded = body;
  while (padded.length % 4) padded += "=";
  let out = null;
  try { out = atob(padded.replace(/-/g, "+").replace(/_/g, "/")); } catch (_) { return null; }
  if (!out || out.length < 5 || decodePrintableRatio(out) < 0.9 || !/[A-Za-z]/.test(out)) return null;
                                                                    
  if (/^[[{]/.test(out.trim())) return null;
  if (!DECODED_MEANING_RE.test(out)) return null;
  return { text: out, kind: "base64" };
}

function tryDecodeHex(token) {
  if (!HEX_TOKEN_RE.test(token)) return null;
  let out = "";
  for (let i = 0; i < token.length; i += 2) out += String.fromCharCode(parseInt(token.slice(i, i + 2), 16));
  if (!out || out.length < 5 || decodePrintableRatio(out) < 0.95 || !/[A-Za-z]/.test(out)) return null;
  if (!DECODED_MEANING_RE.test(out)) return null;
  return { text: out, kind: "hex" };
}

                                                                            
                                                                       
function valueHash(v) { return fnv1a(String(v)); }

                                                                                
                                                                                 
                                                                              
                                                                               
                                                         
let lineOffset = 0;
                                                                               
                                                                             
                                                                             
let lineOffsetExact = true;
function absLine(l) { return l == null ? null : l + lineOffset; }

                                                                                
                                                     
function documentLabel() {
  try {
    const p = String(location.pathname || "");
    const last = p.split("/").filter(Boolean).pop();
    return last ? decodeURIComponent(last) : (location.hostname || "document");
  } catch (_) { return "document"; }
}

                                                                              
                                                          
const valueIndex = new Map();                                                                    

function indexValue(value, channel, place, verdict) {
  const h = valueHash(value);
  let rec = valueIndex.get(h);
  if (!rec) {
    rec = { hash: h, masked: maskValue(value), raw: CONFIG.revealSecrets ? value : null, verdict: verdict || "real", channels: new Set(), places: [], count: 0 };
    valueIndex.set(h, rec);
  }
  rec.count++;
  if (verdict === "real") rec.verdict = "real";
  if (CONFIG.revealSecrets && rec.raw == null) rec.raw = value;
  if (channel) rec.channels.add(channel);
  if (place && rec.places.length < 8 && rec.places.indexOf(place) < 0) rec.places.push(place);
  return rec;
}

                                                                              
                                                                     
                                                                           
                                                                        
                                                                    
                                                                        
const CRED_LABEL = "(?:[A-Za-z0-9_$]*?(?:pass(?:word|wd|phrase|code)|pass(?![A-Za-z0-9_$])|pwd|secret|apikey|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)[A-Za-z0-9_$]*)";
const USER_LABEL = "(?:[A-Za-z0-9_$]*?(?:user(?:name|id)?|login|log[_-]?in|e-?mail|account|id(?![A-Za-z0-9_$]))[A-Za-z0-9_$]*)";
const CONNECT = "(?:[:=]|is(?:\\s+set)?(?:\\s+to)?|will\\s+be)";

                                                                            
                                                                              
                                                                               
                                                                           
                                                                          
                                                                           
                                                                            
                                                                 
const QUOTED_VALUE = String.raw`(?:\\?(["'\x60])([^"'\x60\n]{1,80})\\?\1|([^\s"'\x60,;{}()\[\]]{1,80}))`;
const CODE_PWD_RE = new RegExp("(?:" + CRED_LABEL + ")\\s*" + CONNECT + "\\s*" + QUOTED_VALUE, "gi");
  const CODE_USER_RE = new RegExp("(?:" + USER_LABEL + ")\\s*" + CONNECT + "\\s*" + QUOTED_VALUE, "gi");
                                                                               
                                                                              
                                                                                
                                                                    
  const QUOTED_ONLY = String.raw`(["'\x60])([^"'\x60\n]{1,120})\1`;
  const CODE_PWD_QUOTED_RE = new RegExp("(?:" + CRED_LABEL + ")\\s*" + CONNECT + "\\s*" + QUOTED_ONLY, "gi");
  const CODE_USER_QUOTED_RE = new RegExp("(?:" + USER_LABEL + ")\\s*" + CONNECT + "\\s*" + QUOTED_ONLY, "gi");
                                                                          
const reCaptured = m => (m == null ? null : (m[2] !== undefined ? m[2] : m[3]));

                                                                              
                                                                              
                                                                               
                                                                          
                                                                            
                                                                            
                                            
let pageSourceText = null;
let pageSourceExact = false;

async function loadPageSource() {
  if (!hasDOM || !nativeFetch || typeof location === "undefined") return null;
  try {
    const res = await nativeFetch.call(window, location.href, { credentials: "same-origin", cache: "force-cache" });
    if (!res.ok) { safeCancel(res.body); return null; }
    try {
      const hs = {};
      res.headers.forEach((v, k) => { hs[String(k).toLowerCase()] = String(v); });
      rememberHeaderRow({
        url: location.href, method: "GET", status: res.status,
        headers: hs, source: "document"
      });
    } catch (_) {}
    const ct = res.headers.get("content-type") || "";
    if (ct && !/html|xml|text/i.test(ct)) { safeCancel(res.body); return null; }
    const text = await res.text();
    safeCancel(res.body);
    if (!text || text.length > CONFIG.maxHtmlSourceChars) return null;
    if (!/<(?:!doctype|html|head|body)\b/i.test(text.slice(0, 4000))) return null;
    pageSourceText = text;
    pageSourceExact = true;
                                                                           
                                                                        
                                                                           
                                                                            
    try { forgetInline(); } catch (_) {}
    channelSeen[CH_DOM] += 1;
    return text;
  } catch (_) {
    return null;
  }
}

function htmlSourceSnapshot() {
  if (!hasDOM) return "";
  if (pageSourceExact && pageSourceText) return pageSourceText;
  try {
    const html = String((document.documentElement && document.documentElement.outerHTML) || "");
    if (!html) return "";
    const dt = document.doctype ? String(document.doctype.name || "html") : null;
    const body = clip(html, CONFIG.maxHtmlSourceChars);
    channelSeen[CH_DOM] += 1;
    return dt ? "<!DOCTYPE " + dt + ">\n" + body : body;
  } catch (_) {
    return "";
  }
}

                                                                            
                                                                                
                                                                        
                                                                               
function domSourceLabel() { return documentLabel(); }
function lineIsExact() { return pageSourceExact; }

                                                                              
                                                                               
                       
function docLineOf(needle, offsetBack) {
  if (!needle) return null;
  const src = htmlSourceSnapshot();
  if (!src) return null;
  const at = src.indexOf(needle);
  if (at < 0) return null;
  const loc = lineColAt(src, at);
  if (!loc) return null;
  return Math.max(1, loc.line - (offsetBack || 0));
}

                                                                              
                                                                             
                                                           
                                                                           
                                                                                
                                                                            
                                                                                
                              
  function scanContainerAttributes(root, label) {
    let els = null;
    try { els = root.querySelectorAll("*"); } catch (_) { return 0; }
    if (!els) return 0;
    let found = 0;
    const limit = Math.min(els.length, CONFIG.maxDomElements);
    for (let i = 0; i < limit && found < 40; i++) {
      const el = els[i];
      const attrs = el.attributes;
      if (!attrs) continue;
      for (let j = 0; j < attrs.length; j++) {
        const name = String(attrs[j].name || "");
        const value = String(attrs[j].value == null ? "" : attrs[j].value);
        if (!/^data[-_]/i.test(name)) continue;
        if (PAIR_ATTR_RE.test(name) && value) {
          const sepIdx = value.indexOf(":") >= 0 ? value.indexOf(":") : value.indexOf("=");
          if (sepIdx > 0 && value.length - sepIdx - 1 >= 3) {
            const u = value.slice(0, sepIdx), p = value.slice(sepIdx + 1);
            if (recordCredentialPair(u, p, "hidden DOM attribute", label + " @ " + name,
              name + '="' + maskPairForSnippet(u, p) + '"', {
                channel: CH_DOM, severity: "CRITICAL", lineExact: false,
                container: String(el.tagName || "").toLowerCase()
              })) found++;
            continue;
          }
        }
        if (!CRED_ATTR_RE.test(name)) continue;
        if (!value || value.length > CONFIG.maxCredentialValueChars) continue;
        const isUser = /^(?:data[-_])?(?:user|username|login|account|e-?mail)/i.test(name) || /^data[-_]auth[-_]?(?:user|username)/i.test(name);
        const needle = name + '="' + value + '"';
        const elPath = String(el.tagName || "").toLowerCase() + (el.id ? "#" + el.id : "");
        if (recordDisclosedCredential(isUser ? "username" : "credential", value, "hidden DOM attribute",
          label + " @ " + name, needle + "   (on <" + elPath + ">)", {
            lineExact: false, channel: CH_DOM, severity: isUser ? "MEDIUM" : "CRITICAL",
            container: String(el.tagName || "").toLowerCase(),
            classification: classifyValue(value, name)
          })) found++;
      }
    }
    return found;
  }

                                                                            
                                                                             
                            
  function scanFrameRuntime(win, label) {
    if (!win) return 0;
    let found = 0;
    const walk = (path, value, depth) => {
      if (depth > 3 || value == null) return;
      if (typeof value === "string") {
        const v = value.trim();
        if (v.length < 4 || v.length > 300) return;
        const info = classifyValue(v, path);
        if (info.verdict === "arbitrary") return;
        if (recordDisclosedCredential(/user|login|account|name/i.test(path) ? "username" : "credential", v,
          "exposed in same-origin frame", label + path, null,
          { classification: info, channel: CH_DOM, lineExact: false })) found++;
        return;
      }
      if (typeof value !== "object") return;
      let keys = [];
      try { keys = Object.keys(value); } catch (_) { return; }
      for (let i = 0; i < Math.min(keys.length, 40); i++) {
        const k = keys[i];
        if (FRAME_SKIP_RE.test(k)) continue;
        let child;
        try { child = value[k]; } catch (_) { continue; }                         
        walk(path + "." + k, child, depth + 1);
      }
    };
    let keys = [];
    try { keys = Object.keys(win); } catch (_) { return 0; }
    for (let i = 0; i < Math.min(keys.length, 400); i++) {
      const k = keys[i];
      if (FRAME_SKIP_RE.test(k)) continue;
      let v;
      try { v = win[k]; } catch (_) { continue; }
      walk("." + k, v, 0);
    }
    return found;
  }
  const FRAME_SKIP_RE = /^(?:window|self|top|parent|frames|length|name|origin|closed|document|location|navigator|history|screen|console|performance|crypto|localStorage|sessionStorage|indexedDB|caches|webkit|chrome|opr|onload|onerror|onmessage)$/;

  function scanDomSubTrees() {
    if (!hasDOM || !CONFIG.scanCredentialAttributes) return 0;
    let found = 0;
    try {
                                                                         
      try {
        for (const t of document.querySelectorAll("template")) {
          if (t.content) found += scanContainerAttributes(t.content, domSourceLabel() + " (<template> content)");
        }
      } catch (e) { fail("subtree.template", e); }

                              
      try {
        for (const el of document.querySelectorAll("*")) {
          const sr = el.shadowRoot;
          if (!sr) continue;
          found += scanContainerAttributes(sr, domSourceLabel() + " (shadow root of <" +
            String(el.tagName || "").toLowerCase() + (el.id ? "#" + el.id : "") + ">)");
        }
      } catch (e) { fail("subtree.shadow", e); }

                                                                   
      try {
        for (const f of document.querySelectorAll("iframe,frame")) {
          const fid = f.id ? "#" + f.id : "(unnamed)";
                                                                             
                                                                        
                                                                          
                                                                            
          try {
            const fsrc = f.getAttribute ? f.getAttribute("src") : null;
            if (fsrc) noteThirdParty("frame", fsrc, { frameId: fid });
          } catch (_) {}
          let doc = null, win = null;
          try { doc = f.contentDocument; win = f.contentWindow; } catch (_) { doc = null; }
          if (doc && doc.body) {
            found += scanContainerAttributes(doc, domSourceLabel() + " (frame " + fid + ")");
            found += scanFrameRuntime(win, "iframe " + fid + ":");
            try {
              const html = String(doc.documentElement ? doc.documentElement.outerHTML : "");
              if (html) found += scanTextCredentialDisclosure(html, domSourceLabel() + " (frame " + fid + " text)", CH_DOM, {}, false, 0);
            } catch (_) {}
          } else {
            let sd = null;
            try { sd = f.getAttribute ? f.getAttribute("srcdoc") : null; } catch (_) { sd = null; }
            if (sd) {
                                                                                
              try {
                found += scanTextCredentialDisclosure(sd, domSourceLabel() + " (iframe srcdoc)", CH_DOM, {}, false, 0);
                const hits = scanSecrets(sd, domSourceLabel() + " (iframe srcdoc)");
                if (hits && hits.length) ingestSecrets(hits, domSourceLabel() + " (iframe srcdoc)", CH_DOM);
              } catch (e) { fail("subtree.srcdoc", e); }
            }
          }
        }
      } catch (e) { fail("subtree.frame", e); }
    } catch (e) { fail("subtree", e); }
    return found;
  }

                                                                              
                                                                    
  const PII_SEVERITY_KINDS = {
    email: 2, phone: 2, "phone-np": 2, "national-id": 3, "national-id-np": 3,
    passport: 3, "passport-np": 3, "credit-card": 3, "credit-card-np": 3,
    dob: 2, address: 1, name: 1, ip: 0, ipv4: 0
  };
  function notePiiExposure(f, raw) {
    const hits = (raw.pii || []).filter(Boolean);
    if (!hits.length) return 0;
    const kinds = hits.map(p => p.kind);
    let worst = "MEDIUM";
    for (const k of kinds) {
      const w = PII_SEVERITY_KINDS[String(k).toLowerCase()];
      if (w === 3) { worst = "CRITICAL"; break; }
      if (w === 2 && worst !== "CRITICAL") worst = "HIGH";
    }
    const key = "pii-exposure:" + (f.host || "") + "|" + (f.normalizedPath || f.path || "");
    const summary = hits.map(p => p.kind + " x" + (p.count || 1)).join(", ");
    if (notes.has(key)) return 0;
    addNote(key, {
      kind: "pii-exposure", label: "personal data in response", severity: worst,
      host: f.host, path: f.normalizedPath || f.path, normalizedPath: f.normalizedPath,
      url: f.url ? redactURLString(f.url) : null, method: f.method || null,
      status: f.status == null ? null : f.status, channel: CH_NETWORK,
      piiKinds: kinds, summary,
      note: "The response body contains personal data (" + summary + "). " +
        "Anyone who can reach this endpoint reads it, and every intermediate cache, proxy and log along the way may keep a copy. " +
        "Check that the route is authenticated, that the response is not publicly cacheable, and that the fields returned are the minimum the client needs."
    });
    return 1;
  }

                                                                                
                                                                   
  const PII_ROUTE_RE = /(?:^|\/)(?:enquir(?:y|ies)|leads?|prospects?|students?|pupils?|parents?|customers?|clients?|members?|patients?|employees?|staff|users?|people|persons?|contacts?|subscribers?|applicants?|applicants|attendees?|guardians?)(?:\/|$|\?)/i;
  function notePiiShapedRoute(host, pathText) {
    if (!CONFIG.detectSensitivePaths || !pathText) return 0;
    if (!PII_ROUTE_RE.test(pathText)) return 0;
    const key = "pii-route:" + host + "|" + pathText;
    if (notes.has(key)) return 0;
    addNote(key, {
      kind: "pii-route", label: "route that likely returns personal data", severity: "MEDIUM",
      host, path: pathText, channel: CH_NETWORK,
      note: "This route is named like one that returns other people's records. The tool has not seen its response, so this is a prompt to open it and look, not a confirmed disclosure."
    });
    return 1;
  }

  function scanDomSurfaces() {
  if (!hasDOM) return 0;
  const src = htmlSourceSnapshot();
  let found = 0;
  try { found += scanHtmlComments(src); } catch (e) { fail("scanHtmlComments", e); }
  try { found += scanStyleBlocks(src); } catch (e) { fail("scanStyleBlocks", e); }
  try { found += scanDomCredentials(src); } catch (e) { fail("scanDomCredentials", e); }
  try { found += scanDomSubTrees(); } catch (e) { fail("scanDomSubTrees", e); }
  return found;
}

                                                                              
                                             
function scanHtmlComments(src) {
  if (!CONFIG.scanHtmlComments || !hasDOM || !document.documentElement) return 0;
  const comments = [];
  try {
    if (typeof document.createTreeWalker === "function" && typeof NodeFilter !== "undefined") {
      const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT, null);
      let node, guard = 0;
      while ((node = walker.nextNode()) && guard++ < 2000) {
        const text = String(node.nodeValue || "");
        if (text.trim()) comments.push(text);
      }
    }
  } catch (e) { fail("comments.walk", e); }
  let found = 0;
  for (const text of comments) {
                                                                            
                                                                               
                                               
    const parts = String(text).split("\n");
    let lead = 0;
    while (lead < parts.length && !parts[lead].trim()) lead++;
    const needle = lead < parts.length ? parts[lead].trim().slice(0, 60) : null;
    const line = docLineOf(needle, lead);
                                                                            
                                                                             
                                                                                
                                                  
    const locOverride = line == null ? {} : null;
    const base = line == null ? 0 : line - 1;
    try {
                                                                               
                                                             
      found += scanTextCredentialDisclosure(text, domSourceLabel() + " (HTML comment)", CH_DOM, locOverride, lineIsExact(), base);
    } catch (e) { fail("comments.scan", e); }
  }
  if (comments.length) channelSeen[CH_DOM] += comments.length;
  return found;
}

                                                                               
                                                                               
                                                                       
function scanStyleBlocks(src) {
  if (!CONFIG.scanHtmlComments || !src || typeof src !== "string") return 0;
  const styleRe = /<style\b[^>]*>([\s\S]{0,400000}?)<\/style>/gi;
  let sm, found = 0, guard = 0;
  while ((sm = styleRe.exec(src)) !== null && guard++ < 60) {
    const css = sm[1];
    const blockStart = sm.index + sm[0].indexOf(css);
    const commentRe = /\/\*([\s\S]{0,40000}?)\*\//g;
    let cm;
    while ((cm = commentRe.exec(css)) !== null) {
      const body = cm[1];
                                                                                
                                                                           
                                                                            
                                        
      if (!/(?:pass|pwd|secret|token|cred|auth|user|login|api|key|pin|otp|session|cookie|hash|credential|\bid\b)/i.test(body)) continue;
      const loc = lineColAt(src, blockStart + cm.index);
      try {
        found += scanTextCredentialDisclosure(body, domSourceLabel() + " (CSS comment)", CH_DOM, {}, lineIsExact(), loc.line - 1);
      } catch (e) { fail("style.scan", e); }
    }
  }
  return found;
}

                                                                        
                             
  
                                                                     
  
                                                                
  
                                                                             
                                                                              
                                                                             
                                                                               
  
                                                                               
                                                                               
                                                                        
                                                                          
                                                                             
                                                                                
                                                            
const PAIR_ID_KEY_RE = /(?:user(?:name)?|userid|user_id|loginid|log_in|account|accountid|account_id|systemid|system_id|operator|adminid|admin_id|clientid|client_id|employeeid|employee_id|staffid|staff_id|uid|email|operatorid)(?:$|[^a-z0-9])/i;
const PAIR_PWD_KEY_RE = /(?:pass(?:word|wd|phrase|code)?|pwd|passwd|secret|token|apikey|api_key|auth|credential|pin|otp|private_key|privatekey|client_secret|clientsecret)(?:$|[^a-z0-9])/i;
                                                                           
                                                      
const PAIR_KV_RE = /(?:^|[^\w$.])([A-Za-z_$][\w$.-]{0,48})"?\s*[=:]\s*(?:'([^'\n]{1,120})'|"([^"\n]{1,120})"|`([^`\n]{1,120})`)/g;

                                                                         
                                                                              
                                                    
const PAIR_WINDOW_CHARS = 1200;

                                                                       
  
                                                                           
                                                                       
                                                                              
                                                                             
                    
function objectSpanAt(text, index) {
  let depth = 0, quote = null, lo = -1;
  for (let i = index - 1; i >= 0; i--) {
    const c = text[i];
    if (quote) { if (c === "\\") { i--; continue; } if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "}") depth++;
    else if (c === "{") { if (depth === 0) { lo = i; break; } depth--; }
  }
  if (lo < 0) return null;
  depth = 0; quote = null;
  for (let j = lo; j < text.length; j++) {
    const c = text[j];
    if (quote) { if (c === "\\") { j++; continue; } if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return lo + ":" + j; }
  }
  return null;
}

function scanCredentialPairsInText(text, file, channel, locOf, exact) {
  if (!text || text.length > 4000000) return 0;
  const ch = channel || CH_STATIC;
  const hits = [];
  const re = new RegExp(PAIR_KV_RE.source, "g");
  let m;
  while ((m = re.exec(text)) !== null && hits.length < 40) {
    const key = String(m[1] || "");
    const value = String(m[2] || m[3] || m[4] || "");
    if (!value || value.length < 3) continue;
    if (CRED_STOPWORDS.test(value)) continue;
    const isId = PAIR_ID_KEY_RE.test(key);
    const isPwd = PAIR_PWD_KEY_RE.test(key);
    if (!isId && !isPwd) continue;
    if (isId && isPwd) continue;                                                    
    hits.push({ key, value, index: m.index, end: m.index + m[0].length, id: isId,
                loc: locOf ? locOf(m.index) : null, span: objectSpanAt(text, m.index) });
  }
  if (hits.length < 2) return 0;

  const ids = hits.filter(h => h.id);
  const pwds = hits.filter(h => !h.id);
  let made = 0;
  const seen = new Set();

  for (const p of pwds) {
                                                                              
                                                                             
                                             
    if (classifyValue(p.value, p.key).verdict === "arbitrary") continue;

                                                                              
                                                      
    let best = null, bestDist = Infinity;
    for (const u of ids) {
      if (!/^[A-Za-z0-9._@+-]{3,64}$/.test(u.value)) continue;
      if (p.span && u.span && p.span !== u.span) continue;
      const dist = u.index < p.index ? p.index - u.end : u.index - p.end;
      if (dist < 0 || dist > PAIR_WINDOW_CHARS) continue;
      if (dist < bestDist) { bestDist = dist; best = u; }
    }
    if (!best) continue;

    const key = fnv1a(best.value + ":" + p.value + "|" + file);
    if (seen.has(key)) continue;
    seen.add(key);

    const where = ch === CH_DOM ? "rendered in page text" : "hardcoded in script";
    const line = best.loc && best.loc.line != null ? best.loc.line
      : (p.loc && p.loc.line != null ? p.loc.line : null);
    const snippet = text.slice(Math.max(0, Math.min(best.index, p.index) - 20),
                               Math.max(best.end, p.end) + 20);

    if (recordCredentialPair(best.value, p.value, where, file, snippet, {
      channel: ch, severity: "CRITICAL",
      line, column: (best.loc && best.loc.column) || (p.loc && p.loc.column) || null,
      lineExact: exact
    })) made++;

                                                                         
                                                                             
                      
    recordDisclosedCredential("username", best.value, where, file, snippet, {
      channel: ch, severity: "MEDIUM",
      classification: classifyValue(best.value, "username"),
      line: best.loc ? best.loc.line : line,
      column: best.loc ? best.loc.column : null, lineExact: exact
    });
    recordDisclosedCredential("password", p.value, where, file, snippet, {
      channel: ch, severity: "CRITICAL",
      classification: classifyValue(p.value, "password"),
      line: p.loc ? p.loc.line : line,
      column: p.loc ? p.loc.column : null, lineExact: exact
    });
  }
  return made;
}

function maskPairForSnippet(u, p) {
  return CONFIG.revealSecrets ? u + ":" + p : maskValue(u) + ":" + maskValue(p);
}

                                                                           
                                                                           
                                             
                                                                              
                                                                    
  const CRED_ATTR_RE = /^(?:data[-_])?(?:user(?:name|[-_]?id)?|login|pass(?:word|wd|phrase|code)?|pwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth(?:orization)?|auth[-_]?(?:user(?:name)?|pass(?:word)?|pwd)|credential)s?$/i;
                                                                     
                                                                               
                                                                          
  const PAIR_ATTR_RE = /^(?:data[-_])?(?:auth[-_]?(?:pair|cred|credential|creds|login)|(?:user|login)[-_]?(?:pass|password|pwd)|creds?|credentials?)(?:[-_](?:pair|pairing))?$/i;

function scanDomCredentials(src) {
  if (!CONFIG.scanCredentialAttributes || !hasDOM) return 0;
  let found = 0, scanned = 0;
  let els = null;
  try { els = document.querySelectorAll("*"); } catch (_) { return 0; }
  const limit = Math.min(els.length, CONFIG.maxDomElements);
  for (let i = 0; i < limit && found < CONFIG.maxCredentialAttributes; i++) {
    const el = els[i];
    const attrs = el.attributes;
    if (!attrs) continue;
    for (let j = 0; j < attrs.length; j++) {
const name = String(attrs[j].name || "");
        const value = String(attrs[j].value == null ? "" : attrs[j].value);
        if (!/^data[-_]/i.test(name)) continue;
                                                                            
        if (PAIR_ATTR_RE.test(name) && value) {
                                                                               
                                                                              
          const sepIdx = value.indexOf(":") >= 0 ? value.indexOf(":") : value.indexOf("=");
          if (sepIdx > 0 && value.length - sepIdx - 1 >= 3) {
            const u = value.slice(0, sepIdx), p = value.slice(sepIdx + 1);
            const pline = docLineOf(name + '="' + value + '"', 0);
            const pbyAttr = pline != null;
            const ploc = pline == null ? { line: docLineOf(value, 0), column: null } : { line: pline, column: null };
            scanned++;
            if (recordCredentialPair(u, p, "hidden DOM attribute", domSourceLabel() + " @ " + name,
              name + '="' + maskPairForSnippet(u, p) + '"   (on <' + String(el.tagName || "").toLowerCase() + ">)", {
                channel: CH_DOM, severity: "CRITICAL",
                line: ploc && ploc.line != null ? ploc.line : null,
                column: ploc ? ploc.column : null, lineExact: lineIsExact() && pbyAttr,
                container: el.tagName ? el.tagName.toLowerCase() : null
})) found++;
                                                                             
                                                                               
                                                              
              const pairNote = name + '="' + maskPairForSnippet(u, p) + '"';
              const uVerdict = classifyValue(u, "username").verdict;
              const pVerdict = classifyValue(p, "password").verdict;
              if (pVerdict !== "arbitrary") {
                recordDisclosedCredential("password", p, "hidden DOM attribute", domSourceLabel() + " @ " + name, pairNote, {
                  channel: CH_DOM, severity: "CRITICAL", verdict: pVerdict,
                  line: ploc ? ploc.line : null, column: ploc ? ploc.column : null,
                  lineExact: lineIsExact() && pbyAttr, container: el.tagName ? el.tagName.toLowerCase() : null,
                  classification: classifyValue(p, name)
                });
              }
              if (uVerdict !== "arbitrary") {
                recordDisclosedCredential("username", u, "hidden DOM attribute", domSourceLabel() + " @ " + name, pairNote, {
                  channel: CH_DOM, severity: "MEDIUM", verdict: uVerdict,
                  line: ploc ? ploc.line : null, column: ploc ? ploc.column : null,
                  lineExact: lineIsExact() && pbyAttr, container: el.tagName ? el.tagName.toLowerCase() : null,
                  classification: classifyValue(u, name)
                });
              }
              continue;
          }
        }
        if (!CRED_ATTR_RE.test(name)) continue;
        if (!value || value.length > CONFIG.maxCredentialValueChars) continue;
      scanned++;
                                                                              
                                                                        
      const needle = name + '="' + value + '"';
      let line = docLineOf(needle, 0);
                                                                                 
                                                                               
                                                                
      const byAttribute = line != null;
      if (line == null) line = docLineOf(value, 0);
      const loc = line == null ? null : { line, column: null };
      const isUser = /^(?:data[-_])?(?:user|username|login|account|e-?mail)/i.test(name);
      const hidden = el.hidden === true || el.getAttribute("aria-hidden") === "true" || el.tagName === "TEMPLATE";
      const kind = isUser ? "username" : "credential";
                                                                          
                                                                      
      const elPath = el.tagName ? el.tagName.toLowerCase() + (el.id ? "#" + el.id : "") : null;
      const snippet = needle + (elPath ? "   (on <" + elPath + ">" + (hidden ? ", hidden" : "") + ")" : (hidden ? "   (on a hidden element)" : ""));
      if (recordDisclosedCredential(kind, value, "hidden DOM attribute", domSourceLabel() + " @ " + name, snippet, {
        line: loc ? loc.line : null, column: loc ? loc.column : null, lineExact: lineIsExact() && byAttribute,
        channel: CH_DOM, severity: isUser ? "MEDIUM" : "CRITICAL", container: el.tagName ? el.tagName.toLowerCase() : null,
        classification: classifyValue(value, name)
      })) found++;
      else {
                                                                    
        indexValue(value, CH_DOM, "DOM attribute " + name, classifyValue(value, kind).verdict);
      }
    }
  }
  if (scanned) channelSeen[CH_DOM] += scanned;
  return found;
}

                                                                              
                                                                             
                                             
                                                                             
                                                                             
                                                                             
const SELF_SIGNATURES = ["[x-ray-eye] v", "xrayeye.secretsReport", "[\"x-ray-eye\"]", "revealSecrets"];
function isOwnSource(text) {
  if (typeof text !== "string" || text.length < 2000) return false;
  let hits = 0;
  for (const sig of SELF_SIGNATURES) if (text.indexOf(sig) >= 0) hits++;
  return hits >= 3;
}

const RUNTIME_SKIP = /^(?:window|self|top|parent|frames|length|name|origin|closed|document|location|navigator|history|screen|console|performance|crypto|localStorage|sessionStorage|indexedDB|caches|webkit|chrome|opr|speechSynthesis|google_tag_data|dataLayer|gtag|googletagmanager|_gaq|ga|analytics|fbq|_fbq|gtm|onload|onerror|onmessage|xrayeye|x-ray-eye|__xrayeye|_sentryDebugIdIdentifier|_sentryDebugIds|_sentrySessionId|__stdos__|__fbq__|FB|_fbq|__react_app|__NEXT_DATA__)$/;

function scanRuntimeValue(path, value, depth, out) {
  if (out.found >= CONFIG.maxRuntimeFindings) return;
  if (typeof value === "string") {
    const v = value.trim();
    if (!v || v.length < 4 || v.length > 300) return;
    const pairs = scanDecodedLiteral(v, "window." + path, CH_RUNTIME);
    if (pairs) { out.found++; return; }
    const verdictInfo = classifyValue(v, path);
    const verdict = verdictInfo.verdict;
    if (verdict === "arbitrary") return;
    if (recordDisclosedCredential(/user|login|account|name/i.test(path) ? "username" : "credential", v,
      "exposed on window", "window." + path, "window." + path + " = " + JSON.stringify(v).slice(0, 80), {
      verdict, classification: verdictInfo, channel: CH_RUNTIME
    })) out.found++;
    return;
  }
  if (depth >= CONFIG.maxRuntimeDepth || value === null || typeof value !== "object") return;
  if (value === window || value === document || Array.isArray(value) === false && !(value instanceof Object)) return;
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 40); i++) scanRuntimeValue(path + "[" + i + "]", value[i], depth + 1, out);
    return;
  }
  let keys = [];
  try { keys = Object.keys(value); } catch (_) { return; }
  for (let i = 0; i < Math.min(keys.length, 50); i++) scanRuntimeValue(path + "." + keys[i], value[keys[i]], depth + 1, out);
}

function scanRuntimeGlobals() {
  if (!CONFIG.scanRuntimeGlobals || typeof window === "undefined") return 0;
  let keys = [];
  try { keys = Object.keys(window); } catch (_) { return 0; }
  const out = { found: 0 };
  for (let i = 0; i < keys.length && out.found < CONFIG.maxRuntimeFindings; i++) {
    const k = keys[i];
    if (RUNTIME_SKIP.test(k)) continue;
    let v = null;
    try { v = window[k]; } catch (_) { continue; }
    if (typeof v === "function") continue;
    try { scanRuntimeValue(k, v, 0, out); } catch (e) { fail("runtime.value", e); }
  }
  if (out.found) channelSeen[CH_RUNTIME] += out.found;
  return out.found;
}

                                                                             
                                                                              
                                                              
function scanDecodedLiteral(token, where, channel, at) {
  if (!CONFIG.decodeEncodedLiterals) return 0;
  let found = 0;
  for (const dec of [tryDecodeBase64(token), tryDecodeHex(token)]) {
    if (!dec) continue;
    const text = dec.text;
                                                                           
    const pair = /^([^:\s]{1,60}):([^\s]{1,80})$/.exec(text);
    if (pair) {
      recordCredentialPair(pair[1], pair[2], where, where, dec.kind + "-decoded \"" + clip(token, 60) + "\" -> " + text,
        { decodedFrom: dec.kind, channel, severity: "CRITICAL", encoded: token });
      found++;
    }
    if (recordDisclosedCredential(pair ? "password" : "credential", pair ? pair[2] : text, where, where,
      dec.kind + "-decoded literal \"" + clip(token, 60) + "\" -> " + clip(text, 80), {
        decodedFrom: dec.kind, channel, severity: "HIGH", encoded: token, line: at ? at.line : null, column: at ? at.column : null
      })) found++;
  }
  return found;
}

                                                                               
                                         
function scanEncodedLiterals(text, fileLabel, channel) {
  if (!CONFIG.decodeEncodedLiterals || !text) return 0;
  const LIT_RE = /["'`]([A-Za-z0-9+/=_-]{16,512})["'`]/g;
  let m, found = 0, guard = 0;
  const done = new Set();
  while ((m = LIT_RE.exec(text)) !== null && guard++ < 400 && found < 40) {
    const token = m[1];
    if (done.has(token)) continue;
    done.add(token);
    const loc = lineColAt(text, m.index);
    try { found += scanDecodedLiteral(token, fileLabel, channel, loc); } catch (e) { fail("decoded.literal", e); }
  }
  return found;
}

                                                                              
                                                                       
function resolveStringConstants(text, fileLabel, channel) {
  if (!CONFIG.reconstructStringConstants || !text) return 0;
  const env = new Map();
  const decl = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+);/g;
  let m, found = 0, guard = 0;
  while ((m = decl.exec(text)) !== null && guard++ < 800 && found < 40) {
    const name = m[1];
    const parts = m[2].split("+").map(p => p.trim());
    if (!parts.length) continue;
    let out = "", resolved = true, reconstructed = false;
    for (const p of parts) {
      const lit = /^["'`]([\s\S]*?)["'`]$/.exec(p);
      if (lit) { out += lit[1]; continue; }
      if (env.has(p)) { out += env.get(p); reconstructed = true; continue; }
      resolved = false;
      break;
    }
    if (!resolved || !out) continue;
    if (env.size < 500) env.set(name, out);
    if (!reconstructed || out.length < 6 || out.length > 300) continue;
                                                                          
                                                                    
    if (!CRED_VALUE_RE.test(out)) continue;
    if (!/[._\-]/.test(out) && !(/\d/.test(out) && /[A-Za-z]/.test(out))) continue;
    const verdict = classifyValue(out, name).verdict;
    if (verdict === "arbitrary") continue;
    const at = text.indexOf(m[0]);
    const loc = at >= 0 ? lineColAt(text, at) : null;
    try {
      if (recordDisclosedCredential("credential", out, "reconstructed at runtime", fileLabel,
        name + " = " + clip(m[2], 80), {
          verdict, channel, reconstructedFrom: name, line: loc ? loc.line : null, column: loc ? loc.column : null, severity: "HIGH"
        })) found++;
    } catch (e) { fail("reconstructed.record", e); }
  }
  return found;
}

                                                                           
                                                                              
                                                                           
                                                                             
                                                                           

                                                                                 
  function collectPropertyTable(text) {
    const table = new Map();
    const objRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:Object\.(?:freeze|seal|assign)\s*\(\s*)?\{([\s\S]{0,4000}?)\}\s*\)?\s*;/g;
    let m, guard = 0;
    while ((m = objRe.exec(text)) !== null && guard++ < 400) {
      const objName = m[1];
      const body = m[2];
      const fRe = /([A-Za-z_$][\w$]*)\s*:\s*(["'`])([^"'\`\n]{1,160})\2/g;
      let f;
      while ((f = fRe.exec(body)) !== null) {
        const key = objName + "." + f[1];
        if (!table.has(key)) table.set(key, { value: f[3], at: m.index, obj: objName });
      }
    }
    return table;
  }

                                                                    
  function looksLikeUsernameValue(v) {
    const s = String(v || "");
    return /^[a-z][a-z0-9._-]{2,48}$/.test(s) && !/\d/.test(s) && s.indexOf("!") < 0;
  }

  function resolveMemberConcatenation(text, fileLabel, channel) {
    if (!CONFIG.reconstructStringConstants || !text || text.length > 4000000) return 0;
    let found = 0;
    try {
      const props = collectPropertyTable(text);
      if (!props.size) return 0;
                                                                            
      const concatRe = /((?:[A-Za-z_$][\w$]*\s*\.\s*[A-Za-z_$][\w$]*\s*|(["'`])[^"'`\n]{0,160}\2|[A-Za-z_$][\w$]*)\s*\+\s*){1,12}(?:[A-Za-z_$][\w$]*\s*\.\s*[A-Za-z_$][\w$]*\s*|(["'`])[^"'`\n]{0,160}\3|[A-Za-z_$][\w$]*)/g;
      let m, guard = 0;
      const done = new Set();
      const recovered = [];
      while ((m = concatRe.exec(text)) !== null && guard++ < 3000 && recovered.length < 60) {
        const expr = m[0];
        const parts = expr.split("+").map(s => s.trim()).filter(Boolean);
        if (parts.length < 2) continue;
        let out = "", all = true, anyMember = false;
        for (const p of parts) {
          const lit = /^(["'`])([\s\S]*)\1$/.exec(p);
          if (lit) { out += lit[2]; continue; }
          const member = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/.exec(p);
          if (member && props.has(member[1] + "." + member[2])) {
            out += props.get(member[1] + "." + member[2]).value;
            anyMember = true;
            continue;
          }
          all = false;
          break;
        }
                                                                              
                                                                            
        if (!all || !anyMember || !out) continue;
        if (done.has(out)) continue;
        done.add(out);
        if (out.length < 6 || out.length > 300) continue;
        if (!CRED_VALUE_RE.test(out)) continue;
        const loc = lineColAt(text, m.index);
        const isUser = looksLikeUsernameValue(out);
        const label = isUser ? "username" : "password";
        const verdict = classifyValue(out, label).verdict;
        if (verdict === "arbitrary") continue;
        recovered.push({ value: out, label, loc, expr: clip(expr, 90), isUser });
        if (recordDisclosedCredential(label, out, "reconstructed at runtime", fileLabel,
          clip(expr, 160), {
          verdict, channel, severity: isUser ? "HIGH" : "CRITICAL", lineExact: true,
          reconstructedFrom: "object property concatenation",
          line: loc ? loc.line : null, column: loc ? loc.column : null
        })) found++;
      }
                                                                             
                                                                      
      for (let i = 0; i < recovered.length; i++) {
        for (let j = 0; j < recovered.length; j++) {
          if (i === j) continue;
          if (recovered[i].isUser === recovered[j].isUser) continue;
          const user = recovered[i].isUser ? recovered[i] : recovered[j];
          const pass = recovered[i].isUser ? recovered[j] : recovered[i];
                                                                          
          const ul = user.loc ? user.loc.line : 0, pl = pass.loc ? pass.loc.line : 0;
          if (Math.abs(ul - pl) > 250) continue;
          recordCredentialPair(user.value, pass.value, "reconstructed from a lookup table", fileLabel,
            user.expr + "  ->  " + pass.expr, {
            channel, severity: "CRITICAL", line: pass.loc ? pass.loc.line : null,
            lineExact: true, container: "reconstructed-login",
            reconstructedFrom: "object property concatenation"
          });
        }
      }
    } catch (e) { fail("member.concat", e); }
    return found;
  }

                                                                              
function parseStringObjectLiterals(text) {
  const out = new Map();
  const objRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([\s\S]{0,3000}?)\}\s*;/g;
  let m, guard = 0;
  while ((m = objRe.exec(text)) !== null && guard++ < 300) {
    const fields = new Map();
    const fRe = /([A-Za-z_$][\w$]*)\s*:\s*"([^"\n]{1,120})"/g;
    let f;
    while ((f = fRe.exec(m[2])) !== null) if (!fields.has(f[1])) fields.set(f[1], f[2]);
    if (fields.size) out.set(m[1], { fields, at: m.index });
  }
  return out;
}

                                                                            
                                                                          
                                       
function recordCredentialPair(username, password, where, file, snippet, opts) {
  const o = opts || {};
                                                                             
                                                                              
  if (nonValueReason(username) || nonValueReason(password)) return false;
  const uVerdict = classifyValue(username, "username").verdict;
  const pVerdict = classifyValue(password, "password").verdict;
  const verdict = (uVerdict === "real" || pVerdict === "real") ? "real" : (uVerdict === "arbitrary" && pVerdict === "arbitrary" ? "arbitrary" : "fixture");
  if (verdict === "arbitrary") return false;
  const pairKey = "authpair:" + fnv1a(username + ":" + password + "|" + (o.container || where));
  const severity = severityForVerdict(verdict, o.severity || "CRITICAL");
  const masked = [maskValue(username), maskValue(password)];
  const raw = CONFIG.revealSecrets ? [username, password] : null;
  const listed = CONFIG.revealSecrets ? null : masked;
  const exact = o.lineExact === undefined ? lineOffsetExact : !!o.lineExact;
  const existing = notes.get(pairKey);
  if (!existing) {
    addNote(pairKey, {
      kind: "auth-pair", label: "credential pair",
      exposure: where, container: o.container || null,
      values: listed, valuesRaw: raw,
      severity, verdict, channel: o.channel || null, fixture: verdict === "fixture",
      file, line: absLine(o.line), column: o.column == null ? null : o.column,
      lineExact: exact,
      decodedFrom: o.decodedFrom || null,
      compare: o.compare ? clip(String(o.compare), 400) : null,
      compareAt: o.compareLine == null ? null : { file, line: absLine(o.compareLine), column: o.compareColumn == null ? null : o.compareColumn, lineExact: exact },
      snippet: o.snippet ? clip(String(o.snippet), 240) : null,
      note: o.compare
        ? "Both halves of a working login are in the page, and the comparison that accepts them runs in the browser. The check is bypassable by anyone who reads it, and neither value can be rotated without a deploy. Move the check server-side and remove the literals."
        : "A username and a password are hardcoded together in shipped code. The check itself is elsewhere (a server, or a file this scan did not read), but the pair is what is compared, and both values are readable in the bundle."
    });
  } else {
    if (CONFIG.revealSecrets) {
      existing.valuesRaw = raw;
      existing.values = null;
      if (o.compare) existing.compare = clip(String(o.compare), 400);
    }
                                                                             
                                                          
    if (o.line != null && exact && existing.lineExact === false) {
      existing.line = absLine(o.line);
      existing.column = o.column == null ? null : o.column;
      existing.lineExact = true;
    }
    if (o.compareLine != null && exact && existing.compareAt && existing.compareAt.lineExact === false) {
      existing.compareAt.line = absLine(o.compareLine);
      existing.compareAt.column = o.compareColumn == null ? null : o.compareColumn;
      existing.compareAt.lineExact = true;
    }
  }
  for (const v of [username, password]) indexValue(v, o.channel, where, verdict);
  return !existing;
}

                                                                              
                                                                               
                                                                             
                                                                               
                         
function findComparisonLine(text, refs) {
  if (!text || !refs || !refs.length) return null;
  const lines = String(text).split("\n");
  const cmp = /(?:===|!==|==|!=)/;
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!cmp.test(l)) { offset += l.length + 1; continue; }
    let hit = false;
    for (const r of refs) {
      let re;
      try { re = new RegExp(r); } catch (_) { continue; }
      if (re.test(l)) { hit = true; break; }
    }
    if (!hit) { offset += l.length + 1; continue; }
                                                                             
                                                                              
    const following = lines[i + 1];
    const next = following != null && !/[;{}]\s*$/.test(l) && !/^\s*[{}]/.test(following) ? following : "";
    const body = next ? l + "\n" + next : l;
    return { text: clip(body.trim(), 300), loc: lineColAt(text, offset) };
  }
  return null;
}

function analyzeAuthComparisons(text, fileLabel, channel) {
  if (!CONFIG.analyzeAuthComparisons || !text) return 0;
  const objs = parseStringObjectLiterals(text);
  if (!objs.size) return 0;
  let found = 0;
  for (const [name, rec] of objs) {
    const uField = [...rec.fields.keys()].find(k => /^(?:user(?:name)?|login|identifier|account|e-?mail)$/i.test(k));
    const pField = [...rec.fields.keys()].find(k => /^(?:pass(?:word)?|pwd|passphrase|passcode|secret|pin|token|code)$/i.test(k));
    if (!uField || !pField) continue;
    const refU = escRe(name + "." + uField);
    const refP = escRe(name + "." + pField);
                                                                              
                                                                            
                                                                              
                                                                             
                                                                              
    const cmp = findComparisonLine(text, [refU, refP, "\\b" + escRe(uField) + "\\b", "\\b" + escRe(pField) + "\\b"]);
    if (!cmp) {
      const looseRe = new RegExp("(?:===|==|!==|!=)", "g");
      if (!looseRe.test(text) || text.indexOf(name + "." + uField) < 0) continue;
    }
    const compareText = cmp ? cmp.text : name + "." + uField;
    const compareAt = cmp ? cmp.loc : null;
    const username = rec.fields.get(uField);
    const password = rec.fields.get(pField);
    const at = lineColAt(text, rec.at);
    const snippet = name + " = { " + uField + ": " + JSON.stringify(username) + ", " + pField + ": " + JSON.stringify(password) + " }";
    if (recordCredentialPair(username, password, "hardcoded in script", fileLabel, snippet, {
      channel, severity: "CRITICAL", container: name,
      line: at ? at.line : null, column: at ? at.column : null,
      compare: compareText, compareLine: compareAt ? compareAt.line : null, compareColumn: compareAt ? compareAt.column : null
    })) found++;
                                                       
    if (recordDisclosedCredential("username", username, "hardcoded in script", fileLabel,
      snippet, { channel, severity: "MEDIUM", container: name, containerField: uField,
                 line: at ? at.line : null, column: at ? at.column : null })) found++;
  }
  return found;
}

                                                                           
                                                                    

function scanTextCredentialDisclosure(text, file, channel, locOverride, exact, baseLine, quotedOnly) {
  if (!CONFIG.harvestVisibleText || !text || text.length > 4000000) return 0;
  const ch = channel || CH_STATIC;
  let n = 0;
  const users = [];
                                                                               
                                                                                 
                                                                           
                                                                                
                                            
  const locOf = i => {
    if (locOverride) return locOverride;
    const at = lineColAt(text, i);
    if (!at) return null;
    return baseLine ? { line: at.line + baseLine, column: at.column } : at;
  };
  const re = new RegExp((quotedOnly ? CODE_USER_QUOTED_RE : CODE_USER_RE).source, "gi");
  let m;
  while ((m = re.exec(text)) !== null && users.length < 24) {
                                                                             
                         
    const uLoc = locOf(m.index);
    const v = String(reCaptured(m) || "").replace(/[.,;:]+$/, "");
    if (!v || CRED_STOPWORDS.test(v)) continue;
    if (String(v).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
if (/^(?:https?|www\.)/i.test(v)) continue;
    if (v.indexOf("@") >= 0) continue;
                                                                          
                                                                              
                                                                                
                                                                                 
                           
    const uKey = String(m[0].split(/[:=]|is\s|will\s/)[0] || "username").trim();
    if (classifyValue(v, uKey).verdict === "arbitrary") continue;
    users.push({ value: v, loc: uLoc, key: uKey });
  }
  const re2 = new RegExp((quotedOnly ? CODE_PWD_QUOTED_RE : CODE_PWD_RE).source, "gi");
  while ((m = re2.exec(text)) !== null && n < 25) {
                                                                              
                                                                               
                                                        
    const label = String(m[0].split(/[:=]|is\s|will\s/)[0] || "credential").trim();
    const value = String(reCaptured(m) || "").replace(/[.,;:]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
    if (String(value).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
    const at = Math.max(0, m.index - 40);
    const loc = locOf(m.index);
    if (recordDisclosedCredential(label, value, "hardcoded in script", file,
      text.slice(at, m.index + m[0].length + 20),
      { line: loc ? loc.line : null, column: loc ? loc.column : null, channel: ch, lineExact: exact, severity: "CRITICAL" })) n++;
  }
                                                                               
                                                                       
  for (const u of users.slice(0, 12)) {
    if (recordDisclosedCredential(u.key || "username", u.value, "hardcoded in script", file,
      "username: " + u.value,
      { line: u.loc ? u.loc.line : null, column: u.loc ? u.loc.column : null, channel: ch, lineExact: exact, severity: "MEDIUM",
        classification: classifyValue(u.value, u.key || "username") })) n++;
  }
  if (users.length) {
    const maskedUsers = users.slice(0, 6).map(u => maskValue(u.value));
    const rawUsers = CONFIG.revealSecrets ? users.slice(0, 6).map(u => u.value) : null;
    const listedUsers = CONFIG.revealSecrets ? null : maskedUsers;
                                                                              
                                                                         
    const uKey = "disclosed:users:" + (file || "script");
    const uNote = notes.get(uKey);
    if (uNote) {
      uNote.values = listedUsers;
      uNote.valuesRaw = rawUsers;
    } else {
      addNote(uKey, {
        kind: "disclosed-credential", label: "username", exposure: "hardcoded in script",
        values: listedUsers, valuesRaw: rawUsers, severity: "HIGH",
        where: "hardcoded in script", file: file || null,
        note: "A username is hardcoded in shipped JavaScript. Alongside a hardcoded password this is a complete, working login sitting in the bundle."
      });
    }
  }
                                                                            
                                                                        
                                                                             
                                                             
  try {
    scanCredentialPairsInText(text, file, ch, locOf, exact);
  } catch (e) { fail("pairs", e); }
  return n;
}

function harvestDataAttributes() {
    if (!hasDOM) return;
    try {
      const els = document.querySelectorAll("[data-api],[data-endpoint],[data-url],[data-src],[data-href],[data-action-url],[data-graphql]");
      for (const el of els) {
        if (!el || el.__xrayDataSeen) continue;
        el.__xrayDataSeen = 1;
        for (const attr of ["data-api", "data-endpoint", "data-url", "data-src", "data-href", "data-action-url", "data-graphql"]) {
          const v = el.getAttribute && el.getAttribute(attr);
          if (!v || v.length > 500) continue;
          const u = parseURL(v);
          if (u) {
            record({ source: "dom-attr", url: v, method: "?", observed: false });
          } else if (/^\/[A-Za-z0-9_\-./{}$?=&%:-]+$/.test(v)) {
            record({ source: "dom-attr", url: v, method: "?", observed: false });
          }
        }
      }
    } catch (e) {
      fail("dataAttrs", e);
    }
  }

                                                                                          
  function detectWebpackPublicPath(text, file) {
    if (!text || text.indexOf("__webpack_require__") < 0 && text.indexOf("webpackChunk") < 0) return;
    const re = /__webpack_require__\.p\s*=\s*["']([^"']{1,200})["']/g;
    let m, guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 5) {
      const p = m[1];
      addNote("wpp:" + p, {
        kind: "webpack-publicpath", value: p, file: String(file).split("/").pop(),
        note: "Webpack publicPath. Bundles load runtime assets from here, so it is a real, reachable base path on the host."
      });
      const u = parseURL(p);
      if (u && /^https?:/.test(p)) record({ source: "webpack", url: p, method: "?", observed: false });
    }
  }

  function detectImportScripts(text, file) {
    if (!text || text.indexOf("importScripts") < 0) return;
    const re = /importScripts\s*\(\s*(["'])([^"']{1,300})\1\s*\)/g;
    let m, guard = 0;
    while ((m = re.exec(text)) !== null && guard++ < 20) {
      const s = m[2];
      addNote("importscript:" + s, {
        kind: "service-worker-import", script: s, file: String(file).split("/").pop(),
        note: "Service worker imports this script. Worker fetch handlers routinely hardcode API routes for cache strategies."
      });
      try {
        const base = parseURL(String(file)) || baseURI();
        const abs = new URL(s, base).href;
        if (/^https?:/i.test(abs)) enqueueScript(abs);
      } catch (_) {}
    }
  }

                                                                              
  const LINE_COMMENT_RE = /(^|[^:\\])\/\/([^\n]{4,400})/g;
  const BLOCK_COMMENT_RE = /\/\*([\s\S]{4,4000}?)\*\//g;
  const TODO_RE = /\b(TODO|FIXME|HACK|XXX|WIP|DISABLED|DEPRECATED|NOCHECK|SECURITY|TEMP)\b[:\s][^\n]{0,200}/gi;

  function scanComments(text, file) {
    if (!text || !CONFIG.scanComments) return;
    if (text.length > 4000000) return;
    let guard = 0;

    let m;
    const block = new RegExp(BLOCK_COMMENT_RE.source, "g");
    while ((m = block.exec(text)) !== null && guard++ < 4000) {
      const body = m[1];
      noteCommentRefs(body, file, "block comment");
    }
    const line = new RegExp(LINE_COMMENT_RE.source, "g");
    while ((m = line.exec(text)) !== null && guard++ < 8000) {
      const body = m[2];
      if (/^\s*[/!]/.test(body)) continue;                     
      noteCommentRefs(body, file, "line comment");
    }
    const todo = new RegExp(TODO_RE.source, "gi");
    while ((m = todo.exec(text)) !== null && guard++ < 9000) {
      const raw = m[0];
      addNote("todo:" + fnv1a(raw), {
        kind: "developer-note", tag: String(m[1]).toLowerCase(),
        text: clip(CONFIG.redactSensitive ? hardRedact(redactString(raw)) : raw, 220),
        file: String(file).split("/").pop(),
        note: "Left in shipped code. Markers such as SECURITY or DISABLED frequently sit next to a known weakness."
      });
      try { ingestSecrets(scanCommentsSafely(raw, file), file); } catch (_) {}
    }
  }

  function scanCommentsSafely(text, file) {
    try { return scanSecrets(text, file + " (comment)"); } catch (_) { return []; }
  }

  function noteCommentRefs(body, file, kind) {
    const refs = [];
    let m;
    const call = /\b(fetch|axios(?:\.[a-z]+)?|XMLHttpRequest|open|request|\.get|\.post|\.put|\.delete)\s*\(\s*["'`]([^"'`\n]{2,300})/g;
    while ((m = call.exec(body)) !== null && refs.length < 20) refs.push({ verb: m[1], url: m[2] });
    if (refs.length) {
      for (const r of refs) {
        addNote("cmt:" + r.verb + ":" + r.url.slice(0, 150), {
          kind: "commented-code", verb: r.verb, url: clip(r.url, 300),
          file: String(file).split("/").pop(), commentKind: kind,
          note: "Live-looking API call sitting in a comment. It is dead in the UI but the route is usually still deployed and often unauthenticated."
        });
        try { record({ source: "comment", url: r.url, method: "?", observed: false }); } catch (_) {}
      }
    } else if (/\/(?:api|graphql|admin|internal|v\d)\//.test(body)) {
      for (const u of extractRefs(body).slice(0, 10)) {
        addNote("cmtpath:" + u, {
          kind: "commented-code", url: u, file: String(file).split("/").pop(), commentKind: kind,
          note: "API-shaped path mentioned inside a comment."
        });
        try { record({ source: "comment", url: u, method: "?", observed: false }); } catch (_) {}
      }
    }
  }

                                                                                      
  function parseRobotsOrSitemap(text, url) {
    if (!text || text.length > 2000000) return;
    const isRobots = /robots\.txt$/i.test(url);
    const paths = new Set();
    if (isRobots) {
      let m;
      const re = /^\s*(?:Disallow|Allow)\s*:\s*(\S+)/gim;
      let guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 2000) {
        const p = m[1];
        if (!p || p === "/" || p === "/*") continue;
        if (!/^\//.test(p)) continue;
        paths.add(p);
      }
    } else {
      let m;
      const re = /<loc>\s*([\s\S]*?)\s*<\/loc>/gi;
      let guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 3000) paths.add(m[1].trim());
    }
    if (!paths.size) return;
    addNote("robots:" + url, {
      kind: isRobots ? "robots-paths" : "sitemap-paths", url,
      count: paths.size,
      note: isRobots
        ? "Disallow/Allow entries enumerate paths the site does not want crawled. They are frequently still deployed and reachable directly."
        : "Sitemap entries are the site's own inventory of pages, which maps cleanly onto API routes."
    });
    for (const p of paths) {
      if (p.length > 300) continue;
      try { record({ source: isRobots ? "robots" : "sitemap", url: p, method: "?", observed: false }); } catch (_) {}
    }
  }

                                                                          
                                                                     
                                                                          
  function installWebRTC() {
    const Orig = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (typeof Orig !== "function" || typeof Proxy === "undefined") return;
    const proxy = new Proxy(Orig, {
      construct(Target, args, newTarget) {
        if (active) {
          try {
            const cfg = args[0];
            const list = cfg && (Array.isArray(cfg.iceServers) ? cfg.iceServers : []);
for (const s of list.slice(0, 20)) {
                if (!s) continue;
                                                                               
                                                                         
                                                                            
                                                                            
                let urls;
                if (Array.isArray(s.urls)) urls = s.urls;
                else if (typeof s.urls === "string" && s.urls) urls = [s.urls];
                else if (typeof s.url === "string" && s.url) urls = [s.url];
                else urls = [];
                for (const u of urls.slice(0, 10)) {
                const val = String(u);
                addNote("ice:" + val, {
                  kind: "webrtc-ice", url: clip(val, 200),
                  username: s.username ? maskValue(s.username) : null,
                  credential: s.credential ? maskValue(s.credential) : null,
                  hasCredential: !!s.credential,
                  note: s.credential
                    ? "TURN/STUN server with a credential in page source. Short-lived ephemeral credentials are normal; a static shared secret or a hardcoded IP is not."
                    : "ICE server declared in page source."
                });
              }
            }
          } catch (e) { fail("rtc", e); }
        }
        return Reflect.construct(Target, args, newTarget);
      }
    });
    try { window.RTCPeerConnection = proxy; } catch (_) { return; }
    cleanups.push(() => { try { if (window.RTCPeerConnection === proxy) window.RTCPeerConnection = Orig; } catch (_) {} });
    hooks.push("webrtc");
  }

  function installBroadcastChannel() {
    const Orig = window.BroadcastChannel;
    if (typeof Orig !== "function" || typeof Proxy === "undefined") return;
    const proxy = new Proxy(Orig, {
      construct(Target, args, newTarget) {
        if (active) {
          try {
            const name = String(args[0] || "");
            addNote("bc:" + name, {
              kind: "broadcast-channel", name,
              note: "BroadcastChannel is same-origin only, so this is a cross-tab or cross-frame channel rather than a cross-origin leak. Relevant to SSO and widget token hand-off."
            });
          } catch (e) { fail("broadcast", e); }
        }
        return Reflect.construct(Target, args, newTarget);
      }
    });
    try { window.BroadcastChannel = proxy; } catch (_) { return; }
    cleanups.push(() => { try { if (window.BroadcastChannel === proxy) window.BroadcastChannel = Orig; } catch (_) {} });
    hooks.push("broadcastchannel");
  }

                                                                            
  function installStorageWriteHooks() {
    if (!CONFIG.hookStorageWrites) return;
    const P = (typeof window.Storage !== "undefined") ? window.Storage.prototype : null;
    if (!P) return;
    for (const m of ["setItem", "removeItem"]) {
      const orig = P[m];
      if (typeof orig !== "function") continue;
      const wrapped = function (key, value) {
        if (active) {
          try {
            const area = (this === window.sessionStorage) ? "sessionStorage" : "localStorage";
            storageFinding(area, String(key), m === "setItem" ? value : "", { via: "write" });
            if (m === "setItem" && typeof value === "string") {
              analyzeJWT(value, "write:" + area + ":" + key);
              if (CONFIG.scanSecrets && value.length > 8 && value.length < CONFIG.maxStorageValueChars) {
                for (const h of scanSecrets(value, "write:" + area + ":" + key)) if (h.exposure === "leak") stats.storageSecrets++;
              }
            }
          } catch (e) { fail("storageWrite", e); }
        }
        return Reflect.apply(orig, this, arguments);
      };
      try { P[m] = wrapped; } catch (_) { return; }
      cleanups.push(() => { try { if (P[m] === wrapped) P[m] = orig; } catch (_) {} });
    }
    hooks.push("storage-writes");
  }

  function installCacheOpenHook() {
    if (!CONFIG.hookCacheOpens) return;
    const CS = typeof caches !== "undefined" ? caches : null;
    if (!CS || typeof CS.open !== "function") return;
    const orig = CS.open;
    const wrapped = function (name) {
      if (active) {
        try {
          addNote("cacheopen:" + String(name), {
            kind: "cache-open", name: String(name),
            note: "The application opened a Cache Storage bucket. Its cached responses are readable by any script on this origin."
          });
          stats.cacheOpens = (stats.cacheOpens || 0) + 1;
        } catch (e) { fail("cacheOpen", e); }
      }
      return Reflect.apply(orig, this, arguments);
    };
    try { CS.open = wrapped; } catch (_) { return; }
    cleanups.push(() => { try { if (CS.open === wrapped) CS.open = orig; } catch (_) {} });
    hooks.push("cache-open");
  }

                                                                          
                                                                          
                                                                         
                                                                    
                                                                          
  let jsonHookBusy = false;

  function installJSONParseHook() {
    if (!CONFIG.catchJSONParse) return;
    const orig = JSON.parse;
    const wrapped = function (text, reviver) {
      const out = Reflect.apply(orig, this, arguments);
                                                              
      if (active && !jsonHookBusy && typeof text === "string") {
        try {
          const head = text.slice(0, 400);
          if (text.length > 40 && text.length < 4000000 && /"[^"]{1,40}"\s*:/.test(head) &&
              (/(?:api[_-]?key|apikey|secret|token|password|client[_-]?secret|private[_-]?key|access[_-]?key)/i.test(head) ||
               /(?:sk_live|ghp_|AKIA|AIza|xox[baprs]-|SG\.)/.test(head))) {
            jsonHookBusy = true;
            try {
              const j = Reflect.apply(orig, this, arguments);
              ingestSecrets(scanSecrets(text, "JSON.parse"), "JSON.parse", CH_RUNTIME);
              analyzeJWTsInJSON(j, "JSON.parse");
              if (j && typeof j === "object") harvestBodyFields(j);
            } catch (_) {
            } finally { jsonHookBusy = false; }
          }
        } catch (_) {}
      }
      return out;
    };
    try { JSON.parse = wrapped; } catch (_) { return; }
    cleanups.push(() => { try { if (JSON.parse === wrapped) JSON.parse = orig; } catch (_) {} });
    hooks.push("json-parse");
  }

  let consoleHookBusy = false;

  function installConsoleHook() {
    if (!CONFIG.catchConsoleDumps) return;
    for (const m of ["log", "debug", "info", "warn"]) {
      const orig = console && console[m];
      if (typeof orig !== "function") continue;
      const wrapped = function (...args) {
        if (active && !consoleHookBusy && args.length && args.length <= 12) {
          try {
            for (const a of args) {
              if (typeof a !== "string" && typeof a !== "object" || a === null) continue;
              let text;
              try { text = typeof a === "string" ? a : JSON.stringify(a); } catch (_) { continue; }
              if (!text || text.length < 20 || text.length > 200000) continue;
              if (!/(?:api[_-]?key|apikey|secret|token|password|credential|endpoint|base_?url)/i.test(text)) continue;
              if (/(?:sk_live|ghp_|glpat-|AKIA|ASIA|AIza|xox[baprs]-|SG\.|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.)/.test(text)) {
                consoleHookBusy = true;
                try {
                  addNote("console:" + fnv1a(text), {
                    kind: "console-dump", method: m,
                    preview: clip(CONFIG.redactSensitive ? hardRedact(redactString(text)) : text, 220),
                    note: "The page logged an object containing credential-shaped data. Debug dumps of config objects survive into production more often than expected."
                  });
                  ingestSecrets(scanSecrets(text, "console." + m), "console." + m, CH_RUNTIME);
                } finally { consoleHookBusy = false; }
                break;
              }
            }
          } catch (_) {}
        }
        return Reflect.apply(orig, this, arguments);
      };
      try { console[m] = wrapped; } catch (_) { continue; }
      cleanups.push(() => { try { if (console[m] === wrapped) console[m] = orig; } catch (_) {} });
    }
    hooks.push("console-dump");
  }

  function installCookieWriteHook() {
    if (!CONFIG.catchCookieWrites || !hasDOM || typeof Document === "undefined") return;
    const proto = Document.prototype;
    let desc;
    try { desc = Object.getOwnPropertyDescriptor(proto, "cookie"); } catch (_) { return; }
    if (!desc || typeof desc.set !== "function" || typeof desc.get !== "function") return;
    const origSet = desc.set;
    const restored = Object.getOwnPropertyDescriptor(proto, "cookie");
    const wrapped = function (value) {
      if (active) {
        try {
          const s = String(value);
          const nm = s.split("=")[0].trim();
          if (nm) {
            const val = s.slice(nm.length + 1).split(";")[0];
            storageFinding("cookie", nm, val, { via: "write", flags: s.slice(s.indexOf(";") + 1).slice(0, 200) });
            if (typeof val === "string") analyzeJWT(val, "cookie-write:" + nm);
          }
        } catch (e) { fail("cookieWrite", e); }
      }
      return origSet.call(this, value);
    };
    try {
      Object.defineProperty(proto, "cookie", { get: desc.get, set: wrapped, enumerable: desc.enumerable, configurable: true });
    } catch (_) { return; }
    cleanups.push(() => { try { if (restored) Object.defineProperty(proto, "cookie", restored); } catch (_) {} });
    hooks.push("cookie-write");
  }

                                                                          
                                                                           
                                                                          
  let blindMapsTried = 0;

  function probeBlindSourceMap(href) {
    if (!CONFIG.probeBlindSourceMaps || !nativeFetch) return;
    if (blindMapsTried >= CONFIG.maxBlindMaps) return;
    const u = parseURL(href);
    if (!u || u.protocol !== "https:" && u.protocol !== "http:") return;
                                                                               
                                                                    
                                                                                
                                                                               
                                                                               
                                                  
    if (/\.map(?:$|[?&#])/i.test(u.href)) return;
                                                                                 
                              
    const candidate = u.origin + u.pathname + ".map";
    blindMapsTried++;
    stats.blindMapsTried = blindMapsTried;
    fetchSourceMap(candidate).catch(() => {});
  }

  async function fetchSourceMap(href) {
    if (sourceMapSeen.has(href) || sourceMapSeen.size >= CONFIG.maxSourceMaps) return;
    sourceMapSeen.add(href);
    const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctl ? setT(() => ctl.abort(), CONFIG.scriptTimeoutMs) : null;
    try {
      const res = await nativeFetch.call(window, href, {
        credentials: "same-origin", cache: "force-cache", signal: ctl ? ctl.signal : undefined
      });
      if (!res.ok) { safeCancel(res.body); return; }
      const txt = await res.text();
      safeCancel(res.body);
      if (txt.length > CONFIG.maxMapChars) return;
      const map = safeParse(txt);
      if (!map || !Array.isArray(map.sourcesContent)) return;
      stats.sourceMaps++;
      stats.blindMaps = (stats.blindMaps || 0) + 1;
      addNote("sourcemap:" + href, {
        kind: "sourcemap", url: href, blind: true, sources: map.sources ? map.sources.length : 0,
        note: "Source map recovered by blind <script>.map probe, with no sourceMappingURL comment. The original, unmangled source was scanned."
      });
      const sources = Array.isArray(map.sources) ? map.sources : [];
      for (let i = 0; i < map.sourcesContent.length; i++) {
        const c = map.sourcesContent[i];
        if (typeof c !== "string" || !c || c.length > CONFIG.maxScriptChars) continue;
        scanText(c, href + " > " + String(sources[i] || ("source-" + i)), true);
      }
    } catch (_) {
                                                        
    } finally {
      if (timer) clearT(timer);
    }
  }

                                                                          
                   
                                                                          
  function compareFindings(a, b) {
    return (CONF_RANK[b.confidence] - CONF_RANK[a.confidence])
      || ((b.observed ? 1 : 0) - (a.observed ? 1 : 0))
      || (b.score - a.score)
      || (b.count - a.count)
      || a.host.localeCompare(b.host)
      || a.normalizedPath.localeCompare(b.normalizedPath)
      || a.method.localeCompare(b.method);
  }

  function indexAdd(pathKey, key) {
    let set = pathIndex.get(pathKey);
    if (!set) { set = new Set(); pathIndex.set(pathKey, set); }
    set.add(key);
  }

  function removeFinding(key) {
    const f = store.get(key);
    if (!f) return;
    store.delete(key);
    pending.delete(f);
    const set = pathIndex.get(f.host + "|" + f.normalizedPath);
    if (set) { set.delete(key); if (!set.size) pathIndex.delete(f.host + "|" + f.normalizedPath); }
  }

  function specificSiblings(pathKey) {
    const keys = pathIndex.get(pathKey);
    const out = [];
    if (!keys) return out;
    for (const k of keys) {
      if (k.charAt(0) !== "?") { const f = store.get(k); if (f) out.push(f); }
    }
    return out;
  }

                                                                               
                                                  
  function enforceCap() {
    if (store.size <= CONFIG.maxFindings) return;
    const drop = Math.max(1, Math.ceil((store.size - CONFIG.maxFindings) * 0.25));
    for (let n = 0; n < drop; n++) {
      let worst = null;
      for (const f of store.values()) if (!worst || compareFindings(worst, f) < 0) worst = f;
      if (!worst) break;
      removeFinding(worst.key);
    }
  }

  function addCapped(arr, value, cap) {
    if (arr.length < cap && !arr.includes(value)) arr.push(value);
  }

  function effectiveMinConf() {
    const r = CONF_RANK[String(CONFIG.minConfidence).toUpperCase()];
    if (r === undefined) {
      warnOnce("minConfidence", "CONFIG.minConfidence '" + CONFIG.minConfidence + "' is not LOW, MEDIUM or HIGH. Falling back to LOW.");
      return CONF_RANK.LOW;
    }
    return r;
  }

                                                                                
  function collectIdorInput(raw, u) {
    const names = new Set();
    const pairs = [];
    for (const k of Object.keys(raw.queryParams || {})) names.add(k);
    try {
      for (const [k, v] of u.searchParams.entries()) {
        names.add(k);
        if (pairs.length < 80) pairs.push([k, v]);
      }
    } catch (_) {}
    for (const p of raw.params || []) {
      const nm = String(p).split("=")[0];
      if (nm) names.add(nm);
    }
    const j = raw.requestJson;
    if (j && typeof j === "object") {
      const stack = [j];
      let guard = 0;
      while (stack.length && guard++ < 400) {
        const cur = stack.pop();
        if (Array.isArray(cur)) { for (const x of cur.slice(0, 20)) if (x && typeof x === "object") stack.push(x); continue; }
        if (!cur || typeof cur !== "object") continue;
        for (const k of Object.keys(cur).slice(0, 40)) {
          names.add(k);
          const v = cur[k];
          if (typeof v === "string" || typeof v === "number") { if (pairs.length < 80) pairs.push([k, v]); }
          else if (v && typeof v === "object") stack.push(v);
        }
      }
    }
    return { names: [...names], pairs };
  }

  function record(raw) {
    try {
      return recordUnsafe(raw);
    } catch (e) {
      fail("record", e);
      return null;
    }
  }

  function recordUnsafe(raw) {
    if (!active || !raw || !raw.url) return null;
    const u = parseURL(raw.url);
    if (!u) { stats.skipped++; return null; }

    const method = raw.method ? String(raw.method).toUpperCase() : "?";
    const host = u.host.toLowerCase();
    const path = applyValuePatterns(decodeBraces(u.pathname));
    const normalizedPath = normalizePath(path);
    const thirdParty = siteOf(u.hostname) !== siteOf(location.hostname);
    if (thirdParty && CONFIG.thirdParty === "hide") { stats.hidden++; return null; }
    if (raw.source === "javascript" && NOISE_HOSTS.test(u.hostname)) { stats.skipped++; return null; }

    noteInterestingSurface(u, path);
                                                                              
                                                                               
    try {
      scanEndpointCredentials(raw.url, CH_NETWORK);
      noteSensitivePath(raw.url, CH_NETWORK);
      notePiiShapedRoute(host, path);
    } catch (e) { fail("record.exposed", e); }

                                                                            
    try { analyzeJWTsInURL(u, "url"); } catch (e) { fail("jwt.url", e); }
                                                             
    if (GQL_PATH_RE.test(path) || /graphql/i.test(String(raw.requestContentType || ""))) {
      try { noteGraphQLComplexity(raw.requestJson, raw.requestBody, u); } catch (e) { fail("gql.complexity", e); }
    }

    const rct = raw.responseContentType || "";
    const qct = raw.requestContentType || "";
    const respHeaders = raw.responseHeaders || null;
    const graphql = maybeGraphQL(u, raw.requestJson, path, qct, rct) && !raw.specDeclared
      ? detectGraphQL(u, raw.requestJson, path) : null;

    const status = typeof raw.status === "number" ? raw.status : undefined;
    const challenge = respHeaders ? authChallenge(respHeaders) : null;
    const cors = respHeaders ? corsPosture(respHeaders) : [];

                                                                              
                                                                               
                                                                     
    if (LOGOUT_PATH_RE.test(path)) {
      addNote("logout:" + method + "|" + host + "|" + normalizedPath, {
        kind: "logout-signal", label: "logout call",
        severity: "INFO", channel: CH_NETWORK,
        file: method + " " + host + normalizedPath,
        note: "Logout sent a " + method + " to " + normalizedPath +
          (status !== undefined ? " and got " + status : "") +
          ". Whether this revokes the session server-side is not visible from the page.",
        value: method + " " + host + normalizedPath
      });
    }

    const idorInput = collectIdorInput(raw, u);

    const scored = scoreFinding({
      path, hostname: u.hostname.toLowerCase(), method, source: raw.source, status,
      hasBody: !!raw.requestBody, requestContentType: qct, responseContentType: rct, graphql,
      specDeclared: !!raw.specDeclared, scoreBonus: raw.scoreBonus, isTemplate: !!raw.isTemplate,
      challenge, cors, noAuthDeclared: !!raw.noAuthDeclared, deprecated: !!raw.deprecated,
      hasResponseBody: !!raw.responseBody
    });

    const pathKey = host + "|" + normalizedPath;
    const key = method + "|" + pathKey;
    const ts = Date.now();
    const minConf = effectiveMinConf();

                                                                             
                                                                            
    if (method === "?" && !raw.specDeclared) {
      const siblings = specificSiblings(pathKey);
      if (siblings.length) {
        for (const f of siblings) {
          f.sources.add(raw.source);
          f.lastSeen = ts;
          if (raw.observed && !f.observed) {
            f.observed = true;
            f.confidence = confidenceFrom(f.score, true, f.specDeclared);
            queuePrint(f, "SEEN");
          }
        }
        return siblings[0];
      }
    }

    let f = store.get(key);
    let isNew = false;
    let absorbed = null;

    if (!f) {
      if (method !== "?") absorbed = store.get("?|" + pathKey) || null;
      const score = Math.max(scored.score, absorbed ? absorbed.score : 0);
      const observed = !!raw.observed || (absorbed ? absorbed.observed : false);
      const authoritative = !!raw.specDeclared || (absorbed ? !!absorbed.specDeclared : false);
      const conf = confidenceFrom(score, observed, authoritative);
      if (conf === "IGNORE" || CONF_RANK[conf] < minConf) {
        stats.ignored++;
        return null;
      }
      f = {
        id: ++seq, key, method, host, hostname: u.hostname.toLowerCase(), normalizedPath, thirdParty,
        score, confidence: conf, observed, printed: false,
        reasons: new Set(), sources: new Set(), examples: [], queryParams: new Set(), statuses: new Map(),
        requestContentType: "", responseContentType: "", requestHeaders: null, responseHeaders: null,
        requestBody: "", responseBody: "", graphql: null, wsSamples: [], lastStatus: undefined,
        count: 0, firstSeen: ts, lastSeen: ts,
        specDeclared: !!raw.specDeclared, specOrigin: raw.specOrigin || null, specKind: raw.specKind || null,
        declaredParams: null, requiredParams: null, tags: null, deprecated: !!raw.deprecated,
        noAuthDeclared: !!raw.noAuthDeclared, cors: null, challenge: null, authSeen: false,
        timings: null, piiHits: null, idorCandidates: null,
        bodyFields: null, massAssign: null, cacheRisk: null,
        failed: !!raw.failed
      };
      if (absorbed) {
        const perfOnly = absorbed.sources.size === 1 && absorbed.sources.has("performance");
        removeFinding(absorbed.key);
        for (const r of absorbed.reasons) f.reasons.add(r);
        for (const s of absorbed.sources) f.sources.add(s);
        for (const e of absorbed.examples) f.examples.push(e);
        for (const q of absorbed.queryParams) f.queryParams.add(q);
        for (const rp of raw.params || []) if (f.declaredParams === null) f.declaredParams = [];
        if (!perfOnly) {
          f.count = absorbed.count;
          for (const [s, n] of absorbed.statuses) f.statuses.set(s, n);
        }
        f.firstSeen = absorbed.firstSeen;
        f.printed = absorbed.printed;
        f.requestBody = absorbed.requestBody;
        f.responseBody = absorbed.responseBody;
        f.specDeclared = f.specDeclared || absorbed.specDeclared;
        f.specOrigin = f.specOrigin || absorbed.specOrigin;
        f.idorCandidates = absorbed.idorCandidates;
        f.timings = absorbed.timings;
        f.authSeen = absorbed.authSeen;
      }
      if (raw.params && raw.params.length) f.declaredParams = raw.params.slice(0, 40);
      if (raw.required && raw.required.length) f.requiredParams = raw.required.slice(0, 40);
      if (raw.tags && raw.tags.length) f.tags = raw.tags.slice(0, 6);
      store.set(key, f);
      indexAdd(pathKey, key);
      isNew = true;
    }

    const before = { conf: f.confidence, observed: f.observed, hadStatus: status !== undefined && f.statuses.has(status) };

    f.count += 1;
    f.lastSeen = ts;
    f.sources.add(raw.source);
    for (const r of raw.reasons || []) f.reasons.add(r);
    for (const r of scored.reasons) f.reasons.add(r);
    if (scored.score > f.score) f.score = scored.score;
    if (raw.observed) f.observed = true;
    if (raw.authSeen || hasAuthHeader(raw.requestHeaders)) f.authSeen = true;
    if (f.examples.length < CONFIG.maxExamples) addCapped(f.examples, redactURL(u), CONFIG.maxExamples);
    for (const k of u.searchParams.keys()) { if (f.queryParams.size < 30) f.queryParams.add(k); }
    for (const k of Object.keys(raw.queryParams || {})) { if (f.queryParams.size < 30) f.queryParams.add(String(k)); }
    if (status !== undefined) {
      f.statuses.set(status, (f.statuses.get(status) || 0) + 1);
      f.lastStatus = status;
    }
    if (qct && !f.requestContentType) f.requestContentType = qct;
    if (rct) f.responseContentType = rct;
    if (raw.requestHeaders && !f.requestHeaders) f.requestHeaders = raw.requestHeaders;
    if (respHeaders) {
      f.responseHeaders = f.responseHeaders || {};
      for (const k of Object.keys(respHeaders)) if (!(k in f.responseHeaders)) f.responseHeaders[k] = respHeaders[k];
      f.challenge = f.challenge || authChallenge(f.responseHeaders);
      const c = corsPosture(f.responseHeaders);
      if (c.length) f.cors = c;
    }
    if (raw.requestBody && !f.requestBody) f.requestBody = raw.requestBody;
    if (raw.responseBody && !f.responseBody) f.responseBody = raw.responseBody;
    if (graphql && !f.graphql) f.graphql = graphql;
if (raw.pii && raw.pii.length) {
        f.piiHits = f.piiHits || [];
        for (const p of raw.pii) {
          const cur = f.piiHits.find(x => x.kind === p.kind);
          if (cur) cur.count += p.count; else f.piiHits.push(Object.assign({}, p));
        }
                                                                                 
                                                                                 
                                                                                
                                                                          
        try { notePiiExposure(f, raw); } catch (e) { fail("pii.exposure", e); }
      }
    if (raw.bodyFields && raw.bodyFields.length && !f.bodyFields) {
      f.bodyFields = raw.bodyFields.slice(0, CONFIG.maxBodyFields);
      const mass = f.bodyFields.filter(b => b.massAssign).map(b => b.name);
      if (mass.length) f.massAssign = mass.slice(0, 20);
    }
    analyzeCachePosture(f);
    if (CONFIG.trackTiming && typeof raw.durationMs === "number") {
      f.timings = f.timings || { last: raw.durationMs, min: raw.durationMs, max: raw.durationMs, n: 1 };
      f.timings.last = raw.durationMs;
      f.timings.n++;
      if (raw.durationMs < f.timings.min) f.timings.min = raw.durationMs;
      if (raw.durationMs > f.timings.max) f.timings.max = raw.durationMs;
    }
    addIdorCandidates(f, idorInput.names, idorInput.pairs, raw.source);
    if (idorInput.names.some(n => IDOR_PARAM_RE.test(String(n)))) {
      if (scored.score + 12 > f.score) { f.score = scored.score + 12; f.reasons.add("IDOR candidate parameter"); }
    }
    f.confidence = confidenceFrom(f.score, f.observed, f.specDeclared);

    let ev = null;
    if (isNew) ev = absorbed && absorbed.printed ? "METHOD" : "NEW";
    else if (!before.observed && f.observed) ev = "SEEN";
    else if (CONF_RANK[f.confidence] > CONF_RANK[before.conf]) ev = "UPGRADED";
    else if (status !== undefined && !before.hadStatus && f.statuses.size > 1) ev = "STATUS";
    if (ev) queuePrint(f, ev);

    enforceCap();
    return f;
  }

                                                                          
                 
                                                                          
  function compareSecrets(a, b) {
    return (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)
      || ((a.exposure === "leak" ? 0 : 1) - (b.exposure === "leak" ? 0 : 1))
      || b.count - a.count
      || String(a.file).localeCompare(String(b.file));
  }

  function ingestSecrets(list, file, channel) {
    for (const s of list) {
      try {
        if (secretStore.size >= CONFIG.maxSecrets) { stats.secretsSuppressed++; continue; }
                                                                            
                                                                           
                                                                           
                                                                          
                                                                              
                                                                            
                                                                              
                                                              
        if (s.line != null) s.line = absLine(s.line);
        const lineExact = s.lineExact === undefined ? lineOffsetExact : !!s.lineExact;
        const isMaterial = !!s.masked;
        const cls = isMaterial ? { verdict: "real", reason: "the match is a key header, not a value" }
          : (s.verdict ? { verdict: s.verdict, reason: s.verdictReason || "" }
            : classifyValue(s.raw, s.name));
        const verdict = isMaterial ? "real" : cls.verdict;
                                                                         
                                                            
        s.verdict = verdict;
        s.verdictReason = cls.reason || null;
        s.fixture = verdict === "fixture";
        s.severity = severityForVerdict(verdict, s.severity);
        s.channel = s.channel || channel || CH_STATIC;
        const key = s.id + "|" + fnv1a(s.raw || s.name) + "|" + (s.file || file);
        let f = secretStore.get(key);
        if (!f) {
          f = {
            id: ++secretSeq, key,
            typeId: s.id, name: s.name, category: s.category || "generic",
            severity: s.severity, exposure: s.exposure,
            valueMasked: s.masked ? s.name : maskValue(s.raw),
            length: s.length, shape: s.shape,
            entropyBits: s.entropy ? Math.round(s.entropy.bits * 100) / 100 : null,
            charset: s.entropy ? s.entropy.charset : null,
            file: s.file || file, line: s.line, column: s.column, lineExact,
            context: s.context, verify: s.verify || null,
                                                                               
                                                                  
            channel: s.channel, verdict: s.verdict, fixture: !!s.fixture,
            verdictReason: s.verdictReason || null,
            reconstructedFrom: s.reconstructedFrom || null, container: s.container || null,
            containerField: s.containerField || null,
layer: s.layer, decodedFrom: s.decodedFrom || null,
                                                                            
                                                                            
                                       
                                                                               
                                                                           
      rawValue: CONFIG.revealSecrets && !s.masked && typeof s.raw === "string" ? s.raw : null,
      count: 1, printed: false
          };
          secretStore.set(key, f);
          stats.secrets++;
          indexValue(s.raw || s.name, s.channel, (s.file || file) + (s.line == null ? "" : ":" + s.line), s.verdict);
          queueSecretPrint(f);
        } else {
          f.count++;
                                                                      
                                                
          if (s.line != null && lineExact && f.lineExact === false) {
            f.line = s.line; f.column = s.column; f.lineExact = true;
          }
          indexValue(s.raw || s.name, s.channel, (s.file || file) + (s.line == null ? "" : ":" + s.line), s.verdict);
                                                                              
                                                                
          if (CONFIG.revealSecrets && !s.masked && !f.rawValue && typeof s.raw === "string") f.rawValue = s.raw;
        }
      } catch (e) {
        fail("ingestSecrets", e);
      }
    }
  }

                                                                          
           
                                                                          
  const STYLE = {
    HIGH: "color:#d6336c;font-weight:bold",
    MEDIUM: "color:#e8890c;font-weight:bold",
    LOW: "color:#868e96",
    dim: "color:#868e96",
    ok: "color:#2f9e44;font-weight:bold",
    warn: "color:#f08c00;font-weight:bold",
    crit: "color:#c92a2a;font-weight:bold;background:#fff5f5",
    secret: "color:#7048e8;font-weight:bold"
  };
  const EVENT_PRIORITY = { NEW: 5, METHOD: 4, SEEN: 3, UPGRADED: 2, STATUS: 1 };

                                                                          
                                                                
  function styled(text, css) {
    nativeConsole.log("%c%s", css || "", text);
  }

  const pad = (s, n) => (s.length >= n ? s : s + " ".repeat(n - s.length));
  const shortType = ct => String(ct || "").split(";")[0].trim().replace(/^application\//, "");
  const statusText = f => [...f.statuses.keys()].map(s => (s === 0 ? "ERR" : String(s))).join(",");

  function queuePrint(f, ev) {
    if (!CONFIG.live || !active) return;
    const prev = pending.get(f);
    if (!prev || EVENT_PRIORITY[ev] > EVENT_PRIORITY[prev]) pending.set(f, ev);
    if (!queuePrint.timer) queuePrint.timer = setT(flush, CONFIG.printDelayMs);
  }

  function queueSecretPrint(f) {
                                                                               
                                          
    if (!CONFIG.live || !active || !CONFIG.showSecrets) return;
    if (f.exposure === "by-design" || (SEV_RANK[f.severity] || 0) < SEV_RANK.LOW) return;
    pendingSecrets.set(f, true);
    if (!queuePrint.timer) queuePrint.timer = setT(flush, CONFIG.printDelayMs);
  }

  function flush() {
    queuePrint.timer = null;
    const items = [...pending.entries()];
    pending.clear();
    items.sort((a, b) => compareFindings(a[0], b[0]));
    for (const [f, ev] of items) {
      try { printFinding(f, ev); } catch (e) { fail("print", e); }
    }
    const sp = [...pendingSecrets.keys()];
    pendingSecrets.clear();
    sp.sort(compareSecrets);
    for (const f of sp) {
      try { printSecret(f); } catch (e) { fail("printSecret", e); }
    }
  }

  let rateWindowStart = 0;
  let rateCount = 0;
  let rateSuppressed = 0;
  let rateTimer = null;

  function allowPrint() {
    const t = Date.now();
    if (t - rateWindowStart >= CONFIG.livePrintWindowMs) { rateWindowStart = t; rateCount = 0; }
    if (rateCount >= CONFIG.livePrintBudget) {
      rateSuppressed++;
      stats.printSuppressed++;
      if (!rateTimer) {
        rateTimer = setT(() => {
          rateTimer = null;
          if (rateSuppressed > 0 && active) {
            styled("[x-ray-eye] " + rateSuppressed + " findings not printed (output rate limit). Run xrayeye.report() to see everything.", STYLE.dim);
          }
          rateSuppressed = 0;
        }, CONFIG.livePrintWindowMs);
      }
      return false;
    }
    rateCount++;
    return true;
  }

  function line(label, value) {
    nativeConsole.log("  " + label + ":", value);
  }

  function formatGraphQL(g) {
    return g.operations.map(o => o.type + (o.operation ? " " + o.operation : "")).join(", ") + (g.batched ? " (batched)" : "");
  }

  function authTag(f) {
    const bits = [];
    if (f.challenge) bits.push("challenge:" + f.challenge);
    if (f.authSeen) bits.push("sent-auth");
    if (f.noAuthDeclared) bits.push("spec:no-auth");
    return bits.join(" ");
  }

                                                                           
                                                                               
                                                                             
  function dataGlance(f) {
  const body = f.responseBody;
  if (!body) return null;
  let head;
  try { head = String(payloadPreview(body) || ""); } catch (_) { return null; }
  head = head.replace(/\s+/g, " ").trim();
  if (!head) return null;
  if (head.length > 130) head = head.slice(0, 130) + "…";
  const bytes = String(body).length;
  const size = bytes >= 1024 ? (bytes / 1024).toFixed(1) + " KB" : bytes + " B";
  return head + "   [" + (f.responseContentType ? shortType(f.responseContentType) : "text") + ", " + size + "]";
  }

                                                                                 
                                                                           
function showsRawValues(f) {
    return !!(f.piiHits && f.piiHits.length)
      || !!(f.responseBody && CONFIG.showResponseBody)
      || !!f.requestBody
      || (!!f.wsSamples && f.wsSamples.length)
      || (!!f.massAssign && f.massAssign.length);
  }

  function printFinding(f, ev) {
    if (!store.has(f.key)) return;
    if (!allowPrint()) return;
    f.printed = true;

    if (ev === "STATUS") {
      styled("  + new status " + (f.lastStatus === 0 ? "ERR" : f.lastStatus) + " on " + f.method + " " + f.host + f.normalizedPath, STYLE.dim);
      return;
    }

    const tag = "[" + (f.confidence === "MEDIUM" ? "MED" : f.confidence) + "]";
    const state = f.observed ? "SEEN" : (f.specDeclared ? "SPEC" : "REF ");
    const note = ev === "UPGRADED" ? " (upgraded)" : ev === "SEEN" ? " (now observed)" : ev === "METHOD" ? " (method resolved)" : "";
    const at = authTag(f);
    const st = f.statuses.size ? "  -> " + statusText(f) + (f.responseContentType ? " " + shortType(f.responseContentType) : "") : "";
    const header = tag + " " + state + " " + pad(f.method, 9) + clip(f.examples[0] || f.host + f.normalizedPath, 150)
      + st + (f.count > 1 ? "  x" + f.count : "") + (f.thirdParty ? "  [3P]" : "") + (at ? "  (" + at + ")" : "") + note
                                                                          
                                                    
      + (showsRawValues(f) && CONFIG.revealSecrets ? "  {cleartext}" : "");

    nativeConsole.groupCollapsed("%c%s", STYLE[f.confidence] || "", header);
    try {
                                                                                  
                                                                                
                                                                            
                                                                       
                                                                     
      line("Values", CONFIG.revealSecrets
        ? "CLEARTEXT. revealSecrets is on, so any addresses, tokens and personal data in this group are real. Do not share this console."
        : "MASKED. revealSecrets is off, so any values in this group are masked but field names are real.");
                                                                            
                                                                 
      const glance = dataGlance(f);
      if (glance) line("Data", glance);
                                                                              
                                                                             
                                                                   
      if (!f.observed && !f.responseBody && !f.requestBody) {
        const u = absoluteUrl(f) || f.examples[0] || f.host + f.normalizedPath;
        line("Contents", "NOT CAPTURED. The application never called this route while you were watching, so nothing is known about what it returns. That is different from an empty response.");
        line("Get the preview", "xrayeye.fetchEndpoint(" + JSON.stringify(u) + ", { confirm: 'AUTHORIZED' })   (or xrayeye.authorize() once)");
      }
      if (f.normalizedPath !== (parseURL(f.examples[0] || "") || {}).pathname) line("Endpoint", f.method + " " + f.host + f.normalizedPath);
      line("Seen via", [...f.sources].join(", "));
      line("Why", [...f.reasons].join(" | "));
      if (f.queryParams.size) line("Query params", [...f.queryParams].join(", "));
      if (f.declaredParams && f.declaredParams.length) {
        line("Declared params", (f.declaredParams || []).join(", "));
        if (f.requiredParams && f.requiredParams.length) line("Required params", f.requiredParams.join(", "));
      }
      if (f.tags && f.tags.length) line("Tags", f.tags.join(", "));
      if (f.idorCandidates && f.idorCandidates.length) {
        for (const c of f.idorCandidates) {
          line("IDOR candidate", c.name + (c.enumerable ? "  [enumerable id shape]" : "") +
            (c.shapes.length ? "  shapes: " + c.shapes.map(s => s.kind).join(", ") : ""));
        }
      }
      if (f.graphql) line("GraphQL", formatGraphQL(f.graphql));
      if (f.cacheRisk && f.cacheRisk.length) {
        for (const c of f.cacheRisk) line("Cache risk (" + c.severity + ")", c.label + " - " + clip(c.detail, 150));
      }
      if (f.massAssign && f.massAssign.length) line("Mass-assignment candidates", f.massAssign.join(", "));
      if (f.bodyFields && f.bodyFields.length) {
        const idorFields = f.bodyFields.filter(b => b.idor).map(b => b.name);
        if (idorFields.length) line("IDOR-relevant response fields", idorFields.slice(0, 15).join(", "));
      }
      if (f.requestContentType) line("Request type", f.requestContentType);
      if (f.requestBody) line("Request body", capPreviewLines(payloadPreview(f.requestBody, Infinity), CONFIG.maxPreviewLines));
      if (f.statuses.size > 1) line("Status codes", Object.fromEntries(f.statuses));
      if (f.responseHeaders && Object.keys(f.responseHeaders).length) line("Response headers", f.responseHeaders);
      if (f.cors && f.cors.length) line("CORS", f.cors.join(", "));
                                                                                
                                                                           
                                                                           
      if (CONFIG.showResponseBody && f.responseBody) line("Response preview", capPreviewLines(payloadPreview(f.responseBody, Infinity), CONFIG.maxPreviewLines));
      if (f.piiHits && f.piiHits.length) line("PII in response", f.piiHits.map(p => p.kind + " x" + p.count).join(", "));
      if (f.timings) line("Timing ms", "last " + Math.round(f.timings.last) + ", min " + Math.round(f.timings.min) + ", max " + Math.round(f.timings.max));
      if (CONFIG.showRequestHeaders && f.requestHeaders && Object.keys(f.requestHeaders).length) line("Request headers", f.requestHeaders);
      if (f.wsSamples.length) line("WebSocket samples", f.wsSamples);
      if (f.specOrigin) line("Declared in", f.specOrigin);
      if (f.examples.length > 1) line("Other URLs", f.examples.slice(1));
    } finally {
      nativeConsole.groupEnd();
    }
  }

  function printSecret(f) {
    if (!secretStore.has(f.key)) return;
    if (!allowPrint()) return;
    f.printed = true;
    const sev = f.severity;
    const css = sev === "CRITICAL" ? STYLE.crit : sev === "HIGH" ? STYLE.HIGH : STYLE.MEDIUM;
                                                                              
                                                                          
                                        
    const role = credentialRole(f, f.rawValue || f.valueMasked || "");
    const roleTag = role === "unknown" ? "" : "  <" + role + ">";
    const head = "[" + sev + "] SECRET  " + f.name + "  (" + f.exposure + ")" + roleTag +
      (f.decodedFrom ? "  [via " + f.decodedFrom + "]" : "");
    nativeConsole.groupCollapsed("%c%s", css, head);
    try {
      line("Type", f.typeId + "  (" + f.category + (f.layer ? ", detection layer " + f.layer : "") + ")");
      line("Value", shownValue(f.valueMasked, f.rawValue) +
        (CONFIG.revealSecrets
          ? (f.rawValue ? "   [cleartext]" : "   [not retained: it was read before the switch was on]")
          : ""));
      if (f.entropyBits !== null) line("Entropy", f.entropyBits + " bits/char (" + f.charset + ")" + (f.shape ? ", shape " + f.shape : ""));
      line("Location", f.file + (f.line == null ? "" : ":" + f.line + (f.column == null ? "" : ":" + f.column)));
      if (f.context) line("Context", f.context);
      if (f.count > 1) line("Occurrences", f.count);
      if (f.verify) line("Before reporting", f.verify);
    } finally {
      nativeConsole.groupEnd();
    }
  }

  function printNote(n) {
    if (n.kind === "graphql-field") {
      line(n.type + "." + n.field, "role=" + (n.role || "type") + (n.args && n.args.length ? " args=" + n.args.join(",") : "") + (n.via ? " via " + n.via : ""));
    } else if (n.kind === "graphql-suggestion") {
      line("leaked field", n.field + "  (from a 'Did you mean' error)");
    } else if (n.kind === "surface") {
      line(n.host + n.path, n.reasons.join(", "));
} else if (n.kind === "disclosed-credential") {
                                                                               
                       
  const role = credentialRole({ name: n.label, context: n.context, container: n.container }, (n.value != null ? n.value : n.valueMasked) || "");
  const tag = role === "unknown" || role === "identifier" ? "" : " <" + role + ">";
  line((n.label || "credential") + tag, disclosedValues(n).join(", ") + "   (" + (n.exposure || n.where || "") + (n.file ? "  " + n.file : "") + ")");
    } else {
      line(n.kind, JSON.stringify(n));
    }
  }

                                                                          
          
                                                                          
  function list(opts) {
    const o = opts || {};
    let arr = [...store.values()];
    if (o.min) { const r = CONF_RANK[String(o.min).toUpperCase()] || 0; arr = arr.filter(f => CONF_RANK[f.confidence] >= r); }
    if (o.observed !== undefined) arr = arr.filter(f => f.observed === !!o.observed);
    if (o.thirdParty !== undefined) arr = arr.filter(f => f.thirdParty === !!o.thirdParty);
    if (o.host) arr = arr.filter(f => f.host.includes(String(o.host).toLowerCase()));
    if (o.method) arr = arr.filter(f => f.method === String(o.method).toUpperCase());
    if (o.search) arr = arr.filter(f => (f.host + f.normalizedPath).toLowerCase().includes(String(o.search).toLowerCase()));
    if (o.idor) arr = arr.filter(f => f.idorCandidates && f.idorCandidates.length);
    if (o.spec) arr = arr.filter(f => f.specDeclared);
    if (o.unauth) arr = arr.filter(f => f.noAuthDeclared || f.cors && f.cors.indexOf("wildcard-origin") >= 0);
    if (o.challenge) arr = arr.filter(f => !!f.challenge);
    arr.sort(compareFindings);
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function listSecrets(opts) {
    const o = opts || {};
    let arr = [...secretStore.values()];
    if (o.severity) { const r = SEV_RANK[String(o.severity).toUpperCase()] || 0; arr = arr.filter(s => (SEV_RANK[s.severity] || 0) >= r); }
    if (o.exposure) arr = arr.filter(s => s.exposure === String(o.exposure).toLowerCase());
    if (o.category) arr = arr.filter(s => s.category === String(o.category).toLowerCase());
    if (o.search) arr = arr.filter(s => (s.name + " " + s.file + " " + s.typeId).toLowerCase().includes(String(o.search).toLowerCase()));
                                                                          
                                                                             
    if (o.verdict) arr = arr.filter(s => s.verdict === String(o.verdict).toLowerCase());
    if (o.channel) arr = arr.filter(s => s.channel === String(o.channel).toLowerCase());
    if (o.real) arr = arr.filter(s => s.verdict === "real");
    arr.sort(compareSecrets);
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function listNotes(opts) {
    const o = opts || {};
    let arr = [...notes.values()];
    if (o.kind) arr = arr.filter(n => n.kind === String(o.kind).toLowerCase());
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

                                                                             
                                                                             
                                                                           
                                                    
  function cspBlocksConnect() {
  try {
  const metas = document.querySelectorAll('meta[http-equiv="Content-Security-Policy" i]');
  for (const m of metas) {
  const c = String(m.getAttribute("content") || "");
  const cm = /(^|;)\s*connect-src\s+([^;]*)/i.exec(c);
  const src = cm ? cm[2].trim() : (/(^|;)\s*default-src\s+([^;]*)/i.exec(c) || [])[2];
  if (src === undefined) continue;
  if (/^'none'$/i.test(src.trim())) return "connect-src 'none'";
  }
  } catch (_) {                                         }
  return null;
  }

                                                                           
                                                                          
                                                                           
                                                                        
  function authorize() {
  CONFIG.activeRead = true;
  styled("[x-ray-eye] Active reads ENABLED for this session.", STYLE.warn);
  styled("[x-ray-eye] fetchEndpoint() now sends real requests without the per-call { confirm } flag.", STYLE.warn);
  styled("[x-ray-eye] Those requests appear in the target's logs. Keep them on scope.", STYLE.warn);
  styled("[x-ray-eye] Turn it back off with xrayeye.config.activeRead = false", STYLE.dim);
  return true;
  }

                                                                             
                                                                           
                                                                           
  function capColumns(rows, maxCols) {
  const limit = maxCols || CONFIG.maxTableColumns || 5;
  const list = Array.isArray(rows) ? rows : [rows];
  const first = list.find(r => r && typeof r === "object" && !Array.isArray(r));
  if (!first) return { rows, columns: [], dropped: 0 };
  const all = Object.keys(first);
  const kept = all.slice(0, limit);
  const dropped = all.length - kept.length;
  if (!dropped) return { rows: list, columns: all, dropped: 0 };
  const narrowed = list.map(r => {
  if (!r || typeof r !== "object" || Array.isArray(r)) return r;
  const o = {};
  for (const k of kept) o[k] = r[k];
  return o;
  });
  return { rows: narrowed, columns: kept, dropped };
  }

                                                                             
                                                                           
                                                                              
  function capPreviewLines(text, maxLines) {
  const s = String(text == null ? "" : text);
  if (!s) return "";
  const limit = maxLines || CONFIG.maxPreviewLines || 25;
  const lines = s.split("\n");
  if (lines.length <= limit) return s;
  const kept = lines.slice(0, limit).join("\n");
  return kept + "\n      ... (" + (lines.length - limit) + " more line(s); full body in endpoint().responsePreview)";
  }

                                                                          
                                        
                                                                          
                                                                            
                                                                              
                                                                           
                                                                               
  function unreadTargets() {
  const out = [];
  const seen = new Set();
  for (const f of store.values()) {
                                                                              
                                                                              
                                                                           
                                                       
  if (f.observed) continue;
  if (f.responseBody) continue;
  let u = null;
  try { u = absoluteUrl(f); } catch (_) {}
  if (!u || seen.has(u)) continue;
  seen.add(u);
  out.push(u);
  }
  return out;
  }

  async function readAll(opts) {
  const o = opts || {};
  const targets = unreadTargets();
  const limit = o.limit || 25;
  const queue = targets.slice(0, limit);
  if (!queue.length) {
  styled("[x-ray-eye] Nothing left to read: every endpoint already has a body, or there are none.", STYLE.dim);
  return [];
  }
  styled("[x-ray-eye] Reading " + queue.length + " of " + targets.length + " referenced route(s) with GET. These hit the target's logs.", STYLE.warn);
  const wasActive = CONFIG.activeRead;
  CONFIG.activeRead = true;
  const out = [];
  let ok = 0, failed = 0;
  for (let i = 0; i < queue.length; i++) {
  const r = await fetchEndpoint(queue[i], { confirm: "AUTHORIZED" });
  if (r && !r.error) ok++; else failed++;
  if (o.delay) await new Promise(res => setT(res, o.delay));
  }
  if (!wasActive) CONFIG.activeRead = false;
  styled("[x-ray-eye] Done. " + ok + " read, " + failed + " failed or blocked. Records are in the log above.", failed ? STYLE.warn : STYLE.head);
  return out;
  }

                                                                             
                                                                  
  function buildPanel() { return null; }

                                                                          
                                                                   
                                                                          
                                                                      
    
                                                                               
                                                                             
    
                                                                     
                                                                             
                                                                     
    
                                                                              
                                                                              
                                                                             
                                                                            
                                                          
  try {
  if (typeof window !== "undefined" && typeof window.addEventListener === "function" && !window.__xrayeyeBridge) {
  window.__xrayeyeBridge = true;
  const XRE_OUT = "__xray_out__";
  const XRE_IN = "__xray_in__";
                                                                             
                                                                             
                                                                            
                                                              
  const XreCE = (typeof window !== "undefined" && window.CustomEvent) || (typeof CustomEvent !== "undefined" ? CustomEvent : null);

  const xreStatus = () => {
                                                                            
                                                                               
                                                                       
                                                                    
    let requests = 0;
    let seenCount = 0;
    try {
      for (const f of store.values()) {
        requests += (f.count || 0);
        if (f.observed) seenCount++;
      }
    } catch (_) {}
    return {
      endpoints: list({}).length,
      unread: unreadTargets().length,
      secrets: secretStore.size,
      requests,
      seen: seenCount,
      active: active
    };
  };

                                                                              
                                                                     
                                  
  function xreConf(f) {
    const s = Number(f.score || 0);
    const c = s >= 70 ? "HIGH" : s >= 40 ? "MEDIUM" : "LOW";
    if (!f.observed && c === "HIGH") return "MEDIUM";
    return c;
  }

                                                                           
                                                                           
  function xreRows(limit) {
    const out = [];
    try {
      for (const [key, f] of store.entries()) {
        let path = f.normalizedPath || f.path || "";
        if (!path) {
          try { path = new URL(absoluteUrl(f) || f.url, baseURI()).pathname; } catch (_) { path = f.path || ""; }
        }
        let host = f.host || "";
        if (!host) { try { host = new URL(absoluteUrl(f) || f.url, baseURI()).host; } catch (_) {} }
        out.push({
          id: String(key),
          url: (() => { try { return absoluteUrl(f); } catch (_) { return f.url; } })(),
          method: f.method || "ANY",
          host: host,
          path: path,
          score: f.score || 0,
          conf: xreConf(f),
          hits: f.count || 0,
          count: f.count || 0,
          state: f.observed ? "seen" : "referenced",
          observed: !!f.observed,
          failed: !!f.failed,
          thirdParty: !!f.thirdParty,
          graphql: !!f.graphql,
          statuses: f.statuses ? Object.fromEntries(f.statuses) : {},
          hasBody: !!(f.responseBody || f.requestBody),
          firstSeen: f.firstSeen || null,
          lastSeen: f.lastSeen || null,
          sources: f.sources ? [...f.sources] : [],
          reasons: f.reasons ? [...f.reasons] : [],
          queryParams: f.queryParams ? [...f.queryParams] : []
        });
      }
    } catch (e) { fail("bridge.rows", e); }
    out.sort((a, b) => b.score - a.score || b.hits - a.hits);
    return out.slice(0, limit || 300);
  }

  function xreCounts() {
    let high = 0, medium = 0, low = 0, seen = 0, ref = 0;
    for (const f of store.values()) {
      if (f.observed) seen++; else ref++;
      const c = xreConf(f);
      if (c === "HIGH") high++; else if (c === "MEDIUM") medium++; else low++;
    }
    return { total: store.size, high, medium, low, seen, ref };
  }

                                                          
  function xreDetail(id) {
    try {
      const f = store.get(id) || store.get(String(id));
      if (!f) return null;
      const row = xreRows(0).find(r => r.id === String(id)) || {};
      return Object.assign(row, {
        examples: f.examples && f.examples.length ? [...f.examples] : [absoluteUrl(f)],
        normalizedPath: f.normalizedPath || f.path || row.path,
        requestContentType: f.requestContentType || "",
        responseContentType: f.responseContentType || "",
        requestHeaders: f.requestHeaders || null,
        responseHeaders: f.responseHeaders || null,
        requestBody: f.requestBody ? String(f.requestBody) : null,
        responseBody: f.responseBody ? String(f.responseBody) : null,
        wsSamples: f.wsSamples || [],
        piiHits: f.piiHits || []
      });
    } catch (e) { fail("bridge.detail", e); return null; }
  }

  function xreDiag() {
    return {
      version: VERSION,
      hooks: hooks.slice(),
      errors: errors.slice(0, 10),
      coverage: (() => { try { return channelCoverage(); } catch (_) { return null; } })(),
      stats: Object.assign({}, stats),
      topFrame: window === window.top,
      url: String(location.href)
    };
  }

                                                                         
  async function xreRun(cmd) {
    const c = cmd || {};
                                                                          
                                                           
    if (c.cmd === "hello" || c.cmd === "status" || c.cmd === "ping") return { cmd: "status", ok: true, ...xreStatus() };
    if (c.cmd === "authorize") { authorize(); return { cmd: "status", ok: true, ...xreStatus() }; }
    if (c.cmd === "config") {
    try { Object.assign(CONFIG, c.config || {}); } catch (e) { fail("bridge.config", e); }
                                                                        
    return { cmd: "status", ok: true, config: JSON.parse(JSON.stringify(CONFIG)), ...xreStatus(), counts: xreCounts() };
    }
                                                                              
                                                                              
                                                                             
                                               
    if (c.cmd === "list") return { cmd: "list", ok: true, ...xreStatus(), counts: xreCounts(), rows: xreRows(c.limit) };
    if (c.cmd === "detail") return { cmd: "detail", ok: true, ...xreStatus(), finding: xreDetail(c.id) };
    if (c.cmd === "diag") return { cmd: "diag", ok: true, ...xreStatus(), diag: xreDiag() };
    if (c.cmd === "export") return { cmd: "export", ok: true, findings: list({ includeDetails: true }), secrets: listSecrets({}).map(serializeSecret) };
    if (c.cmd === "clear") { try { clear(); } catch (e) { fail("bridge.clear", e); } return { cmd: "status", ok: true, ...xreStatus(), counts: xreCounts() }; }
    if (c.cmd === "stop") { stop({ silent: true }); return { cmd: "status", ok: true, ...xreStatus() }; }
    if (c.cmd === "readAll") {
    await readAll({ limit: c.limit || 25, delay: c.delay || 120 });
    return { cmd: "readAllDone", ok: true, ...xreStatus() };
    }
    return { cmd: "error", ok: false, error: "unknown command " + String(c.cmd) };
  }

                                                   
  const xreDispatch = m => {
    if (!XreCE) return;
    try {
      window.dispatchEvent(new XreCE(XRE_OUT, { detail: JSON.stringify(Object.assign({ xre: 1 }, m)) }));
    } catch (e) {                                                                 }
  };
  let xreHandshaken = false;
  let xreTries = 0;
  if (XreCE) {
  window.addEventListener(XRE_IN, function (ev) {
    let d = null;
    try { d = JSON.parse(ev && ev.detail); } catch (_) { return; }
    if (!d || !d.cmd) return;
    xreHandshaken = true;
    Promise.resolve(xreRun(d)).then(xreDispatch, e => xreDispatch({ cmd: "error", ok: false, error: String(e && e.message) }));
  });
                                                                            
  (function xreHello() {
    if (xreHandshaken || xreTries >= 40) return;
    xreTries++;
    xreDispatch({ cmd: "hello", ...xreStatus() });
    setT(xreHello, 250);
  })();

                                                                             
                                                                             
                                                                             
                                              
  let xreBeat = 0;
  (function xreHeartbeat() {
    xreBeat = setT(() => {
    if (active && !window.__xrayeyeBridgeDead) xreDispatch({ cmd: "status", ...xreStatus() });
    xreHeartbeat();
    }, 2000);
  })();
  cleanups.push(() => { try { clearT(xreBeat); } catch (_) {} });
  }

                                                             
  const xrePost = m => { try { window.postMessage(Object.assign({ source: "x-ray-eye" }, m), "*"); } catch (_) {} };
  window.addEventListener("message", async function (ev) {
    const d = ev && ev.data;
    if (!d || d.source !== "xre" || !d.cmd) return;
    xrePost(await xreRun(d));
  });
  }
  } catch (e) { fail("bridge.install", e); }

                                                                           
                                                                           
                                                                             
                                                                             
  function maskPIIInText(text) {
    if (!text) return text;
    let out = String(text);
    for (const [kind, re] of PII_PATTERNS) {
      const flags = re.flags.indexOf("g") >= 0 ? re.flags : re.flags + "g";
      const rx = new RegExp(re.source, flags);
      out = out.replace(rx, function (match, offset, whole) {
        const at = typeof offset === "number" ? offset : 0;
        const src = typeof whole === "string" ? whole : String(text);
        if (kind === "email" && /\.(js|map|css|png|svg|woff2?)$/i.test(match)) return match;
        if (kind === "ipv4" && NON_PII_IPV4.test(match)) return match;
        if (kind === "credit-card" && !luhn(match)) return match;
        if (kind === "phone") {
          const d = match.replace(/\D/g, "");
          if (d.length < 10 || /^(?:1\.0\.0|127\.)/.test(d)) return match;
                                                                            
                                                                             
                                                                         
          if (typeof piiStandsAlone === "function" && !piiStandsAlone([match], at, src)) return match;
        }
        if (kind === "ssn") return "[SSN]";
        if (kind === "jwt") return "[REDACTED_JWT]";
        return maskValue(match);
      });
    }
    return out;
  }

                                                                             
                                                                      
  function payloadPreview(body, limit) {
    let text = String(body == null ? "" : body);
    if (!text) return null;
    try {
                                                                                 
      const j = safeParse(text);
      if (j !== null && j !== undefined && typeof j === "object") text = JSON.stringify(j, null, 1);
    } catch (_) {                                       }
if (CONFIG.redactSensitive && !CONFIG.revealSecrets) {
                                                                           
                                                                            
                                                                 
      try { text = maskPIIInText(text); } catch (_) {}
      try { text = maskDisclosedPhrases(hardRedact(redactString(text))); } catch (_) {}
    }
                                                                            
                                                                              
                            
    const n = limit === Infinity ? Infinity : (limit || CONFIG.maxPayloadPreviewChars || 1200);
    return text.length > n ? text.slice(0, n) + "\n... (" + (text.length - n) + " more characters)" : text;
  }

                                                                               
  const INTERESTING_HEADERS = /^(?:content-type|content-length|cache-control|pragma|expires|etag|vary|age|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-request-id|x-amzn-trace-id|set-cookie|access-control-allow-origin|access-control-allow-credentials|access-control-allow-headers|access-control-expose-headers|strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-powered-by|server|location|retry-after|www-authenticate)$/i;
  function headerSubset(headers) {
    const out = {};
    let n = 0;
    for (const k of Object.keys(headers || {})) {
      if (!INTERESTING_HEADERS.test(k)) continue;
      if (n++ >= 20) break;
      let v = String(headers[k]);
      if (v.length > 300) v = v.slice(0, 300) + "...";
      out[k] = CONFIG.redactSensitive && !CONFIG.revealSecrets ? redactString(v) : v;
    }
    return out;
  }

                                                                                
                                                                             
                                                                    
function absoluteUrl(f) {
    const raw = String((f && (f.url || (f.host || "") + (f.normalizedPath || f.path || ""))) || "");
    if (!raw) return "";
    if (/^https?:\/\//i.test(raw)) return raw;
    const scheme = String(location.protocol || "https:").replace(/:?$/, ":");
    if (raw.charAt(0) === "/") return String(location.origin || "").replace(/\/$/, "") + raw;
                                                     
    return scheme + "//" + raw.replace(/^\/+/, "");
  }

  function serialize(f, includeDetails) {
      const o = {
        confidence: f.confidence,
        state: f.observed ? "seen" : (f.specDeclared ? "declared" : "referenced"),
                                                                           
                                                                               
                                                                           
                                
                url: absoluteUrl(f),
        observed: !!f.observed,
        failed: !!f.failed,
        method: f.method,
        host: f.host,
        path: f.normalizedPath,
        score: f.score,
        thirdParty: f.thirdParty,
        count: f.count,
        statuses: Object.fromEntries(f.statuses),
        sources: [...f.sources],
        reasons: [...f.reasons],
        queryParams: [...f.queryParams],
        query: f.url && f.url.indexOf("?") >= 0 ? f.url.slice(f.url.indexOf("?")) : null,
        requestPreview: f.requestBody ? payloadPreview(f.requestBody) : null,
        responsePreview: f.responseBody ? payloadPreview(f.responseBody) : null,
        responseHeaders: f.responseHeaders ? headerSubset(f.responseHeaders) : null,
                                                                              
        bodyCaptured: !!(f.requestBody || f.responseBody),
        graphql: f.graphql,
        examples: f.examples.slice(),
        requestContentType: f.requestContentType,
        responseContentType: f.responseContentType,
        auth: {
          sentCredentials: f.authSeen,
          challenge: f.challenge,
          specDeclaresNoAuth: !!f.noAuthDeclared,
          cors: f.cors || []
        },
        idorCandidates: f.idorCandidates || [],
        declaredParams: f.declaredParams || [],
        requiredParams: f.requiredParams || [],
        bodyFields: f.bodyFields || [],
        massAssignCandidates: f.massAssign || [],
        cacheRisk: f.cacheRisk || [],
        tags: f.tags || [],
        deprecated: !!f.deprecated,
        specOrigin: f.specOrigin,
        specKind: f.specKind,
        piiHits: f.piiHits || [],
        timings: f.timings,
      firstSeen: new Date(f.firstSeen).toISOString(),
      lastSeen: new Date(f.lastSeen).toISOString()
    };
if (includeDetails) {
                                                                             
                                                                              
                                                       
          o.requestHeaders = (CONFIG.redactSensitive && !CONFIG.revealSecrets) ? headerSubset(f.requestHeaders) : f.requestHeaders;
          o.responseHeaders = (CONFIG.redactSensitive && !CONFIG.revealSecrets) ? headerSubset(f.responseHeaders) : f.responseHeaders;
          o.requestBody = payloadPreview(f.requestBody);
          o.responseBody = payloadPreview(f.responseBody);
          o.wsSamples = (f.wsSamples || []).slice(0, CONFIG.maxWsSamples).map(s => {
            const copy = Object.assign({}, s);
            if (copy.payload != null) copy.payload = payloadPreview(copy.payload);
            return copy;
          });
        }
    return o;
  }

  function serializeSecret(s) {
return {
  type: s.typeId, name: s.name, category: s.category,
                                                                            
                                                                               
                                            
  role: credentialRole(s, s.rawValue || s.valueMasked || ""),
  severity: s.severity, exposure: s.exposure,
      verdict: s.verdict || null, verdictReason: s.verdictReason || null,
      fixture: !!s.fixture, channel: s.channel || null,
      reconstructedFrom: s.reconstructedFrom || null, container: s.container || null,
                                                                       
                                                                     
      valueMasked: s.rawValue ? null : s.valueMasked, length: s.length, shape: s.shape,
      value: s.rawValue || null,
      entropyBits: s.entropyBits, charset: s.charset,
      file: s.file, line: s.line, column: s.column, lineExact: s.lineExact !== false,
      context: s.context, verify: s.verify,
      detectionLayer: s.layer, decodedFrom: s.decodedFrom,
      occurrences: s.count
    };
  }

                                                                               
                                                                                
                                                                  
  function uniqueSummary() {
    const rows = [];
    let detections = 0;
    for (const rec of valueIndex.values()) {
      detections += rec.count;
      rows.push({
        value: CONFIG.revealSecrets ? rec.raw : null,
        valueMasked: CONFIG.revealSecrets ? null : rec.masked,
        verdict: rec.verdict, fixture: rec.verdict === "fixture",
        detections: rec.count, channels: [...rec.channels], places: rec.places.slice(0, 4)
      });
    }
    rows.sort((a, b) => b.detections - a.detections ||
      String(a.valueMasked || a.value || "").localeCompare(String(b.valueMasked || b.value || "")));
    return { unique: rows.length, detections, rows };
  }

                                                                             
                                                                  
                                                                              
                                                                              
                                                                             
         
  function whereOf(s) {
    const f = String(s.file || "?");
    const short = f.split(/[\\/]/).pop();
    const line = s.line == null ? "" : (s.lineExact === false ? ":~" : ":") + s.line;
    return short + line + (s.column == null ? "" : ":" + s.column);
  }

                                                                             
  function shown(raw, masked) {
    return raw != null ? raw : (masked != null ? masked : "(not retained)");
  }

  function channelCoverage() {
    const cov = {};
    for (const c of CHANNELS) cov[c] = { inspected: channelSeen[c] || 0, findings: 0, unique: 0, fixtures: 0 };
    for (const f of secretStore.values()) {
      const c = f.channel;
      if (!c || !cov[c]) continue;
      cov[c].findings++;
      if (f.fixture) cov[c].fixtures++;
    }
    for (const rec of valueIndex.values()) for (const c of rec.channels) if (cov[c]) cov[c].unique++;
    return cov;
  }

                                                                        
                                                                            
                                                                               
  function triageSummary() {
    const by = { real: [], fixture: [], arbitrary: [] };
    for (const s of secretStore.values()) (by[s.verdict] || by.arbitrary).push(s);
    const pairs = [...notes.values()].filter(n => n.kind === "auth-pair");
    const all = [...secretStore.values()];
    return {
      counts: { real: by.real.length, fixture: by.fixture.length, arbitrary: by.arbitrary.length, total: secretStore.size },
      real: by.real, fixture: by.fixture, arbitrary: by.arbitrary,
      pairs,
                                                                                
                                                                       
      decoded: all.filter(s => s.decodedFrom),
      reconstructed: all.filter(s => s.reconstructedFrom)
    };
  }

  function reportTriage() {
    const t = triageSummary();
    nativeConsole.groupCollapsed("%c%s", STYLE.warn, "[x-ray-eye] credential triage");
    try {
      line("Real credentials", t.counts.real + " of " + t.counts.total);
      for (const s of t.real.slice(0, 40)) {
        line("  " + s.severity, s.name + "  " + whereOf(s) + "  [" + s.channel + "]");
      }
      line("Test fixtures / decoys", t.counts.fixture);
      for (const s of t.fixture.slice(0, 40)) {
        line("  " + s.severity, s.name + "  " + whereOf(s) + "  (" + (s.verdictReason || "fixture marker") + ")");
      }
      line("Credential-shaped but arbitrary", t.counts.arbitrary);
      for (const s of t.arbitrary.slice(0, 20)) {
        line("  " + s.severity, s.name + "  " + whereOf(s) + "  (" + (s.verdictReason || "not a value") + ")");
      }
      line("Hardcoded login pairs", t.pairs.length);
      for (const p of t.pairs.slice(0, 20)) {
        line("  " + p.severity, "" + shown(p.valuesRaw, p.values) + "  at " + p.file + ":" + p.line);
        if (p.compare) line("      check", p.compare.replace(/\s+/g, " ") + (p.compareAt ? "   (" + p.compareAt.file.split("/").pop() + ":" + p.compareAt.line + ")" : ""));
      }
      line("Decoded values", t.decoded.length);
      for (const s of t.decoded.slice(0, 20)) {
        line("  " + s.decodedFrom, s.name + "  " + whereOf(s) + "  shape=" + s.shape);
      }
      line("Reconstructed values", t.reconstructed.length);
      for (const s of t.reconstructed.slice(0, 20)) {
        line("  " + s.name, "built from " + s.reconstructedFrom + "  " + whereOf(s));
      }
      const uniq = uniqueSummary();
      line("Unique values vs detections", uniq.unique + " unique / " + uniq.detections + " detections");
      for (const r of uniq.rows.slice(0, 25)) {
        if (r.detections < 2) continue;
        line("  x" + r.detections, "" + shown(r.value, r.valueMasked) + "  " + r.channels.join(","));
      }
      const cov = channelCoverage();
      line("Coverage by channel", CHANNELS.map(c => c + "=" + cov[c].findings).join("  "));
      for (const c of CHANNELS) line("  " + c, cov[c].inspected + " inspected, " + cov[c].findings + " findings (" + cov[c].unique + " unique, " + cov[c].fixtures + " fixtures)");
    } finally { nativeConsole.groupEnd(); }
  }

  function statsSnapshot() {
    const uniq = uniqueSummary();
    return Object.assign({}, stats, {
      findings: store.size,
      secrets: secretStore.size,
      uniqueValues: uniq.unique,
      detections: uniq.detections,
      channels: channelCoverage(),
      specs: specStore.size,
      notes: notes.size,
      marks: snapshots.size,
      jwt: jwtStore.size,
      storage: storageStore.size,
      authFlows: oauthStore.size,
      frameworks: fwStore.size,
      serviceWorkers: swStore.size
    });
  }

                                                                          
            
                                                                          
  function report(opts) {
    const arr = list(opts);
    if (!arr.length) { styled("[x-ray-eye] No endpoints match.", STYLE.dim); return; }
    const rows = arr.map(f => ({
      conf: f.confidence,
      state: f.observed ? "SEEN" : (f.specDeclared ? "SPEC" : "REF"),
      method: f.method,
      host: f.host,
      path: f.normalizedPath,
      status: statusText(f),
      count: f.count,
      score: f.score,
      "3P": f.thirdParty ? "yes" : "",
      auth: authTag(f),
      idor: f.idorCandidates ? f.idorCandidates.map(c => c.name).join(" ") : "",
      via: [...f.sources].join(",")
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    else nativeConsole.log(JSON.stringify(rows, null, 2));
    styled("[x-ray-eye] " + arr.length + " of " + store.size + " endpoints shown. Sorted by confidence, observed first, then score.", STYLE.dim);
  }

                                                                               
                                                                             
                                                                       
  function credentialKey(s) {
  const ctx = String((s && s.context) || "");
                                                              
  const m = /([A-Za-z_][A-Za-z0-9_.-]{1,40})\s*[:=]\s*["'`]/.exec(ctx);
  if (m) return m[1];
                                         
  const c = String((s && s.container) || "");
  const a = /([A-Za-z][A-Za-z0-9_-]{1,40})\s*$/.exec(c);
  if (a) return a[1];
                                                                               
                                                                                
                       
  return String((s && (s.label || s.name)) || "").replace(/\s*\([^)]*\)\s*$/, "").trim();
  }

                                                                               
                                                                               
                                                                             
                                                                            
                        
  function credentialRole(s, value) {
  const key = String(credentialKey(s)).toLowerCase().replace(/^data-/, "").replace(/^x-/, "");
  if (/(?:^|[_.-])(?:pass|passwd|pwd|pw|secret|passphrase)(?:$|[_.-])/.test(key) || /^(?:pass|password|pwd|secret|passphrase)$/.test(key)) return "password";
  if (/(?:^|[_.-])(?:token|jwt|bearer|apikey)(?:$|[_.-])/.test(key) || /^(?:token|jwt|bearer|auth)$/.test(key)) return "token";
  if (/(?:^|[_.-])(?:id|uid|user|username|userid|operator|admin|account|login|email)(?:$|[_.-])/.test(key) || /^(?:id|uid|user|username|operator|admin|login)$/.test(key)) return "identifier";
                                                                               
                                                        
  const v = String(value == null ? "" : value);
  if (v && !/@/.test(v) && /^[a-z][a-z0-9_]{2,31}$/.test(v) && !/\d/.test(v)) return "identifier";
  return "unknown";
  }

                                                                            
                                                                               
                                                                               
                                                          
  function credentialPairs(arr) {
  const byFile = new Map();
  for (const s of arr) {
  const key = String(s.file || "unknown");
  if (!byFile.has(key)) byFile.set(key, []);
  byFile.get(key).push(s);
  }
  const pairs = [];
  for (const [file, group] of byFile) {
  const withPos = group.map(s => ({ s, pos: (s.line == null ? 1e9 : Number(s.line)) * 1000 + (s.column == null ? 0 : Number(s.column)) }));
  withPos.sort((a, b) => a.pos - b.pos);
  const used = new Set();
  for (const item of withPos) {
  const role = credentialRole(item.s, item.s.rawValue || item.s.valueMasked || "");
  if (role !== "password") continue;
                                                            
  let best = null;
  for (const cand of withPos) {
  if (used.has(cand.s) || cand === item) continue;
  if (cand.pos > item.pos) continue;
  if (credentialRole(cand.s, cand.s.rawValue || cand.s.valueMasked || "") !== "identifier") continue;
  if (!best || cand.pos > best.pos) best = cand;
  }
  if (!best) continue;
  used.add(best.s); used.add(item.s);
  pairs.push({
  file,
  idName: best.s.name.replace(/\s*\(.*\)\s*$/, ""),
  idValue: best.s.rawValue != null ? best.s.rawValue : best.s.valueMasked,
  passName: item.s.name.replace(/\s*\(.*\)\s*$/, ""),
  passValue: item.s.rawValue != null ? item.s.rawValue : item.s.valueMasked,
  severity: item.s.severity,
  line: item.s.line
  });
  }
  }
  return pairs;
  }

  function reportSecrets(opts) {
const arr = listSecrets(opts);
  if (!arr.length) { styled("[x-ray-eye] No credential findings. (Scanned " + stats.scripts + " scripts, " + stats.sourceMaps + " source maps.)", STYLE.dim); return; }
                                                                         
  const pairs = credentialPairs(arr);
  if (pairs.length) {
  nativeConsole.group("%c%s", STYLE.crit, "[x-ray-eye] " + pairs.length + " credential PAIR(S): identifier and secret together, so they form a working login");
  try {
  for (const p of pairs) {
  const show = x => x == null ? "(not held)" : '"' + x + '"';
  styled("  " + p.idName + " = " + show(p.idValue), STYLE.crit);
  styled("  " + p.passName + " = " + show(p.passValue), STYLE.crit);
  styled("  in " + p.file + (p.line ? ":" + p.line : "") + "  - rotate the secret; the identifier alone is far less serious.", STYLE.dim);
  }
  } finally { nativeConsole.groupEnd(); }
  }
  const rows = arr.map(s => ({
  severity: s.severity,
  role: credentialRole(s, s.rawValue || s.valueMasked || ""),
      exposure: s.exposure,
      type: s.typeId,
      category: s.category,
      value: shownValue(s.valueMasked, s.rawValue),
      entropy: s.entropyBits === null ? "" : s.entropyBits,
      charset: s.charset || "",
      where: s.file.split("/").pop() + ":" + s.line,
      n: s.count
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    else nativeConsole.log(JSON.stringify(rows, null, 2));
    const leaks = arr.filter(s => s.exposure === "leak").length;
    const byDesign = arr.filter(s => s.exposure === "by-design").length;
    styled("[x-ray-eye] " + arr.length + " findings: " + leaks + " leak, " + (arr.length - leaks - byDesign) + " needs context, " + byDesign + " shipped by design.", STYLE.dim);
    styled(CONFIG.revealSecrets
      ? "Cleartext values are shown because revealSecrets is on. Do not share this console output or a screenshot of it."
      : "Values are masked. Confirm liveness out of band before reporting anything.", STYLE.dim);
  }

  function reportNotes(opts) {
    const arr = listNotes(opts);
    if (!arr.length) { styled("[x-ray-eye] No notes.", STYLE.dim); return; }
    nativeConsole.groupCollapsed("%c%s", STYLE.dim, "[x-ray-eye] " + arr.length + " notes (" + [...new Set(arr.map(n => n.kind))].join(", ") + ")");
    try { for (const n of arr.slice(0, 200)) printNote(n); } finally { nativeConsole.groupEnd(); }
  }

  function reportSpecs() {
    if (!specStore.size) { styled("[x-ray-eye] No API specs parsed yet.", STYLE.dim); return; }
    nativeConsole.groupCollapsed("%c%s", STYLE.ok, "[x-ray-eye] " + specStore.size + " API documents parsed");
    try {
      for (const s of specStore.values()) {
        line(s.kind.toUpperCase(), s.title + (s.version ? " (" + s.version + ")" : "") + " -> " + s.endpoints + " endpoints");
        line("  source", s.specUrl);
        if (s.bases && s.bases.length) line("  bases", s.bases.join(", "));
        if (s.note) line("  note", s.note);
      }
    } finally { nativeConsole.groupEnd(); }
  }

  function reportSecurity(opts) {
    const o = opts || {};
    const idor = list({ idor: true });
    const unauth = list({ unauth: true });
    const challenged = list({ challenge: true });
    const secrets = listSecrets({});
    const leaks = secrets.filter(s => s.exposure === "leak");
    const third = list({ thirdParty: true });
    const jwtCritical = listJWTs({ severity: "HIGH" });
    const storageHot = listStorage({ sensitive: true });
    const cacheRisky = [...store.values()].filter(f => f.cacheRisk && f.cacheRisk.length);
    const noteCount = k => listNotes({ kind: k }).length;

    nativeConsole.groupCollapsed("%c%s", STYLE.warn, "[x-ray-eye] security triage");
    try {
                                                                           
                                                            
      try { reportTriage(); } catch (e) { fail("triage", e); }
      line("Credential leaks", leaks.length);
      for (const s of leaks.slice(0, 30)) line("  " + s.severity, s.name + " at " + s.file.split("/").pop() + ":" + s.line);
      line("JWT weaknesses", jwtCritical.length + " of " + jwtStore.size + " tokens");
      for (const j of jwtCritical.slice(0, 20)) line("  " + j.severity, j.signals.map(s => s.id).join(",") + "  alg=" + j.alg + (j.weakSecret ? "  WEAK SECRET RECOVERED" : ""));
      line("Secrets in client storage", storageHot.length);
      for (const s of storageHot.slice(0, 25)) line("  " + s.area, clip(s.name, 50) + "  jwt=" + !!s.hasJwt + "  len=" + s.rawLength);
      line("Cache-disclosure risk", cacheRisky.length);
      for (const f of cacheRisky.slice(0, 25)) line("  " + f.cacheRisk[0].severity, f.method + " " + f.host + f.normalizedPath + "  " + f.cacheRisk.map(x => x.id).join(","));
      line("OAuth findings", oauthStore.size);
      for (const f of [...oauthStore.values()].slice(0, 15)) {
        for (const x of f.findings) line("  " + x.severity, f.flow + " " + f.host + "  " + x.label);
      }
      line("Framework / CVE candidates", fwStore.size);
      for (const [name, rec] of fwStore) if (rec.cves && rec.cves.length) line("  " + name + " " + (rec.version || "?"), rec.cves.flatMap(c => c.ids).join(","));
      line("Server Action IDs", noteCount("server-action"));
      line("RSC bypass candidates", noteCount("rsc-bypass-candidate"));
      line("GraphQL dangerous args", noteCount("graphql-dangerous-arg"));
      line("Relay nodes exposure", noteCount("graphql-relay-nodes"));
      line("postMessage wildcard origin", noteCount("postmessage-wildcard"));
      line("Tabnabbing", noteCount("tabnabbing"));
      line("Service workers", swStore.size);
      line("IDOR candidates", idor.length);
      for (const f of idor.slice(0, 30)) line("  " + f.method, f.host + f.normalizedPath + "  params: " + f.idorCandidates.map(c => c.name).join(", "));
      line("Declared or implied unauthenticated", unauth.length);
      for (const f of unauth.slice(0, 30)) line("  " + f.method, f.host + f.normalizedPath + (f.cors && f.cors.length ? "  " + f.cors.join(",") : ""));
      line("Endpoints with an auth challenge", challenged.length);
      for (const f of challenged.slice(0, 30)) line("  " + f.method, f.host + f.normalizedPath + "  " + f.challenge);
      line("Third-party endpoints", third.length);
      if (snapshots.size >= 1) line("Marks available", [...snapshots.keys()].join(", ") + "  (xrayeye.diff() compares them)");
    } finally { nativeConsole.groupEnd(); }
    if (o.expand !== false) reportSecrets({ exposure: "leak" });
  }

                                                                          
           
                                                                          
                                                                          
                                 
                                                                          
  function listJWTs(opts) {
    const o = opts || {};
    let arr = [...jwtStore.values()];
    if (o.severity) { const r = SEV_RANK[String(o.severity).toUpperCase()] || 0; arr = arr.filter(j => (SEV_RANK[j.severity] || 0) >= r); }
    if (o.signal) arr = arr.filter(j => j.signals.some(s => s.id === o.signal));
    if (o.alg) arr = arr.filter(j => String(j.alg).toUpperCase().indexOf(String(o.alg).toUpperCase()) === 0);
    arr.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || b.firstSeen - a.firstSeen);
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function serializeJWT(j) {
    return {
      severity: j.severity, alg: j.alg, typ: j.typ || null, kid: j.kid || null,
      sub: j.sub, iss: j.iss, aud: j.aud, exp: j.exp, iat: j.iat,
      claims: j.claims, signals: j.signals,
      weakSecretRecovered: !!j.weakSecret, weakSecretMasked: j.weakSecret || null,
                                                                     
      tokenMasked: j.token ? null : j.masked, token: j.token || null, sources: j.sources,
      firstSeen: new Date(j.firstSeen).toISOString()
    };
  }

  function reportJWTs(opts) {
    const arr = listJWTs(opts);
    if (!arr.length) { styled("[x-ray-eye] No JWTs observed. (Tokens in headers, bodies, URLs, fragments, storage and websocket frames are all analysed.)", STYLE.dim); return; }
    const rows = arr.map(j => ({
      severity: j.severity, alg: j.alg, sub: j.sub || "", iss: j.iss || "",
      exp: j.exp || "", signals: j.signals.map(s => s.id).join(","),
      weak: j.weakSecret ? "YES" : "", where: j.sources.slice(0, 2).join(" | ")
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    else nativeConsole.log(JSON.stringify(rows, null, 2));
    styled("[x-ray-eye] " + arr.length + " distinct tokens. Decoding and secret checks are local; nothing was sent.", STYLE.dim);
  }

  function listStorage(opts) {
    const o = opts || {};
    let arr = [...storageStore.values()];
    if (o.area) arr = arr.filter(s => s.area === String(o.area).toLowerCase());
    if (o.sensitive) arr = arr.filter(s => s.classified || s.hasJwt);
    if (o.search) arr = arr.filter(s => (s.area + " " + s.name).toLowerCase().includes(String(o.search).toLowerCase()));
    arr.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || a.area.localeCompare(b.area) || a.name.localeCompare(b.name));
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function serializeStorage(s) {
    return {
      area: s.area, name: s.name,
      valueMasked: s.raw ? null : s.masked, value: s.raw || null, length: s.rawLength,
      sensitiveName: !!s.classified, containsJwt: !!s.hasJwt,
      pii: (s.pii || []).map(p => p.kind + " x" + p.count),
      note: s.note || null, at: s.at
    };
  }

  function reportStorage(opts) {
    const arr = listStorage(opts);
    if (!arr.length) { styled("[x-ray-eye] Nothing found in client-side storage.", STYLE.dim); return; }
    const byArea = arr.reduce((a, s) => { a[s.area] = (a[s.area] || 0) + 1; return a; }, {});
    styled("[x-ray-eye] storage: " + Object.entries(byArea).map(([k, v]) => k + "=" + v).join(", "), STYLE.dim);
    const rows = arr.slice(0, (opts && opts.limit) || 120).map(s => ({
      area: s.area, key: clip(String(s.name), 60), len: s.rawLength,
      sensitive: s.classified ? "yes" : "", jwt: s.hasJwt ? "yes" : "",
      pii: (s.pii || []).map(p => p.kind).join(","),
      value: clip(shownValue(s.masked, s.raw), 48)
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    styled(CONFIG.revealSecrets
      ? "Cleartext values are shown because revealSecrets is on. A JWT or credential in web storage is readable by any script on the origin."
      : "Values are masked. A JWT or credential in web storage is readable by any script on the origin.", STYLE.dim);
  }

  function reportOAuth(opts) {
    if (!oauthStore.size) { styled("[x-ray-eye] No OAuth or OIDC flows observed.", STYLE.dim); return; }
    const flows = [...oauthStore.values()];
    nativeConsole.groupCollapsed("%c%s", STYLE.warn, "[x-ray-eye] " + flows.length + " auth flows");
    try {
      for (const f of flows.slice(0, 40)) {
        line(f.flow.toUpperCase() + "  " + f.host + new URL(f.url, "http://x").pathname);
        if (f.clientId) line("  client_id", f.clientId);
        if (f.issuer) line("  issuer", f.issuer);
        if (f.redirectUris.length) line("  redirect_uri", f.redirectUris.map(r => r.value).join(", "));
        if (f.scope) line("  scope", f.scope);
        for (const x of f.findings) line("  " + x.severity, x.label + " - " + clip(x.detail, 160));
      }
      const redirects = listNotes({ kind: "oauth-redirect-uri" });
      if (redirects.length) {
        line("redirect_uri inventory", redirects.length + " distinct");
        for (const r of redirects.slice(0, 40)) line("  " + (r.notes && r.notes.length ? "!" : " "), clip(r.value, 150) + (r.notes && r.notes.length ? "  [" + r.notes.join(", ") + "]" : ""));
      }
    } finally { nativeConsole.groupEnd(); }
    styled("Observation only. Never change a redirect_uri or replay a code from this tool.", STYLE.dim);
  }

  function reportFrameworks() {
    if (!fwStore.size) { styled("[x-ray-eye] No framework fingerprints yet. (They appear once a bundle or inline script is scanned.)", STYLE.dim); return; }
    for (const [name, rec] of fwStore) {
      const vs = [...rec.versions];
      line(name, vs.length ? vs.join(", ") : "(version unknown)");
      for (const cve of rec.cves || []) {
        line("  advisory", cve.ids.join(", ") + "  fixed in " + cve.fixedIn);
        for (const t of cve.titles) line("    ", t);
        line("    how", cve.how);
      }
    }
    styled("Version matches are passive fingerprints, not proof of exploitability. Confirm the version and reproduce before reporting.", STYLE.dim);
  }

  function reportCache() {
    const risky = [...store.values()].filter(f => f.cacheRisk && f.cacheRisk.length);
    if (!risky.length) { styled("[x-ray-eye] No cache-posture risk observed.", STYLE.dim); return; }
    const rows = risky.sort((a, b) => (SEV_RANK[(b.cacheRisk[0] || {}).severity] || 0) - (SEV_RANK[(a.cacheRisk[0] || {}).severity] || 0))
      .slice(0, 60).map(f => ({
        severity: f.cacheRisk[0].severity, method: f.method, path: f.host + f.normalizedPath,
        cacheControl: (f.responseHeaders || {})["cache-control"] || "",
        vary: (f.responseHeaders || {})["vary"] || "",
        setCookie: (f.responseHeaders || {})["set-cookie"] ? "yes" : "",
        pii: (f.piiHits || []).map(p => p.kind).join(","),
        signals: f.cacheRisk.map(s => s.id).join(",")
      }));
    if (nativeConsole.table) nativeConsole.table(rows);
    styled("[x-ray-eye] " + risky.length + " endpoints with cache-disclosure risk. Confirm against a real shared cache before reporting.", STYLE.dim);
  }

  function exportDoc(opts) {
    const o = opts || {};
    return {
      tool: "x-ray-eye",
      version: VERSION,
      page: redactHref(location.href),
      exportedAt: new Date().toISOString(),
      config: {
        redactSensitive: !!CONFIG.redactSensitive,
        minConfidence: String(CONFIG.minConfidence).toUpperCase(),
        thirdParty: CONFIG.thirdParty
      },
      stats: statsSnapshot(),
      specs: [...specStore.values()],
      endpoints: list(o).map(f => serialize(f, !!o.includeDetails)),
      secrets: listSecrets(o).map(serializeSecret),
      jwt: listJWTs(o).map(serializeJWT),
      storage: listStorage(o).map(serializeStorage),
      authFlows: [...oauthStore.values()],
      frameworks: [...fwStore.values()].map(f => ({
        name: f.name, version: f.version || null, kind: f.kind || "lib",
        versions: [...f.versions], cves: f.cves || [], firstSeen: f.firstSeen
      })),
      serviceWorkers: [...swStore.values()],
      serverActions: listNotes({ kind: "server-action" }).map(n => ({ id: n.id, file: n.file })),
      notes: listNotes(o),
      marks: [...snapshots.values()].map(m => ({ label: m.label, at: m.at, endpoints: m.entries.size, storageKeys: (m.storage || new Map()).size })),
                                                                             
                                                                            
                                     
      triage: (() => { const t = triageSummary(); return { counts: t.counts, pairs: t.pairs, decoded: t.decoded.length, reconstructed: t.reconstructed.length }; })(),
      coverage: channelCoverage(),
      uniqueValues: uniqueSummary()
    };
  }

  function exportJSON(opts) {
    return JSON.stringify(exportDoc(opts), null, (opts && opts.pretty === false) ? 0 : 2);
  }

  const csvCell = v => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };

  function exportCSV(opts) {
    const o = opts || {};
    const rows = ["confidence,state,method,host,path,statuses,count,score,thirdParty,authSent,challenge,cors,idorParams,specKind,sources"];
    for (const f of list(o)) {
      rows.push([
        f.confidence, f.observed ? "seen" : (f.specDeclared ? "declared" : "referenced"),
        f.method, f.host, f.normalizedPath, statusText(f), f.count, f.score,
        f.thirdParty, f.authSeen, f.challenge || "", (f.cors || []).join(" "),
        f.idorCandidates ? f.idorCandidates.map(c => c.name).join(" ") : "",
        f.specKind || "", [...f.sources].join(" ")
      ].map(csvCell).join(","));
    }
    return rows.join("\n");
  }

  function exportSecretsCSV() {
                                                                           
                                                                                
                                                                           
                                                                    
    const reveal = CONFIG.revealSecrets;
                                                                              
                                                                            
                                                                
    const rows = ["severity,verdict,channel,exposure,type,category," + (reveal ? "value" : "valueMasked") +
      ",length,shape,entropy,charset,file,line,column,origin,occurrences"];
    for (const s of listSecrets({})) {
      const cells = [s.severity, s.verdict || "", s.channel || "", s.exposure, s.typeId, s.category,
        reveal ? (s.rawValue || "") : s.valueMasked, s.length, s.shape,
        s.entropyBits === null ? "" : s.entropyBits, s.charset || "", s.file, s.line, s.column,
        s.decodedFrom ? s.decodedFrom + "-decoded" : (s.reconstructedFrom ? "reconstructed from " + s.reconstructedFrom : ""),
        s.count];
      rows.push(cells.map(csvCell).join(","));
    }
    return rows.join("\n");
  }

  function exportMarkdown(opts) {
    const o = opts || {};
    const eps = list(o);
    const secs = listSecrets(o);
    const L = [];
    L.push("# API attack surface");
    L.push("");
    L.push("- Page: `" + redactHref(location.href) + "`");
    L.push("- Captured: " + new Date().toISOString());
    const triage = triageSummary();
    const uniq = uniqueSummary();
    const cov = channelCoverage();
    L.push("- Endpoints: " + store.size + " (" + eps.length + " shown) | Secrets: " + secretStore.size + " | Specs: " + specStore.size);
    L.push("- Credential triage: **" + triage.counts.real + " real**, " + triage.counts.fixture +
      " test fixtures, " + triage.counts.arbitrary + " arbitrary | " + uniq.unique + " unique values across " +
      uniq.detections + " detections");
    L.push("");
    if (CONFIG.revealSecrets) {
      L.push("> **Cleartext included.** `config.revealSecrets` is on, so raw credential values appear below. Do not share this report.");
      L.push("");
    }

                                                                              
                                                                            
                                                                          
    L.push("## Coverage by channel");
    L.push("");
    L.push("| Channel | Inspected | Findings | Unique | Fixtures |");
    L.push("|---|---|---|---|---|");
    for (const c of CHANNELS) {
      L.push("| " + c + " | " + cov[c].inspected + " | " + cov[c].findings + " | " + cov[c].unique + " | " + cov[c].fixtures + " |");
    }
    L.push("");

    const leaks = secs.filter(s => s.exposure === "leak");
    if (leaks.length) {
      L.push("## Credential findings (" + leaks.length + ")");
      L.push("");
      L.push("| Severity | Verdict | Channel | Type | Value | Location | Entropy |");
      L.push("|---|---|---|---|---|---|---|");
      for (const s of leaks) {
        L.push("| " + s.severity + " | " + (s.verdict || "-") + " | " + (s.channel || "-") + " | " + s.name + " | `" + shownValue(s.valueMasked, s.rawValue) + "` | " + whereOf(s) + " | " + (s.entropyBits === null ? "-" : s.entropyBits) + " |");
      }
      L.push("");
    }

    const others = secs.filter(s => s.exposure !== "leak");
    if (others.length) {
      L.push("## Other credential-shaped findings (" + others.length + ")");
      L.push("");
      L.push("| Exposure | Verdict | Channel | Type | Value | Location |");
      L.push("|---|---|---|---|---|---|");
      for (const s of others) {
        L.push("| " + s.exposure + " | " + (s.verdict || "-") + " | " + (s.channel || "-") + " | " + s.name + " | `" + shownValue(s.valueMasked, s.rawValue) + "` | " + whereOf(s) + " |");
      }
      L.push("");
    }

                                                                                
                                                               
    if (triage.pairs.length) {
      L.push("## Hardcoded credential pairs (" + triage.pairs.length + ")");
      L.push("");
      L.push("| Severity | Values | Location | Comparison | Check at |");
      L.push("|---|---|---|---|---|");
      for (const p of triage.pairs) {
        const vals = (p.valuesRaw || p.values || []).map(v => "`" + v + "`").join(" / ") || "-";
        L.push("| " + p.severity + " | " + vals + " | " + whereOf(p) + " | `" +
          (p.compare ? String(p.compare).replace(/\s+/g, " ").replace(/\|/g, "\\|") : "not located in this file") + "` | " +
          (p.compareAt ? p.compareAt.file.split(/[\\/]/).pop() + ":" + p.compareAt.line : "-") + " |");
      }
      L.push("");
    }

                                                                               
                                                                   
    const derived = secs.filter(s => s.decodedFrom || s.reconstructedFrom);
    if (derived.length) {
      L.push("## Derived values: decoded and reconstructed (" + derived.length + ")");
      L.push("");
      L.push("| Source | Type | Value | Location | How |");
      L.push("|---|---|---|---|---|");
      for (const s of derived) {
        const how = s.decodedFrom ? s.decodedFrom + "-decoded" : "reconstructed from `" + s.reconstructedFrom + "`";
        L.push("| " + (s.decodedFrom || "concatenation") + " | " + s.name + " | `" + shownValue(s.valueMasked, s.rawValue) + "` | " + whereOf(s) + " | " + how + " |");
      }
      L.push("");
    }

                                                                               
                                                  
    if (uniq.rows.length) {
      L.push("## Unique values (" + uniq.unique + " unique, " + uniq.detections + " detections)");
      L.push("");
      L.push("| Value | Verdict | Detections | Channels | Seen at |");
      L.push("|---|---|---|---|---|");
      for (const r of uniq.rows.slice(0, 60)) {
        L.push("| `" + shown(r.value, r.valueMasked) + "` | " + r.verdict + " | " + r.detections + " | " + (r.channels.join(", ") || "-") + " | " + (r.places.join("; ") || "-") + " |");
      }
      if (uniq.rows.length > 60) {
        L.push("");
        L.push("_" + (uniq.rows.length - 60) + " more unique values omitted._");
      }
      L.push("");
    }

    const disclosed = listNotes({ kind: "disclosed-credential" });
    if (disclosed.length) {
      L.push("## Credentials disclosed in page text or shipped code (" + disclosed.length + ")");
      L.push("");
      L.push("| Kind | Verdict | Where | Value | Location |");
      L.push("|---|---|---|---|---|");
      for (const n of disclosed) {
        L.push("| " + (n.label || "credential") + " | " + (n.verdict || "-") + " | " + (n.exposure || n.where || "-") + " | " +
          (disclosedValues(n).map(v => "`" + v + "`").join(", ") || "-") + " | " + whereOf(n) + " |");
      }
      L.push("");
    }

    const byHost = new Map();
    for (const f of eps) {
      if (!byHost.has(f.host)) byHost.set(f.host, []);
      byHost.get(f.host).push(f);
    }
    for (const host of [...byHost.keys()].sort()) {
      L.push("## " + host);
      L.push("");
      L.push("| Conf | State | Method | Path | Status | Auth | IDOR | Spec |");
      L.push("|---|---|---|---|---|---|---|---|");
      for (const f of byHost.get(host)) {
        L.push("| " + f.confidence + " | " + (f.observed ? "seen" : (f.specDeclared ? "spec" : "ref")) +
          " | " + f.method + " | `" + f.normalizedPath + "` | " + (statusText(f) || "-") +
          " | " + (authTag(f) || "-") +
          " | " + (f.idorCandidates ? f.idorCandidates.map(c => c.name).join(" ") : "") +
          " | " + (f.specKind || "") + " |");
      }
      L.push("");
    }

    if (specStore.size) {
      L.push("## API documents");
      L.push("");
      for (const s of specStore.values()) {
        L.push("- **" + s.kind.toUpperCase() + "** " + s.title + (s.version ? " (" + s.version + ")" : "") + " - " + s.endpoints + " endpoints - " + s.specUrl + (s.note ? " - " + s.note : ""));
      }
      L.push("");
    }

    const jwts = listJWTs({});
    if (jwts.length) {
      L.push("## JWT findings (" + jwts.length + ")");
      L.push("");
      L.push("| Severity | alg | Signals | Subject | Where seen |");
      L.push("|---|---|---|---|---|");
      for (const j of jwts) {
        L.push("| " + j.severity + " | " + j.alg + " | " + j.signals.map(s => s.id).join(", ") + " | " + (j.sub || "-") + " | " + j.sources.slice(0, 2).join(", ") + " |");
      }
      L.push("");
    }

    const st = listStorage({ sensitive: true });
    if (st.length) {
      L.push("## Secrets in client-side storage (" + st.length + ")");
      L.push("");
      L.push("| Area | Key | Length | JWT | " + (CONFIG.revealSecrets ? "Value" : "Masked value") + " |");
      L.push("|---|---|---|---|---|");
      for (const s of st) L.push("| " + s.area + " | `" + clip(String(s.name), 50) + "` | " + s.rawLength + " | " + (s.hasJwt ? "yes" : "") + " | `" + clip(shownValue(s.masked, s.raw), 48) + "` |");
      L.push("");
    }

    const flows = [...oauthStore.values()];
    if (flows.length) {
      L.push("## Auth flows (" + flows.length + ")");
      L.push("");
      for (const f of flows) {
        L.push("- **" + f.flow.toUpperCase() + "** " + f.url);
        if (f.clientId) L.push("  - client_id: `" + f.clientId + "`");
        if (f.redirectUris.length) L.push("  - redirect_uri: " + f.redirectUris.map(r => "`" + r.value + "`").join(", "));
        for (const x of f.findings) L.push("  - **" + x.severity + "** " + x.label + " - " + x.detail);
      }
      L.push("");
    }

    if (fwStore.size) {
      L.push("## Frameworks");
      L.push("");
      for (const [name, rec] of fwStore) {
        L.push("- **" + name + "** " + ([...rec.versions].join(", ") || "version unknown"));
        for (const cve of rec.cves || []) {
          L.push("  - " + cve.ids.join(", ") + " (fixed in " + cve.fixedIn + "): " + cve.titles.join("; "));
        }
      }
      L.push("");
    }

    const cacheRisky = [...store.values()].filter(f => f.cacheRisk && f.cacheRisk.length);
    if (cacheRisky.length) {
      L.push("## Cache-disclosure risk (" + cacheRisky.length + ")");
      L.push("");
      L.push("| Severity | Method | Path | Cache-Control | Set-Cookie | PII | Signals |");
      L.push("|---|---|---|---|---|---|---|");
      for (const f of cacheRisky) {
        const h = f.responseHeaders || {};
        L.push("| " + f.cacheRisk[0].severity + " | " + f.method + " | `" + f.normalizedPath + "` | " + (h["cache-control"] || "-") + " | " + (h["set-cookie"] ? "yes" : "") + " | " + (f.piiHits || []).map(p => p.kind).join(",") + " | " + f.cacheRisk.map(s => s.id).join(",") + " |");
      }
      L.push("");
    }

    return L.join("\n");
  }

  function download(opts) {
    try {
      const o = opts || {};
      const json = exportJSON(o);
      const blob = new Blob([json], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "x-ray-eye-" + String(location.hostname).replace(/[^a-z0-9.-]/gi, "_") + "-" + Date.now() + ".json";
      (document.body || document.documentElement).appendChild(a);
      a.click();
      a.remove();
      setT(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      fail("download", e);
      styled("[x-ray-eye] Download failed. Use copy(xrayeye.export()) instead.", STYLE.dim);
    }
  }

                                                                          
                                        
                                                                          
                                                                            
                                                                    
  function storageFingerprint() {
    const out = new Map();
    const addArea = (area, storeObj) => {
      if (!storeObj) return;
      try {
        const n = Number(storeObj.length) || 0;
        for (let i = 0; i < n; i++) {
          const k = storeObj.key(i);
          if (k === null || k === RELOAD_STORE_KEY || k === RELOAD_CONFIG_KEY) continue;
          let v = "";
          try { v = storeObj.getItem(k); } catch (_) { continue; }
          out.set(area + "|" + k, { area, key: k, len: String(v == null ? "" : v).length, hash: fnv1a(String(v == null ? "" : v)) });
        }
      } catch (_) {}
    };
    addArea("localStorage", (() => { try { return window.localStorage; } catch (_) { return null; } })());
    addArea("sessionStorage", (() => { try { return window.sessionStorage; } catch (_) { return null; } })());
    try {
      for (const part of String(hasDOM && document.cookie || "").split(";")) {
        const i = part.indexOf("=");
        if (i < 1) continue;
        const name = part.slice(0, i).trim();
        if (!name) continue;
        const value = part.slice(i + 1).trim();
        out.set("cookie|" + name, { area: "cookie", key: name, len: value.length, hash: fnv1a(value) });
      }
    } catch (_) {}
    return out;
  }

  function snapshotNow(label) {
    const entries = new Map();
    for (const f of store.values()) {
      entries.set(f.key, {
        key: f.key, method: f.method, host: f.host, path: f.normalizedPath,
        statuses: [...f.statuses.keys()].sort((a, b) => a - b),
        authSeen: f.authSeen, observed: f.observed, confidence: f.confidence,
        count: f.count, challenge: f.challenge || null, cors: f.cors || []
      });
    }
    return { label, at: new Date().toISOString(), entries, storage: storageFingerprint() };
  }

  function mark(label) {
    const l = String(label || ("mark-" + (snapshots.size + 1)));
    const snap = snapshotNow(l);
    snapshots.set(l, snap);
    styled("[x-ray-eye] Marked '" + l + "' with " + snap.entries.size + " endpoints. Log in, then run xrayeye.diff().", STYLE.ok);
    return l;
  }

  function diff(aLabel, bLabel) {
    if (!snapshots.size) {
      styled("[x-ray-eye] No marks yet. Run xrayeye.mark('pre-auth') first, log in, then xrayeye.diff().", STYLE.warn);
      return null;
    }
    const labels = [...snapshots.keys()];
    const a = snapshots.get(aLabel || labels[labels.length - 2] || labels[0]);
    if (!a) { styled("[x-ray-eye] Unknown mark '" + aLabel + "'. Known: " + labels.join(", "), STYLE.warn); return null; }
    const b = (bLabel && bLabel !== "now") ? snapshots.get(bLabel) : null;
    if (bLabel && bLabel !== "now" && !b) { styled("[x-ray-eye] Unknown mark '" + bLabel + "'. Known: " + labels.join(", "), STYLE.warn); return null; }
    const bEntries = b ? b.entries : snapshotNow("now").entries;

    const out = {
      from: a.label, to: b ? b.label : "now", at: new Date().toISOString(),
      newEndpoints: [], goneEndpoints: [], statusChanges: [],
      startedSendingCredentials: [], corsChanges: [], challenged: [],
      unauthenticatedAfterLogin: [], storageAdded: [], storageRemoved: [], storageChanged: []
    };

                                                                          
    try {
      const aSt = a.storage || new Map();
      const bSt = b ? (b.storage || new Map()) : storageFingerprint();
      for (const [k, v] of bSt) {
        const prev = aSt.get(k);
        if (!prev) out.storageAdded.push({ area: v.area, key: v.key, len: v.len });
        else if (prev.hash !== v.hash) out.storageChanged.push({ area: v.area, key: v.key, fromLen: prev.len, toLen: v.len });
      }
      for (const [k, v] of aSt) if (!bSt.has(k)) out.storageRemoved.push({ area: v.area, key: v.key });
    } catch (e) { fail("diff.storage", e); }

    for (const [k, bf] of bEntries) {
      const af = a.entries.get(k);
      if (!af) {
        out.newEndpoints.push({ method: bf.method, path: bf.host + bf.path, statuses: bf.statuses, authSent: bf.authSeen, key: bf.key });
        continue;
      }
      const before = af.statuses.join(","), after = bf.statuses.join(",");
      if (before !== after) {
        const change = { method: bf.method, path: bf.host + bf.path, from: af.statuses, to: bf.statuses, key: bf.key, authSent: bf.authSeen };
        out.statusChanges.push(change);
        const wasBlocked = af.statuses.some(s => s === 401 || s === 403 || s === 0);
        const nowOk = bf.statuses.some(s => s >= 200 && s < 300);
        if (wasBlocked && nowOk && !bf.authSeen) out.unauthenticatedAfterLogin.push(change);
      }
      if (!af.authSeen && bf.authSeen) out.startedSendingCredentials.push({ method: bf.method, path: bf.host + bf.path, key: bf.key });
      if (JSON.stringify(af.cors) !== JSON.stringify(bf.cors)) out.corsChanges.push({ method: bf.method, path: bf.host + bf.path, from: af.cors, to: bf.cors });
      if (bf.challenge) out.challenged.push({ method: bf.method, path: bf.host + bf.path, challenge: bf.challenge });
    }
    for (const [k, af] of a.entries) {
      if (!bEntries.has(k)) out.goneEndpoints.push({ method: af.method, path: af.host + af.path });
    }

    nativeConsole.groupCollapsed("%c%s", STYLE.ok, "[x-ray-eye] diff " + out.from + " -> " + out.to);
    try {
      line("New endpoints", out.newEndpoints.length);
      for (const x of out.newEndpoints.slice(0, 40)) line("  + " + x.method, x.path + "  [" + x.statuses.join(",") + "]" + (x.authSent ? " (sent credentials)" : " (no credentials sent)"));
      line("Status changed", out.statusChanges.length);
      for (const x of out.statusChanges.slice(0, 40)) line("  ~ " + x.method, x.path + "  " + x.from.join(",") + " -> " + x.to.join(","));
      if (out.unauthenticatedAfterLogin.length) {
        line("BLOCKED -> 200 with no credentials", out.unauthenticatedAfterLogin.length);
        for (const x of out.unauthenticatedAfterLogin) line("  ! " + x.method, x.path);
      }
      if (out.startedSendingCredentials.length) line("Started sending credentials", out.startedSendingCredentials.length);
      if (out.corsChanges.length) line("CORS posture changed", out.corsChanges.length);
      if (out.goneEndpoints.length) line("No longer observed", out.goneEndpoints.length);
      const st = out.storageAdded.length + out.storageChanged.length + out.storageRemoved.length;
      if (st) {
        line("Storage changes", st);
        for (const x of out.storageAdded.slice(0, 25)) line("  + " + x.area, x.key + "  (" + x.len + " chars)");
        for (const x of out.storageChanged.slice(0, 25)) line("  ~ " + x.area, x.key + "  " + x.fromLen + " -> " + x.toLen + " chars");
        for (const x of out.storageRemoved.slice(0, 15)) line("  - " + x.area, x.key);
      }
    } finally { nativeConsole.groupEnd(); }
    return out;
  }

                                                                          
              
                                                                          
  function revalidate() {
    const minConf = effectiveMinConf();
    let dropped = 0, changed = 0;
    for (const key of [...store.keys()]) {
      const f = store.get(key);
      if (!f) continue;
      const conf = confidenceFrom(f.score, f.observed, f.specDeclared);
      if (conf === "IGNORE" || CONF_RANK[conf] < minConf) {
        removeFinding(key);
        dropped++;
        continue;
      }
      if (conf !== f.confidence) { f.confidence = conf; changed++; }
    }
    styled("[x-ray-eye] Revalidated at minConfidence=" + String(CONFIG.minConfidence).toUpperCase() + ": " + dropped + " dropped, " + changed + " re-ranked, " + store.size + " remain.", STYLE.dim);
    return { dropped, changed, remaining: store.size };
  }

  function reloadStorage() {
    try { return window.sessionStorage; } catch (_) { return null; }
  }

  function clearReloadSnapshot() {
    const storage = reloadStorage();
    if (!storage || !nativeStorageRemove) return;
    try { Reflect.apply(nativeStorageRemove, storage, [RELOAD_STORE_KEY]); } catch (_) {}
  }

  function reloadReplacer(_key, value) {
    if (value instanceof Map) return { __xrayeyeType: "Map", items: [...value.entries()] };
    if (value instanceof Set) return { __xrayeyeType: "Set", items: [...value.values()] };
    return value;
  }

  function reloadReviver(_key, value) {
    if (!value || value.__xrayeyeType === undefined) return value;
    if (value.__xrayeyeType === "Map") return new Map(value.items || []);
    if (value.__xrayeyeType === "Set") return new Set(value.items || []);
    return value;
  }

  function saveReloadSnapshot() {
    if (!keepOnReload) return;
    const storage = reloadStorage();
    if (!storage || !nativeStorageSet) return;
    try {
      const snapshot = {
        format: 1,
        build: ANALYZER_BUILD,
        url: location.href,
        maps: {
          store, pathIndex, secretStore, specStore, jwtStore, storageStore,
          swStore, oauthStore, fwStore, snapshots, notes, noteKindCount, valueIndex
        },
        errors,
        stats,
        channelSeen,
        sequences: { seq, secretSeq, specSeq, jwtSeq, storageSeq, oauthSeq }
      };
      Reflect.apply(nativeStorageSet, storage, [RELOAD_STORE_KEY, JSON.stringify(snapshot, reloadReplacer)]);
    } catch (_) {}
  }

  function restoreReloadSnapshot() {
    const storage = reloadStorage();
    if (!storage || !nativeStorageGet) return;
    try {
      keepOnReload = Reflect.apply(nativeStorageGet, storage, [RELOAD_CONFIG_KEY]) !== "0";
      if (!keepOnReload) { clearReloadSnapshot(); return; }
      const raw = Reflect.apply(nativeStorageGet, storage, [RELOAD_STORE_KEY]);
      if (!raw) return;
      const data = JSON.parse(raw, reloadReviver);
      if (!data || data.format !== 1 || data.build !== ANALYZER_BUILD ||
          data.url !== location.href) return;
      const maps = {
        store, pathIndex, secretStore, specStore, jwtStore, storageStore,
        swStore, oauthStore, fwStore, snapshots, notes, noteKindCount, valueIndex
      };
      for (const [name, target] of Object.entries(maps)) {
        const saved = data.maps && data.maps[name];
        if (!(saved instanceof Map)) continue;
        target.clear();
        for (const [key, value] of saved) target.set(key, value);
      }
      errors.splice(0, errors.length, ...(Array.isArray(data.errors) ? data.errors : []));
      for (const key of Object.keys(stats)) {
        if (data.stats && typeof data.stats[key] === "number") stats[key] = data.stats[key];
      }
      for (const key of CHANNELS) {
        if (data.channelSeen && typeof data.channelSeen[key] === "number") channelSeen[key] = data.channelSeen[key];
      }
      const sequences = data.sequences || {};
      seq = Number(sequences.seq) || 0;
      secretSeq = Number(sequences.secretSeq) || 0;
      specSeq = Number(sequences.specSeq) || 0;
      jwtSeq = Number(sequences.jwtSeq) || 0;
      storageSeq = Number(sequences.storageSeq) || 0;
      oauthSeq = Number(sequences.oauthSeq) || 0;
    } catch (_) {}
  }

  function installPersistence() {
    if (!keepOnReload || persistenceListening) return;
    const onPageHide = () => saveReloadSnapshot();
    window.addEventListener("pagehide", onPageHide, false);
    persistenceListening = true;
    cleanups.push(() => {
      window.removeEventListener("pagehide", onPageHide, false);
      persistenceListening = false;
    });
  }

  function setPersistence(enabled) {
    keepOnReload = enabled !== false;
    const storage = reloadStorage();
    if (storage && nativeStorageSet) {
      try { Reflect.apply(nativeStorageSet, storage, [RELOAD_CONFIG_KEY, keepOnReload ? "1" : "0"]); } catch (_) {}
    }
    if (!keepOnReload) clearReloadSnapshot();
    else if (active && installed) installPersistence();
    return { enabled: keepOnReload };
  }

  function runInstalls() {
    for (const [name, fn] of installFns) {
      try { fn(); } catch (e) { fail("install " + name, e); }
    }
  }

  function start() {
    if (active && installed) return api;
    active = true;
    installed = true;
    runInstalls();
    try { scanDOM(); } catch (e) { fail("scanDOM", e); }
    styled("[x-ray-eye] Resumed. Hooks: " + hooks.join(", "), STYLE.ok);
    return api;
  }

  function stop(opts) {
    if (!active) return api;
    saveReloadSnapshot();
    active = false;
    installed = false;
    for (const fn of cleanups.splice(0)) { try { fn(); } catch (_) {} }
    hooks.length = 0;
    pending.clear();
    pendingSecrets.clear();
    if (queuePrint.timer) { clearT(queuePrint.timer); queuePrint.timer = null; }
    if (!(opts && opts.silent)) {
      styled("[x-ray-eye] Stopped. " + store.size + " endpoints and " + secretStore.size + " credential findings kept. xrayeye.report(), xrayeye.secrets() or xrayeye.export().", STYLE.dim);
      styled("[x-ray-eye] xrayeye.start() resumes capture.", STYLE.dim);
    }
    return api;
  }

  function clear() {
    store.clear();
    pathIndex.clear();
    secretStore.clear();
    specStore.clear();
    jwtStore.clear();
    storageStore.clear();
    swStore.clear();
    oauthStore.clear();
    fwStore.clear();
    notes.clear();
    snapshots.clear();
    pending.clear();
    pendingSecrets.clear();
    errors.length = 0;
    normalizeCache.clear();
    noteKindCount.clear();
    valueIndex.clear();
    for (const c of CHANNELS) channelSeen[c] = 0;
    for (const k of Object.keys(stats)) stats[k] = 0;
    warned.clear();
    scriptSeen.clear();
    scriptQueue.length = 0;
    sourceMapSeen.clear();
    seq = 0; secretSeq = 0; specSeq = 0; jwtSeq = 0; storageSeq = 0; oauthSeq = 0;
    clearReloadSnapshot();
    styled("[x-ray-eye] Cleared. Hooks stay installed.", STYLE.dim);
    return api;
  }

                                                                          
                    
                                                                          
                                                                             
                                                                             
                                                                           
                                                                          

                                                                             
                                                                    
  const ENDPOINT_CRED_PARAMS = new Set([
    "api_key", "apikey", "api-key", "x-api-key", "apikeykey",
    "access_token", "accesstoken", "refresh_token", "refreshtoken", "id_token", "idtoken",
    "auth_token", "authtoken", "auth", "authorization", "token", "tokens",
    "secret", "client_secret", "clientsecret", "secret_key", "secretkey",
    "private_key", "privatekey", "password", "passwd", "pwd", "pass",
    "session", "session_id", "sessionid", "sid", "jwt", "bearer",
    "otp", "code", "passcode", "pin", "security_token", "securitytoken",
    "awsaccesskeyid", "x-amz-credential", "x-amz-security-token", "x-amz-signature",
    "sig", "signature", "hmac", "shared_key"
  ]);
                                                                           
                                           
  const SIGNATURE_PARAMS = new Set(["sig", "signature", "x-amz-signature", "hmac", "mac"]);
                                                                               
  const SIG_CONTEXT_PARAMS = new Set(["se", "sp", "sv", "sr", "st", "sktid", "skt", "ske", "sks", "skv", "rsct", "rsce", "rscd", "expires", "x-amz-algorithm", "x-amz-date", "x-amz-expires"]);

                                                                   
  function looksLikeEndpointCredential(v) {
    const s = String(v == null ? "" : v);
    if (s.length < 8 || s.length > 400) return false;
    if (/^(?:true|false|null|undefined|none|nan)$/i.test(s)) return false;
                                                      
    if (/^\d+$/.test(s)) return false;
    const classes = (/[a-z]/.test(s) ? 1 : 0) + (/[A-Z]/.test(s) ? 1 : 0) + (/\d/.test(s) ? 1 : 0) + (/[^A-Za-z0-9]/.test(s) ? 1 : 0);
    if (classes < 2) return false;
    return shannon(s) >= 2.5;
  }
  function looksLikeSignature(v) {
    const s = String(v == null ? "" : v);
    if (s.length < 16 || s.length > 200) return false;
    return /^[A-Za-z0-9+/_=-]+$/.test(s) && (/\d/.test(s) && /[A-Za-z]/.test(s));
  }
                                                        
  function looksLikePathToken(seg) {
    const s = String(seg || "");
    if (s.length < 24 || s.length > 400) return false;
    if (/^[0-9a-f]{24,}$/i.test(s)) return true;                              
    if (/^[A-Za-z0-9_-]{24,}$/.test(s) && /\d/.test(s)) return true;                        
    if (s.split(".").length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s)) return true;       
    return false;
  }

  function ingestEndpointCredential(label, value, why, urlText, channel) {
    if (!CONFIG.detectEndpointCredentials) return 0;
    const s = String(value == null ? "" : value);
    if (!s) return 0;
    const key = "epcred:" + label + "|" + fnv1a(s);
    if (notes.has(key)) return 0;
    const verdictInfo = classifyValue(s, label);
                                                                               
                                                                            
                                                                           
      if (verdictInfo.verdict === "arbitrary") return 0;
                                                                              
                                                                  
    const severity = verdictInfo.verdict === "fixture" ? "LOW"
      : SIGNATURE_PARAMS.has(String(label).toLowerCase()) ? "HIGH"
      : /pass|pwd|secret|token/i.test(String(label)) ? "CRITICAL" : "HIGH";
    ingestSecrets([{
      id: "endpoint-credential", name: String(label) + " in endpoint", category: "credential",
      severity, exposure: "leak", raw: s, length: s.length, shape: "endpoint-parameter",
      file: urlText || null, channel: channel || CH_NETWORK, verdict: verdictInfo.verdict
    }], urlText || "endpoint");
    addNote(key, {
      kind: "endpoint-credential", label: String(label), severity, channel: channel || CH_NETWORK,
      valueMasked: maskValue(s), length: s.length, url: urlText || null, why,
      note: "A credential is carried by the request URL. URLs end up in server access logs, proxy logs, browser history, the Referer header sent to every third party on the page, and any analytics script. Anything in a query string should be treated as published."
    });
    return 1;
  }

                                                                                
                                                                                
  function scanEndpointCredentials(rawUrl, channel) {
    if (!CONFIG.detectEndpointCredentials || !rawUrl) return 0;
    let found = 0;
    const urlText = String(rawUrl);
    try {
                                                                   
      const basic = /^[a-z][a-z0-9+.-]*:\/\/([^/\s:@]+):([^/\s@]{1,200})@/i.exec(urlText);
      if (basic) {
        const pw = decodeURIComponentSafe(basic[2]);
        const un = decodeURIComponentSafe(basic[1]);
        found += ingestEndpointCredential("password", pw, "basic auth password embedded in the URL (" + un + ")", redactURLString(urlText), channel);
        found += ingestEndpointCredential("username", un, "basic auth username embedded in the URL", redactURLString(urlText), channel);
      }
                                         
      const qSplit = urlText.indexOf("?");
      const hashSplit = urlText.indexOf("#");
      const queryPart = qSplit < 0 ? "" : urlText.slice(qSplit + 1, hashSplit > qSplit ? hashSplit : undefined);
      const fragPart = hashSplit < 0 ? "" : urlText.slice(hashSplit + 1);
      for (const part of [queryPart, fragPart]) {
        if (!part) continue;
        let pairs;
        try { pairs = new URLSearchParams(part); } catch (_) { continue; }
        for (const [name, value] of pairs) {
          const n = name.trim().toLowerCase();
          if (SIG_CONTEXT_PARAMS.has(n)) continue;
          if (SIGNATURE_PARAMS.has(n)) {
            if (looksLikeSignature(value)) found += ingestEndpointCredential(name, value, "signed-URL signature parameter grants access without a session", redactURLString(urlText), channel);
            continue;
          }
          if (!ENDPOINT_CRED_PARAMS.has(n)) continue;
          if (!looksLikeEndpointCredential(value)) continue;
          found += ingestEndpointCredential(name, value, "credential passed as the " + name + " query parameter", redactURLString(urlText), channel);
        }
      }
                                                                                  
                                                                                 
                                                                               
                                                                              
      const pathOnly = (() => { try { return new URL(urlText); } catch (_) { return null; } })();
      const sameOrigin = pathOnly && String(pathOnly.hostname || "").toLowerCase() === String(location.hostname || "").toLowerCase();
      const segs = sameOrigin ? String(pathOnly.pathname || "").split("/").filter(Boolean) : [];
      for (const seg of segs) {
        if (!looksLikePathToken(seg)) continue;
        if (/^(?:v\d+|api|assets?|static|build|dist|node_modules)$/i.test(seg)) continue;
        found += ingestEndpointCredential("path token", seg, "an unguessable token appears where a resource identifier belongs: /" + segs.join("/"), redactURLString(urlText), channel);
      }
    } catch (e) { fail("epcred.scan", e); }
    return found;
  }
  function redactURLString(s) {
    const t = String(s == null ? "" : s);
    try {
      return t.replace(/(\/\/[^/\s:@]+):([^/\s@]{1,200})@/i, "$1:[REDACTED]@")
        .replace(/([?&][A-Za-z0-9_.\-[\]]+=(?:[^&\s]{0,3}))[^&\s]{4,}/g, "$1[REDACTED]")
                                                                                
                                      
        .replace(/(\/[A-Za-z0-9._~\-]+)(\/[A-Za-z0-9_\-]{24,})(?=\/|$|[?#])/g, "$1/[REDACTED]");
    } catch (_) { return t.slice(0, 200); }
  }
  function decodeURIComponentSafe(s) {
    try { return decodeURIComponent(String(s)); } catch (_) { return String(s); }
  }

                                                                             

  const DIRLIST_SERVER_RE = /<title>\s*index of\s*([^<]*)<\/title>/i;
  const DIRLIST_HEADER_RE = /<h1>\s*index of\s*([^<]*)<\/h1>/i;
  const DIRLIST_PARA_RE = /<a\s+href="[^"]*">\s*Parent\s+Directory\s*<\/a>/i;
  const DIRLIST_DIRLBL_RE = /Directory listing for\s+([^<]*)/i;
  const S3_XML_LIST_RE = /<ListBucketResult[\s>]/i;
  const S3_XML_KEY_RE = /<Key>([^<]{1,400})<\/Key>/gi;
  const S3_XML_PREFIX_RE = /<Prefix>([^<]{1,400})<\/Prefix>/gi;
  const AZ_BLOB_RE = /<EnumerationResults\b/i;
  const APACHE_ROW_RE = /<a\s+href="([^"]{1,400})"[^>]*>([^<]{1,200})<\/a>\s*([^<\n]{0,40})/gi;

  const SENSITIVE_NAME_RE = /(?:^\.(?:env|git|svn|hg|aws|ssh|npmrc|netrc|htpasswd|dockerenv|DS_Store|gitignore)?$)|(?:^\.)|(?:\.(?:env|bak|old|orig|save|swp|swo|sql|sql\.gz|tar\.gz|tgz|zip|rar|7z|dump|pem|key|p12|pfx|jks|keystore|kdbx)$)|(?:^id_(?:rsa|dsa|ecdsa|ed25519)$)|(?:^\.?(?:htpasswd|netrc|npmrc|credentials|passwd|shadow|wp-config|configuration|config)\.?(?:php|bak)?$)/i;

  const listingStore = new Map();

  function sensitiveEntryReason(name) {
    const n = String(name || "").toLowerCase();
    if (/^\.env/.test(n)) return "environment file, which normally holds live secrets";
    if (/^\.(?:git|svn|hg)\//.test(n) || /^\.(?:git|svn|hg)$/.test(n)) return "version control metadata";
    if (/^\.aws\//.test(n) || /credentials$/.test(n)) return "credentials file";
    if (/^\.ssh\//.test(n) || /^id_(?:rsa|dsa|ecdsa|ed25519)$/.test(n)) return "private key";
    if (/^\.(?:npmrc|netrc|htpasswd|dockercfg)$/.test(n)) return "authentication dotfile";
    if (/\.(?:bak|old|orig|save|swp|swo)$/.test(n)) return "backup copy of a config file";
    if (/\.(?:sql|sql\.gz|dump|tar\.gz|tgz|zip|rar|7z)$/.test(n)) return "database or archive dump";
    if (/\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$/.test(n)) return "key or keystore file";
    if (/\.(?:log)$/.test(n)) return "log file";
    return null;
  }

  function isSensitiveEntryName(name) {
    const reason = sensitiveEntryReason(name);
    if (reason) return reason;
    const base = String(name || "").split("/").pop();
    return sensitiveEntryReason(base);
  }

                                                                            
                                                                              
                                       
const DIRLIST_SORT_LABELS = new Set(["name", "last modified", "size", "description", "date", "type", "permissions"]);

  function detectDirectoryListing(text, contentType, u, meta) {
    if (!CONFIG.detectDirectoryListings || !text || text.length > 3000000) return 0;
    const ct = String(contentType || "").toLowerCase();
    const body = String(text);
    let flavour = null, entries = [], rootPath = null, size = 0;

    if (S3_XML_LIST_RE.test(body)) {
      flavour = "s3-xml";
      let m;
      S3_XML_KEY_RE.lastIndex = 0;
      while ((m = S3_XML_KEY_RE.exec(body)) !== null && entries.length < CONFIG.maxDirectoryEntries) entries.push(m[1]);
      S3_XML_PREFIX_RE.lastIndex = 0;
      while ((m = S3_XML_PREFIX_RE.exec(body)) !== null && entries.length < CONFIG.maxDirectoryEntries) entries.push(m[1]);
    } else if (AZ_BLOB_RE.test(body)) {
      flavour = "azure-blob";
      const re = /<Name>([^<]{1,400})<\/Name>/gi;
      let m;
      while ((m = re.exec(body)) !== null && entries.length < CONFIG.maxDirectoryEntries) entries.push(m[1]);
    } else if (/html|text/i.test(ct) || /^\s*</.test(body)) {
      const t = /<title[^>]*>\s*index of\s*([^<]*)<\/title>/i.exec(body) || DIRLIST_HEADER_RE.exec(body);
      const d = DIRLIST_DIRLBL_RE.exec(body);
      const hasRowLink = /<a\s+href="[^"]+"/i.test(body);
      if (t && (DIRLIST_PARA_RE.test(body) || hasRowLink)) {
                                                                          
                                                                            
                                                                         
                                                                  
  const isNginx = /<table/i.test(body) && /(?:<th|last\s*modified)/i.test(body);
  const isApache = /<meta[^>]+name=["']generator["'][^>]+apache/i.test(body)
    || (/\[PARENTDIR\]|Parent\s+Directory/i.test(body) && /[?&]C=[NMDS]/i.test(body));
  flavour = isApache ? "apache-index" : isNginx ? "nginx-autoindex" : "http-index";
  rootPath = (t[1] || (d && d[1]) || "").trim();
  APACHE_ROW_RE.lastIndex = 0;
  let m, guard = 0;
  while ((m = APACHE_ROW_RE.exec(body)) !== null && entries.length < CONFIG.maxDirectoryEntries && guard++ < 4000) {
  const label = String(m[2] || "").trim();
  const href = String(m[1] || "").trim();
                                                                            
                                                                             
  if (!label || label === ".." || label === "../") continue;
  if (/^[?#]/.test(href) || /^[?&]C=[NMDS]/.test(href)) continue;
  if (DIRLIST_SORT_LABELS.has(label.toLowerCase())) continue;
  if (/^parent\s+directory$/i.test(label)) continue;
  if (/^\/?$/.test(href)) continue;
  entries.push(label);
  }
      } else if (d) {
        flavour = "generic-listing";
        rootPath = String(d[1] || "").trim();
        const re = /<a\s+href="([^"]{1,400})"/gi;
        let m;
        while ((m = re.exec(body)) !== null && entries.length < CONFIG.maxDirectoryEntries) {
          const label = String(m[1] || "");
          if (!label || label === "../" || label === "/") continue;
          entries.push(label.replace(/^\/+/, ""));
        }
      }
    } else {
                                                                             
                                                                             
                                                                              
                                                                            
      let j = null;
      try { j = safeParse(body); } catch (_) { j = null; }
      const arrs = [];
      if (Array.isArray(j)) arrs.push(j);
      else if (j && typeof j === "object") {
        for (const k of ["Contents", "contents", "Items", "items", "files", "entries", "keys", "value", "Value", "results", "objects", "blobs", "segments", "CommonPrefixes", "commonPrefixes", "prefixes"]) {
          if (Array.isArray(j[k])) arrs.push(j[k]);
        }
      }
      if (arrs.length) {
        const names = [];
        const push = (v) => { if (v && names.length < CONFIG.maxDirectoryEntries) names.push(String(v)); };
        for (const arr of arrs) {
          for (const c of arr.slice(0, CONFIG.maxDirectoryEntries)) {
            if (c == null) continue;
            if (typeof c === "string") { push(c); continue; }
            if (typeof c !== "object") continue;
                                                                                           
                                                            
            push(c.Key || c.key || c.Name || c.name || c.path || c.Prefix || c.prefix || c.blob || c.fileName || c.filename);
          }
        }
                                                                                 
                                                                               
        const bucketShape = arrs.some(a => a.length && a.some(c => c && typeof c === "object" &&
          ("Size" in c || "ETag" in c || "etag" in c || "LastModified" in c || "lastModified" in c ||
            (c.properties && ("contentLength" in c.properties || "content-length" in c.properties)))));
        const filenameish = names.filter(n => /\.[A-Za-z0-9]{1,8}$/.test(n) || /\/$/.test(n)).length;
        const looksLikeNames = names.length >= 3 && filenameish >= Math.ceil(names.length * 0.6);
        const askedForListing = /[?&](?:list-type|prefix|delimiter|list|marker|continuation-token|comp|restype)=/i.test(String((u && u.href) || "")) ||
          /\blists?\b|\blisting\b|\bindex\b|\bfiles?\b|\bobjects?\b|\bblobs?\b|\bbucket\b|\bcontainers?\b/i.test(String((u && u.pathname) || ""));
        if (names.length && (bucketShape || (looksLikeNames && askedForListing))) {
          flavour = "bucket-json";
          for (const n of names) if (entries.length < CONFIG.maxDirectoryEntries) entries.push(n);
          rootPath = (j && (j.Name || j.name || j.container || j.Container || j.prefix || j.Prefix)) || null;
        }
      }
    }

    if (!flavour || !entries.length) return 0;
    size = entries.length;
    const risky = [];
    const seenRisk = new Set();
    for (const e of entries) {
      const reason = isSensitiveEntryName(e);
      if (reason && !seenRisk.has(e)) { seenRisk.add(e); risky.push({ name: e, why: reason }); }
    }
    const key = "listing:" + (u ? u.href.split("?")[0] : "unknown");
    if (!listingStore.has(key)) {
      listingStore.set(key, {
        id: key, url: u ? redactURL(u) : "", path: u ? u.pathname : "",
        flavour, root: rootPath, entryCount: size, entries: entries.slice(0, CONFIG.maxDirectoryEntries),
        sensitive: risky, channel: meta && meta.channel ? meta.channel : CH_NETWORK,
        at: new Date().toISOString()
      });
    }
    addNote(key, {
      kind: "directory-listing", label: flavour, severity: risky.length ? "CRITICAL" : "HIGH",
      url: u ? redactURL(u) : "", path: u ? u.pathname : "", root: rootPath,
      entryCount: size, entries: entries.slice(0, 40), sensitive: risky,
      channel: (meta && meta.channel) || CH_NETWORK,
      note: "The server returned a browsable index of " + size + " entr" + (size === 1 ? "y" : "ies") +
        (risky.length
          ? ", including " + risky.length + " that should not be reachable: " + risky.slice(0, 6).map(r => r.name + " (" + r.why + ")").join(", ") + "."
          : ". No individually sensitive filename was visible, but the directory itself should not be listable.")
    });
    channelSeen[CH_NETWORK]++;
    return size;
  }

                                                                             
                                           
  function detectServedDotfile(text, u) {
    if (!text || !u) return 0;
    const p = String(u.pathname || "").toLowerCase();
    let kind = null, why = null;
    if (/(?:^|\/)\.env(?:\.[\w-]+)?$/.test(p)) { kind = "environment file"; why = "an environment file lists application secrets as KEY=value pairs"; }
    else if (/(?:^|\/)\.git\/(?:config|HEAD|index)$/.test(p)) { kind = "VCS metadata"; why = "source control metadata exposes the repository layout and often the remote URL with a credential in it"; }
    else if (/(?:^|\/)\.(?:aws|docker|npm|netrc|npmrc|htpasswd)$/.test(p) || /^\/\.aws\/credentials$/.test(p)) { kind = "authentication dotfile"; why = "this file exists to hold a credential"; }
    else if (/(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/.test(p)) { kind = "private key"; why = "a private key was served to the browser"; }
    if (!kind) return 0;
    const key = "dotfile:" + u.pathname;
    addNote(key, {
      kind: "served-dotfile", label: kind, severity: "CRITICAL",
      url: redactURL(u), path: u.pathname, channel: CH_NETWORK,
      note: "The server returned the contents of a " + kind + ": " + why + ". This is a direct disclosure, not an inference."
    });
                                                               
    try {
      const hits = scanSecrets(String(text).slice(0, 200000), "served:" + u.pathname);
      if (hits && hits.length) ingestSecrets(hits, "served:" + u.pathname);
    } catch (e) { fail("dotfile.scan", e); }
    return 1;
  }

                                                                            

  const SENSITIVE_PATH_RULES = [
    [/(?:^|\/)\.git(?:\/|$)/i, "version control metadata", "CRITICAL"],
    [/(?:^|\/)\.svn(?:\/|$)/i, "version control metadata", "CRITICAL"],
    [/(?:^|\/)\.hg(?:\/|$)/i, "version control metadata", "CRITICAL"],
    [/(?:^|\/)\.env(?:\.[\w-]+)?$/i, "environment file", "CRITICAL"],
    [/(?:^|\/)\.aws\/credentials$/i, "AWS credentials file", "CRITICAL"],
    [/(?:^|\/)\.ssh\//i, "SSH key material", "CRITICAL"],
    [/(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i, "private key", "CRITICAL"],
    [/\.(?:pem|p12|pfx|jks|keystore|kdbx)$/i, "key or keystore file", "CRITICAL"],
    [/(?:^|\/)\.(?:npmrc|netrc|htpasswd|dockercfg)$/i, "authentication dotfile", "HIGH"],
    [/(?:^|\/)wp-config\.php(?:\.bak|\.old|\.save|\.orig|\.txt)?$/i, "WordPress configuration with database credentials", "CRITICAL"],
    [/(?:^|\/)web\.config$/i, "IIS configuration", "HIGH"],
    [/(?:^|\/)\.htaccess$/i, "server configuration", "MEDIUM"],
    [/(?:^|\/)(?:backup|backups|dump|dumps)(?:\/|$)/i, "backup directory", "HIGH"],
    [/(?:^|\/)\.DS_Store$/i, "macOS directory metadata", "LOW"],
    [/(?:^|\/)\.gitignore$/i, "repository ignore list", "LOW"],
    [/\.(?:bak|old|orig|save|swp|swo|sql|sql\.gz|dump|tar\.gz|tgz|zip|rar|7z)$/i, "backup or database dump", "HIGH"],
    [/(?:^|\/)actuator\/(?:env|configprops|heapdump|mappings)$/i, "Spring Boot management endpoint", "CRITICAL"],
    [/(?:^|\/)(?:server-status|server-info|phpinfo\.php|jolokia|trace\.axd|elmah\.axd)$/i, "diagnostic endpoint", "HIGH"],
    [/(?:^|\/)(?:admin|administrator|wp-admin|manager\/html)(?:\/|$)/i, "administrative interface", "MEDIUM"],
    [/(?:^|\/)\.well-known\/(?!security\.txt|openid-configuration|assetlinks\.json|webfinger|mta-sts)[^/]+/i, "well-known file that is not the published set", "MEDIUM"]
  ];

  function noteSensitivePath(pathOrUrl, channel, extra) {
    if (!CONFIG.detectSensitivePaths) return 0;
    const p = String(pathOrUrl == null ? "" : pathOrUrl);
    if (!p || p.length > 1000) return 0;
    let path = p;
    try { path = new URL(p).pathname; } catch (_) {                   }
    const hit = [];
    for (const [re, why, severity] of SENSITIVE_PATH_RULES) if (re.test(path)) hit.push({ why, severity });
    if (!hit.length) return 0;
    const top = hit[0];
    const key = "senspath:" + path;
    if (notes.has(key)) return 0;
    addNote(key, {
      kind: "sensitive-path", label: top.why, severity: top.severity,
      path, url: /^https?:/i.test(p) ? redactURLString(p) : null,
      channel: channel || CH_NETWORK, allReasons: hit.map(h => h.why),
      note: "A reachable path points at " + top.why + ": " + path +
        (hit.length > 1 ? " (also " + hit.slice(1).map(h => h.why).join(", ") + ")" : "") +
        (extra ? " " + extra : "")
    });
    return 1;
  }

                                                                                 
  function scanSourceForSensitivePaths(text, fileLabel, channel) {
    if (!CONFIG.detectSensitivePaths || !text || text.length > 4000000) return 0;
    let found = 0;
    try {
      const re = /["'`(\[](\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,300})["'`)\]]/g;
      let m, guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 4000) {
        found += noteSensitivePath(m[1], channel || CH_STATIC, "referenced in " + (fileLabel || "source"));
      }
    } catch (e) { fail("senspath.src", e); }
    return found;
  }

                                                                            

                                                                         
  function sevRank(s) { const v = SEV_RANK[String(s || "").toUpperCase()]; return v === undefined ? -1 : v; }

  function listDirectories(opts) {
    const o = opts || {};
    const all = [...listingStore.values()];
    const rows = all.filter(d => !o.path || String(d.path || "").indexOf(o.path) >= 0);
    return rows.map(d => ({
      url: d.url, path: d.path, flavour: d.flavour, root: d.root,
      entryCount: d.entryCount, entries: o.entries === false ? undefined : d.entries,
      sensitive: d.sensitive, at: d.at
    }));
  }

  function listSensitivePaths(opts) {
    const o = opts || {};
    return [...notes.values()]
      .filter(n => n.kind === "sensitive-path")
      .filter(n => !o.severity || sevRank(n.severity) >= sevRank(o.severity))
      .map(n => ({ path: n.path, url: n.url || null, why: n.label, severity: n.severity, channel: n.channel, reasons: n.allReasons || [n.label], at: n.at }))
      .sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  }

                                                                                
                                                                      
  function exposedSummary(opts) {
    const o = opts || {};
    const items = [];
    for (const s of listSecrets({})) {
      items.push({
        kind: "secret", severity: s.severity, title: s.name, category: s.category,
        valueMasked: s.valueMasked, value: s.rawValue || null, length: s.length,
        where: s.file || null, exposure: s.exposure, channel: s.channel || null,
        confidence: s.confidence || null, verdict: s.verdict || null
      });
    }
    for (const n of notes.values()) {
      if (n.kind === "endpoint-credential") {
        items.push({
          kind: "endpoint-credential", severity: n.severity, title: n.label + " in endpoint URL",
          category: "credential", valueMasked: n.valueMasked, value: CONFIG.revealSecrets ? n.value : null,
          length: n.length, where: n.url, exposure: "leak", channel: n.channel, why: n.why
        });
      } else if (n.kind === "directory-listing") {
        items.push({
          kind: "directory-listing", severity: n.severity, title: "directory index: " + n.flavour,
          category: "exposure", where: n.url || n.path, exposure: "leak", channel: n.channel,
          entryCount: n.entryCount, sensitiveEntries: n.sensitive || []
        });
      } else if (n.kind === "served-dotfile") {
        items.push({
          kind: "served-dotfile", severity: n.severity, title: "served " + n.label,
          category: "exposure", where: n.url, exposure: "leak", channel: n.channel
        });
      } else if (n.kind === "pii-exposure") {
        items.push({
          kind: "pii-exposure", severity: n.severity, title: "personal data in response: " + n.summary,
          category: "privacy", where: n.method ? (n.method + " " + (n.url || n.path)) : (n.url || n.path),
          exposure: "leak", channel: n.channel, piiKinds: n.piiKinds || []
        });
      } else if (n.kind === "pii-route") {
        items.push({
          kind: "pii-route", severity: n.severity, title: "likely personal-data route: " + n.path,
          category: "privacy", where: n.path, exposure: "reachable", channel: n.channel
        });
      } else if (n.kind === "sensitive-path") {
        items.push({
          kind: "sensitive-path", severity: n.severity, title: n.label + ": " + n.path,
          category: "exposure", where: n.path, exposure: "reachable", channel: n.channel
        });
      }
    }
    const rows = o.severity ? items.filter(i => sevRank(i.severity) >= sevRank(o.severity)) : items;
    rows.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || String(a.title).localeCompare(String(b.title)));
    return rows;
  }

  function reportExposed(opts) {
    const rows = exposedSummary(opts);
    const bySev = {};
    for (const r of rows) bySev[r.severity] = (bySev[r.severity] || 0) + 1;
                                                                                
                                                                        
    if (CONFIG.revealSecrets) {
      styled("[x-ray-eye] EXPOSED: " + rows.length + " item(s). Credential values are shown in cleartext because revealSecrets is on. Do not share this output or a screenshot of it.", STYLE.warn);
    } else {
      styled("[x-ray-eye] EXPOSED: " + rows.length + " item(s)", STYLE.head);
    }
    const order = Object.keys(bySev).sort((a, b) => sevRank(b) - sevRank(a));
    if (order.length) console.log("  " + order.map(k => k + " " + bySev[k]).join("   "));
    for (const r of rows) {
      const val = r.value ? "  " + r.value : (r.valueMasked ? "  " + r.valueMasked : "");
      console.log("  [" + (r.severity || "INFO") + "] " + r.kind + ": " + r.title + val + "\n      " + (r.where || ""));
    }
    const dirs = listDirectories({});
    if (dirs.length) console.log("\n  Directory indexes: " + dirs.length + " (" + dirs.map(d => d.entryCount + " entries at " + d.path).join("; ") + ")");
    const sp = listSensitivePaths({});
    if (sp.length) console.log("  Sensitive paths:  " + sp.length + " (" + sp.slice(0, 12).map(x => x.path).join(", ") + (sp.length > 12 ? ", ..." : "") + ")");
    return api;
  }

  function reportDirectories() {
    const dirs = listDirectories({});
    console.log("[x-ray-eye] DIRECTORY LISTINGS: " + dirs.length);
    if (!dirs.length) { console.log("  none observed"); return api; }
    for (const d of dirs) {
      console.log("  [" + (d.sensitive && d.sensitive.length ? "CRITICAL" : "HIGH") + "] " + d.flavour + "  " + (d.url || d.path));
      console.log("      " + d.entryCount + " entries" + (d.root ? "  root=" + d.root : ""));
      if (d.sensitive && d.sensitive.length) {
        for (const s of d.sensitive) console.log("      !! " + s.name + "  (" + s.why + ")");
      }
      const head = (d.entries || []).slice(0, 20);
      if (head.length) console.log("      " + head.join(", ") + ((d.entries || []).length > 20 ? ", ..." : ""));
    }
    return api;
  }

                                                                          
                                                                              
                                                                         
                                                                          
  const PROBE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.staging",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info", "/actuator/mappings",
    "/actuator/configprops", "/actuator/beans", "/actuator/httptrace",
    "/config.json", "/config.js", "/config.yaml", "/bootstrap", "/__config", "/__env",
    "/env.json", "/settings.json", "/runtime-config.js",
    "/internal/config/anonymous", "/api/config", "/api/config/public", "/api/settings", "/api/env",
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui/", "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/graphql", "/graphiql", "/playground", "/console",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/wp-json", "/wp-config.php.bak", "/xmlrpc.php",
    "/elmah.axd", "/trace.axd", "/metrics", "/healthz", "/readyz",
    "/.well-known/security.txt", "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
    "/admin", "/administrator", "/debug", "/trace", "/jolokia", "/h2-console", "/console/",
    "/robots.txt", "/sitemap.xml",
    "/manifest.json", "/asset-manifest.json", "/build-manifest.json", "/version", "/info"
  ];

  function probe(opts) {
    const o = opts || {};
    const paths = (o.paths || PROBE_PATHS).slice(0, 200);
    const origin = String(o.origin || location.origin).replace(/\/$/, "");
    const target = origin + (paths[0] || "");

    if (!nativeFetch) { styled("[x-ray-eye] fetch is unavailable, cannot probe.", STYLE.warn); return null; }

    if (o.dryRun) {
      nativeConsole.log("[x-ray-eye] probe dry run. " + paths.length + " GET requests would be sent to " + origin + ":");
      for (const p of paths) nativeConsole.log("  " + origin + p);
      return { dryRun: true, origin, paths };
    }

    if (!(o.confirm === "AUTHORIZED" || CONFIG.allowActiveProbe === true || CONFIG.activeRead === true)) {
      styled("[x-ray-eye] probe() is ACTIVE. It sends " + paths.length + " requests the application never sent.", STYLE.warn);
      styled("[x-ray-eye] Check the target's scope and rules of engagement first. Every request below will be logged by the target.", STYLE.warn);
      styled("[x-ray-eye] Preview with xrayeye.probe({ dryRun: true }). To run, use xrayeye.probe({ confirm: 'AUTHORIZED' }).", STYLE.warn);
      for (let i = 0; i < Math.min(paths.length, 12); i++) nativeConsole.log("  " + origin + paths[i]);
      if (paths.length > 12) nativeConsole.log("  ... and " + (paths.length - 12) + " more");
      return null;
    }

    styled("[x-ray-eye] probe: sending " + paths.length + " GET requests to " + origin + ". Logged below.", STYLE.warn);
    for (const p of paths) nativeConsole.log("  GET " + origin + p);
    stats.probes += paths.length;

    const started = nowMs();
    const results = [];
    const queue = paths.slice();
    const concurrency = Math.max(1, Math.min(6, Number(o.concurrency) || 3));

    const runner = async () => {
      while (queue.length) {
        const p = queue.shift();
        const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = ctl ? setT(() => ctl.abort(), Number(o.timeoutMs) || 8000) : null;
        const t0 = nowMs();
        try {
          const res = await nativeFetch.call(window, origin + p, {
            method: "GET",
            credentials: o.credentials || "same-origin",
            redirect: "manual",
            signal: ctl ? ctl.signal : undefined
          });
          const ct = res.headers.get("content-type") || "";
          let preview = "";
          if (/json|text|html|xml|yaml/i.test(ct)) {
            try { preview = clip(redactString(await res.text()), 400); } catch (_) {}
          }
          safeCancel(res.body);
          const row = { path: p, status: res.status, contentType: ct, bytes: res.headers.get("content-length") || "", preview, ms: Math.round(nowMs() - t0) };
          results.push(row);
          record({
            source: "probe", observed: true, url: origin + p, method: "GET",
            status: res.status, responseContentType: ct,
            responseHeaders: collectResponseHeaders(res.headers),
            responseBody: preview,
            pii: detectPII(preview),
            durationMs: row.ms
          });
          if (res.status !== 404 && res.status !== 401 && res.status !== 403) {
            addNote("probe:" + origin + p, { kind: "surface", host: origin, path: p, reasons: ["probe returned HTTP " + res.status], status: res.status });
          }
        } catch (e) {
          results.push({ path: p, status: 0, error: String((e && e.message) || e), ms: Math.round(nowMs() - t0) });
        } finally {
          if (timer) clearT(timer);
        }
      }
    };

    const runners = [];
    for (let i = 0; i < concurrency; i++) runners.push(runner());
    Promise.all(runners).then(() => {
      const interesting = results.filter(r => r.status && r.status !== 404 && r.status !== 401 && r.status !== 403);
      styled("[x-ray-eye] probe finished in " + Math.round(nowMs() - started) + "ms. " + interesting.length + " of " + results.length + " responded with something other than 404/401/403.", STYLE.ok);
      if (interesting.length && nativeConsole.table) nativeConsole.table(interesting);
      styled("[x-ray-eye] Results are recorded as normal findings. xrayeye.report({ probe: true }) is not needed, they are in the store.", STYLE.dim);
    }).catch(e => fail("probe", e));

    return { origin, count: paths.length, started: true };
  }

                                                                          
                                                                      
                                                                          
  function installFetch() {
    if (!nativeFetch) return;
    const original = window.fetch;

    const wrapper = function fetch(...args) {
      let ctx = null;
      if (active) {
        try { ctx = captureFetchRequest(args[0], args[1]); } catch (e) { fail("fetch.capture", e); }
      }
      const p = Reflect.apply(original, this, args);
      if (ctx) {
        try {
          if (p && typeof p.then === "function") {
                                                                                            
            p.then(res => onFetchResponse(ctx, res), () => onFetchError(ctx));
          }
        } catch (e) { fail("fetch.attach", e); }
      }
      return p;
    };

    window.fetch = wrapper;
    cleanups.push(() => { if (window.fetch === wrapper) window.fetch = original; });
    hooks.push("fetch");
  }

  const RAW_AUTH_HEADER_RE = /^(authorization|x-api-key|api-key|x-auth-token|auth-token|x-access-token|access-token|x-id-token|id-token|x-jwt|jwt|proxy-authorization)$/;

                                                                   
  function rawAuthValues(headersLike) {
    const out = [];
    if (!headersLike) return out;
    try {
      const visit = (name, value) => {
        const lk = String(name).toLowerCase();
        if (RAW_AUTH_HEADER_RE.test(lk) && typeof value === "string" && value) out.push({ name: lk, value });
      };
      if (typeof headersLike.forEach === "function") headersLike.forEach((v, k) => visit(k, v));
      else if (Array.isArray(headersLike)) for (const p of headersLike) if (p && p.length >= 2) visit(p[0], p[1]);
      else if (typeof headersLike === "object") for (const k of Object.keys(headersLike)) visit(k, headersLike[k]);
    } catch (_) {}
    return out;
  }

  function captureFetchRequest(input, init) {
    stats.fetch++;
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    const ctx = { url: "", method: "GET", headers: {}, bodyInfo: null, requestClone: null, startedAt: nowMs() };

                                                                                
                                                                   
    try {
      if (isRequest) rawAuthValues(input.headers).forEach(x => analyzeJWT(x.value, "request header:" + x.name));
      if (init && init.headers) rawAuthValues(init.headers).forEach(x => analyzeJWT(x.value, "request header:" + x.name));
    } catch (e) { fail("fetch.jwt", e); }

    if (isRequest) {
      ctx.url = input.url;
      ctx.method = input.method || "GET";
      ctx.headers = headersToObject(input.headers);
    } else {
      ctx.url = String(input);
    }
    if (init && init.method) ctx.method = String(init.method).toUpperCase();
    if (init && init.headers) Object.assign(ctx.headers, headersToObject(init.headers));

    if (init && init.body !== undefined && init.body !== null) {
      ctx.bodyInfo = describeBody(init.body);
    } else if (isRequest && input.body && !input.bodyUsed) {
                                                                                       
      if (TEXTUAL.test(ctx.headers["content-type"] || "")) {
        try { ctx.requestClone = input.clone(); } catch (_) {}
      } else {
        ctx.bodyInfo = { display: "[" + (ctx.headers["content-type"] || "binary") + " body]" };
      }
    }
    return ctx;
  }

  function onFetchResponse(ctx, res) {
    try {
                                                                            
      const ct = (res.headers && res.headers.get("content-type")) || "";
      let clone = null;
      const specLike = looksLikeSpecURL((parseURL(ctx.url) || {}).pathname || "");
      if (res.body && res.type !== "opaque" && TEXTUAL.test(ct) && !/event-stream/i.test(ct)) {
        if (CONFIG.showResponseBody || specLike) {
          try { clone = res.clone(); } catch (_) {}
        }
      }
      const meta = {
        source: "fetch", url: ctx.url, method: ctx.method, observed: true,
        requestHeaders: ctx.headers, requestContentType: ctx.headers["content-type"] || "",
        status: res.status, responseContentType: ct,
        responseHeaders: collectResponseHeaders(res.headers),
        durationMs: nowMs() - ctx.startedAt,
        specLike
      };
      finishFetch(ctx, meta, clone).catch(e => fail("fetch.finish", e));
    } catch (e) {
      fail("fetch.response", e);
    }
  }

  function safeParse(text) {
    try { return JSON.parse(text); } catch (_) { return null; }
  }

                                                                           
                                          
  function postProcess(meta) {
    try {
      const u = parseURL(meta.url);
      if (!u) return;
      const text = meta.responseText;

                                                                     
      if (text && CONFIG.detectDirectoryListings) {
        try {
          detectDirectoryListing(text, meta.responseContentType, u, meta);
          detectServedDotfile(text, u);
        } catch (e) { fail("postProcess.listing", e); }
      }

      if (text && (looksLikeSpecURL(u.pathname) || SPEC_CONTENT_HINT.test(meta.responseContentType || ""))) {
        const j = meta.responseJson || safeParse(text);
        if (j) { meta.responseJson = j; ingestSpecBody(j, u.href); }
      }
      if (text && (GQL_PATH_RE.test(u.pathname) || GQL_CT_RE.test(String(meta.responseContentType || "")))) {
        harvestGraphQLSuggestions(text, u.href);
      }

                                                                                 
      if (text && CONFIG.analyzeJWTs) {
        analyzeJWTsInJSON(safeParse(text), "response");
      }

                                                                              
      if (text && CONFIG.harvestBodyFields) {
        const j = meta.responseJson || safeParse(text);
        if (j && typeof j === "object") meta.bodyFields = harvestBodyFields(j);
      }

      const oauth = analyzeOAuth(u, meta);
      if (oauth && oauth.flow === "discovery" && !meta.responseJson) {
        meta.responseJson = text ? safeParse(text) : null;
        analyzeOAuth(u, meta);
      }
      noteRSC(u, meta);
      noteAIEndpoint(u);

                                                                               
      if (CONFIG.captureCSP && meta.responseHeaders) {
        const cspHeader = meta.responseHeaders["content-security-policy"] ||
          meta.responseHeaders["content-security-policy-report-only"];
        if (cspHeader) {
          const csp = parseCSP(cspHeader);
          if (!meta.responseHeaders["content-security-policy"]) csp.reportOnly = true;
          noteCSP(csp, u.origin);
        }
      }

                                                                                
      if (/(?:^|\/)(?:robots\.txt|sitemap[^/]*\.xml)$/i.test(u.pathname) && text) {
        try { parseRobotsOrSitemap(text, u.href); } catch (e) { fail("robots", e); }
      }
    } catch (e) {
      fail("postProcess", e);
    }
  }

  const SPEC_CONTENT_HINT = /json|yaml|yml|html|plain/i;

  async function finishFetch(ctx, meta, clone) {
    let reqInfo = ctx.bodyInfo;
    if (!reqInfo && ctx.requestClone) {
      try {
        const r = await readPreview(ctx.requestClone.body, CONFIG.maxRequestBytesRead);
        reqInfo = describeText(r.text, CONFIG.maxRequestBodyChars);
      } catch (_) {}
    }
    if (reqInfo) { meta.requestBody = reqInfo.display; meta.requestJson = reqInfo.json; }
    if (clone) {
      try {
        const cap = meta.specLike ? CONFIG.maxSpecBytes : CONFIG.maxResponseBytesRead;
        const r = await readPreview(clone.body, cap);
        if (r.text) {
          meta.responseBody = describeText(r.text, CONFIG.maxResponseBodyChars).display;
          meta.pii = detectPII(r.text);
          meta.responseText = r.text;
                                                                       
                                                                    
          if (r.truncated && meta.specLike) {
            addNote("spec-truncated:" + meta.url, {
              kind: "spec-truncated", url: redactHref(meta.url),
              bytesRead: r.text.length, cap,
              note: "The API description was larger than the read budget, so it could not be parsed. Raise CONFIG.maxSpecBytes and reload to ingest it."
            });
          }
        }
      } catch (_) {}
    }
                                                                           
                                                                            
                                                                              
                                                                              
                                                          
    const reflected = noteReflections(meta);
    if (reflected) meta.scoreBonus = (meta.scoreBonus || 0) + 20;
                                                                           
                                                                       
    noteUrlCredentials(meta);
                                                                             
                                                                               
                                                  
    noteLeaks(meta);
                                                                            
                                                                     
    noteParameters(meta);
    postProcess(meta);
    record(meta);

                                                                             
                                       
                                                        
                                                                                  
                                                                       
                                                        
                                                            
    if (meta.responseText) {
      try {
        const _rowsToShow = CONFIG.maxTableRows || 5;
        const _previewLines = 25;

                                                                            
        let _parsed;
        let _isJson = false;
        try { _parsed = JSON.parse(meta.responseText); _isJson = true; } catch (_) {}

        if (_isJson && _parsed !== null && typeof _parsed === "object") {
                                                                            
          const _foundArrays = [];
          const _visited = new WeakSet();

          (function _findArrays(value, path) {
            if (!value || typeof value !== "object" || _visited.has(value)) return;
            _visited.add(value);
            if (Array.isArray(value)) {
              if (value.length > 0) _foundArrays.push({ path, rows: value });
                                                                          
              value.forEach(function(item, idx) {
                _findArrays(item, path + "[" + idx + "]");
              });
              return;
            }
            for (const [k, child] of Object.entries(value)) {
              _findArrays(child, path + "." + k);
            }
          })(_parsed, meta.url);

          if (_foundArrays.length) {
                                                                           
            for (const { path, rows } of _foundArrays) {
              nativeConsole.log(
                "%c" + path + " ” showing " + Math.min(_rowsToShow, rows.length) +
                " of " + rows.length + " rows",
                "color: #4f8ef7; font-weight: bold;"
              );
              if (nativeConsole.table) nativeConsole.table(rows.slice(0, _rowsToShow));
            }
          } else {
                                                                           
            const _lines = JSON.stringify(_parsed, null, 2).split("\n");
            nativeConsole.log(
              "%c[x-ray-eye] " + meta.url + " ” first " + _previewLines + " lines",
              "color: #4f8ef7; font-weight: bold;"
            );
            nativeConsole.log(
              "%c" + _lines.slice(0, _previewLines).join("\n") +
              (_lines.length > _previewLines ? "\n…" : ""),
              "color: #a0c4ff;"
            );
          }

        } else {
                                                                          
                                                                           
          const _raw = _isJson
            ? String(_parsed)                                              
            : meta.responseText;                         
          const _lines = _raw.split("\n");
          nativeConsole.log(
            "%c[x-ray-eye] " + meta.url + " ” first " + _previewLines + " lines",
            "color: #4f8ef7; font-weight: bold;"
          );
          nativeConsole.log(
            "%c" + _lines.slice(0, _previewLines).join("\n") +
            (_lines.length > _previewLines ? "\n…" : ""),
            "color: #a0c4ff;"
          );
        }

      } catch (_previewErr) {                                  }
    }
                                                                            
  }

  function onFetchError(ctx) {
    try {
      if (ctx.requestClone && ctx.requestClone.body) safeCancel(ctx.requestClone.body);
      const info = ctx.bodyInfo;
      record({
        source: "fetch", url: ctx.url, method: ctx.method, observed: true,
        requestHeaders: ctx.headers, requestContentType: ctx.headers["content-type"] || "",
        requestBody: info ? info.display : "", requestJson: info ? info.json : undefined, status: 0,
        failed: true
      });
    } catch (e) {
      fail("fetch.error", e);
    }
  }

  function installXHR() {
    if (typeof XMLHttpRequest === "undefined") return;
    const proto = XMLHttpRequest.prototype;
    const origOpen = proto.open;
    const origSend = proto.send;
    const origSetHeader = proto.setRequestHeader;
    const meta = new WeakMap();

    const open = function open(method, url) {
      if (active) {
        try {
          const prev = meta.get(this);
          if (prev && prev.handler) { try { this.removeEventListener("loadend", prev.handler); } catch (_) {} }
          meta.set(this, { method: String(method || "GET").toUpperCase(), url: String(url), headers: {}, handler: null });
        } catch (e) { fail("xhr.open", e); }
      }
      return Reflect.apply(origOpen, this, arguments);
    };

    const setRequestHeader = function setRequestHeader(name, value) {
      if (active) {
        try {
          const m = meta.get(this);
          if (m) putHeader(m.headers, name, value);
                                                                         
          analyzeJWT(value, "xhr request header:" + String(name).toLowerCase());
        } catch (e) { fail("xhr.header", e); }
      }
      return Reflect.apply(origSetHeader, this, arguments);
    };

    const send = function send(body) {
      if (active) {
        try {
          const m = meta.get(this);
          if (m) {
                                                                        
            if (m.handler) { try { this.removeEventListener("loadend", m.handler); } catch (_) {} }
            stats.xhr++;
            const info = describeBody(body);
            const xhr = this;
            const startedAt = nowMs();
            m.handler = () => onXhrDone(xhr, m, info, startedAt);
            this.addEventListener("loadend", m.handler, { once: true });
          }
        } catch (e) { fail("xhr.send", e); }
      }
      return Reflect.apply(origSend, this, arguments);
    };

    proto.open = open;
    proto.setRequestHeader = setRequestHeader;
    proto.send = send;
    cleanups.push(() => {
      if (proto.open === open) proto.open = origOpen;
      if (proto.setRequestHeader === setRequestHeader) proto.setRequestHeader = origSetHeader;
      if (proto.send === send) proto.send = origSend;
    });
    hooks.push("xhr");
  }

  function onXhrDone(xhr, m, info, startedAt) {
    try {
      const ct = xhr.getResponseHeader("content-type") || "";
      let text = "";
      const respHeaders = CONFIG.captureResponseHeaders && typeof xhr.getAllResponseHeaders === "function"
        ? parseRawHeaderString(safeGetAllHeaders(xhr)) : null;
      if (CONFIG.showResponseBody && TEXTUAL.test(ct)) {
        try {
          if (xhr.responseType === "" || xhr.responseType === "text") text = xhr.responseText || "";
          else if (xhr.responseType === "json" && xhr.response !== null) text = JSON.stringify(xhr.response) || "";
          else if (xhr.responseType === "document" || xhr.responseType === "blob") text = "";
        } catch (_) {}
      }
      const meta = {
        source: "xhr", url: m.url, method: m.method, observed: true,
        requestHeaders: m.headers, requestContentType: m.headers["content-type"] || "",
        requestBody: info ? info.display : "", requestJson: info ? info.json : undefined,
        status: xhr.status, responseContentType: ct, responseHeaders: respHeaders,
        durationMs: nowMs() - startedAt
      };
      const specLike = looksLikeSpecURL((parseURL(m.url) || {}).pathname || "");
      const bodyCap = specLike ? CONFIG.maxSpecBytes : RAW_CAP;
      if (text) {
        const body = text.slice(0, bodyCap);
        meta.responseBody = describeText(body, CONFIG.maxResponseBodyChars).display;
        meta.pii = detectPII(body);
        meta.responseText = body;
        if (text.length > bodyCap && specLike) {
          addNote("spec-truncated:" + m.url, {
            kind: "spec-truncated", url: redactHref(m.url),
            bytesRead: body.length, cap: bodyCap,
            note: "The API description was larger than the read budget, so it could not be parsed. Raise CONFIG.maxSpecBytes and reload to ingest it."
          });
        }
      }
      meta.specLike = specLike;
      postProcess(meta);
      record(meta);
    } catch (e) {
      fail("xhr.done", e);
    }
  }

  function safeGetAllHeaders(xhr) {
    try { return xhr.getAllResponseHeaders() || ""; } catch (_) { return ""; }
  }

  function installBeacon() {
    if (typeof navigator === "undefined" || typeof navigator.sendBeacon !== "function") return;
    const original = navigator.sendBeacon;
    const hadOwn = Object.prototype.hasOwnProperty.call(navigator, "sendBeacon");
    const wrapper = function sendBeacon(url, data) {
      if (active) {
        try {
          stats.beacon++;
          const info = describeBody(data);
          record({
            source: "beacon", url, method: "POST", observed: true,
            requestBody: info ? info.display : "", requestJson: info ? info.json : undefined,
            requestContentType: (data && data.type) || ""
          });
        } catch (e) { fail("beacon", e); }
      }
      return Reflect.apply(original, this, arguments);
    };
    navigator.sendBeacon = wrapper;
    cleanups.push(() => {
      if (navigator.sendBeacon !== wrapper) return;
      if (hadOwn) navigator.sendBeacon = original; else delete navigator.sendBeacon;
    });
    hooks.push("beacon");
  }

  function describeWsData(d) {
    if (typeof d === "string") return describeText(d, 400).display;
    if (typeof Blob !== "undefined" && d instanceof Blob) return "[Blob " + d.size + " bytes]";
    if (d && typeof d.byteLength === "number") return "[binary " + d.byteLength + " bytes]";
    return "[unknown]";
  }

  function instrumentSocket(ws, finding) {
    const limit = Math.max(1, Math.floor(CONFIG.maxWsSamples / 2));
    let inCount = 0;
    let outCount = 0;
    const push = (dir, data) => {
      if (finding.wsSamples.length < CONFIG.maxWsSamples) finding.wsSamples.push({ dir, data: describeWsData(data) });
    };
    ws.addEventListener("message", ev => {
      if (!active || inCount >= limit) return;
      inCount++;
      try { push("in", ev.data); } catch (e) { fail("ws.message", e); }
    });
    const origSend = ws.send;
    ws.send = function send(data) {
      if (active && outCount < limit) {
        outCount++;
        try { push("out", data); } catch (e) { fail("ws.send", e); }
      }
      return Reflect.apply(origSend, this, arguments);
    };
  }

  function installWebSocket() {
    const Original = window.WebSocket;
    if (typeof Original !== "function" || typeof Proxy === "undefined") return;
    const proxy = new Proxy(Original, {
      construct(Target, args, newTarget) {
        const ws = Reflect.construct(Target, args, newTarget);
        if (active) {
          try {
            stats.websocket++;
            const finding = record({ source: "websocket", url: args[0], method: "WEBSOCKET", observed: true });
            if (finding) instrumentSocket(ws, finding);
          } catch (e) { fail("ws.construct", e); }
        }
        return ws;
      }
    });
    window.WebSocket = proxy;
    cleanups.push(() => { if (window.WebSocket === proxy) window.WebSocket = Original; });
    hooks.push("websocket");
  }

  function installEventSource() {
    const Original = window.EventSource;
    if (typeof Original !== "function" || typeof Proxy === "undefined") return;
    const proxy = new Proxy(Original, {
      construct(Target, args, newTarget) {
        const es = Reflect.construct(Target, args, newTarget);
        if (active) {
          try {
            stats.eventsource++;
            const finding = record({
              source: "eventsource", url: args[0], method: "GET", observed: true,
              responseContentType: "text/event-stream"
            });
            let n = 0;
            if (es && typeof es.addEventListener === "function") {
              es.addEventListener("message", ev => {
                if (!active || !finding) return;
                const limit = Math.max(1, Math.floor(CONFIG.maxWsSamples / 2));
                if (n++ >= limit) return;
                try { finding.wsSamples.push({ dir: "in", data: describeWsData(ev.data) }); } catch (e) { fail("sse.message", e); }
              });
            }
          } catch (e) { fail("sse.construct", e); }
        }
        return es;
      }
    });
    window.EventSource = proxy;
    cleanups.push(() => { if (window.EventSource === proxy) window.EventSource = Original; });
    hooks.push("eventsource");
  }

                                                                              
                                                                               
                                                               
  function installWorker() {
    for (const name of ["Worker", "SharedWorker"]) {
      const Original = window[name];
      if (typeof Original !== "function" || typeof Proxy === "undefined") continue;
      const proxy = new Proxy(Original, {
        construct(Target, args, newTarget) {
          if (active) {
            try {
              stats.worker++;
              const src = String(args[0] || "");
              addNote("worker:" + src, { kind: "worker", script: redactHref(src), note: "requests made inside this worker are not visible to x-ray-eye" });
              if (/^https?:/i.test(src)) enqueueScript(src);
            } catch (e) { fail("worker.construct", e); }
          }
          return Reflect.construct(Target, args, newTarget);
        }
      });
      window[name] = proxy;
      cleanups.push(() => { if (window[name] === proxy) window[name] = Original; });
      hooks.push(name.toLowerCase());
    }
  }

                                                                          
                                                                     
                                                                   
                                                                          
  const PERF_API_INITIATORS = new Set(["fetch", "xmlhttprequest", "beacon", "eventsource"]);
  const JS_EXT = /\.m?js(?:[?#]|$)/i;

  function handlePerf(entries) {
    for (const e of entries) {
      const name = e && e.name;
      if (typeof name !== "string") continue;
      if (JS_EXT.test(name)) { enqueueScript(name); continue; }
      if (!PERF_API_INITIATORS.has(e.initiatorType)) continue;
      stats.performance++;
      record({
        source: "performance", url: name, method: "?", observed: true,
        status: typeof e.responseStatus === "number" && e.responseStatus > 0 ? e.responseStatus : undefined
      });
    }
  }

  function startPerformanceObserver() {
    if (!CONFIG.usePerformanceEntries || typeof PerformanceObserver === "undefined") return;
    const obs = new PerformanceObserver(list => {
      try { handlePerf(list.getEntries()); } catch (e) { fail("perf", e); }
    });
    try {
      obs.observe({ type: "resource", buffered: true });
    } catch (_) {
      obs.observe({ entryTypes: ["resource"] });
      handlePerf(performance.getEntriesByType("resource"));
    }
    cleanups.push(() => obs.disconnect());
    hooks.push("resource-timing");
  }

                                                                          
                                                                          
                                                                          
  const REF_PATTERNS = [
    /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{4,}/gi,
    /["'`](\/(?:api|apis|graphql|gql|rest|rpc|jsonrpc|odata|trpc|internal|admin|debug|wp-json|actuator|v\d+)(?:[\/?#][^\s"'`<>\\]*)?)["'`]/gi,
    /["'`](\/[^\s"'`<>\\]*(?:users?|accounts?|profiles?|auth|login|logout|oauth|orders?|products?|payments?|bookings?|files?|upload|download|messages?|notifications?|settings?|config|search|admin|invoices?|reports?|tickets?|subscriptions?)[^\s"'`<>\\]*)["'`]/gi,
                                                                          
    /["'`](\/[\w\-./]*(?:\.do|\.jsp|\.action|\.ashx|\.asmx|\.svc|\.php|\.aspx|\.cgi)(?:\?[\w=&%.-]*)?)["'`]/gi
  ];

  function extractRefs(text) {
    const found = new Set();
    for (const proto of REF_PATTERNS) {
      const re = new RegExp(proto.source, proto.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        let c = (m[1] || m[0]).replace(/[),;.]+$/, "");
        c = c.replace(/\$\{[^}]*\}/g, "{param}").replace(/\{\{[^}]*\}\}/g, "{param}");
        found.add(c);
        if (found.size >= CONFIG.maxRefsPerScript) return [...found];
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    return [...found];
  }

function recordRefs(text, source) {
      for (const url of extractRefs(text)) {
                                                                    
                                                                               
        if (/\$\{/.test(url) || /["'`)\]}]\s*$/.test(url)) continue;
        stats.scriptRefs++;
        const template = /\{[A-Za-z_][\w]*\}/.test(url) || /\{\{[^}]{1,40}\}\}/.test(url);
        record({ source, url, method: "?", observed: false, isTemplate: template });
      }
    }

                                                                          
                                                                             
                                                                           
                                                                             
                                                                          
  const CHUNK_PREFIX_RE = /["'`]((?:[A-Za-z0-9_\-]+\/)*[A-Za-z0-9_\-]*(?:static|assets|chunks)[A-Za-z0-9_\-./]*)["'`]/g;
                                                                          
  const CHUNK_SUFFIX_RE = /["'`](\.[A-Za-z0-9_\-.]*\.?m?js)["'`]/g;
  const WEBPACK_MAP_RE = /\{(?:"?\d{1,6}"?\s*:\s*["'][0-9a-zA-Z_\-]{6,24}["']\s*,){1,200}["']?\d{1,6}["']?\s*:\s*["'][0-9a-zA-Z_\-]{6,24}["']\s*\}/g;
  const CHUNK_LITERAL_RE = /["'`]((?:\.\/|\/)[A-Za-z0-9_\-./]*?\.chunk\.m?js)["'`]/g;
                                                                           
                                                                             
  const IMPORT_LITERAL_RE = /\bimport\s*\(\s*["'`]([^"'`\n\r]{1,300})["'`]\s*\)/g;
  const WORKER_LITERAL_RE = /\bnew\s+(?:Shared)?Worker\s*\(\s*["'`]([^"'`\n\r]{1,300})["'`]/g;
                                                                               
                                                                                
                                                                       
  const VITE_ANCHORS = ["__vite__mapDeps", "__vitePreload", "__vite__injectQuery"];
                                                                              
                                                                          
                                                                          
  const WEBPACK_U_LIT_RE = /\d{1,8}\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{2,220}?\.(?:m?js)(?:\?[^"']*)?)["']/g;
                                                                              
                                                           
  const WEBPACK_U_TPL3_RE = /(\d{1,8})\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{0,160})["']\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*["']([^"']{0,80})["']/g;
  const WEBPACK_U_TPL4_RE = /(\d{1,8})\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{0,160})["']\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*["']([^"']{0,60})["']\s*\+\s*["']([^"']{0,60})["']/g;
                                                                         
  const PUBLIC_PATH_RE = /(?:__webpack_require__|[A-Za-z_$][\w$]*)\s*\.\s*p\s*=\s*["']([^"']{0,200})["']/;

                                                                           
                                                                              
                                                                              
                                                                                
                                                                      
  function resolveChunkRef(ref, scriptU, base) {
    if (!ref || typeof ref !== "string") return null;
    const s = ref.trim();
    if (!s || s.length > 300) return null;
    try {
      if (/^https?:\/\//i.test(s)) return new URL(s).href;
      if (s[0] === "/") return new URL(s, scriptU.origin + "/").href;
                                                                           
      if (s.indexOf("./") === 0 || s.indexOf("../") === 0) return new URL(s, scriptU.href).href;
                                                                        
                                                                               
                                                                
      return new URL(s, base || (scriptU.origin + "/")).href;
    } catch (_) { return null; }
  }

                                                                           
                                                                              
  function detectBuildBase(text, scriptU) {
    try {
      if (!/\.\s*u\s*=/.test(text)) return null;
      const m = PUBLIC_PATH_RE.exec(text);
      if (!m) return null;
      const v = m[1];
      if (/^https?:\/\//i.test(v)) { const u = new URL(v); return u.href.replace(/\/?$/, "/"); }
      if (v[0] === "/") return new URL(v, scriptU.origin + "/").href;
      if (v.indexOf("./") === 0 || v.indexOf("../") === 0) return new URL(v, scriptU.href).href;
      return null;
    } catch (_) { return null; }
  }

  const CHUNK_FILE_RE = /\.(?:m?js)(?:[?#].*)?$/i;

                                                                            
                                                                            
  function grabArrayAfter(text, anchor, span) {
    const i = text.indexOf(anchor);
    if (i < 0) return null;
    const win = text.slice(i, i + (span || 400000));
    const s = win.indexOf("[");
    if (s < 0) return null;
    let depth = 0, q = null, esc = false;
    for (let k = s; k < win.length; k++) {
      const ch = win[k];
      if (q) {
        if (esc) { esc = false; continue; }
        if (ch === "\\") { esc = true; continue; }
        if (ch === q) q = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") { q = ch; continue; }
      if (ch === "[") depth++;
      else if (ch === "]") { depth--; if (!depth) return win.slice(s, k + 1); }
    }
    return null;
  }

  function collectChunkStrings(arrText) {
    const out = [];
    if (!arrText) return out;
    try {
      const arr = JSON.parse(arrText);
      if (Array.isArray(arr)) {
        for (const p of arr) if (typeof p === "string" && CHUNK_FILE_RE.test(p)) out.push(p);
        return out;
      }
    } catch (_) {}
    const rx = /["'`]([^"'`\\\n\r]{1,300})["'`]/g;
    let m;
    while ((m = rx.exec(arrText)) !== null) {
      if (CHUNK_FILE_RE.test(m[1])) out.push(m[1]);
      if (out.length > 400) break;
    }
    return out;
  }

  function discoverChunks(text, scriptU) {
    const out = new Set();
    if (!CONFIG.walkChunks || !text) return out;
    const base = detectBuildBase(text, scriptU);

                                                       
    for (const anchor of VITE_ANCHORS) {
      if (out.size >= CONFIG.maxChunks) break;
      for (const ref of collectChunkStrings(grabArrayAfter(text, anchor))) {
        const href = resolveChunkRef(ref, scriptU, base);
        if (href) out.add(href);
        if (out.size >= CONFIG.maxChunks) break;
      }
      if (out.size) break;
    }

                                                                                  
    const litR = new RegExp(WEBPACK_U_LIT_RE.source, "g");
    let lm;
    while ((lm = litR.exec(text)) !== null && out.size < CONFIG.maxChunks) {
      const href = resolveChunkRef(lm[1], scriptU, base);
      if (href) out.add(href);
    }
    const tpl3 = new RegExp(WEBPACK_U_TPL3_RE.source, "g");
    let t3;
    while ((t3 = tpl3.exec(text)) !== null && out.size < CONFIG.maxChunks) {
      const href = resolveChunkRef(t3[2] + t3[1] + t3[3], scriptU, base);
      if (href) out.add(href);
    }
    const tpl4 = new RegExp(WEBPACK_U_TPL4_RE.source, "g");
    let t4;
    while ((t4 = tpl4.exec(text)) !== null && out.size < CONFIG.maxChunks) {
      const href = resolveChunkRef(t4[2] + t4[1] + t4[3] + t4[4], scriptU, base);
      if (href) out.add(href);
    }

                                                                          
    for (const rx of [IMPORT_LITERAL_RE, WORKER_LITERAL_RE]) {
      const r2 = new RegExp(rx.source, "g");
      let m2;
      while ((m2 = r2.exec(text)) !== null && out.size < CONFIG.maxChunks) {
        if (!CHUNK_FILE_RE.test(m2[1])) continue;
        const href = resolveChunkRef(m2[1], scriptU, base);
        if (href) out.add(href);
      }
    }

    const prefixes = new Set(), suffixes = new Set();
    let m;
    const pr = new RegExp(CHUNK_PREFIX_RE.source, "g");
    while ((m = pr.exec(text)) !== null && prefixes.size < 6) prefixes.add(m[1]);
    const sr = new RegExp(CHUNK_SUFFIX_RE.source, "g");
    while ((m = sr.exec(text)) !== null && suffixes.size < 6) suffixes.add(m[1]);

    const maps = [];
    const mr = new RegExp(WEBPACK_MAP_RE.source, "g");
    while ((m = mr.exec(text)) !== null && maps.length < 3) maps.push(m[0]);

    if (prefixes.size && suffixes.size) {
      for (const mapStr of maps) {
        let pairs = [];
        try {
          const obj = JSON.parse(mapStr);
          for (const k of Object.keys(obj).slice(0, 80)) pairs.push([k, String(obj[k])]);
        } catch (_) {
          const rx = /"?(\d{1,6})"?\s*:\s*["']([0-9a-zA-Z_\-]{6,24})["']/g;
          let p2;
          while ((p2 = rx.exec(mapStr)) !== null && pairs.length < 80) pairs.push([p2[1], p2[2]]);
        }
        for (const pref of prefixes) {
          for (const suf of suffixes) {
            for (const [id, hash] of pairs.slice(0, 40)) {
              for (const cand of [pref + id + "." + hash + suf, pref + id + suf, pref + hash + suf]) {
                if (cand.length > 200) continue;
                const href = resolveChunkRef(cand, scriptU, detectBuildBase(text, scriptU));
                if (href) out.add(href);
              }
            }
          }
        }
      }
    }

    const lr = new RegExp(CHUNK_LITERAL_RE.source, "g");
    while ((m = lr.exec(text)) !== null && out.size < CONFIG.maxChunks) {
      const href = resolveChunkRef(m[1], scriptU, base);
      if (href) out.add(href);
    }
    return out;
  }

                                                                          
                                                                             
                                                       
                                                                          
  const SOURCEMAP_RE = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)/g;
  const sourceMapSeen = new Set();

  async function followSourceMaps(text, scriptU) {
                                                                         
                                                              
    followSourceMaps.found = false;
    if (!CONFIG.followSourceMaps || !nativeFetch || !text) return;
    if (sourceMapSeen.size >= CONFIG.maxSourceMaps) return;
    const refs = [];
    const re = new RegExp(SOURCEMAP_RE.source, "g");
    let m;
    while ((m = re.exec(text)) !== null && refs.length < 3) {
      const r = String(m[1] || "").trim();
      if (!r || r.startsWith("data:")) continue;
      refs.push(r);
    }

    for (const ref of refs) {
      let href;
      try { href = new URL(ref, scriptU.href).href; } catch (_) { continue; }
      if (sourceMapSeen.has(href)) continue;
      sourceMapSeen.add(href);
      const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
      const timer = ctl ? setT(() => ctl.abort(), CONFIG.scriptTimeoutMs) : null;
      try {
        const res = await nativeFetch.call(window, href, {
          credentials: "same-origin", cache: "force-cache", signal: ctl ? ctl.signal : undefined
        });
        if (!res.ok) { safeCancel(res.body); continue; }
        const txt = await res.text();
        safeCancel(res.body);
        if (txt.length > CONFIG.maxMapChars) continue;
        const map = safeParse(txt);
        if (!map || !Array.isArray(map.sourcesContent)) continue;
        stats.sourceMaps++;
        followSourceMaps.found = true;
        addNote("sourcemap:" + href, { kind: "sourcemap", url: href, sources: map.sources ? map.sources.length : 0, note: "original source recovered, variable names intact" });
        const sources = Array.isArray(map.sources) ? map.sources : [];
        for (let i = 0; i < map.sourcesContent.length; i++) {
          const c = map.sourcesContent[i];
          if (typeof c !== "string" || !c || c.length > CONFIG.maxScriptChars) continue;
          scanText(c, href + " > " + String(sources[i] || ("source-" + i)), true);
        }
      } catch (_) {
                                                                            
      } finally {
        if (timer) clearT(timer);
      }
    }
  }

  function scanText(text, fileLabel, fromMap, channel, baseLine, exact) {
    if (!text) return;
                                                                              
                                                                           
                                                                              
                                                                         
    if (isOwnSource(text)) return;
                                                                                
                                                                    
                                                                               
                                                                               
                                                                      
                             
                                                                                    
                                                                                  
                                                                                
                     
    let externalMap = false;
    if (fromMap) {
      const owner = String(fileLabel || "").split(" > ")[0];
      const ou = parseURL(owner);
      const ownerHost = ou ? String(ou.hostname || "").toLowerCase() : "";
      const pageHost = String(location.hostname || "").toLowerCase();
      if (ownerHost && pageHost && ownerHost !== pageHost) externalMap = true;
    }
                                                                        
                                                                
                                                                             
                                                                                
    if (!externalMap) {
      const ownerHost2 = (parseURL(String(fileLabel || "").split(" > ")[0]) || {}).hostname;
      if (ownerHost2 && VENDOR_SDK_HOSTS.test(String(ownerHost2))) return;
    }
    if (externalMap) return;
    const ch = channel || CH_STATIC;
                                                                              
                                                              
    channelSeen[ch] += 1;
    const prevOffset = lineOffset, prevExact = lineOffsetExact;
    lineOffset = baseLine || 0;
    lineOffsetExact = exact === undefined ? true : !!exact;
    try {
      recordRefs(text, "javascript");
                                                                          
                                                                           
                                                                                
                                             
      noteRoleChecks(text, fileLabel);
      ingestSecrets(scanSecrets(text, fileLabel), fileLabel, ch);
      detectFrameworksIn(text);
      detectServerActions(text, fileLabel);
      if (CONFIG.detectWebpackPublicPath) detectWebpackPublicPath(text, fileLabel);
      try { detectImportScripts(text, fileLabel); } catch (_) {}
      try { scanTextCredentialDisclosure(text, fileLabel, ch, undefined, undefined, 0, true); } catch (_) {}
                                                                              
                                                                      
      try { analyzeAuthComparisons(text, fileLabel, ch); } catch (_) {}
      try { scanEncodedLiterals(text, fileLabel, ch); } catch (e) { fail("decoded.scan", e); }
                                                                              
                                                                           
                                                      
      try { scanSourceForSensitivePaths(text, fileLabel, ch); } catch (e) { fail("senspath.scan", e); }
      try { resolveStringConstants(text, fileLabel, ch); } catch (e) { fail("reconstructed.scan", e); }
      try { resolveMemberConcatenation(text, fileLabel, ch); } catch (e) { fail("memberconcat.scan", e); }
      if (CONFIG.scanComments) scanComments(text, fileLabel);
      if (!fromMap) {
        const u = parseURL(String(fileLabel).split("#")[0].split(" > ")[0]);
        if (u) {
          for (const c of discoverChunks(text, u)) enqueueChunk(c);
          followSourceMaps(text, u).then(() => {
                                                                              
            if (!followSourceMaps.found) probeBlindSourceMap(u.href);
          }).catch(e => fail("sourceMaps", e));
        }
      }
    } catch (e) {
      fail("scanText", e);
    } finally {
      lineOffset = prevOffset;
      lineOffsetExact = prevExact;
    }
  }

  const scriptSeen = new Set();
  const scriptQueue = [];
  let scriptActive = 0;

  function enqueueScript(src) {
    if (!CONFIG.scanJavaScript || !active) return;
    const u = parseURL(src);
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return;
                                                                          
                                                                          
                                                                          
                          
    try { noteThirdParty("script", u.href); } catch (_) {}
    const key = "s:" + u.origin + u.pathname + u.search;
    if (scriptSeen.has(key) || scriptSeen.size >= CONFIG.maxScripts) return;
    scriptSeen.add(key);
    scriptQueue.push(u.href);
    pumpScripts();
  }

  function enqueueChunk(href) {
    const u = parseURL(href);
    if (!u) return;
    const key = "c:" + u.origin + u.pathname + u.search;
    if (scriptSeen.has(key)) return;
    if (scriptSeen.size >= CONFIG.maxScripts + CONFIG.maxChunks) return;
    scriptSeen.add(key);
    stats.chunks++;
    if (scriptQueue.length < CONFIG.maxChunks + CONFIG.maxScripts) scriptQueue.push(u.href);
    pumpScripts();
  }

  function pumpScripts() {
    while (active && scriptActive < CONFIG.scriptConcurrency && scriptQueue.length) {
      const href = scriptQueue.shift();
      scriptActive++;
      scanScript(href)
        .catch(e => fail("scanScript", e))
        .finally(() => { scriptActive--; pumpScripts(); });
    }
  }

  const yieldToMain = () => new Promise(r => setT(r, 0));

  async function scanScript(href) {
    if (!nativeFetch) return;
    let timer = null;
    try {
      const sameOrigin = new URL(href).origin === location.origin;
      const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
      if (ctl) timer = setT(() => ctl.abort(), CONFIG.scriptTimeoutMs);
                                                                               
                                                                                 
      const res = await nativeFetch.call(window, href, {
        credentials: sameOrigin ? "same-origin" : "omit",
        cache: "force-cache",
        signal: ctl ? ctl.signal : undefined
      });
      if (!res.ok || /html/i.test(res.headers.get("content-type") || "")) { stats.scriptsSkipped++; return; }
      const text = await res.text();
      safeCancel(res.body);
      if (text.length > CONFIG.maxScriptChars) { stats.scriptsSkipped++; return; }
      stats.scripts++;
      await yieldToMain();
      if (active) scanText(text, href, false);
    } catch (_) {
      stats.scriptsSkipped++;
    } finally {
      if (timer) clearT(timer);
    }
  }

                                                                          
                 
                                                                          
  const seenForms = new WeakSet();
  let seenInline = new WeakSet();

  function scanDOM() {
    if (!hasDOM) return;
                                                                            
                                                                          
    try {
      if (CONFIG.scanForms) {
        document.querySelectorAll("form[action]").forEach(form => {
          if (seenForms.has(form)) return;
          seenForms.add(form);
                                                                                          
          const action = form.getAttribute("action");
          if (!action) return;
          record({ source: "form", url: action, method: form.getAttribute("method") || "GET", observed: false });
        });
      }
    } catch (e) { fail("scanDOM.forms", e); }

    try {
                                                                          
                                                                            
                                                                               
                                                                                
                                                                         
                             
      const docBaseLine = text => {
        const body = String(text);
        const firstLine = body.replace(/^\s+/, "").split("\n")[0].slice(0, 60).trim();
        if (!firstLine) return 0;
        const docLine = docLineOf(firstLine, 0);
        if (docLine == null) return 0;
        const lead = body.split("\n").findIndex(l => l.indexOf(firstLine) >= 0);
        return docLine - ((lead < 0 ? 0 : lead) + 1);
      };
      document.querySelectorAll("script").forEach(s => {
        if (s.src) { enqueueScript(s.src); return; }
        if (!CONFIG.scanJavaScript || seenInline.has(s)) return;
        seenInline.add(s);
        const text = s.textContent || "";
        if (!text || text.length > CONFIG.maxScriptChars) return;
        scanText(text, domSourceLabel() + " (inline script)", true, CH_STATIC, docBaseLine(text), lineIsExact());
      });
    } catch (e) { fail("scanDOM.scripts", e); }

    try { scanTabnabbing(); } catch (e) { fail("scanDOM.tabnabbing", e); }
                                                                             
                                                                              
    try { scanDomSurfaces(); } catch (e) { fail("scanDOM.surfaces", e); }
    try { scanRuntimeGlobals(); } catch (e) { fail("scanDOM.runtime", e); }
    try { if (CONFIG.harvestStateBlobs) harvestFrameworkState(); } catch (e) { fail("scanDOM.state", e); }
    try { if (CONFIG.harvestMetaTags) harvestMetaTags(); } catch (e) { fail("scanDOM.meta", e); }
    try { if (CONFIG.harvestLinkHints) harvestLinkHints(); } catch (e) { fail("scanDOM.links", e); }
    try { if (CONFIG.harvestDataAttributes) harvestDataAttributes(); } catch (e) { fail("scanDOM.dataAttrs", e); }
    try { harvestVisibleText(); } catch (e) { fail("scanDOM.visibleText", e); }
  }

                                                                                
                                                                                
                                                                                
                                                                             
  function forgetInline() {
    seenInline = new WeakSet();
  }

  function forgetScripts() {
    scriptSeen.clear();
  }

                                                                             
                                                                        
                                                                               
                                                                               
                                                                               
                                                                            
                         
  function purgeCleartext() {
    for (const f of secretStore.values()) {
      f.rawValue = null;
      if (typeof f.context === "string") f.context = clip(maskDisclosedPhrases(f.context), 220);
    }
    for (const n of notes.values()) {
      if (n.kind !== "disclosed-credential") continue;
      if (n.value != null) { n.valueMasked = maskValue(n.value); n.value = null; }
      if (Array.isArray(n.valuesRaw) && n.valuesRaw.length) {
        n.values = n.valuesRaw.map(maskValue);
        n.valuesRaw = null;
      }
      if (typeof n.snippet === "string") n.snippet = clip(maskDisclosedPhrases(n.snippet), 240);
    }
    for (const s of storageStore.values()) s.raw = null;
    for (const j of jwtStore.values()) j.token = null;
    for (const rec of valueIndex.values()) rec.raw = null;
  }

  function applyReveal(on) {
    const was = revealOn;
    revealOn = on;
    if (!on) {
      try { purgeCleartext(); } catch (e) { fail("reveal.purge", e); }
      styled("[x-ray-eye] revealSecrets off. Cleartext retained while it was on has been dropped.", STYLE.dim);
      return;
    }
    if (was) return;
    const held = new Set();
    for (const f of secretStore.values()) if (f.rawValue) held.add(f.key);
    try { forgetInline(); forgetScripts(); } catch (e) { fail("reveal.forget", e); }
    try { scanDOM(); } catch (e) { fail("reveal.rescan", e); }
                                                                               
                                                                     
    try { sweepStorage(); armIndexedDbRetries(); } catch (e) { fail("reveal.sweep", e); }
    let newly = 0;
    for (const f of secretStore.values()) {
      if (!f.rawValue || held.has(f.key)) continue;
      newly++;
      try { queueSecretPrint(f); } catch (e) { fail("reveal.print", e); }
    }
    styled("[x-ray-eye] revealSecrets on. Sources were re-read; " + newly + " finding(s) now hold cleartext." +
      (newly ? " Run xrayeye.secretsReport() or xrayeye.markdown() to read them." : " Nothing readable was found again."), STYLE.warn);
  }

  function startMutationObserver() {
    if (!hasDOM || typeof MutationObserver === "undefined") return;
    let timer = null;
    let obs = null;
    let stopped = false;
    let announced = false;

    const announce = () => {
      if (announced) return;
      announced = true;
      hooks.push("dom");
    };

    const onMutate = () => {
      if (timer) clearT(timer);
      timer = setT(scanDOM, 500);
    };

                                                                            
                                                                         
                                                                                  
    const attach = () => {
      if (stopped) return;
      const root = document.documentElement ||
        (document.getElementsByTagName ? document.getElementsByTagName("html")[0] : null);
      if (!root) {
        if (!stopped) setT(attach, 50);
        return;
      }
      try {
        obs = new MutationObserver(onMutate);
                                                                                       
        obs.observe(root, { childList: true, subtree: true });
        announce();
                                                                   
        try { scanDOM(); } catch (e) { fail("scanDOM", e); }
      } catch (e) {
        fail("dom.observe", e);
      }
    };

    if (document.readyState === "loading") {
      try {
        document.addEventListener("DOMContentLoaded", () => { try { attach(); } catch (e) { fail("dom", e); } }, { once: true });
      } catch (_) {}
    }
    attach();

    cleanups.push(() => {
      stopped = true;
      if (timer) clearT(timer);
      if (obs) { try { obs.disconnect(); } catch (_) {} }
    });
  }

                                                                          
                                                                                
                                                                                
                                                                  
                                                                          
  function iframeSnippet() {
    return [
      "(function(){",
      "if(window.__XRAYEYE_CHILD__)return;window.__XRAYEYE_CHILD__=1;",
      "var post=function(m){try{parent.postMessage(m,'*')}catch(e){}};",
      "var f=window.fetch;",
      "if(f){window.fetch=function(){",
      "try{post({__xrayeye:1,kind:'fetch',url:String(arguments[0]),method:(arguments[1]&&arguments[1].method)||'GET'})}catch(e){}",
      "return f.apply(this,arguments)};}",
      "var o=XMLHttpRequest.prototype.open;",
      "XMLHttpRequest.prototype.open=function(m,u){",
      "try{post({__xrayeye:1,kind:'xhr',url:String(u),method:String(m)})}catch(e){}",
      "return o.apply(this,arguments)};",
      "var ow=window.WebSocket;",
      "if(ow&&typeof Proxy!=='undefined'){window.WebSocket=new Proxy(ow,{construct:function(T,a,n){",
      "try{post({__xrayeye:1,kind:'ws',url:String(a[0]),method:'WEBSOCKET'})}catch(e){}",
      "return Reflect.construct(T,a,n)}})}",
      "var oe=window.EventSource;",
      "if(oe&&typeof Proxy!=='undefined'){window.EventSource=new Proxy(oe,{construct:function(T,a,n){",
      "try{post({__xrayeye:1,kind:'sse',url:String(a[0]),method:'GET'})}catch(e){}",
      "return Reflect.construct(T,a,n)}})}",
      "post({__xrayeye:1,kind:'ready',href:String(location.href)});",
      "})();"
    ].join("\n");
  }

  function installMessageBridge() {
    if (typeof window.addEventListener !== "function") return;
    const onMsg = ev => {
      try {
        const d = ev.data;
        if (!d || d.__xrayeye !== 1) return;
        const origin = ev.origin || "";
        if (d.kind === "ready") {
          addNote("frame:" + origin + ":" + d.href, {
            kind: "iframe", origin, href: redactHref(d.href),
            note: "this frame is reporting into the parent"
          });
          return;
        }
        let abs = String(d.url || "");
        try { abs = new URL(abs, origin).href; } catch (_) {}
        record({ source: "iframe", observed: true, url: abs, method: String(d.method || "GET") });
      } catch (e) {
        fail("frameBridge", e);
      }
    };
    window.addEventListener("message", onMsg);
    cleanups.push(() => window.removeEventListener("message", onMsg));
    hooks.push("iframe-bridge");
  }

                                                                          
         
                                                                          
  function help() {
                                                                        
                                                                             
                                                     
    const sample = (() => {
      try {
        const unread = unreadTargets();
        if (unread.length) return unread[0];
        const any = list({}).filter(f => f.observed && f.responseBody);
        if (any.length) return absoluteUrl(any[0]);
      } catch (_) {}
      return "<url from xrayeye.findings()>";
    })();
    const shown = String(sample).slice(0, 120);
    for (const l of [
      "x-ray-eye commands",
      "",
      "  START HERE",
      "    xrayeye.exposed()                      everything exposed right now, worst first",
      "    xrayeye.findings()                     every endpoint found, so you can copy a real URL",
      "    xrayeye.endpoint()                     all endpoints in detail; or endpoint(url) for one",
      "    xrayeye.calls()                       every request the app made, with request/response bodies",
      "    xrayeye.callsReport()                  print them; referenced-only routes are listed as such",
      "    xrayeye.fetchEndpoint(" + JSON.stringify(shown) + ", { confirm:'AUTHORIZED' })   read a route the app never called (ACTIVE)",
    "    xrayeye.exposed()                      everything exposed right now, worst first",
    "    xrayeye.directories()                 directory indexes and bucket listings found",
    "    xrayeye.sensitivePaths()               dotfiles, VCS metadata, keys, backups",
    "    xrayeye.exposedReport() / directoriesReport()   print them",
    "    xrayeye.security()                  full triage across every surface below",
      "",
      "  TRIAGE (read this first)",
      "    xrayeye.triageReport()              real credentials, test fixtures, arbitrary strings ” separately",
      "    xrayeye.triage()                    the same split as data, each with the reason for its verdict",
      "    xrayeye.secrets({ real:true })      only the findings judged to be actual credentials",
      "    xrayeye.authPairs()                 hardcoded username+password pairs and the check that accepts them",
      "    xrayeye.coverage()                  what was inspected per channel, against what was found",
      "    xrayeye.unique()                    one row per distinct value, with its detection count",
      "",
      "  SURFACE",
      "    xrayeye.report({ min:'MEDIUM', idor:true, unauth:true, challenge:true, spec:true })",
      "    xrayeye.specs()                     parsed OpenAPI / GraphQL / Postman documents",
      "    xrayeye.notes({ kind:'graphql-field' })",
      "",
      "  CREDENTIALS",
      "    xrayeye.secretsReport({ exposure:'leak', severity:'HIGH' })",
      "    xrayeye.secrets({ verdict:'real' | 'fixture', channel:'dom' })  the same four channels as coverage",
      "    xrayeye.secrets({ category:'cloud' })",
      "    xrayeye.config.revealSecrets = false  mask values instead (cleartext is shown by default)",
      "                                         either way the sources are re-read; turning it off drops the cleartext",
      "",
      "  TOKENS",
      "    xrayeye.jwtReport({ severity:'HIGH' })",
      "    xrayeye.jwt({ signal:'weak-hmac-secret' })   alg:none, weak secret, no exp, long TTL",
      "",
      "  CLIENT STORAGE",
      "    xrayeye.storageReport({ area:'localStorage' })",
      "    xrayeye.storage({ sensitive:true })",
      "",
      "  AUTH FLOWS",
      "    xrayeye.oauthReport()               OAuth/OIDC flows, redirect_uri inventory, weak state",
      "    xrayeye.frameworks()                fingerprints plus passive CVE candidates",
      "    xrayeye.serverActions()             Next.js Server Action IDs found in client chunks",
      "    xrayeye.serviceWorkers()            registration and scope review",
      "",
      "  CACHE",
      "    xrayeye.cacheReport()               cacheable responses carrying PII or Set-Cookie",
      "",
      "  AUTH STATE",
      "    xrayeye.mark('pre-auth')            snapshot endpoints AND client storage",
      "    xrayeye.diff()                      new endpoints, status changes, storage deltas",
      "",
      "  EXPORT",
      "    xrayeye.markdown()                  report-ready markdown",
      "    xrayeye.csv() / xrayeye.secretsCSV()",
      "    xrayeye.export({ includeDetails:true })",
      "    xrayeye.download()",
      "",
      "  CONTROL",
      "    xrayeye.sweep()                     re-run storage, service worker and tabnabbing sweeps",
      "    xrayeye.rescan()                    re-run DOM/script discovery",
      "    xrayeye.revalidate()                re-apply minConfidence",
      "    xrayeye.config                      live settings",
      "    xrayeye.stats / xrayeye.errors / xrayeye.hooks",
      "    xrayeye.clear() / xrayeye.stop() / xrayeye.start()",
      "",
      "  CROSS-FRAME",
      "    copy(xrayeye.iframeSnippet())       paste inside a same-site iframe",
      "",
      "  ACTIVE (opt-in, sends requests the app did not send)",
      "    xrayeye.probe({ dryRun:true })      list the paths first",
      "    xrayeye.probe({ confirm:'AUTHORIZED' }) only after checking scope and rules of engagement",
      "",
      "  This tool flags hypotheses. It never proves a vulnerability on its own."
    ]) nativeConsole.log(l);
  }

                                                                          
               
                                                                          
                                                                                     
                                                                               
                                                                          
                                                      
                                                                              
                                                                               
                                                                            
                                                                            
                                                                          
                                                    
  function collectArrays(payload, maxDepth) {
  const found = [];
  const seen = typeof WeakSet === "function" ? new WeakSet() : null;
  const cap = maxDepth || 8;
  const walk = (val, path, depth) => {
  if (!val || typeof val !== "object" || depth > cap) return;
  if (seen) { if (seen.has(val)) return; seen.add(val); }
  if (Array.isArray(val)) {
  if (val.length) found.push({ path: path || "(root)", rows: val });
                                                                           
                                        
  for (let i = 0; i < Math.min(val.length, 4); i++) walk(val[i], path + "[" + i + "]", depth + 1);
  return;
  }
  for (const k of Object.keys(val)) walk(val[k], path ? path + "." + k : k, depth + 1);
  };
  walk(payload, "", 0);
  found.sort((a, b) => b.rows.length - a.rows.length);
  return found;
  }

                                                                            
                                                       
  function bestRecords(found) {
  const objs = found.find(f => f.rows[0] && typeof f.rows[0] === "object" && !Array.isArray(f.rows[0]));
  return objs || found[0] || null;
  }

                                                                        
                                                    
  function envelopeFields(payload, skip) {
  const out = [];
  for (const k of Object.keys(payload || {})) {
  const v = payload[k];
  if (Array.isArray(v)) { out.push(k + ": " + v.length + " record(s)"); continue; }
  if (v && typeof v === "object") { out.push(k + ": {" + Object.keys(v).slice(0, 5).join(", ") + "}"); continue; }
  out.push(k + ": " + JSON.stringify(v));
  }
  return out;
  }

  async function fetchEndpoint(target, opts) {
    const o = opts || {};
    if (!target) {
                                                                      
      const next = (() => { try { return unreadTargets()[0] || null; } catch (_) { return null; } })();
      nativeConsole.log("[x-ray-eye] fetchEndpoint needs a URL. " +
        (next ? "On this page that would be: xrayeye.fetchEndpoint(" + JSON.stringify(next) + ", { confirm: 'AUTHORIZED' })"
              : "xrayeye.findings() lists the routes that were found; pass one of those URLs."));
      return null;
    }
    if (!nativeFetch) { nativeConsole.log("[x-ray-eye] fetch is unavailable, cannot read the endpoint."); return null; }

                                                                            
    const known = list({}).find(f => matchesFinding(f, target));
    const alreadyObserved = !!(known && (known.observed || known.responseBody));
    let url = String(target);
    if (!/^https?:\/\//i.test(url)) {
      const host = (known && (known.hostname || known.host)) || "";
      url = host ? "https://" + host + (url.charAt(0) === "/" ? url : "/" + url) : String(location.origin).replace(/\/$/, "") + (url.charAt(0) === "/" ? url : "/" + url);
    }

    if (alreadyObserved) {
      const d = endpointDetail(url)[0] || endpointDetail(target)[0];
      nativeConsole.log("[x-ray-eye] " + url + " was already observed by the app. No request sent.");
      if (d) nativeConsole.log(d.responsePreview || d.requestPreview || "(no body captured)");
      return d || null;
    }

    if (o.dryRun) {
      nativeConsole.log("[x-ray-eye] would send one GET to " + url);
      return { dryRun: true, url };
    }
    if (!(o.confirm === "AUTHORIZED" || CONFIG.allowActiveProbe === true || CONFIG.activeRead === true)) {
      styled("[x-ray-eye] fetchEndpoint() is ACTIVE: it sends one GET the application never sent.", STYLE.warn);
      styled("[x-ray-eye] The target will log it. Check scope and rules of engagement first.", STYLE.warn);
      styled("[x-ray-eye] To run once: xrayeye.fetchEndpoint('" + String(target) + "', { confirm: 'AUTHORIZED' })", STYLE.warn);
      styled("[x-ray-eye] Or enable it for the session: xrayeye.authorize()", STYLE.warn);
      return null;
    }

    let res = null, text = "", err = null;
                                                                              
                                                                            
                                                                         
                                                               
    const _urlHost = (/^(?:https?:)?\/\/([^/?#]+)/i.exec(url) || [])[1] || "";
    const _pageHost = String(location.host).toLowerCase();
    const sameOrigin = _urlHost.toLowerCase() === _pageHost;
    const creds = o.credentials || (sameOrigin ? "include" : "omit");
                                                                               
                                                                    
    const baseHeaders = { "Accept": "application/json" };
    const reqHeaders = o.headers ? Object.assign({}, baseHeaders, o.headers) : baseHeaders;
    try {
      res = await nativeFetch(url, { method: o.method || "GET", credentials: creds, headers: reqHeaders });
      text = await res.text();
    } catch (e) { err = e; }

                                                                           
                                                                        
                                                                          
                                                                          
                                                                         
  try {
  const shown = text ? describeText(text, CONFIG.maxResponseBodyChars).display : "";
  const pii = text ? detectPII(text) : null;
  record({
  source: "probe", url, method: String(o.method || "GET"), observed: true,
  status: res ? res.status : 0,
  responseText: text,
  responseBody: shown || undefined,
  pii: pii && pii.length ? pii : null,
  responseContentType: (res && res.headers && res.headers.get && res.headers.get("content-type")) || "",
  responseHeaders: res && res.headers ? headersToObject(res.headers) : null,
  requestContentType: ""
  });
  } catch (e) { fail("fetchEndpoint.record", e); }

    const detail = endpointDetail(url)[0] || null;
                                                                              
                                                                      
    let listing = null;
    try {
      const pu = parseURL(url);
      if (text && CONFIG.detectDirectoryListings) {
        detectDirectoryListing(text, (res && res.headers && res.headers.get && res.headers.get("content-type")) || "", pu, null);
        const rows = listDirectories({ path: pu ? pu.pathname : "" });
        listing = rows.length ? rows[rows.length - 1] : null;
      }
    } catch (e) { fail("fetchEndpoint.listing", e); }
    const status = res ? res.status : 0;
    const preview = detail && detail.responsePreview ? detail.responsePreview : payloadPreview(text);
    const pii = detail && detail.piiHits && detail.piiHits.length ? detail.piiHits.map(p => p.kind + " x" + (p.count || 1)).join(", ") : "none detected";

    styled("[x-ray-eye] " + (o.method || "GET") + " " + url + "  ->  " + (err ? "FAILED: " + err.message : status), err ? STYLE.warn : (status >= 400 ? STYLE.warn : STYLE.head));
    if (err) {
                                                                             
                                                                          
                                                                         
                                                        
  const csp = cspBlocksConnect();
  nativeConsole.log("  " + err.message);
  if (csp) {
  nativeConsole.log("  Cause: this page's Content-Security-Policy sets " + csp + ", so the browser blocks the request before it leaves. No fetch can succeed here, and this is not a CORS problem.");
  nativeConsole.log("  To read the route anyway, open it directly: " + url);
  } else {
  nativeConsole.log("  Most often this is CORS: the browser blocks the read unless the API sends Access-Control-Allow-Origin for " + String(location.origin) + ".");
  nativeConsole.log("  That absence is itself a finding for an API a browser is expected to call. Open the URL in a tab to see the raw response.");
  nativeConsole.log("  To send credentials anyway: xrayeye.fetchEndpoint(" + JSON.stringify(target) + ", { confirm:'AUTHORIZED', credentials:'include' })");
  }
  return { url, error: String(err.message), likelyCause: csp ? "csp-connect-none" : "cors-or-network" };
    }
nativeConsole.log(capPreviewLines(payloadPreview(text, Infinity), CONFIG.maxPreviewLines) || "(empty body)");
  nativeConsole.log("  content-type: " + ((res && res.headers && res.headers.get && res.headers.get("content-type")) || "-") +
  "   length: " + text.length + "   PII: " + pii);
                                                                               
  let tableInfo = null;
  try {
  const payload = text ? safeParse(text) : null;
  if (payload !== null && payload !== undefined) {
  const found = collectArrays(payload);
  const best = bestRecords(found);
  if (found.length) {
  const rowCap = CONFIG.maxTableRows || 5;
  nativeConsole.log("  Records: " + found.length + " array(s) found; showing the largest");
  if (!Array.isArray(payload) && typeof payload === "object") {
  const env = envelopeFields(payload, best ? best.path : null);
  if (env.length) nativeConsole.log("  Envelope: " + env.join("   |   "));
  }
  for (const a of found.slice(0, 1)) {
  const capped = capColumns(a.rows, CONFIG.maxTableColumns);
  const cols = capped.columns;
  nativeConsole.log("    " + a.path + ": " + a.rows.length + " row(s)" + (cols.length ? " x " + cols.length + " column(s)" : ""));
  if (nativeConsole.table) nativeConsole.table(capped.rows.length > rowCap ? capped.rows.slice(0, rowCap) : capped.rows);
  else nativeConsole.log(JSON.stringify((capped.rows.length > rowCap ? capped.rows.slice(0, rowCap) : capped.rows), null, 1));
  if (capped.dropped) nativeConsole.log("      (top " + cols.length + " of " + (cols.length + capped.dropped) + " columns: " + cols.join(", ") + ")");
  if (a.rows.length > rowCap) nativeConsole.log("      (top " + rowCap + " of " + a.rows.length + " rows; the rest is in endpoint().responsePreview)");
  }
                                                                             
                                                    
  if (found.length > 1) {
  nativeConsole.log("    also: " + found.slice(1, 6).map(a => a.path + " (" + a.rows.length + " row(s))").join(", "));
  }
  if (best) {
  tableInfo = {
  field: best.path, rowCount: best.rows.length,
  columns: best.rows[0] && typeof best.rows[0] === "object" ? Object.keys(best.rows[0]).slice(0, 60) : [],
  arraysFound: found.length
  };
  }
  } else {
  nativeConsole.log("  No arrays found" + (payload && typeof payload === "object" ? ", so the response is a plain object." : ", so the body is not a record list. The preview above is what came back."));
                                                                       
  if (payload && typeof payload === "object" && nativeConsole.table) nativeConsole.table(payload);
  }
  }
  } catch (e) { fail("fetchEndpoint.table", e); }
    if (status === 401 || status === 403) nativeConsole.log("  This route needs credentials. Send them explicitly: xrayeye.fetchEndpoint('" + url + "', { confirm:'AUTHORIZED', headers:{ Authorization:'Bearer ...' } })");
    if (listing) {
      nativeConsole.log("  DIRECTORY LISTING: " + listing.flavour + " with " + listing.entryCount + " entries" + (listing.sensitive && listing.sensitive.length ? ", including " + listing.sensitive.length + " sensitive" : ""));
      nativeConsole.log("  entries: " + (listing.entries || []).slice(0, 30).join(", "));
      if (listing.sensitive && listing.sensitive.length) {
        for (const s of listing.sensitive) nativeConsole.log("    !! " + s.name + "  (" + s.why + ")");
      }
    }
if (status >= 400) nativeConsole.log("  A 4xx/5xx here is not proof the route is absent: it may need a method, a body, a session or a header.");
                                                                              
                                                                                 
                                                                   
  if (detail && tableInfo) {
  detail.recordField = tableInfo.field;
  detail.rowCount = tableInfo.rowCount;
  detail.columns = tableInfo.columns;
  detail.arraysFound = tableInfo.arraysFound;
  } else if (tableInfo) {
  return { url, status, recordField: tableInfo.field, rowCount: tableInfo.rowCount, columns: tableInfo.columns, arraysFound: tableInfo.arraysFound, body: preview };
  }
  return detail || { url, status, body: preview };
  }

                                                                             
                                                                             
                                                                               
                                                                             

const api = {
    version: VERSION,
    config: CONFIG,

    report,
    security: reportSecurity,
    specs: () => [...specStore.values()],
    reportSpecs,

secretsReport: reportSecrets,
      secrets: opts => listSecrets(opts).map(serializeSecret),
      notes: opts => listNotes(opts).slice(),
      reportNotes,
                                                                             
exposed: opts => exposedSummary(opts),
    exposedReport: reportExposed,
                                            
                                                                            
                                                                             
                                                                           
                                                                 
    securityAnalysis,
    securityHeaders: () => analyzeSecurityHeaders(),
    securityLeaks: () => analyzeResponseLeaks(),
    securityInjection: () => analyzeInjection(),
    securityAuthz: () => analyzeFunctionAuthz(),
    securitySessions: () => analyzeSessions(),
                                                                  
    potentialPoints: () => analyzePotentialPoints(),
    attackSurface: () => analyzeAttackSurface(),
    schemaModel: () => analyzeSchema(),
                                                                        
                                                                        
                                                                            
                                                                         
    technologyIntel: () => analyzeTechnology(),
                                                                         
                                                                      
                                                                            
                                                                  
    thirdParty: () => analyzeThirdParty(),
    dataFlow: () => analyzeDataFlow(),
                                                                           
                                                                             
                                                                      
    setSecurityHeaders: setExternalHeaders,
    analyzerBuild: ANALYZER_BUILD,
    diagnostics: () => analyzerDiagnostics(),
      directories: opts => listDirectories(opts),
      directoriesReport: reportDirectories,
      sensitivePaths: opts => listSensitivePaths(opts),

                                                                         
                                                 
    triageReport: reportTriage,
    triage: () => {
      const t = triageSummary();
      return {
        counts: t.counts,
        real: t.real.map(serializeSecret), fixture: t.fixture.map(serializeSecret),
        arbitrary: t.arbitrary.map(serializeSecret),
        pairs: t.pairs.map(p => ({
          severity: p.severity, verdict: p.verdict, file: p.file, line: p.line, column: p.column,
          container: p.container, channel: p.channel, valuesMasked: p.values,
          values: p.valuesRaw || null, compare: p.compare || null, compareAt: p.compareAt || null,
          note: p.note
        }))
      };
    },
    authPairs: () => [...notes.values()].filter(n => n.kind === "auth-pair").map(p => ({
      file: p.file, line: p.line, column: p.column, container: p.container,
      valuesMasked: p.values, values: p.valuesRaw || null,
      compare: p.compare || null, compareAt: p.compareAt || null
    })),
                                                               
    coverage: () => channelCoverage(),
                                                                  
    unique: () => uniqueSummary(),

    jwtReport: reportJWTs,
    jwt: opts => listJWTs(opts).map(serializeJWT),
    storageReport: reportStorage,
    storage: opts => listStorage(opts).map(serializeStorage),
    oauthReport: reportOAuth,
    authFlows: () => [...oauthStore.values()],
    frameworks: () => [...fwStore.values()].map(f => ({
      name: f.name, version: f.version || null, kind: f.kind || "lib",
      versions: [...f.versions], cves: f.cves || []
    })),
    cacheReport: reportCache,
    serviceWorkers: () => [...swStore.values()],
    serverActions: () => listNotes({ kind: "server-action" }).map(n => ({ id: n.id, file: n.file })),

    findings: opts => list(opts).map(f => serialize(f, !!(opts && opts.includeDetails))),

                                                                           
                                                                                
      endpoint: match => endpointDetail(match),
      calls: opts => observedCalls(opts),
      fetchEndpoint: (target, opts) => fetchEndpoint(target, opts),
      authorize,
      readAll: opts => readAll(opts),
      unread: () => unreadTargets(),
      callsReport: reportCalls,

    mark,
    diff,

    sweep: () => { sweepStorage(); armIndexedDbRetries(); inspectServiceWorkers().catch(() => {}); scanTabnabbing(); return api; },
    rescan: () => { forgetInline(); scanDOM(); return api; },
    cspCheck: () => crossCheckCSP(),

    markdown: exportMarkdown,
    csv: exportCSV,
    secretsCSV: exportSecretsCSV,
    export: exportJSON,
    download,

    revalidate,
    iframeSnippet,
    probe,

    clear, stop, start, setPersistence, help,

    get stats() { return statsSnapshot(); },
                                                                               
                                                                            
                                                                                
                                                                      
    get active() { return active; },
    get errors() { return errors.slice(); },
    get hooks() { return hooks.slice(); },
    get marks() { return [...snapshots.keys()]; }
  };

                                                                          
                                                                        
                                                                          
  restoreReloadSnapshot();

  installFns.push(
    ["persistence", installPersistence],
    ["fetch", installFetch], ["xhr", installXHR], ["beacon", installBeacon],
    ["websocket", installWebSocket], ["eventsource", installEventSource],
    ["worker", installWorker], ["frame-bridge", installMessageBridge],
    ["service-worker", installServiceWorkerHook],
    ["postmessage", installPostMessageHook],
    ["storage-writes", installStorageWriteHooks],
    ["cache-open", installCacheOpenHook],
    ["webrtc", installWebRTC],
    ["broadcastchannel", installBroadcastChannel],
    ["json-parse", installJSONParseHook],
    ["console-dump", installConsoleHook],
    ["cookie-write", installCookieWriteHook],
    ["resource-timing", startPerformanceObserver], ["dom", startMutationObserver]
  );
  installed = true;
  runInstalls();

                                                                             
                                                                              
                                                                         
                                                                            
                                                            
  try {
  if (false) {
  if (document.body) buildPanel();
  else document.addEventListener("DOMContentLoaded", function () {
  try { buildPanel(); } catch (_) {}
  }, { once: true });
  }
                                                                               
                                                                            
                                          
  } catch (_) {}

                                                                                
  try { sweepStorage(); armIndexedDbRetries(); } catch (e) { fail("boot.sweepStorage", e); }
  inspectServiceWorkers().catch(e => fail("boot.sw", e));
  try { if (CONFIG.harvestMetaTags) harvestMetaTags(); if (CONFIG.harvestLinkHints) harvestLinkHints(); } catch (e) { fail("boot.domHarvest", e); }

                                                                      
                                                                                
                                             
  try {
    Object.defineProperty(window, "xrayeye", { value: api, configurable: true, writable: true, enumerable: false });
  } catch (_) {
    window.xrayeye = api;
  }
  try {
    Object.defineProperty(window, "x-ray-eye", { value: api, configurable: true, writable: true, enumerable: false });
  } catch (_) {
    window["x-ray-eye"] = api;
  }

  styled("[x-ray-eye] v" + VERSION + " LIVE  (hooks: " + (hooks.join(", ") || "none") + ")", STYLE.ok);
  nativeConsole.log("Browse normally. Endpoints, credentials, JWTs, client storage, auth flows, specs and frameworks are all collected passively.");
  nativeConsole.log("Call it as xrayeye.* (the hyphenated name needs indexing: window['x-ray-eye']).");
  nativeConsole.log("Start with xrayeye.security(). Then xrayeye.mark('pre-auth') before logging in and xrayeye.diff() after.");
  nativeConsole.log("Known blind spots: requests made inside Web Workers, and cross-origin iframes (use xrayeye.iframeSnippet() for same-site frames).");
  styled("Everything is passive. The only active path is xrayeye.probe(), which is refused unless you confirm.", STYLE.dim);
  if (CONFIG.revealSecrets) {
    styled("[x-ray-eye] Credential values are shown in cleartext. Set config.revealSecrets = false to mask them and drop what was kept.", STYLE.warn);
  }

  try { scanDOM(); } catch (e) { fail("boot.scanDOM", e); }
                                                                                
                                                                               
                                                                              
                                                                      
  loadPageSource().then(() => {
    try { forgetInline(); scanDOM(); } catch (e) { fail("boot.rescanDOM", e); }

                                                                               
                                                                          
                                                                           
                                                                             
                                           
      
                                                                             
                                                                             
                                                                           
                                     
    setT(() => {
      try {
                                                                             
                                                                               
                                                                         
        if (window.__XRAY_NO_AUTO_FETCH__) return;
        const n = unreadTargets().length;
        if (!n) return;
        styled("[x-ray-eye] Auto-fetching " + n + " discovered endpoint(s) to preview their data...", STYLE.head);
        readAll({ limit: 25, delay: 0 });
      } catch (err) { fail("boot.autoFetch.init", err); }
    }, 2500);                                                             
                                                                            

  }).catch(e => fail("boot.pageSource", e));
                                                                             
                                                             
  try { crossCheckCSP(); } catch (e) { fail("boot.csp", e); }
  setT(() => { try { crossCheckCSP(); } catch (e) { fail("csp.check", e); } }, 12000);
  if (CONFIG.catchJSONParse || CONFIG.catchConsoleDumps || CONFIG.catchCookieWrites) {
    styled("[x-ray-eye] intrusive hooks are ON (JSON.parse / console / document.cookie). These wrap page functions and can cause visible side effects. Switch them off if the page misbehaves.", STYLE.warn);
  }
})();

