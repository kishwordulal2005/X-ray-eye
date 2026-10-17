/*
 * x-ray-eye v3
 * Passive browser-side attack-surface discovery for authorized security testing.
 *
 * Paste into the DevTools console of a page you are allowed to test, then browse.
 *
 * Naming: the display name contains hyphens, so it cannot be a bare identifier.
 *   window.xrayeye          callable, use xrayeye.report()
 *   window["x-ray-eye"]     same object, only reachable by indexing
 *
 * Design rules:
 *   1. Never change what the page sees. Hooks call the original function once,
 *      with the original arguments, and return its result untouched.
 *   2. Never block the page. Bodies are read from clones, in the background,
 *      with a byte cap and a timeout.
 *   3. Never throw into page code. Every capture path is wrapped.
 *   4. Redact before storing. Raw secrets and raw tokens are never kept.
 *   5. Passive by default. Anything that sends a request the app did not send
 *      itself lives behind xrayeye.probe() and is refused unless the tester
 *      explicitly opts in and confirms authorization.
 *   6. This tool flags hypotheses. Fingerprints, version matches and cache
 *      posture are evidence to confirm, never proof of exploitability.
 *
 * What it collects:
 *   - endpoints (runtime traffic + code references + declared API specs)
 *   - hardcoded credentials and keys, classified leak / by-design / needs-context
 *   - JWTs, decoded and locally weakness-tested (alg:none, weak HMAC secret,
 *     missing exp, long TTL, enumerable sub, admin-shaped claims)
 *   - client-side storage: localStorage, sessionStorage, cookies, IndexedDB,
 *     Cache API, and optionally injected window globals
 *   - OAuth/OIDC flows, redirect_uri inventory, weak or missing state
 *   - framework fingerprints with passive CVE candidates, Next.js Server
 *     Action IDs and .rsc transport variants
 *   - IDOR candidate parameters, identifier shapes and mass-assignment fields
 *   - internal, staging, admin and debug surface
 *   - cache-disclosure risk (cacheable responses carrying PII or Set-Cookie)
 *   - auth-response metadata (challenge headers, CORS posture, timings)
 */
(() => {
  "use strict";

  const VERSION = "3.2.0";

  // Stop a previous instance: an earlier x-ray-eye, a build still calling
  // itself EASYapi, or the original Smart API Discovery.
  try {
    const prior = window.xrayeye || window.EASYapi;
    if (prior && typeof prior.stop === "function") {
      prior.stop({ silent: true });
    } else if (typeof window.__SMART_API_DISCOVERY_CLEANUP__ === "function") {
      window.__SMART_API_DISCOVERY_CLEANUP__();
    }
  } catch (_) {}

  // ---------------------------------------------------------------------
  // Configuration (live-editable through xrayeye.config)
  // ---------------------------------------------------------------------
  const CONFIG = {
    // capture limits
    maxRequestBodyChars: 3000,
    maxResponseBodyChars: 2500,
    maxRequestBytesRead: 65536,
    maxResponseBytesRead: 16384,
    // API descriptions are routinely far larger than a normal body. Reading one
    // under the normal cap truncates the JSON and it silently fails to parse.
    maxSpecBytes: 3145728,
    maxJsonParseChars: 262144,
    readTimeoutMs: 3000,

    // store limits
    maxFindings: 2000,
    maxExamples: 5,
    maxWsSamples: 6,
    maxSecrets: 500,
    maxSpecEndpoints: 1500,
    maxNotes: 2500,
    maxNotesPerKind: 200,

    // response metadata
    captureResponseHeaders: true,
    trackTiming: true,
    responseHeaderAllow: [
      "www-authenticate", "access-control-allow-origin", "access-control-allow-credentials",
      "access-control-expose-headers", "access-control-allow-headers", "vary",
      "cache-control", "pragma", "age", "etag", "expires", "last-modified",
      "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after",
      "location", "set-cookie", "server", "x-powered-by", "x-aspnet-version", "x-runtime",
      "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
      "x-frame-options", "x-content-type-options", "permissions-policy",
      "x-amzn-requestid", "x-amz-cf-id", "cf-ray", "x-github-request-id", "x-request-id",
      "x-nextjs-cache", "x-matched-path", "x-now-route-matches", "x-nextjs-data"
    ],

    // static scanning
    scanJavaScript: true,
    scanForms: true,
    usePerformanceEntries: true,
    maxScripts: 80,
    maxScriptChars: 3000000,
    maxRefsPerScript: 400,
    scriptConcurrency: 3,
    scriptTimeoutMs: 15000,

    // source maps
    followSourceMaps: true,
    maxSourceMaps: 12,
    maxMapChars: 8000000,

    // lazy chunk discovery
    walkChunks: true,
    maxChunks: 150,

    // secrets
    scanSecrets: true,
    minSecretLength: 6,
    entropyBase64: 4.5,
    entropyHex: 3.0,
    entropyMinLen: 14,
    decodeBase64Blobs: true,
    maxBlobsPerScript: 40,

    // JWT analysis. Decoding and weak-secret checks are entirely local.
    analyzeJWTs: true,
    jwtWeakSecretTest: true,
    maxJwtFindings: 300,
    maxWeakSecretTries: 14,

    // client-side storage sweep
    sweepStorage: true,
    sweepIndexedDB: true,
    sweepCaches: true,
    // Comparing window keys against a clean iframe mutates the DOM. Off by default.
    sweepWindowGlobals: false,
    maxStorageFindings: 500,
    maxIndexedDbRecords: 400,
    maxCacheEntries: 60,
    maxStorageValueChars: 20000,

    // auth flows
    trackOAuth: true,
    maxOAuthFlows: 120,

    // frameworks / server actions
    detectFrameworks: true,
    frameworkCveMap: true,
    detectServerActions: true,
    maxServerActions: 200,

    // service workers
    inspectServiceWorkers: true,

    // DOM checks
    detectTabnabbing: true,
    detectPostMessageWildcard: true,

    // passive DOM / config harvesting
    harvestStateBlobs: true,
    harvestMetaTags: true,
    harvestLinkHints: true,
    harvestDataAttributes: true,
  // Rendered page text is scanned too. Credentials are routinely pasted into
  // a visible note, a demo banner or a <pre> block, and those never appear in
  // a script, a comment or storage.
  harvestVisibleText: true,
  // Off by default: cleartext is never retained unless the operator opts in.
  revealSecrets: false,
  maxVisibleTextChars: 300000,
    scanComments: true,
    detectWebpackPublicPath: true,

    // CSP
    captureCSP: true,

    // hooks that wrap things the page uses, but only observe
    hookStorageWrites: true,
    hookCacheOpens: true,
    hookWebRTC: true,

    // source maps
    probeBlindSourceMaps: true,
    maxBlindMaps: 40,

    // response body analysis
    harvestBodyFields: true,
    maxBodyFields: 60,

    // output
    live: true,
    minConfidence: "LOW", // LOW | MEDIUM | HIGH
    thirdParty: "tag", // "tag" or "hide"
    showRequestHeaders: true,
    showResponseBody: true,
    showSecrets: true,
    redactSensitive: true,
    livePrintBudget: 40,
    livePrintWindowMs: 2000,
    printDelayMs: 250,
    debug: false,

    // Active probing. Must be switched on AND confirmed per call.
    allowActiveProbe: false,

    // INTRUSIVE hooks. These wrap functions the page itself depends on
    // (JSON.parse, console.*, the document.cookie setter). They can produce
    // visible side effects, so they are off unless you switch them on.
    catchJSONParse: false,
    catchConsoleDumps: false,
    catchCookieWrites: false
  };

  const CONF_RANK = { IGNORE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
  const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

  // ---------------------------------------------------------------------
  // Native references, captured once so later page changes cannot break us
  // ---------------------------------------------------------------------
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
  const hasDOM = typeof document !== "undefined" && !!document;
  const nativeAtob = typeof atob === "function" ? atob : null;

  const nowMs = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------
  let active = true;
  let installed = false;
  let seq = 0;
  let secretSeq = 0;
  let specSeq = 0;
  const cleanups = [];
  const hooks = [];
  const installFns = [];

  const store = new Map();        // endpoint key -> finding
  const pathIndex = new Map();    // host|path -> Set(keys)
  const secretStore = new Map();  // secret key -> finding
  const specStore = new Map();    // spec key -> spec record
  const jwtStore = new Map();     // token hash -> jwt finding
  const storageStore = new Map(); // area|key -> storage finding
  const swStore = new Map();      // scope -> service worker record
  const oauthStore = new Map();   // flow key -> oauth record
  const fwStore = new Map();      // framework name -> fingerprint record
  const snapshots = new Map();    // label -> snapshot
  const notes = new Map();        // note key -> note
  const pending = new Map();      // finding -> event name (print queue)
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

  // ---------------------------------------------------------------------
  // Entropy (Shannon), charset aware
  // ---------------------------------------------------------------------
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

  // Returns { bits, charset, threshold } or null when the value is not a
  // random-looking blob (emails, usernames, paths and numbers are not secrets
  // by entropy and are judged by context instead).
  function entropyProfile(v) {
    if (v.length < CONFIG.entropyMinLen) return null;
    if (HEX_CHARSET.test(v)) return { bits: shannon(v), charset: "hex", threshold: CONFIG.entropyHex };
    if (B64_CHARSET.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) {
      return { bits: shannon(v), charset: "base64", threshold: CONFIG.entropyBase64 };
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Redaction
  // ---------------------------------------------------------------------
  // Keys are normalized (lowercase, letters and digits only) so "x-api-key",
  // "X_API_KEY" and "apiKey" all map to "xapikey" / "apikey".
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

  // Header names that merely contain a sensitive word but carry no secret.
  // Redacting them would destroy the CORS and auth-posture signals we collect.
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

  // key=value / "key": value pairs inside free text (form bodies, truncated JSON)
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

  // Shows enough of a value to reason about it and never enough to use it.
  function maskValue(v) {
    const s = String(v);
    if (s.length <= 4) return "*".repeat(s.length);
    return s.slice(0, 3) + "*".repeat(Math.min(s.length - 4, 24)) + s.slice(-2) + " (len " + s.length + ")";
  }

  // ---------------------------------------------------------------------
  // PII detection. Flags only. Response bodies are never rewritten by this.
  // ---------------------------------------------------------------------
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
        seen++;
        const cur = hits.get(kind);
        if (cur) cur.count++;
        else hits.set(kind, { kind, count: 1, sample: maskValue(m[0]) });
      }
    }
    return [...hits.values()];
  }

  // ---------------------------------------------------------------------
  // URL helpers
  // ---------------------------------------------------------------------
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

  // Builds a display URL without userinfo, with sensitive query/fragment values removed.
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
    // userinfo in an absolute URL is a credential leak on its own.
    let out = u.protocol + "//" + u.host + decodeBraces(u.pathname);
    if (u.username) out = u.protocol + "//" + maskValue(u.username) + "@" + u.host + decodeBraces(u.pathname);
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

  // A declared path template has to collapse to the same token as the concrete
  // value the app actually sends, otherwise /orders/{orderId} and /orders/1001
  // are recorded as two unrelated endpoints. Names are flattened first so
  // userId, user_id and USER_ID all resolve the same way.
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

  // Heuristic registrable-domain guess. Good enough to tag third-party traffic.
  function siteOf(hostname) {
    const h = String(hostname).toLowerCase();
    if (h.startsWith("[") || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const last2 = parts.slice(-2).join(".");
    return MULTI_TLD.has(last2) ? parts.slice(-3).join(".") : last2;
  }

  const NOISE_HOSTS = /(^|\.)(w3\.org|schema\.org|schemas\.microsoft\.com|ietf\.org|reactjs\.org|react\.dev|npmjs\.com|github\.com|githubusercontent\.com|gnu\.org|apache\.org|creativecommons\.org|wikipedia\.org|mozilla\.org|json-schema\.org|purl\.org|opensource\.org|fb\.me)$/i;

  // Non-production surface that shows up in bundles and is worth a look.
  const INTERESTING_HOST_RE = /(^|\.)(internal|staging|stage|stg|qa|uat|preprod|pre-prod|dev|test|testing|sandbox|admin|backstage|ops|debug|preview|canary|blue|mgmt|management)(\.|$)/i;
  // Managed datastore hostnames leak account id, region and topology.
  const INTERESTING_AWS_SERVICE_RE = /\.(rds|redshift|elasticache|opensearch|elasticsearch|eks|ecs|qldb|docdb|kinesis|dynamodb|elb|sqs|sns)\.[a-z0-9-]+\.amazonaws\.com$/i;
  const INTERESTING_PATH_RE = /(^|\/)(\.env($|\.)|\.git(\/|$)|phpinfo|info\.php|actuator|debug|internal|admin|backstage|_admin|wp-config|config\.(json|ya?ml)|__env|__config|swagger|openapi|graphiql|playground|v2\/api-docs|v3\/api-docs|server-status|wp-json|elmah|trace\.axd|\.well-known\/security\.txt|metrics|healthz|readyz)/i;

  // =====================================================================
  // SECRET SCANNER
  // Layer 1 high-signal vendor formats, Layer 2 generic key=value,
  // Layer 3 charset-aware Shannon entropy, Layer 4 noise filter,
  // Layer 5 base64/percent decode then re-scan, Layer 6 classification.
  // =====================================================================

  // FNV-1a. Used only to key findings so raw secret material is never stored.
  function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h.toString(16);
  }

  const SECRET_PATTERNS = [
    // ---- cloud / infrastructure
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

    // ---- code hosting / CI
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

    // ---- payments
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

    // ---- messaging / notifications
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

    // ---- SaaS / third party
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

    // ---- keys and certificates
    { id: "private-key", name: "Private Key Block", category: "keys", severity: "CRITICAL", exposure: "leak",
      re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g, group: 1, masked: true,
      verify: "Check whether this is documentation sample material or a real key. A real key in a bundle is critical; sample keys are noise." },
    { id: "certificate", name: "X.509 Certificate", category: "keys", severity: "INFO", exposure: "by-design",
      re: /(-----BEGIN CERTIFICATE-----)/g, group: 1, masked: true },

    // ---- credentials embedded in URLs and connection strings
    { id: "url-userinfo", name: "Credentials in URL", category: "auth", severity: "HIGH", exposure: "leak",
      re: /\b(https?:\/\/[^\/\s:@"'\\]{1,64}:[^\/\s@"'\\]{1,64}@[^\/\s"'\\]+)/g, group: 1,
      verify: "Basic auth in a URL leaks through logs, referrers and browser history." },
    { id: "mongodb-uri", name: "MongoDB Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b(mongodb(?:\+srv)?:\/\/[^\/\s:@"']{1,64}:[^\/\s@"']{1,64}@[^\/\s"']+)/g, group: 1 },
    { id: "db-dsn", name: "Database Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b((?:postgres(?:ql)?|mysql|mariadb|amqps?|redis|rediss|clickhouse|cockroachdb|mssql):\/\/[^\/\s:@"'\\]{1,64}:[^\/\s@"'\\]{1,64}@[^\/\s"'\\]+)/g, group: 1 },
    { id: "jdbc-uri", name: "JDBC Connection String", category: "database", severity: "CRITICAL", exposure: "leak",
      re: /\b(jdbc:[a-z0-9]+:\/\/[^\/\s:@"']{1,64}:[^\/\s@"']{1,64}@[^\/\s"']+)/g, group: 1 },

    // ---- auth material
    { id: "jwt-literal", name: "Hardcoded JWT", category: "auth", severity: "MEDIUM", exposure: "needs-context",
      re: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})/g, group: 1,
      verify: "Check exp and whether it is a long-lived service token rather than a short-lived user token." },
    { id: "bearer-literal", name: "Hardcoded Authorization Header", category: "auth", severity: "HIGH", exposure: "leak",
      re: /(["']authorization["']\s*[:=]\s*["'](?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,})/gi, group: 1 },
    { id: "basic-literal", name: "Hardcoded Basic Auth Header", category: "auth", severity: "HIGH", exposure: "leak",
      re: /(["']authorization["']\s*[:=]\s*["']Basic\s+[A-Za-z0-9+/=]{12,})/gi, group: 1 },

    // ---- observability
    { id: "sentry-token", name: "Sentry Auth Token", category: "observability", severity: "CRITICAL", exposure: "leak",
      re: /\b(sntrys_[A-Za-z0-9_-]{20,})\b/g, group: 1 },
    { id: "sentry-dsn", name: "Sentry DSN", category: "observability", severity: "INFO", exposure: "by-design",
      re: /(https:\/\/[a-f0-9]{16,}@[A-Za-z0-9.-]+\/[0-9]+)/g, group: 1,
      verify: "DSNs ship by design. Severity comes from the project permissions, not the DSN." }
  ];

  // gitleaks generic-api-key, widened to cover identity fields too. Group 1 is
  // the value, which is what the entropy and noise gates inspect.
  const GENERIC_SECRET_RE =
    /(?:key|api|token|secret|client|passwd|password|pass|pauth|auth|authorization|access|user|username|user_?name|email|mail|login|credential|creds|session|jwt|bearer)(?:[0-9a-z\-_\t .]{0,20})(?:\s|'|"){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|"|\s|=|\x60){0,5}([0-9a-z\-_.=@+]{6,150})(?:['"\n\r\s\x60;,)\]}]|$)/gi;

  // Noise terms are anchored with word boundaries on purpose. An unanchored
  // "0123456789" matches inside real 32-char hex keys and silently kills them.
  const SECRET_NOISE_RE = new RegExp([
    "\\bAKIAIOSFODNN7EXAMPLE\\b", "\\bASIAIOSFODNN7EXAMPLE\\b", "\\bAIzaSyDOCAbC1234567890\\b",
    "\\bEXAMPLE\\b", "\\bPLACEHOLDER\\b", "\\bYOUR_?KEY\\b", "\\bREPLACE_?ME\\b", "\\bCHANGE_?ME\\b", "\\bTODO\\b",
    "\\bx{5,}\\b", "\\*{4,}", "\\b0123456789\\b", "\\babcdef123456\\b", "\\b123456789\\b",
    "\\bdummy\\b", "\\bsample\\b", "\\bredacted\\b", "\\bchangethis\\b", "\\byour-?domain\\b", "\\bexample\\.com\\b",
    "\\btest[-_]?only\\b", "\\blorem\\b", "\\bipsum\\b", "\\bfoo\\b", "\\bbar\\b", "\\bundefined\\b", "\\bnull\\b"
  ].join("|"), "i");

  // Values that are structurally not secrets regardless of entropy.
  function shapeOf(v) {
    const s = String(v);
    // Long mixed strings are treated as opaque blobs. Without this, a 34-char
    // hex SID like SK0123... classifies as an "identifier" and loses its entropy.
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

  function isNoise(v, extra) {
    if (!v) return true;
    if (v.length < CONFIG.minSecretLength) return true;
    if (SECRET_NOISE_RE.test(v)) return true;
    if (/^(?:[A-Za-z]|\$|_){2,}$/.test(v)) return true;
    if (extra && SECRET_NOISE_RE.test(extra)) return true;
    return false;
  }

  // Line index so a match offset can be reported without rescanning the file.
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

  // A context window can contain credentials other than the one that matched.
  // redactString only understands key=value and JWT shapes, so every known
  // vendor pattern is applied again over the window before it is stored.
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

  // Context window around a match, with every value in it masked.
  function contextSnippet(text, offset, length, mask) {
    const from = Math.max(0, offset - 60);
    const to = Math.min(text.length, offset + length + 60);
    let s = text.slice(from, to);
    if (CONFIG.redactSensitive) {
      try { s = mask(s); } catch (_) {}
      s = hardRedact(redactString(s));
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

    // Layer 1: vendor formats.
    for (const pat of SECRET_PATTERNS) {
      let m;
      const re = new RegExp(pat.re.source, pat.re.flags.replace("g", "") + "g");
      let guard = 0;
      while ((m = re.exec(text)) !== null && guard++ < 200) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        const raw = pat.group ? m[pat.group] : m[0];
        if (!pat.masked) {
          if (!raw || isNoise(raw)) continue;
          // A more specific pattern already claimed this exact value.
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

    // Layer 2 + 3 + 4: generic key=value with an entropy gate.
    let m;
    let guard = 0;
    const gen = new RegExp(GENERIC_SECRET_RE.source, GENERIC_SECRET_RE.flags);
    while ((m = gen.exec(text)) !== null && guard++ < 400) {
      if (m[0].length === 0) { gen.lastIndex++; continue; }
      const value = m[1];
      if (!value) continue;
      if (l1Hashes.has(fnv1a(value))) continue; // already reported precisely by layer 1
      if (isNoise(value, m[0].slice(0, m[0].length - value.length))) continue;

      const shape = shapeOf(value);
      let severity = "LOW";
      let exposure = "needs-context";
      let entropy = null;

      if (shape === "email" || shape === "identifier" || shape === "url" || shape === "path") {
        // These are structurally readable. Report them, but never as a leak.
        severity = "LOW";
        exposure = "needs-context";
      } else if (shape === "blob" || shape === "constant") {
        entropy = entropyProfile(value);
        if (!entropy || entropy.bits < entropy.threshold) continue; // Layer 3
        severity = entropy.bits >= 5 ? "HIGH" : "MEDIUM";
        exposure = "leak";
      } else {
        continue; // numbers and literals are never secrets
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

    // Layer 5: base64 blobs and atob() literals, decoded then re-scanned.
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
          // Only plaintext-ish payloads are worth re-scanning.
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

  // =====================================================================
  // NOTES. Lightweight, separately-keyed observations that are not endpoints
  // and not secrets: GraphQL fields, interesting hosts, worker scripts.
  // =====================================================================
  function addNote(key, note) {
    if (notes.has(key)) return notes.get(key);
    if (notes.size >= CONFIG.maxNotes) return null;
    // One noisy kind (a page with 500 tabnabbing links, a big GraphQL schema)
    // must not crowd out every other observation.
    const k = note.kind || "note";
    const n = (noteKindCount.get(k) || 0) + 1;
    if (n > CONFIG.maxNotesPerKind) {
      noteKindCount.set(k, n);
      return null;
    }
    noteKindCount.set(k, n);
    // Deliberately not "id": callers supply their own meaningful ids (Server
    // Action ids, CVE ids) and overwriting them loses the actual finding.
    note.noteId = ++seq;
    notes.set(key, note);
    stats.notes++;
    return note;
  }

  // =====================================================================
  // IDOR candidate parameters and identifier shapes (fully passive)
  // =====================================================================
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

  // An id-shaped value is only useful to show if it is short and low entropy.
  // Anything that looks like a credential is masked before it can be stored.
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
    // Values are kept with the parameter name they came from. A flat list would
    // let a credential from one parameter be stored as another parameter's id.
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
        if (looksLikeJWT(v)) continue; // never store raw credentials
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

  // =====================================================================
  // GraphQL. Structured detection plus schema extraction plus the
  // "Did you mean" leak that works even when introspection is disabled.
  // =====================================================================
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

  // Cheap gate so the parser only runs on traffic that can plausibly be GraphQL.
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
// A GraphQL error arrives inside a JSON string, so the quotes around the field
// name are backslash-escaped: Did you mean \"user\". Matching the raw text
// therefore missed every real server response and only ever hit the literal
// unescaped form. Normalise the escapes before matching.
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
// Apollo and graphql-js phrase the missing-field error differently from the
// older "does not exist on type" wording, and Apollo is what most servers run.
const re3 = /Cannot query field\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?\s+on type\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)/g;
while ((m = re3.exec(norm)) !== null && n < 180) {
n++; stats.graphqlFields++;
addNote("gql-field:" + m[2] + "." + m[1], { kind: "graphql-field", type: m[2], field: m[1], via: "error-message", source });
}
return n;
}

  // =====================================================================
  // API spec ingestion. One /openapi.json turns into the whole surface.
  // =====================================================================
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
    // Bases are joined as base + path, so any trailing slash here would produce
    // a double slash in every endpoint derived from the spec.
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

      // Relay's nodes field defaulted onto every connection in a real HackerOne
      // P1 (report 489146) and leaked records the authenticated UI never showed.
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
        // A free-form filter argument was the entry point for a $12k
        // unauthenticated RCE on Mozilla (HackerOne 3782701) via sift $where.
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

  // =====================================================================
  // Body and header description
  // =====================================================================
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

  // Response headers are the cheapest source of auth posture, CORS posture and
  // rate-limit information. Only an allowlist is kept.
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
      // Cookie names are useful, cookie values never are.
      const masked = String(value).split(";").map(part => {
        const i = part.indexOf("=");
        const nm = (i >= 0 ? part.slice(0, i) : part).trim();
        return nm && /^[\w.-]+$/.test(nm) ? nm + "=[REDACTED]" : null;
      }).filter(Boolean);
      if (masked.length) out[lk] += masked.join(", ");
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

  // XMLHttpRequest exposes headers as one CRLF-delimited string.
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

  // Stream.cancel() rejects rather than throws when a stream is locked or
  // already disturbed. An uncancelled rejection surfaces in the page as an
  // unhandledrejection, which would be a visible side effect of our hooks.
  function safeCancel(body) {
    try {
      if (body && typeof body.cancel === "function") {
        const p = body.cancel();
        if (p && typeof p.catch === "function") p.catch(() => {});
      }
    } catch (_) {}
  }

  // Reads at most maxBytes from a stream, then cancels it. Never waits longer than timeoutMs.
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

  // =====================================================================
  // Scoring
  // =====================================================================
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
    // 28 on purpose: a bare /.env or /actuator/env must clear the LOW bar on
    // its own, otherwise the most interesting config paths get dropped as IGNORE.
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
    // A form action or a data-* endpoint attribute is a first-party
    // declaration of an endpoint the app itself uses. Without a base score
    // these two sources score 0 on their own, fall under the LOW cut-off and
    // were dropped as IGNORE, so they never appeared in findings at all.
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

  // `authoritative` means the endpoint is declared by the application's own API
  // spec, so it is not downgraded for being unobserved.
  function confidenceFrom(score, observed, authoritative) {
    let c = score >= 75 ? "HIGH" : score >= 45 ? "MEDIUM" : score >= 22 ? "LOW" : "IGNORE";
    if (!observed && !authoritative && c === "HIGH") c = "MEDIUM";
    return c;
  }

  // =====================================================================
  // JWT ANALYSIS
  // Decoding and weak-secret verification are entirely local. Nothing is sent.
  // =====================================================================
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

  // Locally verifies an HMAC signature against a guessed secret. This is a
  // local computation against material we already hold; it issues no requests.
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

  // The weak secrets that actually show up in real deployments.
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

  // Real cookies and headers carry prefixes ("Token eyJ...", "sso=<jwt>",
  // "r-<jwt>"), so a JWT is also looked for inside a longer value.
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
        sources: [source], weakSecret: null, firstSeen: Date.now()
      };
      jwtStore.set(key, f);
    } else {
      // The same token is often seen in several places. Every distinct place is
      // evidence, so merge sources rather than keeping only the first.
      const prev = jwtStore.get(key);
      if (prev.sources.indexOf(source) < 0 && prev.sources.length < 16) prev.sources.push(source);
    }

    const rec = jwtStore.get(key);
    // Weak-secret search is async and local; results land later.
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
          rec.weakSecret = maskValue(s);
          rec.signals.push({
            id: "weak-hmac-secret", label: "weak HMAC secret recovered", severity: "CRITICAL",
            detail: "The signature verifies against a trivially guessable secret (" + maskValue(s) + "). Anyone can forge tokens with arbitrary claims. Verified locally, no requests sent."
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

  // Pulls a JWT out of a URL query string and records where it was found.
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

  // Walks any parsed JSON for JWT-shaped values. Keys that name a token are
  // reported even when the value does not parse, so nothing is silently lost.
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

  // =====================================================================
  // CLIENT-SIDE STORAGE SWEEP
  // Read-only. Never writes, clears or mutates any storage.
  // =====================================================================
  function storageFinding(area, key, value, extra) {
    if (storageStore.size >= CONFIG.maxStorageFindings) return null;
    const sk = area + "|" + key;
    if (storageStore.has(sk)) {
      const prev = storageStore.get(sk);
      if (String(prev.rawLength) === String(String(value).length)) return prev;
    }
    const text = String(value == null ? "" : value).slice(0, CONFIG.maxStorageValueChars);
    stats.storageItems++;
    const secrets = analyzeJWT(text, "storage:" + area) ? 1 : 0;
    const rec = {
      id: ++storageSeq, key: sk, area, name: key,
      masked: maskValue(text), rawLength: String(text).length,
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
        if (k === null) continue;
        let v;
        try { v = storeObj.getItem(k); } catch (_) { continue; }
        const rec = storageFinding(area, k, v);
        if (rec && rec.classified) stats.storageSecrets++;
        // Feed values through the full credential scanner too.
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

  // Only app-looking global names are inspected, and never values that are
  // clearly not configuration.
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

  async function sweepIndexedDB() {
    if (!CONFIG.sweepIndexedDB || typeof indexedDB === "undefined" || !indexedDB) return;
    try {
      let dbs = [];
      if (typeof indexedDB.databases === "function") dbs = await indexedDB.databases();
      else {
        // Fallback for engines without databases(): only the open handle.
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
              storageFinding("indexeddb", d.name + "/" + s, text);
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
            // A cached response is still a place a secret can sit. Record the
            // entry and ingest any credential found, rather than only counting.
            storageFinding("cache", (u ? u.pathname : String(req.url)).slice(0, 200), text.slice(0, 400), {
              cache: k, url: u ? redactURL(u) : String(req.url)
            });
            if (CONFIG.scanSecrets) {
              const hits = scanSecrets(text.slice(0, 60000), label);
              for (const h of hits) if (h.exposure === "leak") stats.storageSecrets++;
              if (hits.length) ingestSecrets(hits, label);
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
    // Async sweeps must never reject into the page.
    sweepIndexedDB().catch(e => fail("sweepIndexedDB", e));
    sweepCaches().catch(e => fail("sweepCaches", e));
  }

  // Aliased fields and batched operation arrays were the basis of a $12,500
  // HackerOne bounty (report 3287208). This tool only *reports* the shape it saw
  // in traffic the app already sent. It never sends an aliased request.
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

  // =====================================================================
  // AUTH FLOWS (OAuth 2.0 / OIDC)
  // Observation only. We parse traffic the app already sent; we never craft a
  // request, change a redirect_uri or replay an authorization code.
  // =====================================================================
  const OAUTH_PATH_RE = /(\/oauth2?(\/|$)|\/oauth(\/|$)|\/authorize(\/|$)|\/token(\/|$)|\/login\/oauth|\/signin\/oauth|\/auth\/callback|\/callback(\/|$)|\/openid\/connect|\/\.well-known\/openid-configuration|\/userpool|\/realms?\/[^/]+\/protocol\/openid-connect)/i;
  const OAUTH_STEP_RE = /(\/authorize|\/oauth\/authorize|\/oauth2\/authorize|\/token|\/oauth\/token|\/oauth2\/token|\/userinfo|\/revoke|\/introspect|\/openid-configuration)/i;

  // A state parameter built from a timestamp or a short counter is guessable,
  // which turns OAuth CSRF into account linking.
  function stateLooksWeak(s) {
    const v = String(s || "");
    if (!v) return true;
    if (/^\d{1,13}$/.test(v)) return true;                 // timestamp or counter
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

    // client_secret in a request body is a web-app flow leaking a server secret.
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

  // =====================================================================
  // FRAMEWORK FINGERPRINTING + CURATED CVE MAP
  // A small, deliberately curated seed. Not a vulnerability database.
  // =====================================================================
  const FRAMEWORK_SIGS = [
    { name: "next.js", tests: [/__NEXT_DATA__/, /\/_next\/static\//, /self\.__next_f/], ver: [/__NEXT_DATA__[\s\S]{0,400}?"version"\s*:\s*"([^"]+)"/, /"version"\s*:\s*"(\d+\.\d+\.\d+)"/] },
    { name: "react", tests: [/React\.version\s*=\s*"([^"]+)"/, /react-dom(-|\/)/], ver: [/React\.version\s*=\s*"([^"]+)"/, /"react"\s*:\s*"?(\d+\.\d+\.\d+)/] },
    { name: "vue", tests: [/Vue\.version\s*=\s*"([^"]+)"/, /data-v-[0-9a-f]{8}/, /__VUE__/], ver: [/Vue\.version\s*=\s*"([^"]+)"/] },
    { name: "angular", tests: [/ng-version[=:]\s*["']?([\d.]+)/, /\bAngular\b.*\bversion\b/i], ver: [/ng-version[=:]\s*["']?([\d.]+)/] },
    { name: "svelte", tests: [/svelte-[a-z0-9]{6}/, /SvelteComponent/], ver: [/svelte@(\d+\.\d+\.\d+)/] },
    { name: "remix", tests: [/@remix-run\//, /__remixContext/], ver: [/@remix-run\/[^"'\s]*@?(\d+\.\d+\.\d+)/] },
    { name: "nuxt", tests: [/__NUXT__/, /nuxt-link/, /\/_nuxt\//], ver: [/nuxt@(\d+\.\d+\.\d+)/, /"nuxt"\s*:\s*"?(\d+\.\d+\.\d+)/] },
    { name: "gatsby", tests: [/___gatsby/, /gatsby-chunk/], ver: [] },
    { name: "vite", tests: [/@vite\/client/, /__vite\w*MapDeps/, /import\.meta\.url/], ver: [/@vite\/client\?v=(\d+)/] },
    { name: "webpack", tests: [/webpackChunk\w*\s*=/, /__webpack_require__/], ver: [] },
    { name: "jQuery", tests: [/jQuery\.fn\.jquery\s*=\s*"([^"]+)"/, /\$\.fn\.jquery\s*=\s*"([^"]+)"/], ver: [/jquery\s*=\s*"(\d+\.\d+\.\d+)/, /jquery@(\d+\.\d+\.\d+)/] },
    { name: "axios", tests: [/axios[\s\S]{0,60}?VERSION\s*=\s*"([^"]+)"/], ver: [/axios@(\d+\.\d+\.\d+)/] },
    { name: "sentry", tests: [/Sentry\.init\(/, /sentry\.io\/api/], ver: [/@sentry\/browser@(\d+\.\d+\.\d+)/] }
  ];

  // Only advisories confirmed to exist and to be recent. Extend deliberately.
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
      recordFramework(sig.name, version);
    }
  }

  function recordFramework(name, version) {
    let rec = fwStore.get(name);
    if (!rec) {
      rec = { name, versions: new Set(), cves: [], firstSeen: new Date().toISOString() };
      fwStore.set(name, rec);
      stats.frameworks++;
    }
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

  // =====================================================================
  // NEXT.JS: Server Action IDs and RSC transport variants
  // Server Action IDs ship inside public client chunks. Extracting them is
  // static analysis of assets the browser already downloaded.
  // =====================================================================
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
    // Only raise a bypass hypothesis when the app is actually Next.js.
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

  // =====================================================================
  // SERVICE WORKERS
  // =====================================================================
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

        // A scope that reaches outside the current directory intercepts more
        // of the origin than the developer likely intended.
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

        // Reuse the existing static scanner on the worker script.
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
          // Re-check after registration resolves so the real scope is known.
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

  // =====================================================================
  // DOM CHECKS: postMessage target origin, tabnabbing
  // =====================================================================
  function installPostMessageHook() {
    if (!CONFIG.detectPostMessageWildcard || typeof window.postMessage !== "function") return;
    const original = window.postMessage;
    const wrapper = function postMessage(message, targetOrigin, transfer) {
      if (active) {
        try {
          // A wildcard or omitted target origin means any frame, including a
          // cross-origin one, can read this payload. That is the CSWSH root cause.
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

  // =====================================================================
  // RESPONSE BODY FIELDS: IDOR leads and mass-assignment candidates
  // =====================================================================
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

  // =====================================================================
  // AI / LLM endpoint discovery
  // =====================================================================
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

  // Combines signals we already hold into a cache-disclosure chain. This is the
  // CVE-2024-26144 class (session cookie or PII served with a publicly
  // cacheable response) and the 2026 Next.js cache-key family.
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

  // =====================================================================
  // DOM / CONFIG HARVESTING (passive, read-only)
  // Framework state blobs, meta tags, link hints, data-* attributes, CSP
  // directives, webpack publicPath, commented-out code, robots/sitemap.
  // =====================================================================

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

  // Walks a state blob and records anything that looks like a URL or endpoint,
  // plus config objects whose keys name an API base.
  function ingestStateTree(node, source, keyPath, depth, state) {
    // Always returns the accumulator. State blobs are frequently not valid
    // JSON (Nuxt assigns a JS expression), so the null case must be normal.
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

  function ingestStateBlob(label, vendor, text, origin) {
    if (!text) return null;
    const key = "state:" + label + ":" + fnv1a(String(text).slice(0, 4000));
    if (notes.has(key)) return null;
    let json = null;
    try { json = safeParse(text); } catch (_) {}
    try { recordRefs(text, "state"); } catch (_) {}
    try { ingestSecrets(scanSecrets(text, origin), origin); } catch (_) {}
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
      try { ingestStateBlob(g.name, g.vendor, text, "window." + g.name); } catch (e) { fail("state:" + g.name, e); }
    }
    if (!hasDOM) return;
    try {
      const tags = document.querySelectorAll('script#__NEXT_DATA__, script#__NUXT_DATA__, script[type="application/json"], script[data-state="true"]');
      for (const t of tags) {
        if (!t || t.__xrayStateSeen) continue;
        t.__xrayStateSeen = 1;
        // Nodes returned here are not guaranteed to be real Elements, so every
        // accessor is guarded rather than assumed.
        let id = "";
        try { id = (typeof t.getAttribute === "function" ? t.getAttribute("id") : "") || t.id || ""; } catch (_) { id = ""; }
        let type = "";
        try { type = (typeof t.getAttribute === "function" ? t.getAttribute("type") : "") || ""; } catch (_) {}
        const txt = String(t.textContent || "").slice(0, 2000000);
        if (!txt) continue;
        const label = id || type || "application/json";
        const vendor = /NEXT_DATA/.test(label) ? "next.js" : (/NUXT/.test(label) ? "nuxt" : "generic");
        try { ingestStateBlob(label, vendor, txt, "script#" + label); } catch (e) { fail("stateTag", e); }
      }
    } catch (e) {
      fail("stateTags", e);
    }
  }

  // ---------------------------------------------------------------- CSP
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
        if (/^'[a-z-]+'$/i.test(v)) continue; // keyword source
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
    // Declared hosts are a curated endpoint list with almost no false positives.
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

  // Compares the declared CSP whitelist against hosts actually called.
  // Returns the comparison so it can be re-run as traffic accumulates.
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

  // ---------------------------------------------------------------- meta + links + data-*
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

  // ---------------------------------------------------------------------
// Disclosed credentials in rendered text.
// A hardcoded password pasted into a visible note, banner or <pre> block is
// one of the most common real-world mistakes, and it is invisible to every
// other collector here because it is neither script, comment nor storage.
// The phrase and the value are frequently in different text nodes (a <br>
// splits them), so the whole visible text is joined before matching.
// ---------------------------------------------------------------------
const VISIBLE_SKIP_TAGS = /^(?:SCRIPT|STYLE|NOSCRIPT|TEMPLATE|TEXTAREA|OPTION|SELECT)$/;
const disclosedSeen = new Set();
const CRED_SEP = "(?:is(?:\\s+set)?(?:\\s+to)?|will\\s+be|are|=|:|\\u2013|-|\\u2192|->)";
const PWD_PHRASE_RE = new RegExp(
  "((?:pass(?:word|wd|code)?|pwd|passphrase|secret|api[\\s_-]?key|auth[\\s_-]?token|access[\\s_-]?token|private[\\s_-]?key))" +
  "[^\\n]{0,24}?" + CRED_SEP + "\\s*[`'\\\"\u2018\u201c]?([^\\s`'\",;.<>()\\[\\]{}\u2019\u201d]{3,64})", "gi");
const USER_PHRASE_RE = new RegExp(
  // Case-insensitivity is scoped to the label only. A global "i" flag made the
  // capitalised-second-word check match any lowercase word, so "username: admin
  // curl" was reported as the username "admin curl".
  "((?i:user(?:[\\s_-]?name|[\\s_-]?id)?|login|log[\\s_-]?in|email[\\s_-]?id|e-?mail|account|student[\\s_-]?id|employee[\\s_-]?id|operator[\\s_-]?id|admin[\\s_-]?id))" +
  "[^\\n]{0,24}?" + CRED_SEP + "\\s*[`'\\\"\u2018\u201c]?([A-Za-z0-9._%+-]{2,40}(?:\\s+[A-Z][A-Za-z]{1,19})?)", "g");
// Words that follow a label but are not the value itself.
const CRED_STOPWORDS = /^(?:is|are|was|were|the|a|an|and|or|not|no|none|null|nil|empty|blank|required|optional|needed|must|should|will|be|set|here|below|above|this|that|it|they|same|as|your|our|their|hidden|disabled|shown|given|provided|default|custom|enter|type|input|field|form|login|signin|sign-in|check|reset|change|update|confirm|again|new|old|correct|wrong|true|false|yes|no\.?|n\/a|tbd|todo|xxx+|xxx+|secret|password|passwd|admin|user|username)$/i;

function visibleTextSnapshot() {
  const root = document.body || document.documentElement;
  if (!root) return { text: "" };
  // Feature-detect rather than throwing: an environment without a tree walker
  // simply has no visible text to read, and that is not an error worth
  // recording against the tool.
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
        // A credential in a hidden node is still a disclosure, but skip
        // aria-hidden template scaffolding used by UI frameworks.
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
  // Mixed case, or digits plus a symbol, or a long run: reads like a secret
  // rather than an English word.
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

  // Password-ish disclosures. Recorded as real secrets so they surface in
  // xrayeye.secrets() and security(), not only as a note.
  const pw = new RegExp(PWD_PHRASE_RE.source, "gi");
  let m;
  while ((m = pw.exec(text)) !== null && found < 40) {
    const label = String(m[1] || "").toLowerCase();
    const value = String(m[2] || "").replace(/[.,;:!?]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
    if (!looksLikeRealPassword(value)) continue;
    const key = "pwd:" + value;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    found++;
    const at = text.indexOf(value, Math.max(0, m.index - 40));
    recordDisclosedCredential(label, value, "rendered in page text", "visible text",
      text.slice(Math.max(0, at - 60), at + value.length + 20));
  }

  // Username-ish disclosures are paired with the note above when they sit in
  // the same block, so the report reads as a usable account hint.
  const us = new RegExp(USER_PHRASE_RE.source, "gi");
  const users = [];
  while ((m = us.exec(text)) !== null && users.length < 12) {
    const value = String(m[2] || "").replace(/[.,;:!?]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
    // Reject the value if any single word inside it is filler. A real
    // identifier like "Iemis Id" has no filler, whereas captures such as
    // "required username" or "admin curl" are prose, not a username.
if (String(value).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
    if (/^(?:https?|www\.)/i.test(value)) continue;
    // An address in a response body is PII, which is already reported
    // separately. Reporting it again as a credential only inflates severity.
    if (String(value).indexOf("@") >= 0) continue;
    users.push(value);
  }
  if (users.length) {
    addNote("visiblecred:users", {
      kind: "disclosed-credential", label: "username", exposure: "rendered in page text",
values: users.slice(0, 6).map(u => maskValue(u)),
      valuesRaw: CONFIG.revealSecrets ? users.slice(0, 6) : null,
      severity: "HIGH", where: "visible text",
      note: "A username is spelled out in page text. Paired with the password disclosure above this is a working login for any reader."
    });
  }
  if (found) stats.hidden = stats.hidden;
}

// Shared registration for a credential that was spelled out in prose.
// `where` distinguishes a rendered page note from a hardcoded string in a
// bundle, because the fix is different but the exposure is identical.
function recordDisclosedCredential(label, value, where, file, snippetText) {
  const key = label + "|" + fnv1a(value);
  if (disclosedSeen.has(key)) return false;
  if (!looksLikeRealPassword(value) && !/^[A-Za-z0-9._%+-]{2,40}$/.test(value)) return false;
  disclosedSeen.add(key);
  const masked = maskValue(value);
  addNote("disclosed:" + key, {
    kind: "disclosed-credential", label: String(label || "credential").toLowerCase(),
    exposure: where, valueMasked: masked, length: value.length,
      value: CONFIG.revealSecrets ? value : null,
    severity: "CRITICAL", where, file: file || null,
    // Never echo the raw value, not even inside the surrounding snippet.
    snippet: snippetText ? clip(String(snippetText).split(value).join(masked), 240) : null,
    note: where === "rendered in page text"
      ? "A credential is spelled out in text the user can read. Anyone who opens the page, or any screenshot, bug report or training material copied from it, learns the login. Remove the note and rotate the value."
      : "A credential is hardcoded as prose inside shipped JavaScript. It is readable in the bundle, in any saved copy of the page, and it survives forever in caches and archives. Remove it and rotate the value."
  });
  try {
    ingestSecrets([{
      id: "credential-disclosure", name: (label || "credential") + " (hardcoded)",
      category: "credential", severity: "CRITICAL", exposure: where,
      raw: value, length: value.length, shape: "prose-disclosure", file: file || "script"
    }], file || "script");
  } catch (e) { fail("disclosed.secret", e); }
  return true;
}

// The same disclosure written as source code rather than as rendered text,
// e.g. 'password is set to "PASSWORD#12"' inside a React component.
const CODE_PWD_RE = /["'`]?\b(pass(?:word|wd|code)?|pwd|passphrase|secret|api[_\-\s]?key|auth[_\-\s]?token|access[_\-\s]?token|private[_\-\s]?key)\b["'`]?\s*(?:[:=]|is(?:\s+set)?(?:\s+to)?|will\s+be)\s*\\?["'`]([^"'`\\\n]{4,80})\\?["'`]/gi;
const CODE_USER_RE = /["'`]?\b(user(?:name|[_\-\s]?id)?|login|log[_\-\s]?in|e-?mail|account)\b["'`]?\s*(?:[:=]|is(?:\s+set)?(?:\s+to)?|will\s+be)\s*\\?["'`]([^"'`\\\n]{2,60})\\?["'`]/gi;

function scanTextCredentialDisclosure(text, file) {
  if (!CONFIG.harvestVisibleText || !text || text.length > 4000000) return 0;
  let n = 0;
  const users = [];
  const re = new RegExp(CODE_USER_RE.source, "gi");
  let m;
  while ((m = re.exec(text)) !== null && users.length < 8) {
    const v = String(m[2] || "").replace(/[.,;:!?]+$/, "");
    if (!v || CRED_STOPWORDS.test(v)) continue;
    if (String(v).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
if (/^(?:https?|www\.)/i.test(v)) continue;
    if (v.indexOf("@") >= 0) continue;
    users.push(v);
  }
  const re2 = new RegExp(CODE_PWD_RE.source, "gi");
  while ((m = re2.exec(text)) !== null && n < 25) {
    const label = String(m[1] || "credential");
    const value = String(m[2] || "").replace(/[.,;:!?]+$/, "");
    if (!value || CRED_STOPWORDS.test(value)) continue;
    if (String(value).split(/\s+/).some(w => CRED_STOPWORDS.test(w))) continue;
    const at = Math.max(0, m.index - 40);
    if (recordDisclosedCredential(label, value, "hardcoded in script", file,
      text.slice(at, m.index + m[0].length + 20))) n++;
  }
  if (users.length) {
    addNote("disclosed:users", {
      kind: "disclosed-credential", label: "username", exposure: "hardcoded in script",
      values: users.slice(0, 6).map(u => maskValue(u)),
      valuesRaw: CONFIG.revealSecrets ? users.slice(0, 6) : null, severity: "HIGH",
      where: "hardcoded in script", file: file || null,
      note: "A username is hardcoded in shipped JavaScript. Alongside a hardcoded password this is a complete, working login sitting in the bundle."
    });
  }
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

  // ---------------------------------------------------------------- webpack / SW imports
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

  // ---------------------------------------------------------------- comments
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
      if (/^\s*[/!]/.test(body)) continue;   // licence banners
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

  // ---------------------------------------------------------------- robots / sitemap
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

  // =====================================================================
  // Hooks: WebRTC ICE, BroadcastChannel, storage writes, cache opens
  // =====================================================================
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
                // iceServers[].urls is a sequence<DOMString>, so a single bare
                // string is the normal way real apps declare a STUN/TURN
                // server. Only accepting the array form silently missed the
                // hardcoded-credential case this whole hook exists to find.
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

  // Observes writes so a token appearing later is captured with its source.
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

  // ---------------------------------------------------------------------
  // Intrusive hooks. OFF by default: these wrap functions the page itself
  // relies on, so they carry a real risk of visible side effects. Enable
  // only when hunting for config blobs and you accept the tradeoff.
  // ---------------------------------------------------------------------
  let jsonHookBusy = false;

  function installJSONParseHook() {
    if (!CONFIG.catchJSONParse) return;
    const orig = JSON.parse;
    const wrapped = function (text, reviver) {
      const out = Reflect.apply(orig, this, arguments);
      // Re-entrancy guard: our own safeParse uses JSON.parse.
      if (active && !jsonHookBusy && typeof text === "string") {
        try {
          const head = text.slice(0, 400);
          if (text.length > 40 && text.length < 4000000 && /"[^"]{1,40}"\s*:/.test(head) &&
              (/(?:api[_-]?key|apikey|secret|token|password|client[_-]?secret|private[_-]?key|access[_-]?key)/i.test(head) ||
               /(?:sk_live|ghp_|AKIA|AIza|xox[baprs]-|SG\.)/.test(head))) {
            jsonHookBusy = true;
            try {
              const j = Reflect.apply(orig, this, arguments);
              ingestSecrets(scanSecrets(text, "JSON.parse"), "JSON.parse");
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
                  ingestSecrets(scanSecrets(text, "console." + m), "console." + m);
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

  // ---------------------------------------------------------------------
  // Blind source-map probe. Plenty of builds ship .map without linking it.
  // ---------------------------------------------------------------------
  let blindMapsTried = 0;

  function probeBlindSourceMap(href) {
    if (!CONFIG.probeBlindSourceMaps || !nativeFetch) return;
    if (blindMapsTried >= CONFIG.maxBlindMaps) return;
    const u = parseURL(href);
    if (!u || u.protocol !== "https:" && u.protocol !== "http:") return;
    if (/\.map($|\?)/i.test(u.pathname)) return;
    const candidate = u.href.split("#")[0] + ".map";
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
      // Most probes miss. That is the expected outcome.
    } finally {
      if (timer) clearT(timer);
    }
  }

  // =====================================================================
  // Endpoint store
  // =====================================================================
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

  // Amortized: drops a batch instead of one-per-insert so a busy page does not
  // pay a full store scan on every single record.
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

  // Gathers IDOR parameter names and the concrete values seen for each of them.
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

    // Credential-shaped query and fragment values, analysed in memory only.
    try { analyzeJWTsInURL(u, "url"); } catch (e) { fail("jwt.url", e); }
    // Aliased or batched GraphQL shapes the app itself sent.
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

    const idorInput = collectIdorInput(raw, u);

    const scored = scoreFinding({
      path, hostname: u.hostname.toLowerCase(), method, source: raw.source, status,
      hasBody: !!raw.requestBody, requestContentType: qct, responseContentType: rct, graphql,
      specDeclared: !!raw.specDeclared, scoreBonus: raw.scoreBonus,
      challenge, cors, noAuthDeclared: !!raw.noAuthDeclared, deprecated: !!raw.deprecated
    });

    const pathKey = host + "|" + normalizedPath;
    const key = method + "|" + pathKey;
    const ts = Date.now();
    const minConf = effectiveMinConf();

    // Method-less evidence (resource timing, code references) attaches to an
    // existing method-specific finding instead of creating a guessed "GET".
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
        bodyFields: null, massAssign: null, cacheRisk: null
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

  // =====================================================================
  // Secret store
  // =====================================================================
  function compareSecrets(a, b) {
    return (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)
      || ((a.exposure === "leak" ? 0 : 1) - (b.exposure === "leak" ? 0 : 1))
      || b.count - a.count
      || String(a.file).localeCompare(String(b.file));
  }

  function ingestSecrets(list, file) {
    for (const s of list) {
      try {
        if (secretStore.size >= CONFIG.maxSecrets) { stats.secretsSuppressed++; continue; }
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
            file: s.file || file, line: s.line, column: s.column,
            context: s.context, verify: s.verify || null,
layer: s.layer, decodedFrom: s.decodedFrom || null,
      // Raw values are only retained when the operator explicitly asks. The
      // default never keeps the cleartext, so a shared export or screenshot
      // cannot leak a live credential.
      rawValue: CONFIG.revealSecrets && typeof s.raw === "string" ? s.raw : null,
      count: 1, printed: false
          };
          secretStore.set(key, f);
          stats.secrets++;
          queueSecretPrint(f);
        } else {
          f.count++;
        }
      } catch (e) {
        fail("ingestSecrets", e);
      }
    }
  }

  // =====================================================================
  // Output
  // =====================================================================
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

  // The text is always passed as an argument, never as the format string,
  // so a URL containing %c, %s or %d cannot corrupt the output.
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
    // Publishable keys and DSNs are shipped by design; they stay in the report
    // but do not interrupt live browsing.
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
      + st + (f.count > 1 ? "  x" + f.count : "") + (f.thirdParty ? "  [3P]" : "") + (at ? "  (" + at + ")" : "") + note;

    nativeConsole.groupCollapsed("%c%s", STYLE[f.confidence] || "", header);
    try {
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
      if (f.requestBody) line("Request body", f.requestBody);
      if (f.statuses.size > 1) line("Status codes", Object.fromEntries(f.statuses));
      if (f.responseHeaders && Object.keys(f.responseHeaders).length) line("Response headers", f.responseHeaders);
      if (f.cors && f.cors.length) line("CORS", f.cors.join(", "));
      if (CONFIG.showResponseBody && f.responseBody) line("Response preview", f.responseBody);
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
    const head = "[" + sev + "] SECRET  " + f.name + "  (" + f.exposure + ")" +
      (f.decodedFrom ? "  [via " + f.decodedFrom + "]" : "");
    nativeConsole.groupCollapsed("%c%s", css, head);
    try {
      line("Type", f.typeId + "  (" + f.category + ", detection layer " + f.layer + ")");
      line("Value", f.valueMasked);
      if (f.entropyBits !== null) line("Entropy", f.entropyBits + " bits/char (" + f.charset + ")" + (f.shape ? ", shape " + f.shape : ""));
      line("Location", f.file + ":" + f.line + ":" + f.column);
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
    } else {
      line(n.kind, JSON.stringify(n));
    }
  }

  // =====================================================================
  // Query
  // =====================================================================
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
    arr.sort(compareSecrets);
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function listNotes(opts) {
    const o = opts || {};
    let arr = [...notes.values()];
    if (o.kind) arr = arr.filter(n => n.kind === String(o.kind).toLowerCase());
    return o.limit ? arr.slice(0, o.limit) : arr;
  }

  function serialize(f, includeDetails) {
    const o = {
      confidence: f.confidence,
      state: f.observed ? "seen" : (f.specDeclared ? "declared" : "referenced"),
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
      o.requestHeaders = f.requestHeaders;
      o.responseHeaders = f.responseHeaders;
      o.requestBody = f.requestBody;
      o.responseBody = f.responseBody;
      o.wsSamples = f.wsSamples;
    }
    return o;
  }

  function serializeSecret(s) {
    return {
      type: s.typeId, name: s.name, category: s.category,
      severity: s.severity, exposure: s.exposure,
      valueMasked: s.valueMasked, length: s.length, shape: s.shape,
      value: s.rawValue || null,
      entropyBits: s.entropyBits, charset: s.charset,
      file: s.file, line: s.line, column: s.column,
      context: s.context, verify: s.verify,
      detectionLayer: s.layer, decodedFrom: s.decodedFrom,
      occurrences: s.count
    };
  }

  function statsSnapshot() {
    return Object.assign({}, stats, {
      findings: store.size,
      secrets: secretStore.size,
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

  // =====================================================================
  // Reports
  // =====================================================================
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

  function reportSecrets(opts) {
    const arr = listSecrets(opts);
    if (!arr.length) { styled("[x-ray-eye] No credential findings. (Scanned " + stats.scripts + " scripts, " + stats.sourceMaps + " source maps.)", STYLE.dim); return; }
    const rows = arr.map(s => ({
      severity: s.severity,
      exposure: s.exposure,
      type: s.typeId,
      category: s.category,
      value: s.valueMasked,
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
    styled("Values are masked. Confirm liveness out of band before reporting anything.", STYLE.dim);
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

  // =====================================================================
  // Export
  // =====================================================================
  // =====================================================================
  // Reports for the new surfaces
  // =====================================================================
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
      tokenMasked: j.masked, sources: j.sources,
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
      area: s.area, name: s.name, valueMasked: s.masked, length: s.rawLength,
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
      pii: (s.pii || []).map(p => p.kind).join(","), value: clip(s.masked, 48)
    }));
    if (nativeConsole.table) nativeConsole.table(rows);
    styled("Values are masked. A JWT or credential in web storage is readable by any script on the origin.", STYLE.dim);
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
        name: f.name, version: f.version || null,
        versions: [...f.versions], cves: f.cves || [], firstSeen: f.firstSeen
      })),
      serviceWorkers: [...swStore.values()],
      serverActions: listNotes({ kind: "server-action" }).map(n => ({ id: n.id, file: n.file })),
      notes: listNotes(o),
      marks: [...snapshots.values()].map(m => ({ label: m.label, at: m.at, endpoints: m.entries.size, storageKeys: (m.storage || new Map()).size }))
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
    const rows = ["severity,exposure,type,category,valueMasked,length,shape,entropy,charset,file,line,occurrences"];
    for (const s of listSecrets({})) {
      rows.push([s.severity, s.exposure, s.typeId, s.category, s.valueMasked, s.length, s.shape,
        s.entropyBits === null ? "" : s.entropyBits, s.charset || "", s.file, s.line, s.count].map(csvCell).join(","));
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
    L.push("- Endpoints: " + store.size + " (" + eps.length + " shown) | Secrets: " + secretStore.size + " | Specs: " + specStore.size);
    L.push("");

    const leaks = secs.filter(s => s.exposure === "leak");
    if (leaks.length) {
      L.push("## Credential findings (" + leaks.length + ")");
      L.push("");
      L.push("| Severity | Type | Value | Location | Entropy |");
      L.push("|---|---|---|---|---|");
      for (const s of leaks) {
        L.push("| " + s.severity + " | " + s.name + " | `" + s.valueMasked + "` | " + s.file + ":" + s.line + " | " + (s.entropyBits === null ? "-" : s.entropyBits) + " |");
      }
      L.push("");
    }

    const others = secs.filter(s => s.exposure !== "leak");
    if (others.length) {
      L.push("## Other credential-shaped findings (" + others.length + ")");
      L.push("");
      L.push("| Exposure | Type | Value | Location |");
      L.push("|---|---|---|---|");
      for (const s of others) {
        L.push("| " + s.exposure + " | " + s.name + " | `" + s.valueMasked + "` | " + s.file + ":" + s.line + " |");
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
      L.push("| Area | Key | Length | JWT | Masked value |");
      L.push("|---|---|---|---|---|");
      for (const s of st) L.push("| " + s.area + " | `" + clip(String(s.name), 50) + "` | " + s.rawLength + " | " + (s.hasJwt ? "yes" : "") + " | `" + clip(s.masked, 48) + "` |");
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

  // =====================================================================
  // mark / diff. Auth-state comparison.
  // =====================================================================
  // Read-only fingerprint of client-side storage, so diff() can show what a
  // page action wrote into localStorage, sessionStorage or cookies.
  function storageFingerprint() {
    const out = new Map();
    const addArea = (area, storeObj) => {
      if (!storeObj) return;
      try {
        const n = Number(storeObj.length) || 0;
        for (let i = 0; i < n; i++) {
          const k = storeObj.key(i);
          if (k === null) continue;
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

    // Storage diff catches state leaks that pure HTTP capture cannot see.
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

  // =====================================================================
  // Lifecycle
  // =====================================================================
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
    for (const k of Object.keys(stats)) stats[k] = 0;
    warned.clear();
    scriptSeen.clear();
    scriptQueue.length = 0;
    sourceMapSeen.clear();
    seq = 0; secretSeq = 0; specSeq = 0; jwtSeq = 0; storageSeq = 0; oauthSeq = 0;
    styled("[x-ray-eye] Cleared. Hooks stay installed.", STYLE.dim);
    return api;
  }

  // =====================================================================
  // Active probing. Opt-in, explicit, and fully logged. This is the only part
  // of the tool that sends requests the application did not send itself.
  // =====================================================================
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

    if (!(o.confirm === "AUTHORIZED" || CONFIG.allowActiveProbe === true)) {
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

  // =====================================================================
  // Hooks. Each one calls the original exactly once and never throws.
  // =====================================================================
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
            // Note: attaching a handler marks p as handled for unhandledrejection purposes.
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

  // Pulls credential-bearing header values without retaining them.
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

    // Auth headers are redacted before they are stored, so the raw value has to
    // be analysed here, in memory, and never written to the store.
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
      // Clone synchronously. Only textual bodies, so large uploads are never buffered.
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
      // The clone must be taken now, before page code can consume the body.
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

  // Specs, GraphQL leaks and PII are extracted from a response once, here,
  // instead of inside every capture path.
  function postProcess(meta) {
    try {
      const u = parseURL(meta.url);
      if (!u) return;
      const text = meta.responseText;

      if (text && (looksLikeSpecURL(u.pathname) || SPEC_CONTENT_HINT.test(meta.responseContentType || ""))) {
        const j = meta.responseJson || safeParse(text);
        if (j) { meta.responseJson = j; ingestSpecBody(j, u.href); }
      }
      if (text && (GQL_PATH_RE.test(u.pathname) || GQL_CT_RE.test(String(meta.responseContentType || "")))) {
        harvestGraphQLSuggestions(text, u.href);
      }

      // Response-side JWTs, from the unredacted body before it is stored masked.
      if (text && CONFIG.analyzeJWTs) {
        analyzeJWTsInJSON(safeParse(text), "response");
      }

      // Response JSON field harvest for IDOR leads and mass-assignment hints.
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

      // Content-Security-Policy connect-src is an authoritative API whitelist.
      if (CONFIG.captureCSP && meta.responseHeaders) {
        const cspHeader = meta.responseHeaders["content-security-policy"] ||
          meta.responseHeaders["content-security-policy-report-only"];
        if (cspHeader) {
          const csp = parseCSP(cspHeader);
          if (!meta.responseHeaders["content-security-policy"]) csp.reportOnly = true;
          noteCSP(csp, u.origin);
        }
      }

      // robots.txt and sitemap.xml are the site's own inventory of what exists.
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
          // A truncated description is unparseable. Say so rather than
          // leaving the tester wondering why nothing was extracted.
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
    postProcess(meta);
    record(meta);
  }

  function onFetchError(ctx) {
    try {
      if (ctx.requestClone && ctx.requestClone.body) safeCancel(ctx.requestClone.body);
      const info = ctx.bodyInfo;
      record({
        source: "fetch", url: ctx.url, method: ctx.method, observed: true,
        requestHeaders: ctx.headers, requestContentType: ctx.headers["content-type"] || "",
        requestBody: info ? info.display : "", requestJson: info ? info.json : undefined, status: 0
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
          // Analyse the raw value now; only the redacted form is stored.
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
            // An XHR object can be reused. Never stack listeners on it.
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

  // A worker global has its own fetch and XMLHttpRequest, so nothing a worker
  // does is visible to us. The best available mitigation is to read the worker
  // script statically and to be explicit about the blind spot.
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

  // =====================================================================
  // Resource Timing: sees requests made before the script was pasted
  // (URL and status only, limited by the browser's timing buffer).
  // =====================================================================
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

  // =====================================================================
  // Static scanning of JavaScript (queued, capped, never blocks the page)
  // =====================================================================
  const REF_PATTERNS = [
    /\b(?:https?|wss?):\/\/[^\s"'`<>\\)]{4,}/gi,
    /["'`](\/(?:api|apis|graphql|gql|rest|rpc|jsonrpc|odata|trpc|internal|admin|debug|wp-json|actuator|v\d+)(?:[\/?#][^\s"'`<>\\]*)?)["'`]/gi,
    /["'`](\/[^\s"'`<>\\]*(?:users?|accounts?|profiles?|auth|login|logout|oauth|orders?|products?|payments?|bookings?|files?|upload|download|messages?|notifications?|settings?|config|search|admin|invoices?|reports?|tickets?|subscriptions?)[^\s"'`<>\\]*)["'`]/gi,
    // Server-side and enterprise entry points that never live under /api.
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
      stats.scriptRefs++;
      record({ source, url, method: "?", observed: false });
    }
  }

  // ---------------------------------------------------------------------
  // Lazy chunk discovery. Purely static: parse runtime maps out of text that
  // was already downloaded. No extra requests are invented here beyond the
  // chunk scripts themselves, which the browser would load on demand anyway.
  // ---------------------------------------------------------------------
  const CHUNK_PREFIX_RE = /["'`]((?:[A-Za-z0-9_\-]+\/)*[A-Za-z0-9_\-]*(?:static|assets|chunks)[A-Za-z0-9_\-./]*)["'`]/g;
  // Must also match a bare ".js" suffix, so the middle group is optional.
  const CHUNK_SUFFIX_RE = /["'`](\.[A-Za-z0-9_\-.]*\.?m?js)["'`]/g;
  const WEBPACK_MAP_RE = /\{(?:"?\d{1,6}"?\s*:\s*["'][0-9a-zA-Z_\-]{6,24}["']\s*,){1,200}["']?\d{1,6}["']?\s*:\s*["'][0-9a-zA-Z_\-]{6,24}["']\s*\}/g;
  const CHUNK_LITERAL_RE = /["'`]((?:\.\/|\/)[A-Za-z0-9_\-./]*?\.chunk\.m?js)["'`]/g;
  // Native ESM dynamic import with a literal specifier. This is the exact,
  // unguessable form: the specifier IS the URL, so no reconstruction needed.
  const IMPORT_LITERAL_RE = /\bimport\s*\(\s*["'`]([^"'`\n\r]{1,300})["'`]\s*\)/g;
  const WORKER_LITERAL_RE = /\bnew\s+(?:Shared)?Worker\s*\(\s*["'`]([^"'`\n\r]{1,300})["'`]/g;
  // Vite/rollup park the lazy-chunk table in a property assignment rather than
  // an argument list, e.g. m.f||(m.f=[...]). Anchoring on "(" only ever matched
  // unminified builds, so real minified runtimes were missed entirely.
  const VITE_ANCHORS = ["__vite__mapDeps", "__vitePreload", "__vite__injectQuery"];
  // Next.js and modern webpack5 emit __webpack_require__.u as a ternary chain
  // rather than an id->hash table, so the id/hash are only recoverable by
  // reading each branch. Both branch shapes are exact, no reconstruction.
  const WEBPACK_U_LIT_RE = /\d{1,8}\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{2,220}?\.(?:m?js)(?:\?[^"']*)?)["']/g;
  // Real shape is "prefix" + id + ".hash.js" (3 parts). Some builds split the
  // hash out into a 4th part, so both arities are handled.
  const WEBPACK_U_TPL3_RE = /(\d{1,8})\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{0,160})["']\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*["']([^"']{0,80})["']/g;
  const WEBPACK_U_TPL4_RE = /(\d{1,8})\s*===\s*[A-Za-z_$][\w$]*\s*\?\s*["']([^"']{0,160})["']\s*\+\s*[A-Za-z_$][\w$]*\s*\+\s*["']([^"']{0,60})["']\s*\+\s*["']([^"']{0,60})["']/g;
  // publicPath assignment (.p="...") that lives alongside a .u= runtime.
  const PUBLIC_PATH_RE = /(?:__webpack_require__|[A-Za-z_$][\w$]*)\s*\.\s*p\s*=\s*["']([^"']{0,200})["']/;

  // Resolves a chunk reference the way the bundler emitted it. Both Vite's
  // lazy-chunk table ("assets/chunks/x.js") and webpack's "static/js/" prefix
  // are relative to the build's base, which is the origin root in practice --
  // NOT the current document and NOT the script folder. Resolving those against
  // either produces a wrong path, so bare refs go to the origin root.
  function resolveChunkRef(ref, scriptU, base) {
    if (!ref || typeof ref !== "string") return null;
    const s = ref.trim();
    if (!s || s.length > 300) return null;
    try {
      if (/^https?:\/\//i.test(s)) return new URL(s).href;
      if (s[0] === "/") return new URL(s, scriptU.origin + "/").href;
      // Explicitly script-relative specifiers keep standard ESM semantics.
      if (s.indexOf("./") === 0 || s.indexOf("../") === 0) return new URL(s, scriptU.href).href;
      // Otherwise the build's own base decides: Next.js sets publicPath
      // "/_next/", so "static/chunks/x.js" must land under /_next/, while Vite
      // leaves base at "/" and it must land at the origin root.
      return new URL(s, base || (scriptU.origin + "/")).href;
    } catch (_) { return null; }
  }

  // Reads the bundler's publicPath (.p) when a runtime chunk declares one.
  // Returns an absolute base ending in "/", or null to fall back to the root.
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

  // Balanced-scan for the first array literal at or after `anchor`. Regexes
  // cannot do this safely on minified code that nests brackets and strings.
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

    // --- 1. exact: Vite / rollup lazy-chunk table ---
    for (const anchor of VITE_ANCHORS) {
      if (out.size >= CONFIG.maxChunks) break;
      for (const ref of collectChunkStrings(grabArrayAfter(text, anchor))) {
        const href = resolveChunkRef(ref, scriptU, base);
        if (href) out.add(href);
        if (out.size >= CONFIG.maxChunks) break;
      }
      if (out.size) break;
    }

    // --- 2. exact: Next.js / webpack5 ternary chain in __webpack_require__.u ---
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

    // --- 3. exact: native import() / Worker with a literal specifier ---
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

  // ---------------------------------------------------------------------
  // Source map following. Source maps keep original variable names, which is
  // exactly what makes a hardcoded credential obvious.
  // ---------------------------------------------------------------------
  const SOURCEMAP_RE = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)/g;
  const sourceMapSeen = new Set();

  async function followSourceMaps(text, scriptU) {
    // Tracks whether this script yielded a linked map, so scanText knows
    // whether a blind <script>.map probe is worth attempting.
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
        // Source maps are frequently blocked or absent. Silence is correct.
      } finally {
        if (timer) clearT(timer);
      }
    }
  }

  function scanText(text, fileLabel, fromMap) {
    if (!text) return;
    try {
      recordRefs(text, "javascript");
      ingestSecrets(scanSecrets(text, fileLabel), fileLabel);
      detectFrameworksIn(text);
      detectServerActions(text, fileLabel);
      if (CONFIG.detectWebpackPublicPath) detectWebpackPublicPath(text, fileLabel);
      try { detectImportScripts(text, fileLabel); } catch (_) {}
      try { scanTextCredentialDisclosure(text, fileLabel); } catch (_) {}
      if (CONFIG.scanComments) scanComments(text, fileLabel);
      if (!fromMap) {
        const u = parseURL(String(fileLabel).split("#")[0].split(" > ")[0]);
        if (u) {
          for (const c of discoverChunks(text, u)) enqueueChunk(c);
          followSourceMaps(text, u).then(() => {
            // If nothing was linked, many builds still ship the map unlinked.
            if (!followSourceMaps.found) probeBlindSourceMap(u.href);
          }).catch(e => fail("sourceMaps", e));
        }
      }
    } catch (e) {
      fail("scanText", e);
    }
  }

  const scriptSeen = new Set();
  const scriptQueue = [];
  let scriptActive = 0;

  function enqueueScript(src) {
    if (!CONFIG.scanJavaScript || !active) return;
    const u = parseURL(src);
    if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return;
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
      // Same-origin scripts normally come from the browser cache. Cross-origin
      // scripts are fetched without credentials and skipped if CORS blocks them.
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

  // =====================================================================
  // DOM scanning
  // =====================================================================
  const seenForms = new WeakSet();
  const seenInline = new WeakSet();

  function scanDOM() {
    if (!hasDOM) return;
    // Each step is isolated. A single throwing DOM API must not cost us the
    // rest of the harvest, which is what a whole-body try/catch would do.
    try {
      if (CONFIG.scanForms) {
        document.querySelectorAll("form[action]").forEach(form => {
          if (seenForms.has(form)) return;
          seenForms.add(form);
          // getAttribute, because form.action can be shadowed by an input named "action".
          const action = form.getAttribute("action");
          if (!action) return;
          record({ source: "form", url: action, method: form.getAttribute("method") || "GET", observed: false });
        });
      }
    } catch (e) { fail("scanDOM.forms", e); }

    try {
      document.querySelectorAll("script").forEach(s => {
        if (s.src) { enqueueScript(s.src); return; }
        if (!CONFIG.scanJavaScript || seenInline.has(s)) return;
        seenInline.add(s);
        const text = s.textContent || "";
        if (text && text.length <= CONFIG.maxScriptChars) scanText(text, "inline script", true);
      });
    } catch (e) { fail("scanDOM.scripts", e); }

    try { scanTabnabbing(); } catch (e) { fail("scanDOM.tabnabbing", e); }
    try { if (CONFIG.harvestStateBlobs) harvestFrameworkState(); } catch (e) { fail("scanDOM.state", e); }
    try { if (CONFIG.harvestMetaTags) harvestMetaTags(); } catch (e) { fail("scanDOM.meta", e); }
    try { if (CONFIG.harvestLinkHints) harvestLinkHints(); } catch (e) { fail("scanDOM.links", e); }
    try { if (CONFIG.harvestDataAttributes) harvestDataAttributes(); } catch (e) { fail("scanDOM.dataAttrs", e); }
    try { harvestVisibleText(); } catch (e) { fail("scanDOM.visibleText", e); }
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

    // Injected at document-start, document.documentElement is usually still
    // null, so attaching must be deferred until a real root node exists.
    // Skipping this silently loses all script discovery on server-rendered pages.
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
        // childList only. Observing attributes on the whole document is far too noisy.
        obs.observe(root, { childList: true, subtree: true });
        announce();
        // The tree may already have been built before we attached.
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

  // =====================================================================
  // Cross-frame bridge. A same-site iframe has its own fetch, so its traffic is
  // invisible from the top frame. Pasting the snippet inside the iframe lets it
  // report upward. No requests are made by the parent to do this.
  // =====================================================================
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

  // =====================================================================
  // Help
  // =====================================================================
  function help() {
    for (const l of [
      "x-ray-eye commands",
      "",
      "  START HERE",
      "    xrayeye.config.revealSecrets = true      show cleartext values (off by default; keeps raw only while enabled)",
    "    xrayeye.security()                  full triage across every surface below",
      "",
      "  SURFACE",
      "    xrayeye.report({ min:'MEDIUM', idor:true, unauth:true, challenge:true, spec:true })",
      "    xrayeye.specs()                     parsed OpenAPI / GraphQL / Postman documents",
      "    xrayeye.notes({ kind:'graphql-field' })",
      "",
      "  CREDENTIALS",
      "    xrayeye.secretsReport({ exposure:'leak', severity:'HIGH' })",
      "    xrayeye.secrets({ category:'cloud' })",
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

  // =====================================================================
  // Public API
  // =====================================================================
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

    jwtReport: reportJWTs,
    jwt: opts => listJWTs(opts).map(serializeJWT),
    storageReport: reportStorage,
    storage: opts => listStorage(opts).map(serializeStorage),
    oauthReport: reportOAuth,
    authFlows: () => [...oauthStore.values()],
    frameworks: () => [...fwStore.values()].map(f => ({
      name: f.name, version: f.version || null, versions: [...f.versions], cves: f.cves || []
    })),
    cacheReport: reportCache,
    serviceWorkers: () => [...swStore.values()],
    serverActions: () => listNotes({ kind: "server-action" }).map(n => ({ id: n.id, file: n.file })),

    findings: opts => list(opts).map(f => serialize(f, !!(opts && opts.includeDetails))),

    mark,
    diff,

    sweep: () => { sweepStorage(); inspectServiceWorkers().catch(() => {}); scanTabnabbing(); return api; },
    rescan: () => { scanDOM(); return api; },
    cspCheck: () => crossCheckCSP(),

    markdown: exportMarkdown,
    csv: exportCSV,
    secretsCSV: exportSecretsCSV,
    export: exportJSON,
    download,

    revalidate,
    iframeSnippet,
    probe,

    clear, stop, start, help,

    get stats() { return statsSnapshot(); },
    get errors() { return errors.slice(); },
    get hooks() { return hooks.slice(); },
    get marks() { return [...snapshots.keys()]; }
  };

  // ---------------------------------------------------------------------
  // Boot. Each step is isolated so one failure cannot disable the rest.
  // ---------------------------------------------------------------------
  installFns.push(
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

  // Read-only sweeps. Every one is wrapped so a failure cannot disable capture.
  try { sweepStorage(); } catch (e) { fail("boot.sweepStorage", e); }
  inspectServiceWorkers().catch(e => fail("boot.sw", e));
  try { if (CONFIG.harvestMetaTags) harvestMetaTags(); if (CONFIG.harvestLinkHints) harvestLinkHints(); } catch (e) { fail("boot.domHarvest", e); }

  // The display name contains hyphens, so it cannot be used as a bare
  // identifier. window.xrayeye is the callable name; window["x-ray-eye"] is the
  // same object, reachable only by indexing.
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

  try { scanDOM(); } catch (e) { fail("boot.scanDOM", e); }
  // Observed hosts only become meaningful once traffic has been seen, so the
  // CSP comparison is repeated rather than only run at boot.
  try { crossCheckCSP(); } catch (e) { fail("boot.csp", e); }
  setT(() => { try { crossCheckCSP(); } catch (e) { fail("csp.check", e); } }, 12000);
  if (CONFIG.catchJSONParse || CONFIG.catchConsoleDumps || CONFIG.catchCookieWrites) {
    styled("[x-ray-eye] intrusive hooks are ON (JSON.parse / console / document.cookie). These wrap page functions and can cause visible side effects. Switch them off if the page misbehaves.", STYLE.warn);
  }
})();

