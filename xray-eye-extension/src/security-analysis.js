/*
 * security-analysis.js - the Bug Bounty Security Analyzer.
 *
 * These are spliced into src/engine.js by tools/build-analysis.js, inside its
 * IIFE, because every one of them reads internal stores (response headers,
 * response bodies, request/response pairs, JWTs, storage, notes) that the
 * public API only exposes already-serialised.
 *
 * ---------------------------------------------------------------------------
 * THE HONESTY RULE
 *
 * This tool is passive. It never sends a payload it did not see the
 * application send itself. That constraint decides what each detector below
 * can honestly claim, and every one of them is labelled to match:
 *
 *   OBSERVED   read out of a response the application already produced.
 *              A verdict, not a hypothesis.
 *   CANDIDATE  a request value came back in a response body. The
 *              application reflected it. Whether it is exploitable is a
 *              separate question this tool does not and cannot answer
 *              passively.
 *   HYPOTHESIS a static signal that is worth a look. Never a finding.
 *
 * Nothing here fires an injection payload. A payload needs a request, a
 * request needs authorization, and an authorized request is a different tool
 * with a different risk profile. What is genuinely missing is stated rather
 * than faked, which is why XSS/SQLi/SSTI appear as REFLECTION CANDIDATES and
 * not as confirmed injection.
 */

// =====================================================================
// Shared helpers
// =====================================================================

const SEC_MAX = 400;   // findings per group; a busy app must not flood

function secFinding(out, kind, id, severity, title, detail, where, evidence, how, basis) {
  if (out.length >= SEC_MAX) return null;
  const f = {
    id, kind, severity, title, detail: detail || "",
    where: where || "", evidence: evidence == null ? "" : String(evidence).slice(0, 300),
    how: how || "", basis: basis || "OBSERVED",
    at: new Date().toISOString()
  };
  out.push(f);
  // Findings are also notes, so they surface in the Notes tab and in the
  // console reports alongside everything else the scanner already records.
  addNote("sec:" + kind + ":" + id, {
    kind: "security-posture", label: kind, severity, title,
    where: f.where, note: detail, how, value: f.evidence, basis: f.basis
  });
  return f;
}

// Header lookup that tolerates the casing the browser happened to use.
function hdr(headers, name) {
  if (!headers) return null;
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (String(k).toLowerCase() === want) return String(headers[k]);
  }
  return null;
}

// =====================================================================
// 1. Security headers, and the cookies they describe
// =====================================================================

// Set-Cookie can legitimately appear several times in one response; the
// browser hands it over joined, or only the first one, depending on version.
// Both shapes are handled rather than guessing.
//
// Two separators, because the engine has two:
//   ", "  how a browser joins several Set-Cookie headers into one value
//   " | " how storeResponseHeader joins them when it has several separately
// Only a comma followed by a name= is a boundary, so the comma inside an
// Expires date ("Expires=Thu, 01 Jan 1970") does not split a cookie in half.
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
    // The value is never stored or reported. A cookie value is a bearer
    // credential and this file already holds enough of them.
    hasValue: value.length > 0,
    valueLength: value.length,
    secure: /;\s*secure\b/.test(rest),
    httpOnly: /;\s*httponly\b/.test(rest),
    sameSite: attr ? attr[2] : null,
    domain: domain ? domain[1].trim() : null,
    isSession
  };
}

// Names that mean "this is the login", so a flag problem on one of them is a
// session problem rather than a cosmetic one.
const SESSION_COOKIE_RE =
  /^(?:sess(?:ion)?(?:id)?|sid|jsessionid|phpsessid|asp\.net(?:[._]sessionid)?|connect\.sid|csrf(?:token)?|xsrf|auth|__session|__secure-.*|remember_me|laravel_session|connect\.session)$/i;

// A 404 is evidence of absence, and an authorization claim needs the opposite.
//
// The lab caught this immediately. The scanner probes a known list of
// sensitive paths, /admin among them, and the server answered 404. The
// analyzer then reported "privileged route with no authentication signal" -
// about a route that does not exist. A tool that says that once has taught the
// operator to ignore the rows that matter.
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

// Whether a response body carries things that identify a person. Deliberately
// narrow: a false positive here becomes a Medium cache finding on an ordinary
// page, and a Medium finding that is wrong costs more credibility than the one
// it would have caught.
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
    // A 404's headers describe an error page, not the application's security
    // posture. Reporting "no HSTS on /admin" for a probed path that does not
    // exist is four false positives for every sensitive path the scanner tries,
    // and the scanner tries a list of them by default.
    if (looksAbsent(f)) continue;
    const where = f.method + " " + (f.host || "") + (f.normalizedPath || f.path || "");
    origins.add(f.host || "");
    const H = f.responseHeaders;

    // ---- cookies -------------------------------------------------------
    for (const raw of splitSetCookie(hdr(H, "set-cookie"))) {
      const c = parseSetCookie(raw);
      if (!c || !c.name) continue;
      // The id prefix matches the kind, so a row's id names its own group. "cookie:"
// against kind "cookie-flag" meant no id-based filter could ever find these.
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

    // ---- transport and framing ----------------------------------------
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

    // ---- content sniffing, capability restriction, cross-origin isolation
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

    // ---- exact version disclosure
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

    // ---- personal data served out of a shared cache
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

    // ---- CORS ----------------------------------------------------------
    // Read from the raw headers, not only from the posture flags. The
    // dangerous case - a specific origin being REFLECTED with credentials -
    // is invisible to a wildcard/null check, and reflection is what a real
    // misconfiguration looks like: "*" is obvious, reflecting the caller's
    // Origin is not.
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
        // The exact flag corsPosture pushes. An earlier version here read
        // "null-origin", which corsPosture has never emitted - so this branch
        // was unreachable and a reflected null origin was silently dropped.
        secFinding(out, "cors", "cors-null:" + f.host + (f.normalizedPath || f.path), "MEDIUM",
          "CORS reflects the null origin",
          "A null origin comes from sandboxed iframes and data: URLs, including " +
          "cross-origin opener abuse. Reflecting it widens who can read the response.",
          where, clip(hdr(H, "access-control-allow-origin") || "", 120), null, "OBSERVED");
      }
    }

    // ---- auth posture ---------------------------------------------------
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

// =====================================================================
// 2. Configuration leaks and verbose errors in real response bodies
// =====================================================================

// Each pattern is evidence that the application produced a diagnostic it did
// not mean to ship. Nothing here is guessed from a URL; every hit is a string
// the server actually returned.
// No ^ or $ anchors anywhere in this catalogue, and that is deliberate.
//
// The body the analyzer reads has usually been through describeText, which
// re-serialises JSON. A pretty-printed config dump arrives as one long line,
// so a line-anchored rule like /^\s*"DATABASE_URL"\s*:/m can never match it -
// and the rule looks perfectly correct while being impossible to satisfy. The
// same applies to the stack-trace rule: word boundaries anchor it, not lines.
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
  // Case-insensitive on purpose. PHP's own error names are lowercase in
  // practice - mysqli_sql_exception, not mysqli_sql_Exception - so a
  // case-sensitive rule misses exactly the string it was written for. The
  // colon after "Fatal error" is also optional, because the server usually
  // wraps that text in <b> and puts the punctuation outside the tag.
  { id: "php-error", re: /Warning:|Fatal error|Parse error|Uncaught\s+\w*(?:Error|Exception)|\b(?:PDOException|ErrorException)\b/i,
    weight: 70, title: "PHP error output in the response",
    detail: "PHP errors leak file paths and occasionally query text." },
  { id: "ruby-error", re: /ActionController::\w+Exception|ActiveRecord::\w+Exception|\.rb:\d+:in/,
    weight: 85, title: "Ruby/Rails exception in the response",
    detail: "Names the controller, the model and the migration context." },
  { id: "node-error", re: /\bat\s+\/[^\s:]+\.js:\d+:\d+|node_modules\/[\w@/.-]+/,
    weight: 70, title: "Node stack trace or module path in the response",
    detail: "Reveals the install layout and dependency versions." },
  // The MariaDB/MySQL wording is long and version-specific, so the substring is
  // truncated to "You have an error in your SQL syntax" rather than copied in
  // full - that part of the message has been stable across versions, and a
  // full-sentence rule breaks the first time the server appends something.
  { id: "sql-error", re: /SQLSTATE\[|ORA-\d{5}|pg_query\(\)|You have an error in your SQL syntax|mysql_fetch|valid MySQL result|mysqli_sql_exception|valid MariaDB result/i,
    weight: 90, title: "database error text in the response",
    detail: "A database error names the engine and often echoes part of the statement. It is the classic route from an error page to a blind SQL injection." },
  { id: "ignition", re: /Whoops!|Ignition\\+(?:\x2f)?\w*|laravel\.com\x2fdocs\x2f\d|Whoops\\?\w*Exception/i,
    weight: 85, title: "debug exception page",
    detail: "A development-mode error page. These routinely include environment variables and source excerpts." },
  // The closing quote before the separator is optional and must be. A JSON body
  // spells the key as "APP_DEBUG": true, so a rule that expects APP_DEBUG
  // directly against the colon never fires on exactly the JSON it was written
  // for - which is why debug flags and env dumps went undetected while the
  // rule looked correct.
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

  // ---- not stack traces: artifacts that were never meant to leave the server
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

// Match signatures against a body and return what was found, with the offset.
//
// Split out from the reporting so it can run over the RAW response text, at
// capture time. That matters more than it looks: the engine redacts known
// secret patterns out of the body it STORES, so by analysis time a SendGrid
// key, a Slack token and a Firebase URL have all been replaced with
// [REDACTED] and match nothing. A Mailgun key in the same response survived,
// which is worse - it makes the detector look partly working rather than
// blind, and it was exactly that: 5 of 9 provider keys in the lab were
// unfindable for a reason that had nothing to do with the signatures.
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

// Runs once per response, over the raw text, before redaction touches it.
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

// One text, one pass over the signature catalogue. Shared by the recorded
// API responses and by the page's own HTML, because a verbose error is just
// as often rendered into the document as returned by an endpoint.
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
  // Read from the notes recorded at capture time, over the RAW body. Re-running
  // the signatures here would match against a body the engine has already
  // redacted, which is how five of nine provider keys in the lab became
  // unfindable.
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

// The page's own HTML.
//
// This is the one surface that carries no network record at all, and it was
// the one that mattered. A server-rendered fatal error - a PHP parse error, a
// SQL exception thrown straight into the markup, a stack trace in the body -
// arrives as the document and produces ZERO captured endpoints, because the
// scanner records fetch, XHR and beacons, not the navigation that already
// happened. So the panel showed an empty analyzer sitting on top of a page
// that was printing a full SQL error and its server-side file path.
//
// The document is read live, so this works whether or not the scanner was
// started before the page loaded, and it never sends anything.
function analyzeDocumentLeaks() {
  if (typeof hasDOM === "undefined" || !hasDOM) return [];
  let src = "";
  try { src = htmlSourceSnapshot(); } catch (_) { return []; }
  if (!src) return [];
  let url = "";
  try { url = String(location.href || ""); } catch (_) { url = ""; }
  return scanLeakText(src, "document " + url, "document:" + url, "the page itself");
}

// =====================================================================
// 3. Injection candidates
//
// Reflection, not injection. The application put its own input back into its
// own response. That is the precondition for reflected XSS, for error-based
// SQLi and for template injection, and it is observable without sending
// anything. Whether the reflection lands in an executable context is a
// question the response body usually answers, and this reads it.
// =====================================================================

// A value distinctive enough that finding it in the response is not a
// coincidence. Short values are excluded on purpose: "1" appears everywhere.
const REFLECTABLE = /^[A-Za-z0-9@!#$%^&*().\-_+=]{6,}$/;

function sinkOf(body, at, valueLen) {
  const before = body.slice(Math.max(0, at - 120), at);
  const after = body.slice(at + valueLen, at + valueLen + 120);
  if (/<script[\s>][\s\S]{0,200}$/i.test(before) || /on\w+\s*=\s*["'][^"']{0,80}$/i.test(before)) {
    return { sink: "script", detail: "the value lands inside a script block or an event-handler attribute" };
  }
  // URL attributes are checked before the generic tag rule on purpose. Every
  // href value sits inside a tag, so the order decides the answer, and
  // href=/src=/action= is the javascript: vector that "lands in a tag" hides.
  if (/(?:href|src|action|formaction|data)\s*=\s*["'][^"']*$/i.test(before)) {
    return { sink: "url", detail: "the value lands in a URL attribute, which is the javascript: vector" };
  }
  if (/jsonp|callback\s*[:=]/i.test(before)) {
    return { sink: "jsonp", detail: "the value lands in a JSONP callback name" };
  }
  // The real JSONP shape. The response is a script that guards on
  // "typeof NAME === 'function'" and then calls NAME - so the callback name is
  // the one thing an attacker controls in a script the browser will execute.
  //
  // The pattern necessarily STRADDLES the reflected value, so it cannot be
  // tested against `before` or `after` alone: `before` ends at "typeof" and
  // `after` begins at "===". A window rebuilt around the value is the only
  // thing that sees the whole guard.
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

// Parameter names that describe what the server does with the value. The name
// is the tell - a parameter called "url" is handed to something that fetches,
// one called "ip" is handed to something that resolves. Neither conclusion is
// safe to draw on the name alone, so everything built on these is a
// CANDIDATE and says so.
const SSRF_PARAMS = /^(?:url|uri|dest|destination|target|proxy|fetch|site|host|domain|endpoint|feed|webhook|redirect_uri|image|img|file|path|src|resource|out|view|next)$/i;
const CMDI_PARAMS = /^(?:cmd|command|exec|execute|shell|ping|ip|addr|host|ns|lookup|dig|trace|target_file|file_?path|dir|user_?agent|agent)$/i;
const REDIRECT_PARAMS = /^(?:redirect|redirect_uri|return|return_url|returnurl|next|returnto|goto|target|rurl|dest|continue|to)$/i;
const NOSQL_PARAMS = /^(?:user|username|login|email|account|password|pass|q|query|search|filter|where|id)$/i;

function analyzeInjection() {
  const out = [];

  // ---- JSONP: a callback name the application executes.
  //
  // Its own finding rather than a sink label. JSONP wraps a script response in
  // a caller-supplied function call, so the callback is not reflected INTO
  // markup - it is invoked, which makes it a script context even though the
  // response body never looks like one. Filing it under XSS hid that.
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

  // ---- parameter-class candidates, beyond reflection by sink.
  //
  // XSS, SQLi and SSTI are all "the value came back". These are "the value
  // went somewhere": a URL the server fetched, a string the server executed,
  // a callback the server invoked, a document it parsed. Reflection is what
  // makes them worth a look; the parameter name is what says where to look.
  // None of them are asserted as reachable.
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
    // A NoSQL operator is a parameter KEY, not a name. The application
    // accepted "?user[$ne]=1" as a structured key, which only means anything
    // if the driver honours operators - that is the test.
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

  // ---- markup injection: a reflection that is not a script context
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

  // ---- a reflected redirect target, recorded from the Location header
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
  // Reflections are recorded at response time by noteReflections, because the
  // stored endpoint keeps a normalized URL with no query string. Reconstructing
  // what was submitted from a URL that no longer holds it is not possible, and
  // guessing at it would produce findings nobody can reproduce.
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
      // Not gated on the sink. The response rendered template syntax and echoed
      // the submitted value; whether the expression is evaluated server-side is
      // exactly the question one payload answers, and this tool does not send it.
      secFinding(out, "injection", "ssti:" + n.noteId + ":" + n.param,
        "MEDIUM",
        "parameter reflected beside template syntax: " + n.param,
        "The response contains template delimiters and the submitted value. Server-side " +
        "template injection is worth ruling out here.",
        n.where, n.evidence,
        "Send " + n.param + "={{7*7}}. Not sent by this tool.",
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
  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

// A credential in the query string. Recorded here, at response time, because
// the stored endpoint keeps a normalized URL with no query string - so by the
// time anything tries to analyse it, the parameter name and the value are
// both gone. This is the same reason reflections are captured here.
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
    // The value is withheld. The parameter NAME is the finding; showing the
    // value would put a live credential into a report.
    value: m[1] + "=[value withheld]",
    note: "A credential was passed in the query string. It lands in browser history, " +
      "in the Referer sent to every third-party resource, and in every proxy log " +
      "between here and the server."
  });
  return 1;
}

// Runs once per response, while both the submitted values and the body are in
// hand. Everything it records is a fact about what the application sent back.
//
// Returns the number of reflections found, so the caller can lift the
// endpoint's score. A response that hands the caller its own input back is not
// an unremarkable HTML page, and without this it scores under the IGNORE cut
// and never reaches the endpoint table at all - so the one response most worth
// looking at was the one the table hid.
function noteReflections(meta) {
  const text = meta.responseText;
  if (!text || typeof text !== "string") return 0;
  const u = parseURL(meta.url);
  if (!u) return 0;
  const host = String(u.host || "");
  const path = String(u.pathname || "/");
  const method = String(meta.method || "GET");

  // A Location header carrying a submitted value is an open redirect the
  // moment the parameter can be set to an external host. Caught here because
  // the query that carried it is gone by analysis time.
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
      // The response content-type travels with the note because the excerpt
      // is clipped around the reflection and the interesting part of an XML
      // declaration sits at the top of the document, outside the clip. An
      // XXE judgement made from a clipped excerpt is a judgement made blind.
      contentType: String(meta.responseContentType || ""),
      sqlError, templateEcho,
      // The value is recorded so the tester can retype exactly what was
      // reflected; a finding nobody can reproduce is not a finding.
      value: p.value,
      evidence: clip(text.slice(Math.max(0, at - 80), at + 160), 220),
      note: "The application reflected the submitted value " + p.name +
        " into its own response (" + s.sink + " context)."
    });
    void n;
  }
  return found;
}

// =====================================================================
// 4. Function-level authorization
//
// BOLA asks "can I read someone else's row". BFLA asks "can this account call
// a function it should not". Answering it needs two identities of different
// privilege making real calls, which a passive scanner cannot do. What is
// possible here is generating the hypotheses worth testing, and being blunt
// about which claims are unproven.
// =====================================================================

const PRIVILEGED_ROUTE_RE =
  /\/(?:admin|administrator|manage[^\/]*|internal|system|console|back-?office|billing|impersonat\w*|su|root|superuser|debug|actuator|metrics|graphql|schema|sys\/|v1\/admin)(?:[\/?]|$)/i;
const ROLE_CHECK_RE =
  /\b(?:isAdmin|isSuperUser|canAccess|hasPermission|hasRole|checkRole|role\s*===?\s*["'](?:admin|super|root|owner)["']|["']?(?:admin|superuser)["']?\s*===?\s*\w+\.role|\.includes\(["']admin["']\))\b/i;

function analyzeFunctionAuthz() {
  const out = [];

  // --- privileged surfaces, and whether any auth signal came with them ----
  for (const f of store.values()) {
    const path = String(f.normalizedPath || f.path || "");
    if (!PRIVILEGED_ROUTE_RE.test(path)) continue;
    // A path the server answered 404 for is not a privileged route, it is a
    // route that is not there. Saying it has no authentication signal is a
    // claim about nothing, and it is the kind of row that teaches an operator
    // to dismiss the whole tab.
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

    // The same operation exposed at two privilege levels is the classic BFLA
    // shape: /orders and /admin/orders.
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

  // --- client-side-only role enforcement ---------------------------------
  // A role check in shipped JavaScript enforces nothing on its own. It is only
  // worth reporting when there is also something to protect, which is what the
  // privileged-route scan above supplies.
  const hasPrivileged = out.length > 0;
  if (hasPrivileged) {
    let checks = 0;
    const samples = [];
    for (const f of store.values()) {
      if (!f.sources) continue;
      // Source text is not retained; the note is produced at scan time instead.
      void f;
    }
    // Recorded during scanning by noteRoleChecks below.
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

  // --- state-changing calls with no authentication signal at all.
  //
  // The most consequential thing this analyzer can say, and the one most
  // often wrong. It is therefore gated hard: the route must have been
  // OBSERVED, must have answered something other than 404, must not have
  // challenged, and must not have received credentials from the application.
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

  // --- GraphQL introspection, answered for anyone
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

  // --- a privileged form field with no CSRF token beside it.
  //
  // Read from the rendered document, because a form is markup rather than a
  // response the analyzer would otherwise see.
  let formHtml = "";
  try { formHtml = htmlSourceSnapshot(); } catch (_) { formHtml = ""; }
  if (formHtml) {
    const formM = /<form\b[^>]*>([\s\S]{0,4000}?)<\/form>/i.exec(formHtml);
    if (formM && /(?:name|id)\s*=\s*["'](?:role|admin|is_admin|isadmin|permission|group|owner|uid)["']/i.test(formM[1])) {
      if (!/csrf|xsrf|_token|authenticity/i.test(formM[1]) && !/csrf|xsrf|_token|authenticity/i.test(formM[0])) {
        secFinding(out, "authz", "csrf-missing:document", "MEDIUM",
          "a form sets a privilege field with no CSRF token",
          "The form posts a role or ownership field and carries nothing that " +
          "identifies the session as the one that loaded it. Any page can make a " +
          "browser submit it.",
          "document " + (typeof location !== "undefined" ? location.href : ""),
          (formM[1].match(/(?:name|id)\s*=\s*["'][^"']+["']/g) || []).slice(0, 5).join(", "),
          "Add a per-session token to the form and verify it server-side.",
          "HYPOTHESIS");
      }
    }
  }

  // --- admin-shaped claims in observed tokens ----------------------------
  for (const j of jwtStore.values()) {
    const adminish = (j.signals || []).some(s => s.id === "admin-claim" || s.id === "privilege-claim");
    if (!adminish) continue;
    // Not a BFLA hypothesis: the claim really is in the token. The id says so,
    // because an id that reads "bfla-" would invite the reader to treat an
    // observed fact as a conclusion.
    secFinding(out, "authz", "jwt-role-claim:" + fnv1a(String(j.sub || "") + String(j.iss || "")),
      "MEDIUM",
      "token carries an administrative claim",
      "A token in the browser carries a role or admin claim. Role claims are " +
      "attacker-editable only if the signature check is weak, so check the token " +
      "before assuming the claim decides anything server-side.",
      "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"),
      j.masked || "", null, "OBSERVED");
  }

  return out.sort((a, z) => sevRank(z.severity) - sevRank(a.severity));
}

// Records role checks while scanning script text, where the text still exists.
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

// =====================================================================
// 5. Session security
// =====================================================================

function analyzeSessions() {
  const out = [];

  // --- where tokens live, and what that costs -----------------------------
  const byArea = {};
  for (const s of storageStore.values()) {
    const key = String(s.area || "?");
    byArea[key] = (byArea[key] || 0) + 1;
    if (s.hasJwt) {
      secFinding(out, "session", "token-localstorage:" + s.name, "MEDIUM",
        "token held in " + s.area + ": " + s.name,
        "Web storage is readable by every script on the origin and survives the tab " +
        "closing. A token here is exposed to any XSS and persists indefinitely.",
        s.area + " / " + s.name, s.masked || "(withheld)",
        "If this is a session token, move it to a Secure, HttpOnly cookie. " +
        "If it is a refresh token, accept the exposure and keep it short-lived.",
        "OBSERVED");
    }
  }

  // --- long-lived tokens, and how they are signed.
  //
  // The engine already decodes every token it sees; this is the reporting
  // half. alg:none gets its own row because it is not a weak secret - it is
  // no verification at all, and it belongs at the top of a triage list rather
  // than buried among lifetime warnings.
  const now = Math.floor(Date.now() / 1000);
  for (const j of jwtStore.values()) {
    const signals = j.signals || [];
    if (signals.some(s => s.id === "alg-none")) {
      secFinding(out, "session", "alg-none:" + fnv1a(String(j.sub || "") + String(j.iss || "")),
        "HIGH", "an unsigned token (alg: none)",
        "The token carries alg:none, so there is no signature for a server to " +
        "verify. If the server accepts it, anyone can mint a token for any user - " +
        "privilege escalation by construction rather than by exploitation.",
        "sub=" + (j.sub || "?") + "  alg=" + (j.alg || "?"), j.masked || "",
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

  // --- logout behaviour ---------------------------------------------------
  // The observable form of "logout works" is that the token stops being sent
  // or stops existing. Without instrumentation of logout this can only be a
  // signal, never a verdict.
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

  // --- cookies without JS-readable flags, summarised ---------------------
  if (byArea.cookie) {
    secFinding(out, "session", "cookies-present", "INFO",
      byArea.cookie + " cookie(s) readable from JavaScript",
      "These are the cookies document.cookie can see, which excludes every " +
      "HttpOnly cookie. Anything not listed here may still be set with HttpOnly - " +
      "absence is not evidence of absence.",
      "document.cookie", null, null, "OBSERVED");
  }

  // ---- cookie lifetime, from Set-Cookie on real responses
  //
  // A cookie with neither Expires nor Max-Age dies with the browser session,
  // which is usually what you want. One with a year is not a session cookie
  // whatever it is called, and outlives every "log out" the user believes in.
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

  // ---- a token carried in the URL. Recorded at response time by
  // noteUrlCredentials, because the stored endpoint URL has no query string.
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

// =====================================================================
// Headers the page can never see
// =====================================================================

// Chrome does not expose Set-Cookie to JavaScript at all. fetch() hides it,
// Headers.forEach() omits it, and getSetCookie() returns an empty array even
// for a same-origin response. The whole cookie-flag group therefore reads
// nothing unless the extension's service worker captures the headers out of
// band with webRequest, where they are visible, and hands them to the page.
//
// The real-browser lab pass found this: the vm sandbox reported cookie flags
// and Chrome reported none, because the sandbox's fetch mock was more
// permissive than the platform. A mock that over-delivers hides exactly this
// kind of gap, which is the reason the lab drives a real browser as well.
function setExternalHeaders(list) {
  let n = 0;
  for (const e of (list || [])) {
    if (!e || !e.url || !e.headers) continue;
    try {
      // Routed through the engine's own record path rather than a parallel
      // store, so an externally-seen response is indistinguishable from one
      // seen in-page everywhere downstream: status, confidence, scoring and
      // the "does this route even exist" check all keep working.
      record({
        source: "webRequest",
        url: e.url,
        method: e.method || "GET",
        observed: true,
        status: typeof e.status === "number" ? e.status : undefined,
        responseHeaders: e.headers,
        // webRequest contributes no path evidence of its own; without a bonus
        // an ordinary route would score under the cut-off and be dropped
        // before the cookie check ever saw it.
        scoreBonus: 30
      });
      n++;
    } catch (err) { fail("setExternalHeaders", err); }
  }
  return n;
}

// =====================================================================
// Parameter intelligence
//
// Every candidate category is decided from the parameter's NAME, which is
// never enough on its own. A parameter called "id" is not an IDOR, it is an
// IDOR candidate, and the difference is the whole point: this tool produces
// leads, and every row says what evidence raised it and what would settle it.
//
// Confidence is set by corroboration, never by the name:
//   HIGH    the name matches AND the application did something with it -
//           reflected it into a dangerous context, or returned a matching error
//   MEDIUM  the name matches AND the value came back in the response, so the
//           application demonstrably handles it
//   LOW     the name matches and nothing else is known
// =====================================================================

const PARAM_CATEGORIES = [
  // ---- object and tenant identifiers
  { cat: "idor", re: /^(?:[iu]id|guid|uuid|[a-z]{2,20}_?id|.*_?ids)$/i,
    strict: /^(?:id|uid|uuid|guid|user_?id|account_?id|tenant_?id|org_?id|organisation_?id|customer_?id|client_?id|order_?id|invoice_?id|project_?id|member_?id|role_?id|group_?id|session_?id|parent_?id|owner_?id|file_?id|doc_?id)$/i,
    next: "Fetch the same object with an account that should not own it and compare the responses.",
    why: "identifies another object's record, which is what object-level authorization is checked against" },

  // ---- server-side fetch targets
  { cat: "ssrf", re: /^(?:url|uri|url_?s|link|href|src|site|host|hostname|ip|ip_?addr|domain|target|dest|destination|endpoint|callback|callback_?url|webhook|webhook_?url|notify_?url|hook|feed|proxy|gateway|remote|remote_?url|resource|img|image|avatar|og_?url|page_?url|return_?url|referrer|referer|continue_?url)$/i,
    strict: /^(?:url|uri|url_?s|link|site|host|hostname|domain|endpoint|callback|callback_?url|webhook|webhook_?url|notify_?url|feed|proxy|remote_?url|img|image|og_?url|page_?url)$/i,
    next: "Point it at a callback you control, or at 169.254.169.254, and see whether the server makes the request.",
    why: "a value the server may fetch, which makes it a server-side request forgery target" },

  // ---- filesystem and upload surface
  { cat: "file", re: /^(?:file|filename|file_?name|filepath|file_?path|path|dir|directory|upload|upload_?file|attachment|document|doc|archive|temp|template|import|export|bulk|csv|folder|image_?path|avatar|save_?as|destination|output|input)$/i,
    strict: /^(?:file|filename|file_?name|filepath|file_?path|path|dir|directory|upload|attachment|document|archive|template|import|export|folder|save_?as|output|input)$/i,
    next: "Try a path traversal sequence and an unexpected extension. Confirm nothing is written and nothing executes.",
    why: "handles a filename or path, which is where traversal, overwrite and upload issues live" },

  // ---- navigation
  { cat: "redirect", re: /^(?:next|next_?url|return|return_?url|returnurl|returnto|return_?to|redirect|redirect_?url|redirect_?uri|redirectto|continue|continue_?url|goto|go|dest|target|rurl|to|uri|path|continue_?path|back)$/i,
    strict: /^(?:next|next_?url|return|return_?url|returnurl|redirect|redirect_?url|redirect_?uri|continue|goto|rurl|continue_?path|back)$/i,
    next: "Request it with an external destination such as https://example.invalid/ and see whether the browser is sent there.",
    why: "a value the application redirects to, which is the standard open-redirect shape" },

  // ---- authentication flows
  { cat: "auth", re: /^(?:login|log_?in|signin|sign_?in|username|user|email|password|passwd|pwd|pass|otp|code|mfa|2fa|token|access_?token|refresh_?token|id_?token|auth|authorization|otp_?code|verification|captcha|reset|forgot|new_?password|sso|saml|oauth|oauth_?code|callback|state|nonce|api_?key|apikey|secret|session)$/i,
    strict: /^(?:login|signin|username|password|passwd|otp|code|mfa|2fa|token|access_?token|refresh_?token|auth|captcha|reset|forgot|sso|saml|oauth|oauth_?code|api_?key|secret|session)$/i,
    next: "Walk the flow with a throwaway account and note each step that changes state without proving who asked.",
    why: "belongs to an authentication or session flow, where state transitions are the question" },

  // ---- money, ownership and workflow state
  { cat: "business", re: /^(?:price|amount|total|subtotal|cost|fee|discount|discount_?pct|coupon|promo|quantity|qty|units|balance|credit|transfer|payment|plan|tier|role|status|state|owner|ownership|approved|approval|verified|active|enabled|locked|banned|workflow|stage|step)$/i,
    strict: /^(?:price|amount|total|subtotal|discount|quantity|qty|balance|credit|transfer|role|status|owner|approved|verified|active|plan|tier)$/i,
    next: "Change one field by one step and check the server still validates it rather than trusting the client.",
    why: "a field the client proposes and the server is supposed to decide, which is where price and role logic breaks" },

  // ---- properties the server should own
  { cat: "massassign", re: /^(?:role|roles|is_?admin|admin|is_?staff|is_?super|permission|permissions|scope|scopes|group|groups|verified|approved|active|status|balance|credit|price|owner_?id|tenant_?id|account_?id|plan|tier|subscription|email|username|user_?id|created_?by|internal)$/i,
    strict: /^(?:role|roles|is_?admin|admin|is_?super|permission|permissions|scope|verified|approved|balance|price|owner_?id|tenant_?id|plan|tier|internal)$/i,
    next: "Send the field in the request body and see whether the server accepts it or ignores it.",
    why: "a property the client can propose that a server should be the only authority for" },

  // ---- query-shaping
  { cat: "sqli", re: /^(?:id|order|orderby|order_?by|sort|sortby|group|groupby|filter|where|q|query|search|find|keyword|limit|offset|page|per_?page|fields|select|column|table)$/i,
    strict: /^(?:order|orderby|sort|sortby|groupby|filter|q|query|search|keyword|limit|offset|per_?page|fields|select)$/i,
    next: "Send a single quote and compare the response with a clean one.",
    why: "shapes a query, which is where a value reaching the query layer matters" },

  // ---- outbound navigation with server participation
  { cat: "client-sink", re: /^(?:message|msg|comment|note|notes|content|body|text|title|description|label|search|q|name|display|html|markdown)$/i,
    strict: /^(?:message|msg|comment|note|content|body|text|title|description|html)$/i,
    next: "Confirm the value is escaped in every context it lands in, not just the one you tested.",
    why: "free text the application may place into a document" }
];

const GRAPHQL_PARAM_RE = /^(?:operationName|operation|variables|query|mutation|subscription|field|fragment)$/i;

// Parameters seen on a request. Recorded at response time because the stored
// endpoint keeps a normalized URL and no query string at all - the parameter
// names are simply not there to be read later.
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
      // Whether the application demonstrably handles the value: the only
      // corroboration available without sending anything.
      reflected: !!value && String(meta.responseText || "").indexOf(String(value)) >= 0,
      isInt: /^\s*-?\d+\s*$/.test(String(value || "")),
      isUrl: /^https?:\/\//i.test(String(value || "")),
      isBool: /^(?:true|false|0|1)$/i.test(String(value || "")),
      categories: cats,
      // Kept short and marked as a shape, not a value. The finding shows what
      // was submitted; the secret never sits in a note waiting to be exported.
      shape: String(value == null ? "" : value).slice(0, 40),
      value: CONFIG.revealSecrets ? String(value).slice(0, 80)
        : (String(value).slice(0, 8) + "...")
    });
    n++;
  };

  // query string
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

  // body
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

  // GraphQL variables, which arrive as an opaque JSON string inside a query
  // parameter and are otherwise invisible to every other pass.
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

// =====================================================================
// Potential points
//
// The table the operator works from. Each row is a lead, never a verdict:
// a parameter name raised it, and the row carries the evidence, the
// confidence and the safe next step so it can be promoted or dismissed
// deliberately rather than by reading a title.
// =====================================================================

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

    // A parameter with no category is still inventory, and inventory is one of
    // the things the panel is for. It is reported at INFO so it cannot be
    // mistaken for a lead.
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

      // Confidence is corroboration, never the name.
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

      // Ids carry the category and the parameter name, not a note sequence number.
// A note id is stable only until something re-runs; "pp:idor:account_id" can
// be filtered, exported, referenced in a report and diffed between runs, which
// is the entire reason a dashboard needs one.
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

// =====================================================================
// Attack-surface graph
//
// domains -> javascript -> endpoints -> parameters -> auth
// A map, not a verdict. Exported so it can be rendered, diffed or read in a
// text editor, which is more use than a picture for anything but a demo.
// =====================================================================
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

// =====================================================================
// Observed schema model
//
// What the API actually returned, built from captured bodies. Used to spot
// fields that were not in the specification and shapes that differ between
// two routes serving what is nominally the same resource.
// =====================================================================
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

// =====================================================================
// Public surface
// =====================================================================

// Bumped whenever the analyzer's commands change shape. The panel compares
// this against its own expected value and refuses to show an empty table
// when they disagree - see the note on hello() in page.js.
const ANALYZER_BUILD = "security-1";

// A picture of what the analyzer could actually see.
//
// Added because "it doesn't detect anything" was reported three times and each
// time the cause was a different thing - a stale injection, a swallowed RPC
// error, a document pass that never ran. Every one of those LOOKED identical
// from outside the page: an empty table. This answers the question directly
// instead of leaving it to inference, so the next report needs one screenshot
// rather than another round of hypotheses.
function analyzerDiagnostics() {
  let docChars = 0, docErr = null, docPreview = "", docMatches = [];
  try {
    if (typeof hasDOM === "undefined" || !hasDOM) docErr = "no DOM in this context";
    else {
      const src = htmlSourceSnapshot();
      docChars = src ? src.length : 0;
      docPreview = src ? clip(src.replace(/\s+/g, " "), 600) : "";
      // Which signatures actually matched the document, by name. "3 leaks" is
      // not an answer on its own - three matches can be three real findings or
      // three false positives on an ordinary page, and those need opposite
      // responses from whoever is reading the report.
      if (src) {
        for (const s of LEAK_SIGNATURES) if (s.re.test(src)) docMatches.push(s.id);
      }
    }
  } catch (e) { docErr = String((e && e.message) || e); }

  const groups = {
    headers: 0, leaks: 0, injection: 0, authz: 0, session: 0
  };
  let analysisErr = null;
  // The findings themselves, not just how many. Reporting "3" forced a second
  // round trip to learn whether they were the SQL error or three false
  // positives on a harmless page - and those two answers look identical.
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
  // The document's own HTML is included, not just captured API responses.
  const leaks = [...analyzeResponseLeaks(), ...analyzeDocumentLeaks()].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const injection = analyzeInjection();
  const authz = analyzeFunctionAuthz();
  const session = analyzeSessions();
  const params = analyzePotentialPoints();
  const surface = analyzeAttackSurface();
  const schema = analyzeSchema();
  // Each row is stamped with the group that produced it. The row's own `kind`
  // is finer-grained than the group ("cookie-flag" inside "headers"), and
  // making the panel re-derive the grouping from an id string would put that
  // knowledge in two places.
  const stamp = (rows, group) => rows.map(r => { r.group = group; return r; });
  stamp(headers, "headers"); stamp(leaks, "leaks"); stamp(injection, "injection");
  stamp(authz, "authz"); stamp(session, "session"); stamp(params, "params");

  // Confidence and status travel with every potential point, because the panel
  // is a work queue rather than a report. A candidate carries how it was
  // raised, what would settle it, and - set by the operator, not by the
  // analyzer - where in review it has got to.
  const confRank = { high: 3, medium: 2, low: 1 };
  for (const r of params) {
    r.confidence = /it was reflected|matching error/.test(r.how || "") ? "high"
      : /came back in the response/.test(r.detail || "") ? "medium" : "low";
    r.status = "unverified";
    r.endpoint = r.where;
    r.category = (CAT_META[r.cat] || { label: r.cat }).label;
  }

  // Deduplication and prioritisation. The same class of lead on the same
  // route from two different passes is one piece of work, not two.
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

  // What was actually examined. An empty result means nothing without this:
  // "no findings" and "nothing to look at" look identical in a table, and
  // only one of them is a result.
  let bodies = 0, responses = 0;
  for (const f of store.values()) {
    if (f.responseHeaders) responses++;
    if (f.responseBody) bodies++;
  }
  const coverage = { endpoints: store.size, responses, bodies };
  // How much of the page itself was readable. An empty leaks group and a
  // zero here are very different facts, and showing only the first one is how
  // a dead scanner gets mistaken for a clean target.
  coverage.documentChars = (function () {
    try { if (typeof hasDOM === "undefined" || !hasDOM) return 0; return htmlSourceSnapshot().length; }
    catch (_) { return 0; }
  })();
  coverage.scannerErrors = (typeof errors !== "undefined" ? errors.length : 0);
  const limits = [
    "No payload is ever sent. Injection findings are REFLECTION CANDIDATES, " +
    "observed in responses the application already produced.",
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
  // An application that answers 404 to everything - a SPA with a catch-all
  // route, or one behind a proxy - would otherwise report a perfectly clean
  // header posture that was never actually observed.
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
    // The potential points are their own group so the panel can rank them,
    // filter them and carry per-row review state without touching the
    // security findings they are derived from.
    params: prioritized,
    surface,
    schema,
    counts: {
      headers: headers.length, leaks: leaks.length, injection: injection.length,
      authz: authz.length, session: session.length, params: prioritized.length
    },
    coverage,
    limits
  };
}
