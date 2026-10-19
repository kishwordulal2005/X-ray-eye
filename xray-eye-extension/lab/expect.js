/*
 * lab/expect.js - what each level is supposed to make the analyzer find.
 *
 * Kept separate from the lab server on purpose. If the expectations lived next
 * to the vulnerabilities, editing the lab would quietly rewrite the answer
 * key, and the suite would keep passing while measuring nothing. Here, adding a
 * vulnerability does not add its own pass condition.
 *
 * Each entry: { group, id, why, level }
 *   group - which analyzer group must produce it
 *   id    - substring the finding id must contain
 *   why   - what a detector would have to actually do to earn this
 */

"use strict";

module.exports = [
  // ---------------------------------------------------------------- L1
  { level: "L1", group: "headers", id: "cookie-flag", why: "read Set-Cookie and see no Secure, no HttpOnly, no SameSite" },
  { level: "L1", group: "headers", id: ":no-secure", why: "a session cookie is not marked Secure" },
  { level: "L1", group: "headers", id: ":no-httponly", why: "a session cookie is readable from JavaScript" },
  { level: "L1", group: "headers", id: "hsts", why: "no Strict-Transport-Security on the response" },
  { level: "L1", group: "headers", id: "csp", why: "no Content-Security-Policy on the response" },
  { level: "L1", group: "headers", id: "xfo", why: "nothing forbids framing the response" },
  { level: "L1", group: "headers", id: "referrer", why: "no Referrer-Policy on the response" },
  { level: "L1", group: "leaks", id: "leak:java-stacktrace", why: "recognise a Java stack trace in a response body" },

  // ---------------------------------------------------------------- L2
  { level: "L2", group: "leaks", id: "leak:sql-error", why: "recognise database error text" },
  { level: "L2", group: "leaks", id: "leak:python-traceback", why: "recognise a Python traceback" },
  { level: "L2", group: "injection", id: "sqli:", why: "a reflected parameter beside a DB error is an SQLi candidate" },
  { level: "L2", group: "injection", id: "xss:", why: "a parameter reflected into an href is an XSS candidate" },
  { level: "L2", group: "injection", id: "ssti:", why: "template syntax beside a reflected parameter" },
  { level: "L2", group: "headers", id: "cors-wild", why: "a wildcard CORS origin on a data endpoint" },

  // ---------------------------------------------------------------- L3
  { level: "L3", group: "headers", id: "csp-unsafe-inline", why: "a CSP that is present and allows unsafe-inline" },
  { level: "L3", group: "headers", id: "csp-unsafe-eval", why: "a CSP that allows unsafe-eval" },
  { level: "L3", group: "headers", id: "csp-wildcard", why: "a CSP with a wildcard script source" },
  { level: "L3", group: "headers", id: ":domain", why: "a cookie scoped to every subdomain via a leading dot" },
  { level: "L3", group: "headers", id: "samesite-none", why: "SameSite=None without Secure" },
  { level: "L3", group: "headers", id: ":no-httponly", why: "a SameSite=None cookie that JavaScript can still read" },
  { level: "L3", group: "leaks", id: "leak:debug-flag", why: "a debug flag serialised into a response" },
  { level: "L3", group: "leaks", id: "leak:config-dump", why: "a configuration block in the response" },
  { level: "L3", group: "leaks", id: "leak:webroot", why: "an absolute server path in the response" },
  { level: "L3", group: "leaks", id: "leak:internal-host", why: "a private address in the response" },
  { level: "L3", group: "authz", id: "bfla-noauth", why: "a privileged route with no authentication signal" },
  { level: "L3", group: "authz", id: "bfla-parity", why: "one resource exposed at two privilege levels" },
  { level: "L3", group: "authz", id: "bfla-clientrole", why: "role enforcement living only in the shipped bundle" },
  // The generic privileged-route rule fires on these two as well as on
  // /l3/admin/orders. Both are legitimate: neither sent credentials or
  // challenged, and both are admin-shaped paths.
  { level: "L3", group: "headers", id: "unauth-privileged:", why: "admin-shaped and config-shaped routes with no auth signal" },

  // ---------------------------------------------------------------- L4
  { level: "L4", group: "leaks", id: "leak:env-dump", why: "provider credentials in a response body" },
  { level: "L4", group: "leaks", id: "leak:php-error", why: "a PHP fatal error in the rendered document" },
  { level: "L4", group: "leaks", id: "leak:sql-error", why: "a database error in the rendered document" },
  { level: "L4", group: "leaks", id: "leak:webroot", why: "an absolute server path in the rendered document" },
  { level: "L4", group: "leaks", id: "leak:internal-hostname", why: "an internal hostname in a response" },
  { level: "L4", group: "injection", id: "xss:", why: "a parameter reflected into a script block" },
  { level: "L4", group: "headers", id: "cors-null", why: "a reflected null origin with credentials allowed" },
  { level: "L4", group: "session", id: "token-ttl", why: "a token valid for far longer than a month" },
  { level: "L4", group: "session", id: "logout", why: "an observed logout call" },
  { level: "L4", group: "authz", id: "jwt-role-claim", why: "a token carrying an administrative claim" },

  // ---- the honest negative -----------------------------------------
  // A route that only ever appeared as a string in a bundle was never called,
  // so saying it has "no authentication signal" is a statement about nothing.
  // The lab's L4 bundle contains the literal '/admin', which the engine
  // correctly records as a code reference - and must then decline to judge.
  { level: "L4", group: "headers", id: "ABSENT:/admin", why: "a route never called must not be reported as unauthenticated" },

  // =================================================================
  // Deeper header hygiene
  // =================================================================
  { level: "L3", group: "headers", id: "cors-reflect", why: "a CORS origin that is reflected rather than wildcarded, with credentials" },
  { level: "L3", group: "headers", id: "cors-expose", why: "Access-Control-Expose-Headers naming internal headers" },
  { level: "L3", group: "headers", id: "cors-no-vary", why: "a reflecting CORS origin with no Vary: Origin" },
  { level: "L3", group: "headers", id: "xcto", why: "no X-Content-Type-Options" },
  { level: "L3", group: "headers", id: "perms", why: "no Permissions-Policy" },
  { level: "L3", group: "headers", id: "coop", why: "no Cross-Origin-Opener-Policy" },
  { level: "L3", group: "headers", id: "version", why: "server and x-powered-by disclosing exact versions" },
  { level: "L3", group: "headers", id: "cache-sensitive", why: "personal data in a publicly cacheable response" },
  { level: "L3", group: "session", id: "cookie-no-expiry", why: "a session cookie with no Expires and no Max-Age" },

  // =================================================================
  // Leak classes that are not stack traces
  // =================================================================
  { level: "L3", group: "leaks", id: "leak:git-config", why: "a .git/config with a credentialed remote URL" },
  { level: "L3", group: "leaks", id: "leak:phpinfo", why: "a phpinfo() page" },
  { level: "L3", group: "leaks", id: "leak:private-key", why: "a PEM private key in a response" },
  { level: "L3", group: "leaks", id: "leak:sendgrid", why: "a SendGrid key" },
  { level: "L3", group: "leaks", id: "leak:twilio", why: "a Twilio account SID" },
  { level: "L3", group: "leaks", id: "leak:mailgun", why: "a Mailgun key" },
  { level: "L3", group: "leaks", id: "leak:slack", why: "a Slack bot token" },
  { level: "L3", group: "leaks", id: "leak:firebase", why: "a Firebase database key" },
  { level: "L3", group: "leaks", id: "leak:sql-dump", why: "an SQL dump with INSERT statements and password hashes" },
  { level: "L3", group: "leaks", id: "leak:cms-version", why: "a CMS version in a meta generator or header" },

  // =================================================================
  // Injection candidates beyond XSS/SQLi/SSTI
  // =================================================================
  { level: "L4", group: "injection", id: "ssrf:", why: "a parameter named like a fetch target, reflected" },
  { level: "L4", group: "injection", id: "cmdi:", why: "a parameter named like a command argument, reflected" },
  { level: "L4", group: "injection", id: "jsonp:", why: "a reflected JSONP callback name" },
  { level: "L4", group: "injection", id: "nosql:", why: "a NoSQL operator reflected into a query parameter" },
  { level: "L4", group: "injection", id: "xxe:", why: "an XML response echoing a reflected parameter" },
  { level: "L4", group: "injection", id: "html:", why: "a reflection that reaches markup but not a script context" },
  { level: "L4", group: "injection", id: "openredirect:", why: "a reflected parameter used as a Location target" },

  // =================================================================
  // Authorization
  // =================================================================
  { level: "L4", group: "authz", id: "authz-write-noauth", why: "a state-changing route with no auth signal" },
  { level: "L4", group: "authz", id: "gql-introspection", why: "GraphQL introspection returned without auth" },
  { level: "L4", group: "authz", id: "csrf-missing", why: "a form posting a privileged field with no CSRF token" },

  // =================================================================
  // Session
  // =================================================================
  { level: "L4", group: "session", id: "token-in-url", why: "a token carried in a query string" },
  { level: "L4", group: "session", id: "cookie-longlife", why: "a cookie that lives for a year" },
  { level: "L4", group: "session", id: "alg-none", why: "an unsigned token" },

  // =================================================================
  // Parameter intelligence - one parameter per candidate category
  // =================================================================
  { level: "L4", group: "params", id: "pp:", why: "potential points are produced from parameter names" },
  { level: "L4", group: "params", id: "pp:idor:account_id", why: "an account identifier becomes an object-authorization candidate" },
  { level: "L4", group: "params", id: "pp:ssrf:callback_url", why: "a callback URL becomes an SSRF candidate" },
  { level: "L4", group: "params", id: "pp:file:filename", why: "a filename becomes a file-handling candidate" },
  { level: "L4", group: "params", id: "pp:redirect:returnUrl", why: "returnUrl becomes a redirect candidate" },
  { level: "L4", group: "params", id: "pp:auth:password", why: "a password parameter becomes an authentication candidate" },
  { level: "L4", group: "params", id: "pp:business:price", why: "a price field becomes a business-logic candidate" },
  { level: "L4", group: "params", id: "pp:massassign:role", why: "a role property becomes a mass-assignment candidate" },
  { level: "L4", group: "params", id: "pp:sqli:sort", why: "a sort field becomes a query-shaping candidate" },
  { level: "L4", group: "params", id: "pp:client-sink:message", why: "a message field becomes an untrusted-output candidate" },
  // A body-sourced parameter must be inventoried the same way a query one is.
  { level: "L4", group: "params", id: "pp:file:upload", why: "a JSON body property is inventoried, not only query parameters" },
  { level: "L4", group: "params", id: "pp:idor:tenant_id", why: "an object identifier inside a JSON body is found too" },
  { level: "L4", group: "params", id: "pp:business:amount", why: "a business field inside a JSON body is found too" },
  // A parameter whose name matches nothing is still inventory, at INFO.
  { level: "L4", group: "params", id: "param:zzz_unmatched", why: "an uncategorised parameter is still recorded as an entry point" }
];