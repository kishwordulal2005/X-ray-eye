/*
 * lab/server.js - a deliberately vulnerable lab, four levels deep.
 *
 *   node lab/server.js            serve on http://127.0.0.1:8787
 *   PORT=9000 node lab/server.js
 *
 * Local only. It binds to loopback, it has no auth, and it exists to be
 * attacked by the analyzer. Every vulnerability here is synthetic.
 *
 * Each level declares not only its routes but the findings it is supposed to
 * produce (lab/expect.js). That pairing is the point: a lab that only proves
 * "something was found" cannot tell a working detector from a lucky regex.
 * Declaring the exact expectations makes every miss a named, fixable gap.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");

const HOST = "127.0.0.1";
const REPO = path.join(__dirname, "..");
const TYPES = { ".html": "text/html", ".js": "application/javascript", ".json": "application/json" };

// The field-reported page, reproduced exactly. A classic PHP news article whose
// id is concatenated straight into a query. The trailing apostrophe is what
// makes it throw, so this only throws when the quote is really there -
// otherwise the replica would pass while the real target still showed nothing.
//
// A function rather than an inline literal because the replica route needs the
// exact same bytes: a subtly different error page would be a lab that tests
// itself instead of the thing it was built to test.
function newsPage(id) {
  if (!String(id).includes("'")) {
    return "<html><body><h1>News</h1><p>Article " + id + "</p></body></html>";
  }
  return "<br />\n<b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; " +
    "check the manual that corresponds to your MariaDB server version for the right syntax to use near " +
    "''' at line 1 in /srv/app/news/index.php:21<br />\nStack trace:#0 /srv/app/news/index.php(21): " +
    "mysqli-&gt;query('select * from n...') #1 /var/www/html/news/index.php(8) #2 {main} thrown in " +
    "/srv/app/news/index.php on line 21";
}

// The field-reported page with the engine loaded into it, which is what
// the extension actually does: navigate first, inject after. The error text
// and the scanner live in the SAME document, and the page makes no XHR at all
// - so every request-based detector has nothing to work with and only the
// document pass can see anything. This is the exact shape of the field report.
function replicaPage() {
  const err = newsPage("18'");
  return "<!DOCTYPE html><html><head><title>News</title></head><body>\n" + err +
    "\n<script src=\"/__src/quiet.js\"></script><script src=\"/__src/engine.js\"></script>" +
    "<script>setTimeout(function(){try{var s=xrayeye.securityAnalysis();" +
    "var g=['headers','leaks','injection','authz','session'];var t=0;g.forEach(function(k){t+=s[k].length});" +
    "window.__replica={endpoints:xrayeye.findings({}).length,coverage:s.coverage,total:t,counts:s.counts," +
    "limits:s.limits,leakIds:s.leaks.map(function(f){return f.id})," +
    "injectionIds:s.injection.map(function(f){return f.id})," +
    "leakTitles:s.leaks.map(function(f){return f.severity+' | '+f.title+' | '+f.basis})};" +
    "document.title='done:'+t;}catch(e){window.__replica={error:String(e&&e.stack||e)};document.title='error';}},900);</script>" +
    // page.js LAST, then a probe helper. This is the whole shipped chain -
    // quiet + engine + driver - running on a page that is nothing but the SQL
    // error. The preview harness answers panel commands from a fixture and the
    // vm suite from a stub, so neither drives page.js itself; this does.
    "<script src=\"/__src/page.js\"></script><script>window.__call=function(c,a){" +
    "return new Promise(function(res){var id=window.__seq=(window.__seq||0)+1,s=false;" +
    "function fin(d){if(!s){s=true;window.removeEventListener('__xrext_res__',on);res(d);}}" +
    "function on(e){var d=null;try{d=JSON.parse(e.detail)}catch(x){return}" +
    "if(!d||d.id!==id)return;fin(d);}" +
    "window.addEventListener('__xrext_res__',on,false);" +
    "setTimeout(function(){fin({id:id,ok:false,error:'timeout'})},12000);" +
    "window.dispatchEvent(new CustomEvent('__xrext_req__',{detail:JSON.stringify({id:id,cmd:c,args:a||{}})}));});};</script>" +
    "</body></html>";
}

// ---------------------------------------------------------------------
// Level 1 - easy. Loud, unmissable, textbook mistakes.
// ---------------------------------------------------------------------
const L1 = {
  id: "L1", name: "Easy", blurb: "No security headers, a bare session cookie, and a stack trace in the body.",
  routes: {
    // A session cookie with none of its protective attributes.
    "/l1/session": () => ({
      status: 200,
      headers: { "set-cookie": "sid=l1-abc123; Path=/" },
      body: JSON.stringify({ ok: true, user: "demo" })
    }),
    // A Java stack trace returned to the browser.
    "/l1/invoice": () => ({
      status: 500,
      ct: "text/plain",
      body:
        "java.lang.NullPointerException: cannot invoke \"Order.getTotal()\"\n" +
        "\tat com.acme.billing.Invoice.render(Invoice.java:214)\n" +
        "\tat java.base/java.lang.Thread.run(Thread.java:840)\n"
    }),
    // Nothing at all: no HSTS, no CSP, no X-Frame-Options, no Referrer-Policy.
    "/l1/ping": () => ({ status: 200, body: JSON.stringify({ pong: 1 }) })
  }
};

// ---------------------------------------------------------------------
// Level 2 - medium. Errors are formatted, inputs come back.
// ---------------------------------------------------------------------
const L2 = {
  id: "L2", name: "Medium", blurb: "Formatted DB errors with the submitted value beside them, and reflections into sinks.",
  routes: {
    // A SQL error carrying the submitted parameter.
    "/l2/lookup": u => ({
      status: 500,
      ct: "text/plain",
      body: "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax " +
        "near '" + (u.searchParams.get("ref") || "") + "' at line 1\n" +
        "mysqli_sql_exception: You have an error in your SQL syntax; check the manual that " +
        "corresponds to your MariaDB server version"
    }),
    // Reflected into an href: the javascript: vector.
    "/l2/redirect": u => ({
      status: 200,
      ct: "text/html",
      body: '<html><body><a href="/go?next=' + (u.searchParams.get("next") || "") + '">continue</a></body></html>'
    }),
    // Template syntax rendered next to a reflection.
    "/l2/greet": u => ({
      status: 200,
      ct: "text/html",
      body: "<div>Hello " + (u.searchParams.get("name") || "") + "</div> {{ 7 * 7 }}"
    }),
    // A Python traceback, a different language entirely.
    "/l2/report": () => ({
      status: 500,
      ct: "text/plain",
      body: "Traceback (most recent call last):\n  File \"/srv/app/reports/views.py\", line 88, in detail\n" +
        "    return Order.objects.get(pk=pk)\n" +
        "django.db.utils.ProgrammingError: relation \"orders_order\" does not exist\n"
    }),
    // A wildcard CORS origin on personal data.
    "/l2/customers": () => ({
      status: 200,
      headers: { "access-control-allow-origin": "*" },
      body: JSON.stringify({ customers: [{ email: "a@example.test" }, { email: "b@example.test" }] })
    })
  }
};

// ---------------------------------------------------------------------
// Level 3 - hard. The headers exist and do nothing; authz is asymmetric.
// ---------------------------------------------------------------------
const L3 = {
  id: "L3", name: "Hard", blurb: "A CSP that is present and worthless, cookies scoped too wide, and split privilege on one resource.",
  routes: {
    // Every header present. None of them doing anything.
    "/l3/dashboard": () => ({
      status: 200,
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "no-referrer",
        "set-cookie": "sid=l3-xyz; Path=/; Domain=.lab.local; SameSite=None"
      },
      body: JSON.stringify({ widgets: 3 })
    }),
    // A privileged surface with nothing indicating it is protected.
    "/l3/admin/orders": () => ({
      status: 200,
      body: JSON.stringify({ orders: [{ id: 9001, owner: "admin", total: 4200 }] })
    }),
    // The same resource, plainly. This is the BFLA shape.
    "/l3/orders": () => ({
      status: 200,
      body: JSON.stringify({ orders: [{ id: 9001, owner: "admin", total: 4200 }] })
    }),
    // A debug flag and a serialised configuration block.
    "/l3/config": () => ({
      status: 200,
      body: JSON.stringify({
        APP_DEBUG: true,
        DATABASE_URL: "postgres://lab:hunter2@10.0.4.17:5432/labdb",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        webroot: "/var/www/lab/public"
      }, null, 2)
    }),

  // ---- deeper header hygiene: every header present, several doing nothing
  "/l3/headers": () => ({
    status: 200,
    headers: {
      // Origin-reflecting CORS with credentials. The dangerous one: the
      // wildcard check cannot see this, because the origin is not "*".
      "access-control-allow-origin": "https://evil.example",
      "access-control-allow-credentials": "true",
      "access-control-expose-headers": "x-internal-token, x-debug",
      "cache-control": "public, max-age=600",
      "server": "Apache/2.4.29 (Ubuntu)",
      "x-powered-by": "PHP/7.2.24"
    },
    body: JSON.stringify({ profile: { email: "admin@lab.local", ssn_last4: "1234" } })
  }),
  // Sensitive data served out of a shared cache with no Vary: Origin.
  "/l3/cached": () => ({
    status: 200,
    headers: { "cache-control": "public, max-age=3600" },
    body: JSON.stringify({ private: "session-scoped content" })
  }),
  // A session cookie with no expiry at all AND no explicit path scoping.
  "/l3/barecookie": () => ({
    status: 200,
    headers: { "set-cookie": "PHPSESSID=abc123def456" },
    body: JSON.stringify({ ok: true })
  }),

  // ---- leak classes that are not stack traces
  "/l3/git": () => ({
    status: 200,
    ct: "text/plain",
    body: "[core]\n\trepositoryformatversion = 0\n\tbare = false\n" +
      "[remote \"origin\"]\n\turl = https://user:ghp_16C7e42F292c6912E7710c838347Ae178B4a@github.com/acme/app.git\n"
  }),
  "/l3/phpinfo": () => ({
    status: 200,
    ct: "text/html",
    body: "<html><body><h1>phpinfo()</h1><table>" +
      "<tr><td>PHP Version</td><td>7.2.24</td></tr>" +
      "<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>" +
      "<tr><td>Configuration File (php.ini) Path</td><td>/etc/php/7.2/cli/php.ini</td></tr>" +
      "</table><p>DOCUMENT_ROOT /home/lab/public_html</p></body></html>"
  }),
  "/l3/keys": () => ({
    status: 200,
    ct: "text/plain",
    body: "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEowIBAAKCAQEAx7Vv8Q9pLmZ3sTqB4nR7yU2cF5hJ8kL1mN4oP6qS9tV2wX5\n" +
      "zA7bC3dE8fG1hI4jK7lM0nO2pQ5rS8tU1vW4xY7zB0cD3eF6gH9iJ2kL5mN8oP1\n" +
      "-----END RSA PRIVATE KEY-----\n"
  }),
  "/l3/providers": () => ({
    status: 200,
    // Realistic shapes. The first version of this fixture used invented
    // values that did not match the shape of a real key - a SendGrid key with
    // one segment instead of two, a Twilio SID one character short, a Firebase
    // URL far too short. Every signature correctly reported nothing, and the
    // honest reading was "the signatures are wrong" when the fixture was. A
    // lab that only uses values it knows are safe teaches nothing.
    body: JSON.stringify({
      SG: "SG.9kL2mN4oP6qS9tV2wX5zA7bC3dE8fG1hI4jK7lM0nO2pQ5.rS8tU1vW4xY7zB0cD3eF6gH9iJ2kL",
      TWILIO_SID: "AC9f8e7d6c5b4a39281706f5e4d3c2b1a2",
      MAILGUN_KEY: "key-3f9a2b1c8d7e6f5a4b3c2d1e0f9a8b7c",
      FIREBASE: "AAAAI7Yabcd:9kL2mN4oP6qS9tV2wX5zA7bC3dE8fG1hI4jK7lM0nO2pQ5rS8tU1vW4xY7zB0cD3eF6gH9iJ2kL5mN8oP1qR4sT7uV0wX3yZ6aB9cD2eF5gH8iJ1kL4mN7oP0qR3sT6uV9wX2yZ5aB8cD1eF4gH7iJ0kL2mN5oP8qR1sT4uV7wX0yZ3aB6cD9eF2gH5iJ8kL1mN4oP7qR0sT3uV6wX9yZ2aB5cD8eF1gH4iJ7kL0mN3oP6qR9sT2uV5wX8yZ1aB4cD7eF0gH3iJ6kL9mN2oP5qR8sT1uV4wX7yZ0aB3cD6eF9gH2iJ5kL8mN1oP4qR7sT0uV3wX6yZ9aB2cD5eF8gH1iJ4kL7mN0oP3qR6sT9uV2wX5yZ8aB1cD4eF7gH0iJ3kL6mN9oP2qR5sT8uV1wX4yZ7aB0cD3eF6gH9iJ2kL5mN8oP1qR4sT7uV0wX3yZ6aB9cD2eF5gH8iJ1kL4mN7oP0qR3sT6uV9wX2yZ5aB8cD1eF4gH7iJ0kL",
      SLACK: "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    }, null, 2)
  }),
  "/l3/backup": () => ({
    status: 200,
    ct: "text/plain",
    body: "INSERT INTO users (id, email, password) VALUES (1,'a@b.test','$2y$10$abc');\n" +
      "-- database dump taken 2026-01-02\n"
  }),
  "/l3/version": () => ({
    status: 200,
    headers: { "x-generator": "Drupal 8 (https://www.drupal.org)" },
    ct: "text/html",
body: "<html><head><meta name=\"generator\" content=\"WordPress 5.9.2\"></head>" +
      "<body><!-- generator: Joomla 3.9.4 --></body></html>"
  })
  },
  // The bundle the page "ships", containing a role check that gates the UI only.
  bundle:
    "export function Panel(user){\n" +
    "  const can = user.isAdmin && user.hasPermission('billing.write');\n" +
    "  return can ? 'admin' : 'user';\n" +
    "}\n"
};

  // ---------------------------------------------------------------------
  // Level 4 - insane. Everything at once, plus the awkward cases.
  // ---------------------------------------------------------------------
const L4 = {
  id: "L4", name: "Insane", blurb: "Env secrets, an unsigned admin token, a reflected script sink, null-origin CORS, and a logout that lies.",
  routes: {
    "/l4/env": () => ({
      status: 200,
      body: JSON.stringify({
        runtime: "prod",
        AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        STRIPE_SECRET: "sk_live_51H8xQeZ7yKd3nB0pLmA9",
        GITHUB_TOKEN: "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        REDIS_URL: "redis://cache.internal.corp:6379/2",
        build_host: "build-07.datacenter.local"
      }, null, 2)
    }),
    // An alg:none token with an admin role and a two-year life.
    "/l4/token": () => ({
      status: 200,
      headers: { "set-cookie": "__Host-sid=; Path=/; Max-Age=0" },
      body: JSON.stringify({ token: UNSIGNED_ADMIN_TOKEN }),
      note: "unsigned, admin role, exp 150 days out"
    }),
    // Reflection straight into a script block.
    "/l4/render": u => ({
      status: 200,
      ct: "text/html",
      body: "<html><body><script>var topic = \"" +
        (u.searchParams.get("t") || "") + "\";</script></body></html>"
    }),
    // A null origin reflected back with credentials.
    "/l4/me": () => ({
      status: 200,
      headers: {
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true"
      },
      body: JSON.stringify({ email: "admin@lab.local", roles: ["admin"] })
    }),
    // Server-rendered, in the document, not in any API response.
    "/l4/page": () => ({
      status: 500,
      ct: "text/html",
      body: "<html><body><b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in " +
        "your SQL syntax; check the manual that corresponds to your MariaDB server version for " +
        "the right syntax to use near ''' at line 1 in " +
        "/srv/lab/app/Controllers/News.php:8<br />Stack trace:#0 /srv/lab/app/Controllers/News.php(8): " +
        "mysqli-&gt;query('select * from n...') #1 /srv/lab/public/news.php(21) #2 {main}</body></html>"
    }),
    // A logout that returns 200 and a fresh cookie: the session never ended.
    "/l4/logout": () => ({
      status: 200,
      headers: { "set-cookie": "sid=l4-still-there; Path=/; HttpOnly" },
      body: JSON.stringify({ loggedOut: true })
    }),

    // The field-reported page, reproduced exactly. Same bytes as the replica,
    // which is the point: a subtly different error page would be a lab testing
    // itself instead of the thing it was built to test.
    "/news/index.php": u => ({
      status: 200, ct: "text/html",
      body: newsPage(u.searchParams.get("id") || "")
    }),
    // ...and the same page with the scanner loaded into it, which is the
    // shape the extension actually meets: navigate first, inject after.
    "/lab/replica": () => ({ status: 200, ct: "text/html", body: replicaPage() }),
    // ---- injection candidates beyond reflected XSS/SQLi/SSTI
  // Each parameter name is the tell. The response just echoes the value back,
  // which is what proves the application is willing to reflect it.
  "/l4/ssrf": u => ({
    status: 200,
    body: JSON.stringify({ fetched: u.searchParams.get("url") || "" })
  }),
  "/l4/cmd": u => ({
    status: 200,
    body: JSON.stringify({ host: u.searchParams.get("ip") || "" })
  }),
  "/l4/jsonp": u => ({
    status: 200,
    ct: "application/javascript",
    body: "/**/ typeof " + (u.searchParams.get("callback") || "") + " === 'function' && " +
      (u.searchParams.get("callback") || "") + "({ok:1});"
  }),
  // The operator key is the finding. The value alongside it is deliberately
  // distinctive so the reflection is recorded at all - a one-character value
  // is not distinguishable from any other one-character value in a response.
  "/l4/nosql": u => ({
    status: 200,
    body: JSON.stringify({ users: [], q: u.searchParams.get("user[$ne]") || "" })
  }),
  "/l4/redirect": u => {
    const next = u.searchParams.get("redirect_uri") || "/";
    return { status: 302, headers: { location: next }, body: "" };
  },
  "/l4/xxe": u => ({
    status: 200,
    headers: { "content-type": "application/xml" },
    body: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" +
      "<r><a>" + (u.searchParams.get("name") || "") + "</a></r>"
  }),
  "/l4/html": u => ({
    status: 200,
    ct: "text/html",
    body: "<html><body><div>" + (u.searchParams.get("note") || "") + "</div></body></html>"
  }),

  // ---- authorization: state changing with no auth signal at all
  "/l4/users": () => ({ status: 200, body: JSON.stringify({ created: true }) }),
  "/l4/graphql": () => ({
    status: 200,
    body: JSON.stringify({
      data: { __schema: { types: [{ name: "User" }, { name: "Order" }] } }
    })
  }),
  "/l4/adminpanel": () => ({
    status: 200, ct: "text/html",
    body: "<html><body><form method='POST' action='/l4/users'>" +
      "<input name='email'><input name='role' value='admin'></form></body></html>"
  }),

  // ---- session: the token rides in the query string
  "/l4/intoken": u => ({
    status: 200,
    body: JSON.stringify({ seen: u.searchParams.get("token") ? "yes" : "no" })
  }),
  "/l4/expired": () => ({
    status: 200,
    headers: { "set-cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000" },
    body: JSON.stringify({ ok: true })
  }),

  // ---- parameter intelligence: every candidate category in one call.
  //
  // One route carrying a parameter from each category, so a category that
  // silently stops matching shows up as one missing row rather than as a
  // general impression that things are fine.
  "/l4/params": u => ({
    status: 200,
    body: JSON.stringify({
      account_id: u.searchParams.get("account_id"),
      callback_url: u.searchParams.get("callback_url"),
      filename: u.searchParams.get("filename"),
      returnUrl: u.searchParams.get("returnUrl"),
      password: u.searchParams.get("password"),
      price: u.searchParams.get("price"),
      role: u.searchParams.get("role"),
      sort: u.searchParams.get("sort"),
      message: u.searchParams.get("message")
    })
  }),
  "/l4/params-body": () => ({
    status: 200,
    body: JSON.stringify({ ok: true })
  })

  },
  bundle:
    "export function Guard(s){\n" +
    "  if (!s || s.role !== 'admin') return '/login';\n" +
    "  return s.isSuperUser ? '/admin' : '/dashboard';\n" +
    "}\n",

};

// Built, not typed. An earlier version carried a hand-written base64 payload
// that decoded to iat=170000000 instead of 1700000000 - a ten-fold error that
// produced a token "issued" in 1975. The date being visibly wrong in the
// analyzer's output is what gave it away; a plausible-looking wrong value
// would have shipped.
const b64u = o => Buffer.from(JSON.stringify(o)).toString("base64url");
const UNSIGNED_ADMIN_TOKEN =
  b64u({ alg: "none", typ: "JWT" }) + "." +
  b64u({ sub: "1", role: "admin", iat: 1700000000, exp: 1830000000 }) + ".";

const LEVELS = [L1, L2, L3, L4];
const BY_PATH = {};
for (const lv of LEVELS) for (const p of Object.keys(lv.routes)) BY_PATH[p] = lv;

function createServer() {
  return http.createServer((req, res) => {
    let u;
    try { u = new URL(req.url, "http://" + HOST); }
    catch (_) { res.writeHead(400).end("bad request"); return; }

    // Bundle endpoints, per level.
    const bundleMatch = /^\/(l\d)\/bundle\.js$/.exec(u.pathname);
    if (bundleMatch) {
      const lv = LEVELS.find(l => l.id.toLowerCase() === bundleMatch[1]);
      const body = (lv && lv.bundle) || "/* none */\n";
      res.writeHead(200, { "content-type": "application/javascript" }).end(body);
      return;
    }

    // The harness page and the engine it loads. Served from the repo so the
    // browser runs the SAME files the extension ships, rather than a copy that
    // can drift from them. Read-only, and confined to a fixed allow-list.
    if (u.pathname === "/lab" || u.pathname === "/lab/browser.html" ||
        u.pathname === "/lab/replica.html" || u.pathname === "/lab/rpcprobe") {
      // The harness pages are addressable without their extension, so the
      // filename has to be reattached. Resolved against a fixed list rather
      // than from the request, so this cannot be walked out of lab/.
      const base = u.pathname.replace(/\/$/, "").split("/").pop();
      const f = path.join(REPO, "lab", base.endsWith(".html") ? base : base + ".html");
      if (!fs.existsSync(f)) { res.writeHead(404).end("no such harness page"); return; }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(fs.readFileSync(f));
      return;
    }
    const srcFile = /^\/__src\/([a-z]+\.js)$/.exec(u.pathname);
    if (srcFile) {
      const f = path.join(REPO, "src", srcFile[1]);
      if (!fs.existsSync(f)) { res.writeHead(404).end("no such file"); return; }
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
      res.end(fs.readFileSync(f));
      return;
    }

    const lv = BY_PATH[u.pathname];
    if (!lv) { res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not found"}'); return; }

    let r;
    try { r = lv.routes[u.pathname](u); }
    catch (e) {
      res.writeHead(500, { "content-type": "text/plain" }).end("lab handler threw: " + e.message);
      return;
    }

    const headers = Object.assign({ "content-type": r.ct || "application/json" }, r.headers || {});
    res.writeHead(r.status || 200, headers);
    res.end(r.body == null ? "" : r.body);
  });
}

function start(port) {
  return new Promise(resolve => {
    const s = createServer();
    s.listen(port || 8787, HOST, () => resolve({ server: s, port: s.address().port, origin: "http://" + HOST + ":" + s.address().port }));
  });
}

module.exports = { start, LEVELS, HOST };

if (require.main === module) {
  start(Number(process.env.PORT) || 8787).then(({ origin }) => {
    console.log("vulnerable lab listening on " + origin);
    console.log("levels: " + LEVELS.map(l => l.id + " " + l.name).join(", "));
  });
}