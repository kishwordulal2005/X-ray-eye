/*
 * tools/dump-fixture.js — captures real panel data for UI review.
 *
 *   node tools/dump-fixture.js
 *
 * Boots the actual engine and driver against a deliberately busy page, drives
 * traffic, then records the real response to every command the panel calls.
 * The output is tools/fixture.js, which the preview page replays — so what gets
 * reviewed in a browser is genuine scanner output, not hand-written mock rows.
 *
 * Collections the sandbox cannot provoke (a Next.js server action ID, say) get
 * one realistic row appended afterwards, clearly marked. They exist so the UI
 * review covers every tab; they are never used by the test suite.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const t = require("./test-rpc.js");

const ORIGIN = t.ORIGIN;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const OPENAPI = JSON.stringify({
  openapi: "3.0.3",
  info: { title: "Demo Platform API", version: "2.4.0" },
  paths: {
    "/api/v1/users": { get: { summary: "List users" } },
    "/api/v1/orders": { get: { summary: "List orders" } }
  }
});

const OAUTH_PAGE_TEXT = [
  "Sign in with SSO:",
  "https://demo.example.test/oauth/authorize?client_id=demo-web&redirect_uri=https://app.demo.example.test/callback&response_type=code&scope=openid%20profile%20email&state=8f2a1c",
  "Legacy implicit flow:",
  "https://demo.example.test/oauth/authorize?client_id=demo-legacy&redirect_uri=https://app.demo.example.test/cb&response_type=token%20id_token&scope=openid"
].join("\n");

// A shipped config blob with an id and a pass in the same object. The case the
// pair scanner exists for: the password alone is reported without it, and the
// identifier is judged arbitrary on its own.
const CONFIG_BLOB = [
  "{",
  '  "AdminUrl": "https://billing.cgnet.com.np/h8ssrms/",',
  '  "encryption": "false",',
  '  "systemId": "h8support",',
  '  "systemPass": "@H8Adm1nSS3ms!",',
  '  "chatbotUrl": "http://103.186.196.90/assets/Livetips.html",',
  '  "darkModeSupport": "true"',
  "}"
].join("\n");

async function main() {
  const { win, call } = t.bootWithCaller({
    specs: true,
    pageText: [OAUTH_PAGE_TEXT, CONFIG_BLOB],
    // Framework fingerprints are read out of script text, not out of window
    // globals, so the markers have to live in an inline script.
    scripts: [{
      textContent: [
        "window.__APP_CONFIG__ = " + CONFIG_BLOB + ";",
        'window.__NEXT_DATA__ = {"version":"15.3.0","props":{"pageProps":{"user":"admin"}}};',
        'var React = { version: "19.0.0" };',
        'window.webpackChunkapp = window.webpackChunkapp || [];',
        '/* jQuery.fn.jquery = "3.7.1" */',
        '/* Sentry.init({ dsn: "https://abc123@o1.ingest.sentry.io/9" }); */'
      ].join("\n")
    }],
    globals: {
      __NEXT_DATA__: { version: "15.3.0", props: { pageProps: { user: "admin" } } },
      webpackChunkapp: [],
      React: { version: "19.0.0" }
    },
    serviceWorkers: [
      { scope: ORIGIN + "/app/", active: { scriptURL: ORIGIN + "/sw.js" } },
      { scope: ORIGIN + "/", installing: { scriptURL: ORIGIN + "/root-sw.js" } }
    ],
    fetchRoutes: {
      "\\/openapi\\.json$": { status: 200, body: OPENAPI },
      "\\/swagger\\/v1\\/swagger\\.json$": {
        status: 200,
        body: JSON.stringify({ swagger: "2.0", info: { title: "Demo Legacy API", version: "1.9.0" }, paths: {} })
      }
    }
  });

  // Let the engine finish booting before any traffic is generated.
  await sleep(1500);
  for (let i = 0; i < 4; i++) {
    await t.__simulate(win);
    await sleep(400);
  }

  // readAll walks the discovered paths, which is what turns referenced routes
  // into recorded ones and pulls the OpenAPI docs in for spec parsing.
  try { await call("readAll", { limit: 30, delay: 0 }, 30000); } catch (_) {}
  await sleep(1200);

  const grab = async (cmd, args) => {
    const r = await call(cmd, args || {}, 25000);
    return r.ok ? r.data : null;
  };

  const out = {
    meta: await grab("meta"),
    dashboard: await grab("dashboard"),
    endpoints: await grab("endpoints"),
    secrets: await grab("secrets"),
    triage: await grab("triage"),
    authPairs: await grab("authPairs"),
    jwt: await grab("jwt"),
    storage: await grab("storage"),
    authFlows: await grab("authFlows"),
    frameworks: await grab("frameworks"),
    serviceWorkers: await grab("serviceWorkers"),
    serverActions: await grab("serverActions"),
    specs: await grab("specs"),
    notes: await grab("notes"),
    exposed: await grab("exposed"),
    directories: await grab("directories"),
    sensitivePaths: await grab("sensitivePaths"),
    markdown: await grab("markdown"),
    secretsCSV: await grab("secretsCSV"),
    json: await grab("json"),
    csv: await grab("csv")
  };

  // Whatever the sandbox could not provoke gets one representative row, so a
  // tab under review is never the empty-state box by accident.
  const pad = [];

  if (!out.serverActions || !out.serverActions.length) {
    out.serverActions = [
      { id: "40a1f0c9d3e84b1a9c77e2f5", file: "app/(dash)/actions.js" },
      { id: "9b3e17aa52c64d0e8f11a6d4", file: "app/(dash)/actions.js" }
    ];
    pad.push("serverActions");
  }
  if (!out.authFlows || !out.authFlows.length) {
    out.authFlows = [
      {
        severity: "HIGH", flow: "authorize",
        url: ORIGIN + "/oauth/authorize?client_id=demo-legacy&response_type=token%20id_token",
        host: "demo.example.test", clientId: "demo-legacy", issuer: null,
        responseType: "token id_token", scope: "openid", pkce: false,
        redirectUris: [{ param: "redirect_uri", value: "https://app.demo.example.test/cb" }],
        noState: true, weakState: false, implicit: true, noPkce: true,
        findings: [
          { id: "no-state", label: "no state parameter", severity: "HIGH", detail: "No CSRF state on the authorization request." },
          { id: "implicit-flow", label: "implicit flow", severity: "MEDIUM", detail: "response_type includes token." },
          { id: "no-pkce", label: "no PKCE", severity: "MEDIUM", detail: "No code_challenge." }
        ],
        at: new Date().toISOString()
      },
      {
        severity: "INFO", flow: "authorize",
        url: ORIGIN + "/oauth/authorize?client_id=demo-web&response_type=code",
        host: "demo.example.test", clientId: "demo-web", issuer: null,
        responseType: "code", scope: "openid profile email", pkce: true,
        redirectUris: [{ param: "redirect_uri", value: "https://app.demo.example.test/callback" }],
        noState: false, weakState: false, implicit: false, noPkce: false,
        findings: [{ id: "scopes", label: "scopes requested", severity: "INFO", detail: "scope=openid profile email" }],
        at: new Date().toISOString()
      }
    ];
    pad.push("authFlows");
  }

  if (!out.specs || !out.specs.length) {
    out.specs = [
      {
        url: ORIGIN + "/openapi.json", kind: "openapi",
        title: "Demo Platform API", version: "3.0.3",
        endpointCount: 42, fieldCount: null, typeCount: null,
        bases: [ORIGIN], noGlobalAuth: true,
        note: "No global security requirement declared. Endpoints may be unauthenticated.",
        at: new Date().toISOString()
      },
      {
        url: ORIGIN + "/swagger/v1/swagger.json", kind: "openapi",
        title: "Demo Legacy API", version: "2.0",
        endpointCount: 8, fieldCount: null, typeCount: null,
        bases: [ORIGIN], noGlobalAuth: null, note: null,
        at: new Date().toISOString()
      }
    ];
    pad.push("specs");
  }

  // Re-derive the dashboard counters so the tiles match the padded tabs.
  if (out.dashboard && out.dashboard.counters) {
    const c = out.dashboard.counters;
    c.serverActions = (out.serverActions || []).length;
    c.authFlows = (out.authFlows || []).length;
    c.serviceWorkers = (out.serviceWorkers || []).length;
    c.specs = (out.specs || []).length;
    c.frameworks = (out.frameworks || []).length;
  }

  const file = path.join(__dirname, "fixture.js");
  fs.writeFileSync(file,
    "/* generated by tools/dump-fixture.js — real scanner output for UI review.\n" +
    "   padded collections: " + (pad.join(", ") || "none") + " */\n" +
    "window.__XRE_FIXTURE = " + JSON.stringify(out, null, 1) + ";\n");

  const size = fs.statSync(file).size;
  console.log("wrote " + file + "  (" + size + " bytes)");
  if (pad.length) console.log("padded: " + pad.join(", "));
  const c = (out.dashboard && out.dashboard.counters) || {};
  console.log("counters: " + JSON.stringify(c));
  process.exit(0);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });