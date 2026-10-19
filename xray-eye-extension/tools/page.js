/*
 * page.js — MAIN world. The bridge between the scanner and the panel.
 *
 * engine.js (x-ray-eye) already exposes a complete public API on
 * window.xrayeye: findings, secrets, JWTs, storage, auth flows, frameworks,
 * specs, notes, triage, exports. None of it needs this file — this file only
 * turns that API into request/response so the side panel can read it.
 *
 * Transport is CustomEvent with a JSON string payload, because that is the
 * only channel that crosses from the page's world into the content script's
 * isolated world without being spoofable-by-accident or structurally awkward.
 *
 *   request  : "__xrext_req__"  detail = {"id":n,"cmd":"...","args":{...}}
 *   response : "__xrext_res__"  detail = {"id":n,"ok":true,"data":...}
 *
 * Everything is wrapped. A scanner fault returns an error object; it is never
 * thrown into the page and never breaks the site's own code.
 */
(() => {
  "use strict";

  const REQ = "__xrext_req__";
  const RES = "__xrext_res__";

  if (window.__xrextDriver) return;
  window.__xrextDriver = true;

  // Give the site its console back. quiet.js silenced it only so engine.js
  // would bind the silent versions; from here on the page logs normally.
  try {
    const q = window.__xreQuiet;
    if (q && q.original) {
      for (const m of Object.keys(q.original)) console[m] = q.original[m];
    }
  } catch (_) {}

  const say = payload => {
    try {
      window.dispatchEvent(new CustomEvent(RES, { detail: JSON.stringify(payload) }));
    } catch (_) {}
  };

  // The engine is injected immediately before this file, so it is normally
  // already there. If a page blocked it, wait briefly rather than failing.
  const engine = () => window.xrayeye || null;

  const asArray = v => (Array.isArray(v) ? v : v == null ? [] : [v]);

  const countBy = (rows, pick) => {
    const out = {};
    for (const r of rows) {
      const k = String(pick(r) || "UNKNOWN").toUpperCase();
      out[k] = (out[k] || 0) + 1;
    }
    return out;
  };

  const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const worstSeverity = list => {
    let top = "INFO";
    for (const s of list || []) {
      if ((SEV_RANK[String(s).toUpperCase()] ?? 0) > (SEV_RANK[top] ?? 0)) top = String(s).toUpperCase();
    }
    return top;
  };

  // ---------------------------------------------------------------------
  // Normalizers.
  //
  // specs(), authFlows() and serviceWorkers() hand back the scanner's raw
  // store records. Those shapes are internal and do not line up with the
  // other tables — the spec URL is called specUrl, its endpoint count is a
  // number rather than a list, and an OAuth flow carries its severity inside
  // a findings array instead of on the record. Rather than teach the panel
  // about each one, the contract is fixed here, so a store change breaks one
  // normalizer instead of every table.
  // ---------------------------------------------------------------------
  function normSpec(s) {
    return {
      url: s.specUrl || s.url || "",
      kind: s.kind || "unknown",
      title: s.title || "",
      version: s.version || "",
      endpointCount: typeof s.endpoints === "number" ? s.endpoints : asArray(s.endpoints).length,
      fieldCount: typeof s.fields === "number" ? s.fields : null,
      typeCount: typeof s.types === "number" ? s.types : null,
      bases: asArray(s.bases),
      noGlobalAuth: s.noAuth === true ? true : (s.noAuth === false ? false : null),
      note: s.note || null,
      at: s.at || null
    };
  }

  function normAuthFlow(f) {
    const findings = asArray(f.findings);
    return {
      severity: worstSeverity(findings.map(x => x.severity)),
      flow: f.flow || "unknown",
      url: f.url || "",
      host: f.host || "",
      clientId: f.clientId || null,
      issuer: f.issuer || null,
      responseType: f.responseType || null,
      scope: f.scope || null,
      pkce: !!f.pkce,
      redirectUris: asArray(f.redirectUris).map(r =>
        typeof r === "string" ? { param: "redirect_uri", value: r } : { param: r.param, value: r.value }),
      noState: findings.some(x => x.id === "no-state"),
      weakState: findings.some(x => x.id === "weak-state"),
      implicit: findings.some(x => x.id === "implicit-flow"),
      noPkce: findings.some(x => x.id === "no-pkce"),
      findings,
      at: f.at || null
    };
  }

  function normSw(w) {
    return {
      scope: w.scope || "",
      script: w.script || "",
      state: w.state || "",
      broadScope: !!w.broadScope,
      at: w.at || null
    };
  }

  // ---------------------------------------------------------------------
  // Read commands. Each returns plain JSON the panel can render directly.
  // ---------------------------------------------------------------------
  const READ = {
    // Liveness + the counters the header always shows.
    hello() {
      return { ok: true, ready: true, url: location.href };
    },

    meta() {
      const x = engine();
      const cfg = x.config ? JSON.parse(JSON.stringify(x.config)) : {};
      return {
        version: x.version,
        url: location.href,
        origin: location.origin,
        topFrame: window === window.top,
        config: cfg,
        stats: JSON.parse(JSON.stringify(x.stats || {})),
        hooks: asArray(x.hooks),
        errors: asArray(x.errors),
        marks: asArray(x.marks)
      };
    },

    // Everything the overview needs in one round trip, so the first paint of
    // the dashboard does not need a dozen sequential requests.
    dashboard() {
      const x = engine();
      const endpoints = x.findings({});
      const secrets = x.secrets({});
      const jwt = x.jwt({});
      const storage = x.storage({});
      const notes = x.notes({});
      const triage = x.triage();
      const unique = x.unique();
      const exposed = x.exposed({});

      const bySeverity = s => {
        const o = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        for (const r of s) o[String(r.severity || "INFO").toUpperCase()] =
          (o[String(r.severity || "INFO").toUpperCase()] || 0) + 1;
        return o;
      };

      return {
        version: x.version,
        url: location.href,
        counters: {
          endpoints: endpoints.length,
          observed: endpoints.filter(e => e.observed).length,
          referenced: endpoints.filter(e => !e.observed).length,
          requests: endpoints.reduce((a, e) => a + (e.count || 0), 0),
          unread: asArray(x.unread()).length,
          secrets: secrets.length,
          realCredentials: triage.counts ? triage.counts.real : 0,
          fixtures: triage.counts ? triage.counts.fixture : 0,
          uniqueValues: unique.unique,
          detections: unique.detections,
          jwt: jwt.length,
          storage: storage.length,
          notes: notes.length,
          frameworks: asArray(x.frameworks()).length,
          specs: asArray(x.specs()).length,
          authFlows: asArray(x.authFlows()).length,
          serviceWorkers: asArray(x.serviceWorkers()).length,
          serverActions: asArray(x.serverActions()).length,
          exposed: exposed.length,
          marks: asArray(x.marks).length,
          errors: asArray(x.errors).length
        },
        endpointSeverity: countBy(endpoints, e => e.confidence),
        secretSeverity: bySeverity(secrets),
        secretExposure: countBy(secrets, s => s.exposure),
        secretCategory: countBy(secrets, s => s.category),
        storageArea: countBy(storage, s => s.area),
        noteKinds: countBy(notes, n => n.kind),
        coverage: x.coverage(),
        topEndpoints: endpoints
          .slice()
          .sort((a, b) => (b.count || 0) - (a.count || 0) || (b.score || 0) - (a.score || 0))
          .slice(0, 8)
          .map(e => ({ url: e.url, method: e.method, count: e.count, observed: e.observed })),
        topSecrets: secrets
          .filter(s => s.verdict === "real")
          .slice(0, 8)
          .map(s => ({
            name: s.name, type: s.type, severity: s.severity,
            value: s.value != null ? s.value : s.valueMasked, file: s.file, exposure: s.exposure
          })),
        frameworks: asArray(x.frameworks()).slice(0, 12),
        stats: JSON.parse(JSON.stringify(x.stats || {})),
        errors: asArray(x.errors).slice(0, 5)
      };
    },

    endpoints(a) {
      const rows = engine().findings(a || {});
      return { total: rows.length, rows };
    },

    endpointDetail(a) {
      return asArray(engine().endpoint(a && (a.match || a.url)));
    },

    calls(a) {
      return engine().calls(a || {});
    },

    secrets(a) {
      const rows = engine().secrets(a || {});
      return { total: rows.length, rows };
    },

    triage() {
      return engine().triage();
    },

    authPairs() {
      return asArray(engine().authPairs());
    },

    unique() {
      return engine().unique();
    },

    coverage() {
      return engine().coverage();
    },

    notes(a) {
      const rows = engine().notes(a || {});
      return { total: rows.length, rows };
    },

    jwt(a) {
      const rows = engine().jwt(a || {});
      return { total: rows.length, rows };
    },

    storage(a) {
      const rows = engine().storage(a || {});
      return { total: rows.length, rows };
    },

    authFlows() {
      return asArray(engine().authFlows()).map(normAuthFlow);
    },

    frameworks() {
      return asArray(engine().frameworks());
    },

    serviceWorkers() {
      return asArray(engine().serviceWorkers()).map(normSw);
    },

    serverActions() {
      return asArray(engine().serverActions());
    },

    specs() {
      return asArray(engine().specs()).map(normSpec);
    },

    exposed(a) {
      const rows = engine().exposed(a || {});
      return { total: rows.length, rows };
    },

    directories(a) {
      return asArray(engine().directories(a || {}));
    },

    sensitivePaths(a) {
      return asArray(engine().sensitivePaths(a || {}));
    },

    unread() {
      return asArray(engine().unread());
    },

    // Bulk reports, fetched as text on demand rather than on every poll.
    markdown(a) { return { text: engine().markdown(a || {}) }; },
    csv(a) { return { text: engine().csv(a || {}) }; },
    secretsCSV() { return { text: engine().secretsCSV() }; },
    json(a) { return { text: engine().export(a || {}) }; },

    // Read a source file for the viewer. Done here, in the page, on purpose:
    // the scanner already fetched this exact file to scan it, so the page has
    // the cookies, the Referer and the origin the CDN expects. A service
    // worker fetch arrives with none of those and is routinely refused, which
    // is why the viewer used to dead-end on "the service worker refused".
    async fetchText(a) {
      const url = String((a && a.url) || "");
      if (!/^https?:\/\//i.test(url)) throw new Error("not an http(s) URL");
      try {
        const res = await fetch(url, { credentials: "include", redirect: "follow" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        const text = await res.text();
        if (text.length > 8 * 1024 * 1024) throw new Error("file is too large to open here");
        return { ok: true, text, bytes: text.length };
      } catch (e) {
        return { ok: false, error: String((e && e.message) || e) };
      }
    }
  };

  // ---------------------------------------------------------------------
  // Write commands. Anything that changes state or sends a request.
  // ---------------------------------------------------------------------
  const WRITE = {
    config(a) {
      const x = engine();
      if (a && a.patch) Object.assign(x.config, a.patch);
      return { config: JSON.parse(JSON.stringify(x.config)) };
    },

    rescan() { engine().rescan(); return { ok: true }; },
    sweep() { engine().sweep(); return { ok: true }; },
    rescanAll() { engine().rescan(); engine().sweep(); return { ok: true }; },
    cspCheck() { return engine().cspCheck(); },
    revalidate() { return engine().revalidate(); },
    iframeSnippet() { return { text: engine().iframeSnippet() }; },

    clear() { engine().clear(); return { ok: true }; },
    start() { engine().start(); return { ok: true }; },
    stop() { engine().stop({ silent: true }); return { ok: true }; },

    // Session-wide authorization for active reads. Kept behind an explicit
    // command so the panel's toggle is the single, visible place it is set.
    authorize() { engine().authorize(); return { ok: true }; },

    // Active: sends real GETs. The panel gates this behind a confirm.
    readAll(a) { return engine().readAll(Object.assign({ limit: 25, delay: 120 }, a || {})); },
    probe(a) { return engine().probe(a || {}); },

    mark(a) { return engine().mark(a && a.label); },
    diff(a) { return engine().diff(a && a.from, a && a.to); }
  };

  const ALIAS = {
    readall: "readAll", read_all: "readAll",
    endpoint: "endpointDetail", endpointDetail: "endpointDetail",
    endpoint_detail: "endpointDetail",
    secretsCSV: "secretsCSV", secrets_csv: "secretsCSV",
    markdown: "markdown", md: "markdown",
    "export-json": "json", exportJSON: "json"
  };

  async function run(cmd, args) {
    const name = ALIAS[cmd] || cmd;
    const x = engine();
    if (!x) {
      return { __deferred: true, error: "scanner not ready on this frame yet" };
    }
    if (Object.prototype.hasOwnProperty.call(READ, name)) return await READ[name](args || {});
    if (Object.prototype.hasOwnProperty.call(WRITE, name)) return await WRITE[name](args || {});
    throw new Error("unknown command: " + cmd);
  }

  window.addEventListener(REQ, async ev => {
    let msg = null;
    try { msg = JSON.parse(ev && ev.detail); } catch (_) { return; }
    if (!msg || !msg.cmd) return;

    // The scanner needs a tick of its own to finish booting on slow pages.
    if (!engine()) {
      for (let i = 0; i < 40 && !engine(); i++) {
        await new Promise(r => setTimeout(r, 50));
      }
    }

    try {
      const data = await run(msg.cmd, msg.args);
      say({ id: msg.id, ok: true, cmd: msg.cmd, data });
    } catch (e) {
      say({
        id: msg.id, ok: false, cmd: msg.cmd,
        error: String((e && e.message) || e)
      });
    }
  }, false);

  // Tell the panel the driver is alive, and let it know it can query now.
  const announce = () => say({ id: 0, ok: true, cmd: "driver-ready", data: { url: location.href } });
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", announce, { once: true });
  } else {
    announce();
  }
})();