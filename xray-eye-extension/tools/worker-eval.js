/*
 * tools/worker-eval.js — evaluates src/background.js the way Chrome does.
 *
 *   node tools/worker-eval.js
 *
 * A service worker that throws once during evaluation never registers. Chrome
 * reports that as a bare "Service worker registration failed. Status code: 15"
 * with no file, no line and no reason — which is why a dead worker and a
 * click that is not arriving look identical from outside.
 *
 * This stubs just enough of the extension API to run the file top to bottom in
 * a context with no chrome.* beyond that. Any unguarded addListener on an
 * API the browser does not provide throws HERE instead of silently killing the
 * extension on the user's machine.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const SRC = fs.readFileSync(path.join(ROOT, "src", "background.js"), "utf8");

const MISSING = "__missing__";

// Only what the worker touches at module scope. Everything else is absent on
// purpose, so an accidental reference surfaces here rather than in production.
function ev(name) {
  const f = function () {};
  f.addListener = function () { attached.push(name); };
  f.removeListener = function () {};
  f.setBadgeText = () => Promise.resolve();
  f.setBadgeBackgroundColor = () => Promise.resolve();
  f.setPanelBehavior = () => Promise.resolve();
  f.open = () => Promise.resolve();
  f.create = () => Promise.resolve();
  f.query = () => Promise.resolve([]);
  f.get = () => Promise.resolve({ id: 1 });
  f.getCurrent = () => Promise.resolve({ id: 1 });
  f.download = () => Promise.resolve(1);
  f.getManifest = () => ({ version: "3.2.0", manifest_version: 3 });
  f.get = () => Promise.resolve({});
  f.set = () => Promise.resolve();
  f.registerContentScripts = () => Promise.resolve();
  f.unregisterContentScripts = () => Promise.resolve();
  f.getRegisteredContentScripts = () => Promise.resolve([]);
  f.executeScript = () => Promise.resolve([]);
  f.sendMessage = () => Promise.resolve();
  return f;
}

const attached = [];
const msgListeners = [];
let toggleEnabled = false;

// onMessage keeps its callbacks so the header watcher can be exercised for
// real, not merely evaluated. A worker that registers the listener and then
// answers nothing is indistinguishable from one that never worked.
function onMessageEvent() {
  const f = function () {};
  f.addListener = function (fn) { attached.push("onMessage"); msgListeners.push(fn); };
  f.removeListener = function () {};
  f.getManifest = () => ({ version: "3.2.0", manifest_version: 3 });
  return f;
}

function makeSidePanel() {
  return {
    open: () => Promise.resolve(),
    setPanelBehavior: (o) => { toggleEnabled = !!(o && o.openPanelOnActionClick); return Promise.resolve(); },
    setOptions: () => Promise.resolve(),
    getOptions: () => Promise.resolve({})
  };
}

const runtime = {
  onInstalled: ev("onInstalled"),
  onStartup: ev("onStartup"),
  onMessage: onMessageEvent(),
  // Deliberately ABSENT: onCommand. If the worker's Chrome is older than
  // 110, chrome.runtime.onCommand is undefined and an unguarded
  // .addListener on it kills the entire worker. The guard must make this a
  // no-op, not a crash.
  getManifest: () => ({ version: "3.2.0", manifest_version: 3 })
};

function baseChromeStub(withSidePanel) {
  const stub = {
    runtime,
    action: { onClicked: ev("action.onClicked"), setBadgeText: ev().setBadgeText, setBadgeBackgroundColor: ev().setBadgeBackgroundColor },
    tabs: { query: ev("tabs.query"), get: ev("tabs.get"), create: ev("tabs.create"), sendMessage: ev("tabs.sendMessage") },
    windows: { getCurrent: ev("windows.getCurrent") },
    downloads: { download: ev("downloads.download") },
    storage: { local: { get: ev("storage.get"), set: ev("storage.set") } },
    scripting: {
      registerContentScripts: ev("scripting.register"),
      unregisterContentScripts: ev("scripting.unregister"),
      getRegisteredContentScripts: ev("scripting.list"),
      executeScript: ev("scripting.execute")
    }
  };
  if (withSidePanel) stub.sidePanel = makeSidePanel();
  return stub;
}

function workerContext(chromeStub) {
  const ctx = {
    console: { log() {}, warn() {}, error() {}, debug() {} },
    setTimeout, clearTimeout, Promise, JSON, Object, Array, String, Number, Boolean, RegExp,
    Error, TypeError, Map, Set, Date, Math, URL, Blob, TextDecoder, TextEncoder,
    Uint8Array, ArrayBuffer,
    fetch: () => Promise.resolve({ ok: true, headers: { get: () => null }, text: () => Promise.resolve("") }),
    chrome: chromeStub
  };
  ctx.globalThis = ctx;
  return ctx;
}

// Runs the worker against a given set of available APIs.
function evaluate(withSidePanel) {
  attached.length = 0;
  toggleEnabled = false;
  const chromeStub = baseChromeStub(withSidePanel);

  const ctx = workerContext(chromeStub);

  try {
    vm.runInNewContext(SRC, ctx, { filename: "background.js" });
    return { threw: null };
  } catch (e) {
    return { threw: e };
  }
}

const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

// With a normal, current browser.
let r = evaluate(true);
check("background.js evaluates without throwing", !r.threw,
  r.threw ? (r.threw.name + ": " + r.threw.message) : "clean");

check("click-to-toggle is enabled on the icon", toggleEnabled === true,
  "openPanelOnActionClick = " + toggleEnabled);

check("NO onClicked handler competes with the toggle",
  attached.indexOf("action.onClicked") < 0,
  attached.indexOf("action.onClicked") >= 0
    ? "an onClicked listener is attached and will never fire"
    : "none attached, as it must be");

check("the message router is attached (twice: ping + main)",
  attached.filter(a => a === "onMessage").length === 2,
  attached.filter(a => a === "onMessage").length + " onMessage listener(s)");

check("install and startup hooks are attached",
  attached.indexOf("onInstalled") >= 0 && attached.indexOf("onStartup") >= 0,
  attached.join(", "));

// On a browser missing an API the worker uses.
r = evaluate(false);
check("a browser with no chrome.sidePanel still loads the worker", !r.threw,
  r.threw ? (r.threw.name + ": " + r.threw.message) : "clean");

check("a missing chrome.runtime.onCommand does not kill the worker",
  r.threw === null || !/onCommand/.test(String(r.threw.message)),
  "onCommand is absent from this stub on purpose");

// ---------------------------------------------------------------------
// The response-header watcher.
//
// This is the only way cookie flags can be analysed at all: Chrome never
// exposes Set-Cookie to page JavaScript - getSetCookie() returns an empty
// array even same-origin, verified in a real browser. If this half silently
// stops working, the panel shows an empty cookie group that reads as "all
// good", so it is tested for behaviour and not merely for evaluating.
// ---------------------------------------------------------------------
{
  const hdrListeners = [];
  const onHeadersReceived = Object.assign(ev("webRequest.onHeadersReceived"), {
    addListener: function (fn, filter, extra) {
      hdrListeners.push({ fn, filter, extra });
    },
    hasListener: () => hdrListeners.length > 0
  });
  const wr = { onHeadersReceived };

  // Second worker run with webRequest present.
  attached.length = 0;
  const mark = msgListeners.length;
  const stub = baseChromeStub(true);
  stub.webRequest = wr;
  const ctx2 = vm.createContext(workerContext(stub));
  ctx2.globalThis = ctx2;
  let threw = null;
  try { vm.runInNewContext(SRC, ctx2, { filename: "background.js" }); }
  catch (e) { threw = e; }

  check("the header watcher evaluates cleanly when webRequest exists", !threw,
    threw ? (threw.name + ": " + threw.message) : "clean");
  check("the header watcher is actually registered", hdrListeners.length === 1,
    hdrListeners.length + " onHeadersReceived listener(s)");

  const l = hdrListeners[0] || {};
  check("it asks for responseHeaders, not requestHeaders",
    Array.isArray(l.extra) && l.extra.indexOf("responseHeaders") >= 0,
    JSON.stringify(l.extra));
  check("it covers both schemes and the request types that carry cookies",
    /http:\/\/\*\/\*/.test((l.filter && l.filter.urls || []).join(",")) &&
    /https:\/\/\*\/\*/.test((l.filter && l.filter.urls || []).join(",")) &&
    (l.filter.types || []).indexOf("main_frame") >= 0 &&
    (l.filter.types || []).indexOf("xmlhttprequest") >= 0,
    JSON.stringify(l.filter && l.filter.types));

  // Fire a realistic event through the registered listener.
  let fired = null;
  if (l.fn) {
    try {
      l.fn({
        tabId: 7, requestId: "1", url: "https://shop.example.test/api/session",
        method: "GET", statusCode: 200,
        responseHeaders: [
          { name: "Set-Cookie", value: "sid=abc; Path=/; HttpOnly; SameSite=None" },
          { name: "Content-Security-Policy", value: "default-src 'self'" },
          { name: "X-Request-Id", value: "ignored" }
        ]
      });
      fired = true;
    } catch (e) { fired = e; }
  }
  check("a response event does not throw", fired === true, fired === true ? "" : String(fired));

  // Ask the worker for what it collected, exactly as the panel does. Only the
  // listeners belonging to THIS run are tried: an earlier run's router is a
  // closure over a different stub and would answer from its own empty state.
  let reply = null;
  for (const router of msgListeners.slice(mark)) {
    try {
      router({ __xre: 1, kind: "responseHeaders", tabId: 7 }, {}, r => { reply = r; });
    } catch (e) { reply = { error: String(e) }; }
    if (reply) break;
  }
  check("the panel can ask the worker for the headers it captured",
    reply && reply.ok === true && Array.isArray(reply.headers),
    reply ? JSON.stringify(reply).slice(0, 140) : "no reply");
  check("the captured headers include Set-Cookie",
    reply && reply.headers && reply.headers.some(h => h.headers && h.headers["set-cookie"]),
    reply && reply.headers ? JSON.stringify(reply.headers[0] || {}).slice(0, 160) : "");
  check("irrelevant headers are not retained",
    reply && reply.headers && !JSON.stringify(reply.headers).includes("X-Request-Id"),
    "X-Request-Id is not in WANTED_HEADERS and should have been dropped");
  check("the worker reports whether the header API was available",
    reply && typeof reply.available === "boolean", JSON.stringify(reply && reply.available));

  // Tab scoping: an observation from another tab must not be handed over.
  let other = null;
  for (const router of msgListeners.slice(mark)) {
    try { router({ __xre: 1, kind: "responseHeaders", tabId: 99 }, {}, r => { other = r; }); } catch (_) {}
    if (other) break;
  }
  check("another tab does not receive this tab's headers",
    !other || !other.headers || other.headers.length === 0,
    other ? other.headers.length + " header row(s) leaked to tab 99" : "no reply");
}

let pass = 0, fail = 0;
console.log("service worker evaluation");
console.log("=".repeat(66));
for (const r of results) {
  if (r.ok) { pass++; console.log("  PASS  " + r.name + (r.ev ? "   (" + r.ev + ")" : "")); }
  else { fail++; console.log("  FAIL  " + r.name + "   -> " + r.ev); }
}
console.log("=".repeat(66));
console.log(pass + " / " + (pass + fail) + " passed" + (fail ? "   *** " + fail + " FAILED ***" : ""));
process.exit(fail ? 1 : 0);
