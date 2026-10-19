/*
 * content.js — ISOLATED world. The only bridge between worlds.
 *
 * The scanner runs in the page's MAIN world because it has to hook
 * window.fetch, read window globals and inspect the real DOM. The panel is an
 * extension page and cannot touch that world at all. So this script sits in
 * the middle, in the isolated world, and carries messages across.
 *
 * Cross-world transport is a CustomEvent on window carrying a JSON string.
 * Chrome delivers DOM events across the world boundary, and a string payload
 * needs no structured-clone shim. Nothing is trusted from the page: every
 * payload is parsed, and the panel only ever renders what the scanner itself
 * produced.
 *
 * The sub-frame copy of this script stays silent on purpose. It still runs the
 * scanner, so iframe traffic is still captured, but a single panel needs one
 * authoritative answer and frame 0 is it. Mixing per-frame stores would blend
 * unrelated origins into one list.
 */
(() => {
  "use strict";

  const REQ = "__xrext_req__";
  const RES = "__xrext_res__";
  const TIMEOUT_MS = 45000;
  const isTop = (() => { try { return window.top === window; } catch (_) { return false; } })();

  // The panel injects this file on demand when a page was already open before
  // the extension loaded. That can land on top of the manifest-injected copy,
  // and two listeners on one channel means every answer is delivered twice.
  if (window.__xrextRelay) return;
  window.__xrextRelay = true;

  let seq = 0;

  function callMainWorld(cmd, args) {
    return new Promise(resolve => {
      const id = ++seq;
      let settled = false;

      const finish = payload => {
        if (settled) return;
        settled = true;
        window.removeEventListener(RES, onRes);
        clearTimeout(timer);
        resolve(payload);
      };

      const onRes = ev => {
        let d = null;
        try { d = JSON.parse(ev && ev.detail); } catch (_) { return; }
        // Ignore anything that is not the answer to this exact question.
        if (!d || d.id !== id) return;
        finish(d);
      };

      // Registered before dispatching, so a synchronous answer cannot land
      // before anyone is listening.
      window.addEventListener(RES, onRes, false);

      const timer = setTimeout(() => finish({
        id, ok: false,
        error: "No answer from the page scanner. It may not have injected on this URL."
      }), TIMEOUT_MS);

      try {
        window.dispatchEvent(new CustomEvent(REQ, {
          detail: JSON.stringify({ id, cmd, args: args || {} })
        }));
      } catch (e) {
        finish({ id, ok: false, error: "dispatch failed: " + String((e && e.message) || e) });
      }
    });
  }

  // Guarded: a throw here kills the whole relay, and a dead relay looks exactly
// like "the scanner did not come up on this page" — the panel retries for
// seconds against something that was never going to answer.
try {
  const rt = chrome && chrome.runtime;
  if (rt && typeof rt.onMessage.addListener === "function") {
    rt.onMessage.addListener((msg, sender, sendResponse) => {
      if (!isTop) return undefined;             // sub-frames do not serve the panel
      if (!msg || msg.__xre !== 1) return undefined;

      callMainWorld(msg.cmd, msg.args).then(sendResponse, e =>
        sendResponse({ ok: false, error: String((e && e.message) || e) })
      );
      return true;                               // response is async
    });
  }
} catch (e) {
  // Nothing to do. There is no logger here that would not itself throw.
}
})();