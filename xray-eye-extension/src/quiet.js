/*
 * quiet.js — MAIN world, runs before engine.js.
 *
 * The engine binds console.log/group/table at boot and holds onto those
 * bound functions for the rest of the session. That is the whole reason the
 * old workflow was console-only: every finding was printed and then had to be
 * read out of a scrolling log.
 *
 * So the console is made silent for exactly as long as engine.js is booting.
 * The engine binds the silent versions, keeps them for life, and the panel
 * becomes its only output surface. page.js restores the real console for the
 * page immediately afterwards, so the site's own logging is untouched and
 * nothing can blame this extension for silencing the page.
 */
(() => {
  "use strict";

  if (window.__xreQuiet) return;
  window.__xreQuiet = { original: {}, silent: {} };

  // Set before the engine boots, because the engine reads it while booting.
  // The engine's own corner panel is a console-mode affordance: it prints
  // findings into the page and offers a "read every route" button. Under the
  // extension that duplicates the side panel and, worse, puts a third party's
  // branding on someone else's site. The side panel is the only surface here.
  window.__XRE_EXTENSION__ = true;

  const METHODS = ["log", "info", "warn", "error", "debug", "table", "trace",
    "group", "groupCollapsed", "groupEnd", "dir", "dirxml", "count", "timeEnd",
    "assert", "profile", "profileEnd"];

  for (const m of METHODS) {
    window.__xreQuiet.original[m] = console[m];
    // A plain function, not an arrow: an arrow's own "length" is read-only and
    // assigning to it throws, which would abort the whole boot.
    const noop = function () {};
    window.__xreQuiet.silent[m] = noop;
  }

  for (const m of METHODS) {
    try { console[m] = window.__xreQuiet.silent[m]; } catch (_) {}
  }
})();