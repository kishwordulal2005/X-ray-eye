# x-ray-eye — Chrome extension

Passive browser-side attack-surface discovery for **authorized** security testing,
as a side panel instead of a console log.

Everything the scanner already finds — endpoints, credentials, JWTs, client-side
storage, OAuth flows, API specs, framework fingerprints, notes and exposures —
is rendered as a searchable table you can sort, filter and export. No more
scrolling a console.

`src/engine.js` is a byte-for-byte copy of `../dark-eye-api.js`. All detection
logic, every classifier and every verdict is the original, unmodified. The
extension only gives it a user interface.

---

## Install

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. **Load unpacked** → select this `xray-eye-extension` folder
4. Click the toolbar icon to open the panel

Requires **Chrome 116+** (MV3 side panel, and `world: "MAIN"` content scripts).

---

## Use

Open the panel on any page and press **Start**. Findings appear live.

**Nothing runs until you press it.** The scanner is deliberately *not* a static
content script. Injecting it on every navigation means a 500 KB engine, sixteen
hooks and a DOM scan on every site the browser merely visits — a cost paid for
a tool that is mostly idle. `content_scripts` in the manifest is empty on
purpose; the service worker registers them at runtime instead, only when asked.

**Toolbar**

| Control | What it does |
|---|---|
| **start / stop** | Runs or pauses the scanner **on this tab only**. Stop leaves the script in place so the findings stay readable. |
| `rescan` | re-read the DOM and page source |
| `sweep` | re-sweep storage, IndexedDB, caches, service workers |
| `read all` | **active.** Sends a real GET to every discovered route. Asks first; these appear in the target's server logs. |
| `clear` | forget everything captured so far |
| `⚙` | jump to Settings |

Also: `filter…` searches the visible table including values, and `all
severities` is a floor filter.

**Settings**

| Setting | Default | Effect |
|---|---|---|
| Start automatically on every page | **off** | Injects on every navigation. Off means you choose. |
| Keep findings when the page reloads | on | Off clears the capture on reload. |
| Sites allowed to start automatically | every site | Match patterns, one per line. Only used by the setting above — **manual Start always works on the current tab**, whatever the list says. |

Turning auto-start on registers the content scripts with
`chrome.scripting.registerContentScripts`, which is what a static manifest
cannot express: a decision made after the user has read the setting. A
non-empty allowlist narrows that registration, so an excluded host is never
injected into even transiently. The panel reports what is currently registered.

### Idle is not an error

An empty table must say *which* of two very different situations it is. With the
scanner stopped, tables read **"The scanner is not running on this page"**,
not "Nothing captured yet" — which would read as a clean result. Not-capturing
also does not raise the red banner, for the same reason: a banner that fires
routinely is a banner you learn to ignore.

| Tab | What it shows |
|---|---|
| **Overview** | Counters, per-channel coverage, severity spread, busiest routes, credentials classified `real`, detected stack |
| **Endpoints** | Every route seen live or referenced in code — method, hit count, status codes, flags (IDOR, cache, PII, mass-assign, GraphQL, third-party) |
| **Credentials** | Hardcoded keys and passwords, triaged into `real` / `fixture` / `arbitrary`, with file, line, exposure and channel |
| **JWT** | Tokens with decoded claims and weakness signals (`alg:none`, no `exp`, enumerable `sub`, admin claims, weak secret) |
| **Storage** | localStorage, sessionStorage, cookies, IndexedDB and Cache API, with PII classification |
| **Auth flows** | OAuth/OIDC authorization requests, redirect URIs, and posture flags (`no state`, `implicit`, `no PKCE`) |
| **Exposure** | One merged list: secrets, credentials in URLs, directory indexes, served dotfiles, sensitive paths, PII |
| **Stack** | Framework fingerprints with CVE candidates, Next.js server actions, service workers |
| **Specs** | Discovered OpenAPI / Swagger / Postman / GraphQL-introspection documents |
| **Notes** | Every discrete observation the scanner recorded, filterable by kind |
| **Export** | Markdown, JSON, endpoint CSV, secrets CSV — previewed on screen, saved to disk |

**Row actions**

Buttons are rendered per row, from what was actually recorded for it � a button
that would fail on click is not drawn.

- **Endpoints** � `open ?` opens the route in a new **background** tab (so working
  down a list doesn't steal focus 30 times), `copy` puts the URL on the clipboard.
- **Credentials** � `go`, `path` and `copy`:
  - `go` � only when the finding has a real file URL. Opens **that source file**
    directly in a foreground tab. There is deliberately no intermediate page:
    on a minified bundle the reported line is line 1 anyway, so a highlight
    added a click without adding information.
  - `path` � only for `exposed on window` findings, where no file exists. Copies
    the expression (`window.WIZ_global_data.G4bawb`) so it can be pasted straight
    into the console.
  - `copy` � the cleartext value.
- Every row also opens a **detail drawer** with the full record. It carries
  `go ?` and `copy` too, and they hide themselves when the record has nothing to
  act on. On a credential the button is `go ?` and points at the file the value
  came from � a credential has no `url`, it has a `file` and a `line`, which is
  exactly why an earlier version hid the button on the records that needed it.

Every action confirms with a toast, so a click is never a silent no-op.

### On minified bundles

`Login-7hSFcFrt.js` is minified onto a single line, so the reported location is
`line 1, column 2855`. That is exact, not approximate — `lineExact: true` in the
drawer says so. `go` opens the file and Ctrl+F on the value is the way in.

---

## False positives

The classifier suppresses four shapes that a large minified bundle produces by
the thousand, all in `classifyValue` / `nonValueReason` in `src/engine.js`:

| Value | Verdict | Why |
|---|---|---|
| `Authorization` under `HEADER_AUTHTOKEN` | arbitrary | an HTTP header name — bundles map their own alias to the header they set |
| `CREATE_PASSWORD` | arbitrary | SCREAMING_SNAKE constant, no entropy |
| `attachment_key_scope`, `bdz_playback_state`, `sponsored_ad` | arbitrary | snake_case label |
| `cddc5233…` (32 hex), `85780403…` (64 hex) | arbitrary | a hash digest, almost always a persisted GraphQL query hash |
| `db49896c…` (40 hex) under `engineRevision` | arbitrary | SHA-1 build revision — also covered by the revision-key rule |

Hex digests are matched at their real widths: MD5 32, SHA-1 40, SHA-256 64,
SHA-512 128, plus a short git revision (which must carry a hex letter, or a plain
seven-digit number reads as a commit hash). Both digest and revision rules
consult the key first: **the same 40-hex string under `userPassword` is still
reported**, because a leaked hash is worth reviewing even when it is not directly
usable. `repro-fp.js` asserts exactly that pair.

### Id and password are reported together

A shipped config object is the commonest credential leak there is:

```json
{ "systemId": "h8support", "systemPass": "@H8Adm1nSS3ms!" }
```

The password was reported. The identifier was **not** — `systemId` is a database
key and `h8support` carries no secret shape, so it was judged arbitrary on its
own and dropped. That leaves the operator holding a password with no account,
which is the least useful half of a finding. The engine's own wording for a pair
is *"rotate the secret; the identifier alone is far less serious"*.

`scanCredentialPairsInText()` now reads a config object and reports both halves
as one pair. Two rules keep it honest:

- **Both halves must be in the same object literal.** A character-distance
  window alone was not enough — two config objects side by side are within
  1200 characters, and pairing a `userEmail` from the first with an
  `apiPassword` from the second invents a confident, wrong claim that they are
  one login. `repro-pairfp.js` exists because of exactly that: it caught the
  false pair before it shipped.
- **The password decides.** An identifier half is allowed to be `arbitrary`
  on its own — that is precisely why it needed a partner.

Pairs appear above the credential table and as a dashboard tile.

### Trailing punctuation is not stripped from values

`@H8Adm1nSS3ms!` was reported as `@H8Adm1nSS3ms`. Four call sites ran
`.replace(/[.,;:!?]+$/, "")` to tidy values lifted out of prose, and `!` is one
of the most common last characters in a real password. Copying that finding gave
you a password that does not work. `!` and `?` are no longer stripped; `.` `,`
`;` `:` still are, since at the end of a credential value they are far more
often sentence punctuation.

### The blind `.map` probe cannot chain

The "is this already a map?" guard read `u.pathname`, but the probe URL was built
by appending to `href`. So `app.js?v=1` probed `app.js?v=1.map` — whose *pathname*
was still `/app.js`, invisible to the guard. That result was scanned as a script
and probed `app.js?v=1.map.map`, and on. On a Flutter app it reported one blob
four times: `.js`, `.js.map`, `.map.map`, `.map.map.map`.

The guard now reads the whole URL, and the candidate drops the query string first
— the map for `app.js?v=1` is `app.js.map`, never `app.js?v=1.map`.

`tools/repro-mapchain.js` covers it. Its two gates were both run against the
pre-fix code to confirm they actually fail without the fix: an earlier version of
that test passed *with* the bug still in place, because the fixture 404'd the
chained URL and the chain died on the network rather than on the guard.

These rules deliberately trade recall for precision. A secret written as all-lowercase
words joined by underscores (`correct_horse_battery`) is now suppressed. That is
a small class and the trade is worth it — the alternative is a table where a
fifth of the rows are bundle constants. The `real` findings are what the tool is
for, and everything suppressed is still visible in the **Notes** tab.

`verdictReason` is now propagated into the secret record, so the panel shows *why*
something was triaged the way it was. A verdict with no reason is one an operator
cannot argue with.

---

## Four things worth knowing

### It injects itself into tabs that were already open

A content script only runs on pages loaded *after* the extension was installed or
reloaded. Open a tab that was already sitting there and nobody answers — which
used to read as "no scanner on this page" even on a perfectly normal URL. Now a
failed message is treated as "not injected yet", and the scripts are pushed into
frame 0 on demand via `chrome.scripting`, once per tab.

If it still cannot run, the panel says *why*: a restricted scheme (`chrome://`,
the Web Store) is reported by name, anything else tells you to reload the tab.

### Errors clear themselves

The status banner needs **two consecutive successful reads** before it
disappears. A page mid-navigation routinely fails one poll, and a banner that
outlives its own problem is worse than no banner at all.

### The page is left alone

The engine builds a fixed panel in the page corner — a "read every route" button
and a live tally. That is a console-mode affordance, and under the extension it
duplicates the side panel while putting the tool's UI on top of the site being
tested. `quiet.js` sets `__XRE_EXTENSION__` before the engine boots, and
`buildPanel()` returns early on it. **No node is appended to the page at all** —
the side panel is the only surface.

Checked two ways: `test-rpc.js` fails if anything is appended to the body (run
against the un-gated engine it reports `1 node(s) appended: __xrayeye_root`),
and `tools/live-check.html` loads the three real scripts on a demo page and
reports what it finds to the console and the title.

### The console stays quiet on purpose

`src/quiet.js` silences the console for exactly as long as the engine boots.
The engine binds `console.log`/`table` at startup and holds those functions for
the whole session, so silencing it during boot is what makes the panel the only
output surface. `src/page.js` then hands the real console straight back to the
page, so the site's own logging is completely unaffected.

### Values show in cleartext by default

The scanner ships with `revealSecrets: true`, so it holds cleartext and provides
no mask of its own. The panel shows it as-is — an operator reading a credential
table wants the value, not a mask they have to keep unticking.

Ticking **mask values** on the Credentials tab masks *in the panel*: first three
characters, length, last two (`sk_********************A9 (29)`). It applies to every
surface — tables, the detail drawer, note snippets and the export preview — so
turning it on once covers the whole panel.

A saved report is **not** masked. It is written by the scanner, may contain
cleartext, and the save button says so before it saves. That is the only place a
secret is meant to leave the browser.

### Copy buttons carry the value, not the mask

`copy` on a credential row puts the **cleartext** on the clipboard even while
masking is on — the point of the button is to move the value somewhere useful.
The row still displays a mask.

### Saved reports keep their real extension

`report.md` lands as `report.md`, not `report.md.txt`. Two things had to be got
right for that, and both are easy to get wrong again:

- The download payload must declare its **real MIME type**
  (`text/markdown`, `application/json`, `text/csv`). A `text/plain` payload
  makes Chrome rewrite the filename to `.txt`.
- It must **not** use `URL.createObjectURL`. That exists in an extension page but
  *not* in an MV3 service worker, so the download throws
  `createObjectURL is not a function` — a failure that only shows up once the
  extension is loaded, never in a page-based preview.

The panel logs the filename the browser actually used, not the one it asked for,
so any future drift shows up there instead of silently on disk.

---

## Layout

```
manifest.json          MV3 manifest: side panel + two content scripts
src/
  quiet.js             MAIN, first. Silences console for the engine's boot only.
  engine.js            MAIN. The scanner, byte-identical to ../dark-eye-api.js
  page.js              MAIN. Turns window.xrayeye into request/response
  content.js           ISOLATED. The only bridge between the two worlds
  background.js        Service worker: panel, badge, downloads
panel/
  panel.html           Markup
  panel.css            Styling
  panel.js             Rendering, filtering, exports, row actions
icons/                 Generated PNGs
tools/                 Development only, not shipped
```

> `panel/viewer.html`, `viewer.css` and `viewer.js` are an earlier "open the
> source at this line" viewer. Nothing references them any more and they are safe
> to delete — say the word and I will remove them.

### How the worlds connect

The scanner must run in the **page's world** — it hooks `window.fetch`, reads
window globals and inspects the real DOM. The panel is an extension page and
cannot touch that world. So:

```
panel  ──chrome.tabs.sendMessage──▶  content.js (ISOLATED)
                                          │  CustomEvent + JSON on window
                                          ▼
                                      page.js (MAIN)  ──▶  window.xrayeye
```

`content.js` answers only from the **top frame**. Sub-frames still run the
scanner so iframe traffic is captured, but mixing per-frame stores would blend
unrelated origins into one list.

---

## Development

```bash
node tools/test-rpc.js        # 41 checks over the panel's whole RPC surface
node tools/dump-fixture.js    # capture real scanner output for UI work
node tools/build-preview.js   # regenerate preview.html from panel.html
node tools/preview-server.js  # serve the folder for UI review
node tools/make-icons.js      # regenerate icons/
```

`tools/test-rpc.js` boots the real engine and driver in a sandbox with a real
CustomEvent transport, drives traffic, and sends every command the panel sends —
asserting both that each answers and that the **field names the tables read
actually exist**. A table rendering a missing column shows blanks, which looks
exactly like "nothing found".

`tools/preview.html` is generated from `panel/panel.html` and replays captured
scanner output, so the UI can be reviewed and screenshotted without a live
target. It is not shipped.

### Updating the engine

Replace `src/engine.js` with a newer build, then:

```bash
node tools/test-rpc.js
node tools/repro-fp.js
```

`src/page.js` reads only the scanner's public API (`secrets`, `jwt`, `storage`,
`findings`, `triage`, `exposed`, `markdown`, …), so it survives engine changes.
The three raw store reads — `specs()`, `authFlows()`, `serviceWorkers()` — are
normalized in one place each, so an internal shape change breaks one
normalizer rather than every table.

> **Note:** `src/engine.js` has been edited relative to the original
> `../dark-eye-api.js` — the false-positive rules above and the `verdictReason`
> propagation live in it. Your console-paste copy of the tool does **not** have
> them. Copy `src/engine.js` over `dark-eye-api.js` if you want the same
> classifier there. It was left untouched rather than overwritten.

`tools/repro-fp.js` is the probe for those rules: it feeds the exact shapes that
came back marked CRITICAL on a real bundle and prints what the classifier decided,
with the reason — including two genuine credentials, so a fix that suppresses too
much shows up immediately.

---

## Scope and limits

- **Passive by default.** `probe()` is the only active path and is refused
  unless you explicitly confirm authorization. `read all` is a separate,
  separately-confirmed action.
- **Blinded to two things:** requests made inside Web Workers, and
  cross-origin iframes.
- **Flags hypotheses.** Fingerprints, version matches and cache posture are
  evidence to confirm, never proof of exploitability.
- Chrome blocks extensions on `chrome://`, the Web Store and other extensions'
  pages. The panel will say so rather than appear broken.

Use only against systems you are authorized to test.