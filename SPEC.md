# SPEC: L33 `dash-actions` (dashboard redesign and actions)

Source: `docs/design/guided-setup-dashboard.md` §5.3 (L33 requests), §6.3 to §6.8, §8, §9 and §11
(L33 rows); `docs/PLAN.md` Wave 7, card L33. Builds on L32 `dash-core` (the envelope: who may
connect, launch token, cookie, CSRF, headers, rate limits; its SPEC is in the L32 PR body) and on
L31 (`ms-projects` records) and L34 (`ms dev`, already on `main`).

User request (2026-11-19), after using the L32 page in Chrome: "The dashboard looks very crude with
very few actionable items. Can we improve the UI with the morsec theme and fonts … and start the
next loop with more functionalities." This loop is both:

- **(A) a real redesign** in the landing page's look (`site/src/shared.css`, `site/src/index.html`)
  with the real fonts, now vendored, and every layout bug in the user's screenshots fixed;
- **(B) the actions** of design §6.4 to §6.8 behind the L32 envelope, each with its route, its
  approval (Touch ID raised by msd, never by the page), its receipt and its tests, plus the CLI
  commands that give them parity (`ms set`, `ms rm`, `ms undo`).

The dashboard becomes the one place a vault value may reach a browser (Show) or the clipboard
(Copy). That is the accepted ARI-42 exception recorded in `ARI42.md` (GW-1, INJ-5, design D1);
this loop builds every control the exception names and proves each with a test.

## Goal

A non-technical user opens `ms dashboard` and, without a terminal, can: see at a glance whether
morsec is on and what needs them; stop or start morsec; approve or deny the request an agent is
waiting on; give a key a website or command (or take one away); see, copy, replace or delete a
key's value; undo an import for one secret or a whole project; run the leak scan; re-check the
agents. Where the dashboard must not do something itself (connect an agent, set up a project),
it shows the exact command with a Copy button and says why. The page looks like morsec's landing
page, in light and dark, from 375 px to wide screens, with no horizontal page scroll.

## Decisions

### Look (A)

- **D-1 Fonts are vendored now (replaces L32 D-1).** The user authorized the download on
  2026-11-19. Five woff2 files, Latin subset, under `crates/ms-dash/assets/fonts/`:

  | File | Family, axes / weight, style |
  |---|---|
  | `archivo-latin-var.woff2` | Archivo, variable `wdth` 62..125 and `wght` 300..700, normal |
  | `instrument-serif-latin-400.woff2` | Instrument Serif 400, normal |
  | `instrument-serif-latin-400-italic.woff2` | Instrument Serif 400, italic |
  | `ibm-plex-mono-latin-400.woff2` | IBM Plex Mono 400, normal |
  | `ibm-plex-mono-latin-500.woff2` | IBM Plex Mono 500, normal |

  **Source (the builder downloads; nothing is fetched at run time).** The exact files the landing
  page loads: fetch the stylesheet
  `https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,300..700&family=IBM+Plex+Mono:wght@400;500&family=Instrument+Serif:ital@0;1&display=swap`
  (the URL in `site/src/index.html` line 6) with a current desktop Chrome `User-Agent` (so it
  answers woff2), take the `src: url(https://fonts.gstatic.com/s/…woff2)` of each `/* latin */`
  block (Archivo normal; Plex Mono 400 and 500; Instrument Serif normal and italic) and download
  those five URLs. Licences from the official repository at a pinned commit:
  `https://raw.githubusercontent.com/google/fonts/<commit>/ofl/archivo/OFL.txt`,
  `…/ofl/instrumentserif/OFL.txt`, `…/ofl/ibmplexmono/OFL.txt`, saved as `OFL-Archivo.txt`,
  `OFL-InstrumentSerif.txt`, `OFL-IBMPlexMono.txt`. The builder records in
  `crates/ms-dash/assets/fonts/SOURCES.txt` the five resolved gstatic URLs, the google/fonts commit
  and the SHA-256 of all eight files, and pins the same hashes in a test. If those hosts are not
  reachable from the build sandbox, the builder stops and asks; it does not convert TTFs with a new
  tool or take files from any other mirror.

  Served at `/fonts/<file>` (`font/woff2`, `text/plain; charset=utf-8` for the licences) from
  `include_bytes!`, under the same headers as every response. CSS `@font-face` with
  `font-display: swap`, `url('/fonts/…')` only; CSP unchanged (`font-src 'self'`). The OFL texts
  are served (`/fonts/OFL-*.txt`, linked from the footer's "Fonts" link) and the release SBOM lists
  the three fonts as file components with `OFL-1.1` and their hashes
  (`packaging/lib/sbom.py`), so the licence travels with the binary. No new crate, no npm.

  *Settled 2026-11-19 (orchestrator):* the user asked for the landing page's fonts; the builder
  downloads them as above. Done: the gstatic URLs, the google/fonts commit
  (`5bd87dfc525c8a0d1d8529d3684716e00c3fc59a`, the tip of `main` that day, resolved with
  `git ls-remote https://github.com/google/fonts`, the one extra host touched, read-only) and
  the eight SHA-256 are in `SOURCES.txt` and `assets::fonts_are_pinned`.

- **D-2 Theme.** Tokens copied unchanged from `site/src/shared.css` (paper, paper-2, ink, ink-2,
  muted, rule, faint, signal, deny, and their dark values), dark mode by `prefers-color-scheme`
  only (no toggle: the page holds no preference). Vocabulary from the landing page:
  - hairline rules (1 px `--rule`) for structure: header, tables, inputs, section rules; cards get
    a 1 px `--faint` border, not a filled background;
  - labels: Archivo 500, `font-stretch: 118–125%`, 11–11.5 px, uppercase, `letter-spacing: .08em`;
  - headings: Instrument Serif italic; the Home headline as large as the landing page's;
  - refs, hosts, paths, commands: IBM Plex Mono; key refs in `--signal` (the landing `.ref` style);
  - buttons: the landing `.btn` rectangle (uppercase stretched label, 1 px border), `.btn.solid`
    for the one primary action per screen, `.btn.danger` (deny red border and text) for destructive
    actions;
  - signal blue for refs and primary actions, deny red for warnings and destructive actions, and
    nothing else coloured.

- **D-3 Type and spacing scale.** Base 15 px, ratio 1.25: 12, 15, 19, 23, 29, 37, 46, 57 px as
  `--t-0 … --t-7`; weight and stretch carry hierarchy before size. Spacing 4 px grid (`--s-1 …
  --s-8`: 4, 8, 12, 16, 24, 32, 48, 64). `font-variant-numeric: tabular-nums` on every count,
  time, line number and port. Line length ≤ 72ch for prose.

- **D-4 Interaction rules.** Every control at least 44×44 px (inline text links excepted); a
  visible `:focus-visible` ring (1.5 px signal, 2 px offset) on everything focusable; every input
  has a `<label>` (no placeholder-as-label; example values go in a hint line under the field, in
  muted text, never in `placeholder`); hover styling only inside `@media (hover: hover)`;
  transitions only on named properties (`background-color`, `color`, `border-color`, `opacity`)
  and ≤ 150 ms, and none under `prefers-reduced-motion: reduce`; `aria-current="page"` on the nav
  link of the current screen; status changes announced through one `aria-live="polite"` region.
  Every screen has a loading state, an empty state and an error state, each saying what to do
  next.

- **D-5 Layout fixes for the screenshot bugs.**
  1. *Projects grid painting a light block in dark mode:* the "gap as border" trick
     (`.grid { background: var(--rule) }`) is removed. Grids are
     `repeat(auto-fill, minmax(min(100%, 300px), 1fr))` with a real `gap` and a transparent
     background; each card draws its own border, so an empty track paints nothing.
  2. *Home stat row cut off:* `repeat(auto-fit, minmax(min(100%, 180px), 1fr))`, `min-width: 0`
     on every grid and flex child, labels may wrap.
  3. Tables scroll inside their own `.tw` container (`overflow-x: auto`, `max-width: 100%`); under
     720 px the Project and Activity tables become stacked rows (each cell with its column label),
     so nothing needs sideways scrolling at 375 px. `html, body { overflow-x: clip }` stays as a
     backstop, not as the fix.
  4. Long mono strings (`overflow-wrap: anywhere`) never set a column's minimum width.

- **D-6 Screens (what each shows and does).** The nav is Home, Projects, Activity, Agents, Scan;
  Project and Secret are reached from them and show a breadcrumb. The header's right side is the
  status control (D-9). The footer reads: "Local to this Mac. Values are shown only after Touch ID,
  and hidden again after 15 seconds." plus the version and a "Fonts" licence link. "Read-only" is
  gone.

  | Screen | Focal point | Shows | Actions |
  |---|---|---|---|
  | **Home** | "morsec is on." / "morsec is stopped." (Instrument Serif italic, `--t-7`) with one line under it ("Agents use your keys without seeing them" / "Every agent request is refused until you start it again"), then **Needs you** | Needs you: the pending approval card (D-11), then warnings (D-10), then keys not usable yet (up to 5, "and N more" link). Empty: "Nothing needs you right now." Then counts, each a link: Projects → Projects; Protected → Projects; Not usable yet → Projects filtered; Blocked in 24 h → Activity `?result=blocked&since=24h`. Then the agents strip (name, connected or not, last seen) | Stop / Start (header), Approve once, Approve for this session, Deny, each warning's fix |
  | **Projects** | the card grid | One card per project: name (serif italic), root (mono, muted), "N protected · M not usable yet", badges (in code, committed to git, scan stopped early) in deny red when present. "Keys not in a project" table below. Empty: how to add one | **Add project** (D-17: path field → checked command with Copy). Card → Project |
  | **Project** | name + root, with "N secrets, M not usable yet" | Table: Variable, Key (signal ref), Provider, Tier, Mode, Status, Last use (relative). Code findings (file:line, provider, masked). Git warnings in plain words ("`.env` was committed in 2 commits: the values in git history are not protected; rotate them"). The `ms dev -- <cmd>` hint with Copy | Per row: Open, Undo this one. **Undo whole project** (danger, Touch ID). Re-run setup: command with Copy |
  | **Secret** | the key ref (mono, signal) and its status in words | Provider, tier, mode, added, value box (D-12), where it is used (project, file:line, variable), rules (hosts, git hosts, commands, folders, variables), last 20 uses | Show, Copy, Replace, Delete, Undo this one; rules edit (D-14) |
  | **Activity** | the table | Filters (D-15), table: When, Agent, Key, What, Result; "Showing 8 of 8" / "Showing 200 of 1,240. Narrow the filters to see older ones" | Verify the chain, Export JSON, Export CSV (as L32) |
  | **Agents** | one card per agent | Claude Code, Codex: installed, connected, sessions, blocked, last seen; msd's checks as a list with pass/fail marks | Connect / Disconnect as commands with Copy (D-16); **Re-check** (msd re-runs its checks) |
  | **Scan** | last result or "No scan since msd started" | Files, findings (file:line, key, encoding), skipped keys, notes; "Scanning…" while it runs | **Run scan** (Touch ID, D-18) |

- **D-7 Wording.** One vocabulary everywhere (page, API `status` strings, `ms init` summary stays
  as it is): a key is **protected** (its rule allows something), or **not usable yet**, because it
  **needs a website** (swap) or **needs a command** (run), or is **not stored**. The Home tile
  "NEED A HOST OR COMMAND" becomes "Not usable yet". Agent names first and the pid as muted detail
  ("Terminal · pid 26566"); `other("dashboard")` is shown as "Dashboard".

- **D-8 Times.** Relative in the cell ("just now", "4 min ago", "2 h ago", "yesterday 14:02",
  then a date in the user's locale beyond 7 days) with the absolute local time (ISO 8601 with
  offset) in the cell's `title` and in a `<time datetime>` attribute. Activity rows refresh their
  relative text when the screen re-renders; nothing ticks per second.

### Actions (B)

- **D-9 Header status is a control.** "● On" with a **Stop** button (danger outline); "Stopped"
  in deny red with a **Start** button. Stop asks an inline confirmation ("Stop every agent's access
  now? Stop / Cancel"), then `POST /api/stop`: no Touch ID (AUTH-4: stopping only refuses, same as
  `ms stop`). Start → `POST /api/start` → Touch ID (as `ms start`).

- **D-10 Warnings say what they mean and offer the fix.** msd's alerts become structured:
  `Daemon::alert` takes an `AlertKind` (`CaReissued { hosts }`, `SettingsChanged { path }`,
  `ProxyDown`, `VaultUnlisted`, `FloorNotSaved`, `ProjectsUnreadable`, `BindingSkipped`, `Other`)
  and keeps the same text for `ms status` (unchanged output). Home and Agents get
  `warnings: [{ id, title, detail, fix }]` where `fix` is one of `{ action: "<route>", label }`
  (a button the dashboard can do), `{ command: "<shell-quoted command>" }` (Copy button), or none.
  `id` is a stable hash of kind + text. Mapping:

  | Kind | Title (plain words) | Fix |
  |---|---|---|
  | CaReissued | "Some tools may not trust morsec yet" — detail: "morsec made a new certificate for N websites. Tools that check the macOS trust store (curl, Python, Git) will refuse morsec's connections until you trust it once." | command `ms init --trust` (asks for your Mac password, so it runs in a terminal); Dismiss |
  | SettingsChanged | "Claude Code's settings changed" (agent named from the path) — "Check it still sends its requests through morsec." | action Re-check (D-16); command `ms doctor`; Dismiss |
  | ProxyDown | "morsec's proxy is not running" — "Agents can't use keys that go to websites." | command `ms doctor` |
  | VaultUnlisted, FloorNotSaved | "morsec couldn't read or save its state" | command `ms doctor` |
  | ProjectsUnreadable | "Project records failed their check" — "Undo is off until they are fixed. Keys and rules keep working." | command `ms doctor` |
  | BindingSkipped, Other | the alert text, inert | command `ms doctor` |

  **Dismiss** (`POST /api/warnings/{id}/dismiss`) clears that alert in msd memory, no Touch ID,
  writes a receipt; it is offered only for CaReissued and SettingsChanged (informational).

- **D-11 Approve or deny the waiting request.** The Home card renders the pending request as
  `ms approve` does: agent, key, tier, working directory, and every argument on its own numbered,
  quoted line, all through an inert renderer (the same escapes as `ms_approve::render::inert`,
  done in msd: the API sends the rendered strings), never truncated, with a live "expires in 1:42".
  **Approve once** / **Approve for this session** → `POST /api/approvals/{id}/approve`
  `{ "scope": "once" | "session" }` → msd's `HumanApprover::decide(id, true, scope)` raises Touch ID
  with the reason it renders from the real request (unchanged). **Deny** →
  `POST /api/approvals/{id}/deny`, no Touch ID (as `ms approve`). The `id` binds the click to the
  request that was shown: a different or answered id gets 409 "That request is no longer waiting".

- **D-12 Show and Copy (design §6.6, D1).** Both are refused while stopped and need Touch ID on
  every use, test keys included.
  - msd builds an `ApprovalRequest` for the dashboard session with key = the key, tier = the key's
    tier, `argv` = `["dashboard", "show" | "copy", <key>]` (so the once-token is bound to that key
    and that action), and asks through a new **confirm path** (D-19). The Touch ID reason, rendered
    by msd: "show the value of `<key>` in the morsec dashboard" / "copy the value of `<key>` to the
    clipboard (cleared after 30 s)", inert.
  - **Show:** `POST /api/keys/{key}/show` → `200 {"key", "value", "hide_after_ms": 15000}` with
    `Cache-Control: no-store` (as every response). The response body is built by hand into a
    `Zeroizing<Vec<u8>>` and handed to hyper as `Bytes::from_owner` of it, so msd's copy is wiped
    when hyper drops the body. `SecretBytes` gets no `Serialize` (REVIEW.md). Values that are not
    UTF-8 answer 409 "This value is not text; use Copy" (Copy then also refuses: the pasteboard
    gets text only, so 409 "not text" there too). The page writes the value into one element with
    `textContent`; control, bidi and invisible characters are shown escaped (`\u{…}`) with a note;
    the element has `user-select: none` (use Copy, whose clipboard entry is marked and cleared);
    it is cleared and the reference dropped after 15 s, on `blur`, on `visibilitychange` to hidden,
    on `pagehide` and on navigation; never written to storage, the URL, the console or history. A
    "Hide" button hides it early.
  - **Copy:** `POST /api/keys/{key}/copy` → Touch ID → msd writes the pasteboard itself
    (`crates/msd/src/pasteboard.rs`, D-20) → `200 {"cleared_after_ms": 30000}`. The response never
    contains the value.
  - Limits: 10 Show + Copy per 10 minutes in all sessions together, counted before Touch ID (so a
    flood can't raise a flood of sheets); 429 "Too many in 10 minutes. Wait N min" over it.
  - Receipt per use, and per refusal: see D-22.

- **D-13 Replace, Add, Delete.**
  - **Replace** (`POST /api/keys/{key}/replace {"value"}`; CLI `ms set <key>`): Touch ID ("replace
    the value of `<key>`"), refused while stopped, inside agent sessions (CLI) and for keys this
    build can't use. The new value comes from a hidden field (`type="password"`,
    `autocomplete="off"`, `spellcheck=false`, not inside a `<form>`, sent with `fetch`, cleared right
    after) and is never echoed: the answer says "replaced `<key>`". In msd: read the old value into a
    `SecretBytes`, `vault.put(new)`; if `put` fails, `put(old)` again and report which state the key
    is in. Name, rules, refs and receipts don't change. The macOS backend's replace is
    delete-then-add (not atomic, `replace_locked`), and the `Vault` trait is frozen (REVIEW.md), so
    this restore-on-failure in msd is how design §6.8's "old value stays in use" is met; between
    delete and add a request for the key fails closed (no such key).
  - **Add** (`POST /api/keys {"key", "value", "mode", "tier"}`; CLI `ms add`, unchanged): a new key
    only, from a hidden field; no Touch ID (as `ms add`: a new key's rule allows nothing). Offered
    on Projects ("Add a key") with key-name validation messages from `KeyName`.
  - **PutKey no longer replaces (closes a gap found while specifying).** Today msd's `PutKey`
    silently replaces an existing key for any caller outside an agent session, with no approval,
    though `ms add` refuses. From L33, `PutKey` on an existing key is refused for every caller with
    "`<key>` already exists. Replace it with: ms set `<key>`"; replacing goes only through
    `KeyReplace` (Touch ID). L31's import never puts an existing key (plan refuses duplicates;
    `reuse` rows put nothing), so `ms init` / `ms import` are unaffected; the builder confirms with
    the existing tests.
  - *Settled 2026-11-19 (orchestrator):* close the gap: replacing a value needs `KeyReplace`
    with Touch ID; `PutKey` refuses an existing key for every caller (T-95).
  - **Delete** (`POST /api/keys/{key}/delete {"force": bool}`; CLI `ms rm <key> [--force]`): Touch
    ID ("delete `<key>` and its rule; this can't be undone"). Refused (409) while a project record
    still has a line holding its ref, naming each `project file:line`, unless `force`. Deletes the
    value (`vault.delete`), then the rule (a tightening, through `change_rule`). The page asks to
    type the key's last segment to confirm, then Touch ID.

- **D-14 Rules edit on the Secret screen.** `POST /api/keys/{key}/rules {"edit": {...}}` with one
  edit per request: `add_host`, `remove_host`, `add_command` (`{"words": [..]}`), `remove_command`,
  `add_folder`, `remove_folder`, `set_tier`. The edit logic moves from `ms-cli/src/rules.rs` into
  `ms_rules::edit` (one `apply(rule, Edit) -> Result<KeyRule>` used by both the CLI and msd, so
  validation and normalisation are identical). msd applies it to the current rule and sends the
  result through the existing `propose` path: `ms_rules::classify_rule` decides; **loosening needs
  Touch ID, tightening needs none**, exactly as `ms rules`; loosening is refused while stopped.
  Hosts: one field (`api.example.com` or `*.example.com`, hint under the field); commands: one word
  per space, previewed as chips before sending; a word with a space or a quote needs
  `ms rules --add-command '<JSON>'` (said under the field). Git hosts, variables, SSH host keys and
  mint scopes are shown read-only with their `ms rules` command (deferred, see below).

- **D-15 Activity filters.** Labelled controls: **Since** (select: last hour, 24 hours, 7 days,
  30 days, everything), **Project** (select from the projects), **Key** (text; hint "for example
  `shop/stripe-secret-key`" under it, no placeholder), **Agent** (select: any, Claude Code, Codex,
  Terminal, Dashboard, ms dev, other), **Result** (select). Filters live in the hash
  (`#/activity?result=blocked&since=24h`) so Home's counts link straight to a filtered view. The
  table: When (D-8), Agent ("Claude Code · pid 4411"), Key (signal ref → Secret), What (mechanism
  and target, mono, wraps), Result (coloured word plus reason).

- **D-16 Agents: Connect and Disconnect stay commands; Re-check is a button.**
  - `ms connect` / `ms disconnect` are **not** run by msd in L33. Reasons: (1) the connector code
    lives in the CLI and writes the absolute path of the `ms` binary the user invoked
    (`ms_path()`: the first stable `ms` on the user's PATH); msd runs under launchd with a minimal
    PATH and would write its own idea of where `ms` is into the agent's settings; (2) the terminal
    shows the exact diff of `~/.claude/settings.json` / `~/.codex/config.toml` and asks, which is
    the consent step for editing agent configuration (SDLC-4); (3) **Disconnect removes the agent's
    sandbox and proxy settings**, a loosening an agent could reach by driving the user's browser
    (T-69) and then benefit from in its next session; doing it from msd would need its own Touch ID
    flow and a refactor of `ms-connect` into the daemon. That is a follow-up loop (see Deferred).
  - The Agents card shows the command (`ms connect claude-code`, `ms disconnect codex`) with a
    **Copy command** button (`navigator.clipboard.writeText`, the page's own text, never a value)
    and "then press Re-check".
  - **Re-check** (`POST /api/agents/recheck`, no Touch ID, no receipt: it changes nothing) makes msd
    re-read each connector's state file, re-fingerprint the watched settings files (`drift.rs`),
    re-test that its proxy port accepts a connection, and clear a SettingsChanged alert whose file
    is unchanged since it was raised plus re-checked; answers the fresh `AgentsView`. For the full
    check it shows `ms doctor` with Copy (`ms doctor` static checks stay in the CLI).
  - *Settled 2026-11-19 (orchestrator):* Connect / Disconnect stay copyable commands in L33;
    running them from msd is the follow-up loop L35 `dash-connect`.

- **D-17 Add project stays `ms init` in the terminal; the page builds the command.** Running the
  import from msd would move L31's scan and value reading out of the user's terminal process into
  the daemon (msd would read arbitrary folders, including macOS-protected ones like `~/Documents`,
  under its own TCC identity), and would let a browser-driving agent (T-69) start an import that
  loosens new keys' rules with one approval. `ms init` refuses inside agent sessions for the same
  reason. So **Add project** is a labelled path field → `POST /api/projects/check-path {"path"}`
  (no mutation): msd canonicalises it, refuses machine-mode and refused roots with the reason
  (`ms_projects::mode::detect` / `refused_root`: "That is your home folder; pick the project
  folder"), says whether it is already a project, and answers the shell-quoted command
  `cd '<path>' && ms init` with Copy. Re-scan on the Project screen is the same command.
  *Settled 2026-11-19 (orchestrator):* Add project stays a copyable command in L33; running the
  import from msd is the follow-up loop L35 `dash-connect`.

- **D-18 Run scan.** `POST /api/scan/run` → Touch ID (the same `["ms", "scan"]` approval as today,
  through the confirm path) → `202 {"started": true}`; the scan runs on a blocking thread; `GET
  /api/scan` gains `running: bool`, and the page polls it every 2 s while running. Refused while
  stopped and while a scan runs (409).

- **D-19 One approval broker, a confirm path for dashboard actions.** A terminal command reviews
  its own request in the terminal (`inline_review`) and then decides it. The dashboard click is
  that review: msd adds `HumanApprover::confirm(req, timeout) -> ApprovalOutcome`, which takes the
  one approval slot (so `ms approve` and Home see "Touch ID is up for: …", and `ms stop` ends it
  through the epoch), raises Touch ID at once with the given reason (marked `deciding`, so no other
  process can decide it), and on success issues a **once** token bound to the request; msd then
  `verify`s the token against the same binding right before acting (L11 SPEC D-6), which uses it
  up. If the slot is taken: 409 "Another request is waiting for you on Home. Answer it first". The
  10 s per-session cooldown after a refusal applies (the dashboard session is the browser's
  process). The page shows "Confirm with Touch ID on this Mac…" while the request is open and
  disables the screen's action buttons.

- **D-20 The pasteboard writer.** `crates/msd/src/pasteboard.rs`, a dedicated FFI module with a
  module-level `#![allow(unsafe_code)]` and a `// SAFETY:` comment per block (REVIEW.md), using
  the already-locked `objc2` 0.6 / `objc2-foundation` 0.3 (`msg_send!` on `NSPasteboard`
  looked up by class name, AppKit linked with `#[link(name = "AppKit", kind = "framework")]`): no
  new crate. Steps: `generalPasteboard`, `prepareForNewContentsWithOptions:
  NSPasteboardContentsCurrentHostOnly` (no Universal Clipboard to other devices), `clearContents`,
  `setString:forType: public.utf8-plain-text`, `setData: <empty> forType:` for
  `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`; remember `changeCount`;
  after 30 s, `clearContents` only if `changeCount` is unchanged (the user copied something else:
  leave it). The NSString holding the value is released right after; the Rust copy is a
  `SecretBytes`. A `Clipboard` trait in msd lets tests use a fake; a debug-only
  `msd --test-pasteboard-to FILE` (memory vault and debug build only, like `--test-open-to`)
  appends `{len, sha256[..8], markers, cleared}` lines, never the value. If msd has no GUI
  session (no pasteboard server), Copy answers 503 "the clipboard is not reachable from msd".

- **D-21 Undo (design §6.7), in msd.** `POST /api/projects/{slug}/undo` and
  `POST /api/keys/{key}/undo`; CLI `ms undo <project> [--key <key>]` → new IPC `ProjectUndo`.
  - Refused while stopped, inside agent sessions and sandboxed callers (IPC), and while the project
    records are unreadable (fails closed). Touch ID; the sheet's reason names every file that will
    receive a value ("write 3 values back into shop/.env, shop/.env.local").
  - New `ms_projects::undo`: open the root as a directory fd (`O_DIRECTORY|O_NOFOLLOW`), walk each
    recorded relative path component by component with `openat(O_NOFOLLOW)` (no `..`, no absolute
    path, no symlink at any level), require a regular file owned by the user with one link, read it
    (bounded as `ms-import`), and require that the recorded line still holds exactly
    `VAR=ms://<key>` in the recorded quote style. Any check failing skips that line and lists it
    with the reason; the rest go ahead. The value is encoded for the recorded quote style by a
    function proven to round-trip through `ms-import`'s dotenv parser; a value that can't be
    written in that style (a newline in an unquoted value, a `'` in a single-quoted one) is
    skipped and listed. Each file is rewritten once, atomically (temp file in the same directory
    through the directory fd, mode kept, `fsync`, `renameat`), after re-checking it is the file
    read (dev, inode, bytes).
  - Then: delete each key whose every recorded line was restored and that no other project
    record refers to (value and rule); remove the agent hint block (`ms_projects::hint::remove`,
    new: only the exact `<!-- morsec:begin -->…<!-- morsec:end -->` block with the project's
    slug, same file checks as `apply`); update the record (per-secret undo removes those secrets;
    whole-project undo drops the record when nothing was skipped, else keeps the skipped lines),
    saved with a new MAC and floor.
  - Values go only from the vault into the recorded file: never into the IPC reply, the HTTP
    reply, the record, a receipt or a log. The answer lists restored and skipped `file:line VAR`.
  - macOS may ask once whether msd may access a protected folder (`~/Documents`, `~/Desktop`);
    if it is refused, those lines are skipped with "macOS did not let morsec write here".

- **D-22 Every action is checked twice and leaves a receipt.**
  - **Request-time process re-check.** Every `POST` route except `/api/session` calls
    `DashData::check_connection(peer, local)` again on a blocking thread before acting, and refuses
    (403 + `blocked` receipt) if it now fails or names another pid or start time than the check at
    accept. Values and destructive actions additionally require `Sec-Fetch-Site: same-origin` to be
    **present** (L32 checks it only when present): browsers always send it, other clients don't.
  - All L32 checks still apply (Host, Origin, JSON, 64 KiB, cookie, CSRF, 20 req/s). Action
    routes also share a bucket of 30 per minute per session.
  - **Receipts.** Every action, refused or done, writes one receipt: session = the dashboard
    session (`other("dashboard")`, the browser's pid and start time: this is the `actor =
    dashboard` of design §6.6, since `ms-core` types are frozen), key = the key (or
    `morsec/daemon` for stop, start, scan, dismiss), mechanism = the key's mode (`run` for
    morsec's own), target = `dashboard: <action>` (`show value`, `copy value`, `replace value`,
    `add key`, `delete key`, `undo`, `rules change (loosen|tighten)`, `approve`, `deny`, `stop`,
    `start`, `scan`, `dismiss warning`), approval token id when Touch ID confirmed, result
    `allowed` / `approved` / `denied` / `blocked` / `failed`. The Activity filter "Dashboard" finds
    them. A value never appears in one (canary test).
  - The approval requests and receipts that name a key carry key names and file paths only.

- **D-23 New API shape.** `ms-dash` keeps `DashData` (reads, unchanged contract: no view has a
  value field) and adds a separate trait `DashActions` that msd implements, one method per action,
  each taking an `Actor { session, peer, local }`. Exactly one method returns a value:
  `show(&Actor, &KeyName) -> Result<Revealed, ApiError>`, where `Revealed` wraps `SecretBytes` and
  is turned into the response only by `http::reveal_response` (the one place a value is written to
  a response). Responses for actions: `{"ok": true, "message"}` or `{"error", "code"}` with `code`
  one of `touch_id_failed`, `busy`, `stopped`, `referenced`, `rate_limited`, `not_text`,
  `invalid`, `gone`, `internal`; the page maps each to plain words and the next step.

- **D-24 IPC (additive; `PROTOCOL_VERSION` stays 1).** Appended to `RequestBody`:
  `KeyReplace { key }` (raw value frame follows: `carries_value` covers it),
  `KeyDelete { key, force }`, `ProjectUndo { slug, keys: Option<Vec<KeyName>> }`; appended to
  `ResponseBody`: `Undone { restored: Vec<UndoLine>, skipped: Vec<UndoSkip>, deleted_keys }`
  (paths, lines, variable names, reasons; no value). `owner_loop` → "L33 dash-actions". All three
  refused inside agent sessions and from sandboxed callers (`caller_sandboxed`, as `ProjectSave`)
  and while stopped. Show and Copy get **no** IPC request: they exist only inside msd's dashboard
  (deviation from design §5.3, which listed `KeyReveal` / `KeyCopy`: no client process should ever
  receive a value it can print). `DashOpen` is unchanged.

- **D-25 CLI.** `ms set <key>` (value typed hidden, or piped on stdin, as `ms add`; review on this
  terminal then Touch ID; refuses inside agent sessions before reading the value), `ms rm <key>
  [--force]`, `ms undo <project> [--key <key>]` (prints restored and skipped lines). Same binary as
  `mors`. `ms projects` already exists (L31). `ms add` on an existing key now says "replace it with
  ms set `<key>`".

- **D-26 Parity (`crates/ms-dash/src/parity.rs`).** Every L33 exemption becomes a screen or keeps
  a stated reason:

  | Subcommand | L33 |
  |---|---|
  | `stop`, `start`, `approve`, `status`, `stats` | Screen `/` |
  | `set`, `rm`, `add`, `rules` | Screen `/secret` (`add` also `/projects`) |
  | `undo` | Screen `/project` |
  | `scan` | Screen `/scan` |
  | `doctor` | Screen `/agents` (Re-check; `--live` and the CLI's static checks stay in the CLI: they start agents or read the terminal's environment) |
  | `init`, `import` | Exempt: "runs in your terminal: the scan reads your files with your terminal's permissions and loosens new keys' rules; the Projects screen checks the folder and gives the command (L33 D-17)" |
  | `connect`, `disconnect` | Exempt: "edits the agent's settings with a diff you confirm in the terminal; Disconnect removes the agent's sandbox; the Agents screen gives the command (L33 D-16)" |
  | `run`, `mcp`, `dev`, `dashboard`, `help` | Exempt, reasons as L32 (`dev`: the Project screen shows the command) |

  `parity_routes_exist` also checks that each "Screen" subcommand's action route exists in
  `http.rs`'s route table.

- **D-27 Loop size.** Everything above is in L33; the build goes in four steps so each review sees
  a coherent slice: (1) look and fonts with no new behaviour, (2) envelope additions (D-19, D-22,
  D-23) and the admin actions (stop, start, approve, deny, rules, re-check, dismiss, scan, add
  project check), (3) value actions (show, copy, replace, add, delete) and the pasteboard, (4) undo
  and the CLI. The minimum the user asked for is all of (1) to (4); only the items under
  "Deferred" move out.

### Builder's notes (L33 build, 2026-11-19)

Where the build chose within the decisions above, or departed from their letter:

- **B-1 FFI module.** The pasteboard's Objective-C calls are in `crates/msd/src/pasteboard/ffi.rs`
  (module-level `#![allow(unsafe_code)]`, a `// SAFETY:` per block, AppKit linked there);
  `pasteboard.rs` holds the logic (markers, the 30 s clear), the `Clipboard` trait, the fakes
  and the named tests. REVIEW.md wants the unsafe module to hold nothing else.
- **B-2 Delete while stopped** is refused (409 `stopped`), like Replace, Undo and the IPC
  requests (D-24); D-13 did not say.
- **B-3 Check-path and Re-check write no receipt**: neither changes anything (D-16 says so for
  Re-check; Add project's check only reads the folder's own entries).
- **B-4 Two more answer codes** than D-23 lists: `refused` (the process re-check, a missing
  `Sec-Fetch-Site`, a refused caller; 403) and `unavailable` (no pasteboard without a desktop
  session; 503).
- **B-5 Undo of one key from the Secret screen** (`POST /api/keys/{key}/undo`) undoes that key in
  every project whose record holds it; the Project screen's row uses
  `POST /api/projects/{slug}/undo {"key"}`. `ms undo` exits 3 when a line was skipped.
- **B-6 The agent hint block** is removed when a whole-project Undo drops the record (nothing
  skipped); a per-key Undo leaves it.
- **B-7 "No other project refers to it":** `ms init` names keys after their project
  (`shop/…`), and the record check refuses a key of another project, so the case is a key whose
  other lines in the same project were skipped; the test covers that.
- **B-9 Fix round 1:** morsec's own requests (argv `ms …` / `dashboard …`) are approved once
  only, in the broker; `Sec-Fetch-Site: same-origin` is also required for Approve, Start, Rules
  and Run scan; the pasteboard is written as one item after `prepareForNewContents…` with no
  clear in between; Undo takes the records lock only after the approval, re-checks the records
  and deletes keys only after the records are saved; one msd lock covers every check-then-write
  of a value.
- **B-10 IPC:** `PendingApproval` gains an optional `admin` field, written only when true, so
  agent requests read as before; an older `ms approve` (its struct denies unknown fields) can't
  read an admin request from this msd. `ms` and `msd` ship together, so this is additive.
- **B-8 Activity's "other" agent** is any session that is none of Claude Code, Codex,
  Terminal, Dashboard and ms dev.

## Acceptance criteria

1. **Fonts.** The five woff2 files and three OFL texts are in `crates/ms-dash/assets/fonts/`, from
   the sources in D-1 recorded in `SOURCES.txt`, SHA-256 pinned in a test; served at `/fonts/…` with
   the right content types and the security headers; `@font-face` refers only to them; the asset
   test still finds no URL outside the page's origin (licence and `SOURCES.txt` files excluded);
   the SBOM lists the fonts.
2. **Theme and layout.** Tokens, type scale, labels, buttons and rules as D-2 to D-4. In dark mode
   no grid or empty track paints a light block (Projects with 1, 2 and 5 cards); the Home counts
   never overflow at 375, 768, 1000 and 1280 px; no screen scrolls horizontally at 375 px; tables
   scroll in their container or stack.
3. **Accessibility.** Labels on every input, no placeholder text in any input, 44 px targets,
   visible focus, `aria-current` on the nav, live region for results, reduced motion respected,
   hover only under `(hover: hover)`.
4. **Screens.** Home, Projects, Project, Secret, Activity, Agents, Scan as D-6 to D-8, each with
   loading, empty and error states; footer as D-6.
5. **Warnings.** Structured alerts and the mapping of D-10; `ms status` text unchanged; Dismiss only
   where listed, with a receipt.
6. **Stop / Start.** Stop needs no Touch ID and takes effect at once (`ms stop` semantics); Start
   needs Touch ID; both write receipts; the header reflects the state.
7. **Approve / Deny.** As D-11; the approval is bound to the shown id; Deny needs no Touch ID; the
   request's text is rendered inert and in full.
8. **Rules edit.** As D-14: shared `ms_rules::edit`; loosening needs Touch ID, tightening none;
   loosening refused while stopped; invalid input answers the same message as `ms rules`.
9. **Show.** As D-12: Touch ID every use, once-token bound to key and action, value only in the
   show response (`no-store`), `textContent`, cleared after 15 s / blur / hidden / pagehide /
   navigation, never in storage, URL, console or history; non-text refused.
10. **Copy.** As D-12 and D-20: the value never reaches the browser; pasteboard written by msd with
    the concealed, transient and current-host-only markers; cleared after 30 s only if unchanged.
11. **Rate limit.** Show + Copy at most 10 per 10 minutes in all; action routes 30 per minute per
    session; the 11th Show raises no Touch ID sheet.
12. **Replace and Add.** As D-13: Replace needs Touch ID, never echoes, restores the old value
    when the store fails; Add creates new keys only; `PutKey` refuses to replace an existing key for
    every caller.
13. **Delete.** Touch ID; refused while referenced unless forced; removes value and rule.
14. **Undo.** As D-21 for one secret and for a whole project, from the dashboard and `ms undo`.
15. **Scan.** Run from the page with Touch ID; progress and result shown; refused while stopped or
    running.
16. **Agents.** Commands with Copy for connect and disconnect; Re-check re-runs msd's checks and
    clears a settled SettingsChanged alert.
17. **Add project.** Path checked by msd, reasons for refused folders, shell-quoted command.
18. **Envelope for actions.** Every action route enforces L32's checks plus the request-time
    process re-check, the 30/min bucket, and `Sec-Fetch-Site: same-origin` present for value and
    destructive actions; every route is refused without cookie, without CSRF, with a foreign
    Origin, and from an agent process tree.
19. **Receipts.** One per action (done or refused) as D-22; none carries a value.
20. **IPC and CLI.** `KeyReplace`, `KeyDelete`, `ProjectUndo`, `Undone` appended,
    `PROTOCOL_VERSION` 1; `ms set`, `ms rm`, `ms undo` (and `mors`) work and are refused inside
    agent sessions.
21. **Parity.** D-26; `dash_parity_covers_every_subcommand` passes with the new subcommands.
22. **No value leaks.** Canary values never appear in any API response except `show`, in any
    receipt, msd log line, IPC reply, error or approval reason.
23. **Docs.** `docs/threat-model.md` rows T-89 to T-103 with their tests (gate-checked); `ARI42.md`
    rows below and the change-log line; README / `docs` mention of `ms set`, `ms rm`, `ms undo`;
    the gate (`npm run build`, CA variables unset, outside the sandbox) passes.
24. **Browser QA** as the QA section, with screenshots in the loop's proof folder.

## Tests per criterion

Every new test carries a `// protects=…; fails_when=…; no_claim=…` card. Paths are relative to the
repo root.

| # | Tests |
|---|---|
| 1 | `crates/ms-dash/src/assets.rs::fonts_are_pinned`, `crates/ms-dash/src/assets.rs::fonts_have_licences`, `crates/ms-dash/src/assets.rs::font_faces_use_only_vendored_files`, `crates/ms-dash/src/assets.rs::dash_assets_have_no_external_urls` (updated: allows `url('/fonts/…')` only), `crates/ms-dash/tests/http.rs::fonts_served_with_headers`, `packaging/tests/test_packaging.py::test_sbom_lists_fonts` |
| 2 | `crates/ms-dash/src/assets.rs::css_has_no_gap_painted_grids` (no `background: var(--rule)` on a grid), `crates/ms-dash/src/assets.rs::css_grids_shrink` (every grid track uses `min(100%, …)`), browser QA screenshots |
| 3 | `crates/ms-dash/src/assets.rs::inputs_are_labelled_without_placeholders`, `crates/ms-dash/src/assets.rs::hover_only_under_hover_media`, `crates/ms-dash/src/assets.rs::transitions_are_named_and_short`, `crates/ms-dash/src/assets.rs::reduced_motion_respected`, browser QA (keyboard pass) |
| 4 | `crates/ms-dash/tests/http.rs::api_views_round_trip` (extended), `crates/msd/src/daemon.rs::dashboard_views_from_records` (extended: wording of D-7), browser QA |
| 5 | `crates/msd/src/daemon/dash_actions.rs::alerts_map_to_warnings`, `crates/msd/src/daemon/dash_actions.rs::status_text_unchanged`, `crates/msd/src/daemon/dash_actions.rs::dismiss_only_informational` |
| 6 | `crates/msd/src/daemon/dash_actions.rs::stop_needs_no_approval`, `crates/msd/src/daemon/dash_actions.rs::start_from_dashboard_needs_touch_id` |
| 7 | `crates/msd/src/daemon/dash_actions.rs::approve_from_dashboard_binds_id`, `crates/msd/src/daemon/dash_actions.rs::deny_needs_no_touch_id`, `crates/msd/src/daemon/dash_actions.rs::pending_card_is_inert_and_complete` |
| 8 | `crates/ms-rules/src/edit.rs::edit_matches_cli_semantics`, `crates/msd/src/daemon/dash_actions.rs::rules_edit_loosen_needs_touch_id`, `crates/msd/src/daemon/dash_actions.rs::rules_edit_tighten_needs_none`, `crates/ms-cli/tests/rules_cli.rs` (existing, still passing over `ms_rules::edit`) |
| 9 | `crates/msd/src/daemon/dash_actions.rs::reveal_requires_fresh_approval`, `crates/msd/src/daemon/dash_actions.rs::reveal_token_bound_to_key_and_action`, `crates/msd/src/daemon/dash_actions.rs::reveal_refused_while_stopped`, `crates/ms-dash/tests/actions.rs::reveal_response_is_no_store`, `crates/ms-dash/src/assets.rs::dash_js_never_stores_values` (no `localStorage`, `sessionStorage`, `indexedDB`, `console.`, `history.pushState` with data, in the assets), `crates/ms-dash/src/assets.rs::reveal_is_cleared` (the clear timers and listeners exist), `crates/msd/src/daemon/dash_actions.rs::reveal_refuses_non_text` |
| 10 | `crates/ms-dash/tests/actions.rs::copy_never_sends_value_to_browser`, `crates/msd/src/pasteboard.rs::pasteboard_cleared_after_30s`, `crates/msd/src/pasteboard.rs::pasteboard_left_alone_when_changed`, `crates/msd/src/pasteboard.rs::pasteboard_markers_set` (fake), `crates/msd/src/main.rs::test_pasteboard_to_needs_the_memory_vault` |
| 11 | `crates/msd/src/daemon/dash_actions.rs::reveal_rate_limited`, `crates/ms-dash/tests/actions.rs::action_bucket_per_session` |
| 12 | `crates/msd/src/daemon/dash_actions.rs::replace_keeps_old_value_on_failure`, `crates/msd/src/daemon/dash_actions.rs::replace_needs_touch_id`, `crates/ms-dash/tests/actions.rs::replace_never_echoes_value`, `crates/msd/src/daemon.rs::put_key_refuses_existing_key`, `crates/msd/src/daemon/dash_actions.rs::add_key_new_only` |
| 13 | `crates/msd/src/daemon/dash_actions.rs::delete_refused_while_referenced`, `crates/msd/src/daemon/dash_actions.rs::delete_needs_touch_id_and_removes_rule` |
| 14 | `crates/ms-projects/src/undo.rs::undo_refuses_symlink_swap`, `crates/ms-projects/src/undo.rs::undo_stays_inside_root`, `crates/ms-projects/src/undo.rs::undo_only_writes_exact_ref_line`, `crates/ms-projects/src/undo.rs::undo_round_trips_with_parser` (property test), `crates/ms-projects/src/undo.rs::undo_is_atomic_per_file`, `crates/ms-projects/src/hint.rs::hint_block_removed_once`, `crates/msd/src/daemon/dash_actions.rs::undo_refuses_tampered_record`, `crates/msd/src/daemon/dash_actions.rs::undo_deletes_only_unreferenced_keys`, `crates/msd/src/daemon/dash_actions.rs::undo_reason_names_every_file`, `crates/ms-cli/tests/set_rm_undo.rs::undo_end_to_end` |
| 15 | `crates/msd/src/daemon/dash_actions.rs::scan_from_dashboard_needs_touch_id`, `crates/ms-dash/tests/actions.rs::scan_runs_in_background` |
| 16 | `crates/msd/src/daemon/dash_actions.rs::recheck_clears_settled_drift`, `crates/ms-dash/tests/actions.rs::recheck_changes_nothing` |
| 17 | `crates/msd/src/daemon/dash_actions.rs::check_path_refuses_machine_roots`, `crates/msd/src/daemon/dash_actions.rs::copy_commands_are_shell_quoted` (paths with `'`, `$()`, newlines, bidi) |
| 18 | `crates/ms-dash/tests/actions.rs::every_action_route_checks_envelope` (iterates the route table: no cookie, no CSRF, foreign Origin, cross-site, missing `Sec-Fetch-Site` on value routes), `crates/ms-dash/tests/actions.rs::action_rechecks_connection_owner`, `crates/ms-cli/tests/dash_actions.rs::agent_tree_cannot_act` (a fake `claude` process tree posts to every action route) |
| 19 | `crates/msd/src/daemon/dash_actions.rs::dashboard_action_writes_receipt` (one per action, done and refused, fields as D-22) |
| 20 | `crates/ms-ipc/src/protocol.rs::l33_requests_round_trip`, `crates/ms-ipc/tests/ipc.rs::key_replace_carries_value_frame`, `crates/msd/src/daemon/dash_actions.rs::key_requests_refused_in_agent_session`, `crates/ms-cli/tests/set_rm_undo.rs::set_rm_undo_cli`, `crates/ms-cli/tests/set_rm_undo.rs::mors_is_ms` |
| 21 | `crates/ms-cli/src/main.rs::dash_parity_covers_every_subcommand`, `crates/ms-dash/src/parity.rs::parity_routes_exist` (extended) |
| 22 | `crates/msd/src/daemon.rs::dashboard_never_serves_a_canary` (extended: every route but `show`), `crates/ms-cli/tests/dash_actions.rs::dashboard_actions_end_to_end` (dev msd, fixture project with canary values, every action through curl from outside the agent tree, then receipts, log and IPC replies grepped for the canaries) |
| 23 | `scripts/threat_model_check.py` (gate), ARI-42 scan (gate), `npm run build` |
| 24 | Browser QA (PROOF.md, screenshots) |

## Browser QA (required, with proof)

Against a **throwaway dev msd only**. QA must never touch the real login keychain, the real
`~/Library/Application Support/morsec`, the real `~/.claude` / `~/.codex`, or the user's msd. The
PROOF records every command run.

1. Setup, all under one fresh `0700` directory `$Q` (in the scratchpad or `$TMPDIR`):
   `HOME=$Q/home` for both processes (connector state and agent settings land there),
   `msd --foreground --vault memory --socket $Q/msd.sock --state-dir $Q/state --dash-port 7411
   --test-touch-id allow --test-open-to $Q/open.txt --test-pasteboard-to $Q/paste.txt`, debug
   build, with `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`
   unset. `ms` with `MORSEC_SOCKET=$Q/msd.sock MORSEC_DEV_UNVERIFIED_DAEMON=1 HOME=$Q/home`.
2. Guards, checked and printed before anything starts, and the run aborts if one fails: `$Q` is
   not under the real `$HOME/Library`; the socket is not the platform default; `--vault memory` is
   in msd's argv; the modification time and file list of the real
   `~/Library/Application Support/morsec` and the count of morsec items in the login keychain
   (`security dump-keychain` without `-d`, counting the morsec service) are recorded before and
   compared after.
3. Fixture: a project under `$Q/home/code/shop` with a `.env` of fake canary values (one swap key
   with a known provider, one with none, one run-mode database URL, one committed to a throwaway
   git history, one key written into `src/`), set up with `ms init`; plus a loose key from
   `ms add`; plus an agent request left pending (a fake-agent process asking for a production key)
   so Home shows the approval card; plus a CaReissued and a SettingsChanged alert.
4. Browser: a **detached** headless Chrome started outside the agent's process tree (gstack's
   `/browse` runs inside the agent tree and is refused by msd, as L32 found: that refusal and its
   receipt are recorded as a check of the envelope), sign-in URL from `$Q/open.txt`.
5. Screenshots of **every screen** (Home, Projects, Project, Secret, Activity, Agents, Scan) at
   **1280 and 375 px**, **light and dark** (28), plus: Home with nothing pending; the Touch ID
   waiting state; a revealed value and the same screen 16 s later (hidden); Copy done; an error
   state (`--test-touch-id deny` run); Undo result with a skipped line; Add project refusing the
   home folder; Projects with 1 card in dark mode at 1000 px (the screenshot bug).
6. Walk every action once in the browser and once refused, and record the receipts
   (`ms log` against the dev msd). Check `$Q/paste.txt` shows the markers and the clear.
7. Keyboard-only pass on Home and Secret (tab order, focus ring, Enter/Space on buttons).
8. Tear down: stop msd, compare the guards' before/after, delete `$Q`.

**Manual Touch ID checks (cannot be automated; recorded in PROOF.md as not verified unless a
person does them on a Mac with Touch ID):** the real sheet's text for Show, Copy, Replace, Delete,
Undo, Start, loosen and Approve; cancel and timeout; that a real `pbpaste` after 30 s is empty and
that a clipboard manager (if installed) skipped the entry; LaunchServices opening a real browser.

## Threat model (`docs/threat-model.md`, new section "Dashboard actions (L33)")

| ID | Threat | Control | Tests | Status |
|---|---|---|---|---|
| T-89 | A value is shown or copied without the person (an agent driving the browser, a stolen session) | Touch ID raised by msd on every Show and Copy; once-token bound to session, key and action, verified right before use; request-time process re-check; `Sec-Fetch-Site` required | `reveal_requires_fresh_approval`, `reveal_token_bound_to_key_and_action`, `action_rechecks_connection_owner` | partial (T-69: the person may approve a sheet an agent caused) |
| T-90 | Show/Copy floods (sheet fatigue, oracle) | 10 per 10 min in all, counted before Touch ID; 10 s cooldown after a refusal | `reveal_rate_limited` | mitigated |
| T-91 | A shown value outlives its use in the browser (cache, storage, history, console, bfcache, selection) | `no-store`; `textContent`; cleared after 15 s, blur, hidden, pagehide, navigation; no storage or console use; `user-select: none` | `reveal_response_is_no_store`, `dash_js_never_stores_values`, `reveal_is_cleared` | partial (browser memory until GC; screen capture) |
| T-92 | A copied value spreads (clipboard managers, Universal Clipboard, other apps later) | msd writes the pasteboard with concealed, transient, current-host-only; clears after 30 s if unchanged; the browser never has it | `copy_never_sends_value_to_browser`, `pasteboard_markers_set`, `pasteboard_cleared_after_30s`, `pasteboard_left_alone_when_changed` | partial (any same-user process can read the pasteboard for 30 s; the exception's residual) |
| T-93 | An agent with Automation over the browser (or a browser it launched) clicks destructive or loosening actions | Process check per connection and per action; Touch ID on start, approve, loosen, show, copy, replace, delete, undo, scan; receipts; Stop, Deny, tighten and Add need none (they only refuse or allow nothing) | `agent_tree_cannot_act`, `every_action_route_checks_envelope`, the per-action Touch ID tests | partial (as T-69) |
| T-94 | A tampered `projects.toml`, a symlink swap or an edited file makes Undo write values elsewhere | MAC and floor (fail closed); root fd + per-component `openat(O_NOFOLLOW)`; regular file, owner, one link; exact `VAR=ms://<key>` line in its quote style; atomic per-file rewrite after a dev/inode/bytes re-check | `undo_refuses_tampered_record`, `undo_refuses_symlink_swap`, `undo_stays_inside_root`, `undo_only_writes_exact_ref_line`, `undo_is_atomic_per_file` | mitigated |
| T-95 | A key's value is swapped without the person (a detached process, a browser-driving agent), or lost on a failed replace | `PutKey` never replaces; `KeyReplace` needs Touch ID and is refused in agent sessions; restore-on-failure | `put_key_refuses_existing_key`, `replace_needs_touch_id`, `replace_keeps_old_value_on_failure` | mitigated (was open before L33: `PutKey` replaced with no approval) |
| T-96 | A key still in use is deleted, or deleted by an agent | Touch ID; refused while referenced unless forced; refused in agent sessions | `delete_refused_while_referenced`, `delete_needs_touch_id_and_removes_rule`, `key_requests_refused_in_agent_session` | mitigated |
| T-97 | The dashboard rules edit loosens without approval or differs from `ms rules` | One `ms_rules::edit` for both; msd's `classify_rule`; loosening = Touch ID, refused while stopped | `edit_matches_cli_semantics`, `rules_edit_loosen_needs_touch_id`, `rules_edit_tighten_needs_none` | mitigated |
| T-98 | CSRF, a foreign Origin or a non-browser client with a stolen cookie reaches an action | L32 envelope on every action route, `Sec-Fetch-Site: same-origin` required on value and destructive routes | `every_action_route_checks_envelope` | mitigated |
| T-99 | A value posted for Replace or Add, or restored by Undo, leaks (echo, error, log, receipt, IPC reply) | Never echoed; names only in messages and receipts; values only as raw frames (IPC) or into the recorded file (Undo) | `replace_never_echoes_value`, `dashboard_actions_end_to_end` (canaries) | partial (hyper's request and write buffers are not zeroized) |
| T-100 | Shell injection through a command the page offers to copy (a crafted folder or agent name) | Commands built and single-quoted by msd; control and bidi characters refused in paths | `copy_commands_are_shell_quoted` | mitigated |
| T-101 | Approve on the dashboard approves a different request than the one shown | Decision bound to the pending id; inert, complete rendering from msd | `approve_from_dashboard_binds_id`, `pending_card_is_inert_and_complete` | mitigated |
| T-102 | morsec is started from the dashboard without the person, or a Stop is undone | Start = Touch ID, re-checked under the flag lock (as `ms start`); Stop = no approval | `start_from_dashboard_needs_touch_id`, `stop_needs_no_approval` | mitigated |
| T-103 | The browser's password manager or autofill saves a value typed into Replace or Add | Not in a `<form>`, `autocomplete="off"`, field cleared after send | browser QA | partial (browser heuristics vary) |

Open threats added: T-89, T-91, T-92, T-93 (unowned: same root as T-69, a macOS permission the
user grants; the Touch ID sheet makes each use deliberate, it does not hide a shown value from a
same-user program), T-99 (hyper buffers), T-103.

## ARI-42 (`ARI42.md`)

| ID | Change | Status after |
|---|---|---|
| GW-1, INJ-5 | The accepted exception takes effect. Its controls are now tested (T-89 to T-92): Touch ID every use, once-token bound to key and action, 15 s hide, msd-written marked pasteboard cleared at 30 s, copy never in the browser, 10 / 10 min, receipt per use, agent trees refused per connection and per action. New control: `PutKey` can't replace a value (T-95) | Partial (exception recorded; review date unchanged) |
| AUTH-3 | Touch ID for start, approve, loosen, show, copy, replace, delete, undo and scan from the dashboard; `ms set`, `ms rm`, `ms undo` use the same approver; confirm path keeps one slot | Partial (strengthened) |
| AUTH-4 | Stop from the dashboard, no approval | Partial (strengthened) |
| MCP-3 | Request-time process re-check, action bucket, required `Sec-Fetch-Site` | Met (unchanged; evidence added) |
| INJ-3 | Inert rendering of the pending request and warnings in msd; `textContent` everywhere | Partial (strengthened) |
| OUT-1 | Undo paths root-relative with `O_NOFOLLOW` and exact-line checks; rules edits through one validator; bounded bodies; shell-quoted commands | Partial (strengthened) |
| LOG-1, LOG-2 | A receipt for every dashboard action and refusal; refused actions from agent trees count towards the session's alert | Partial (strengthened) |
| GW-2 | Fonts pinned by SHA-256 and in the SBOM; no new crate (`objc2` already locked) | Partial (strengthened) |
| SDLC-4 | Undo removes the agent hint block; connect and disconnect stay in the terminal with their diff | Partial (unchanged) |

## Deferred (with reasons)

- **Running Connect / Disconnect from msd** (D-16) and **Add project / re-scan from msd** (D-17):
  a follow-up loop (proposed L35 `dash-connect`) that moves the needed `ms-connect` and import code
  behind msd with its own Touch ID flow. L33 gives the commands with Copy.
- **Rules edits for git hosts, variables, SSH host keys and mint scopes** and commands with quoted
  words: CLI only (`ms rules`), shown read-only with the command. They are rare and need input
  formats that are easy to get wrong in a form.
- **`ms doctor` static checks in the page**: Re-check covers msd's own checks; the CLI's checks read
  the terminal's environment.
- **A theme toggle**: the page follows the system.
- **Zeroizing hyper's buffers** (T-99 residual): needs a custom body and connection buffer
  strategy; recorded, not built.

## Out of scope

- Remote access, more than one user, Linux; a menu-bar app (L25 stays deferred).
- `ms doctor --live`, agent run-time paths (`ms run`, `ms mcp`), `ms dev` (L34, done).
- Changing the frozen interfaces (`ms-core` types, `Vault`, `Approver`, `ReceiptSink`, IPC v1
  framing): everything above is additive.

## Residuals (for PROOF.md)

- T-69 / T-93: an agent the user has given Automation over the browser can drive a signed-in tab
  and cause a Touch ID sheet; the person may approve it. Each sheet names the key and action.
- A same-user program can read a shown value (screen capture) or the pasteboard during its 30 s.
- hyper's request and write buffers holding a posted or shown value are not zeroized.
- Undo into a folder macOS protects may be refused by macOS; those lines are skipped and listed.
- The real Touch ID sheets, real pasteboard and real browser opening are checked by hand only.
- T-94, T-95, T-96 (fix round 1, review S4): a detached process outside every agent tree and
  every sandbox (an agent command that double-forked out, T-04) can still send `KeyReplace`,
  `KeyDelete` or `ProjectUndo`. The gate is the approval: the card, `ms approve` and the Touch
  ID sheet name the requesting program and PID, the request is approved once only (never for the
  session) and `ms set`'s is bound to an msd-keyed fingerprint of the new value.
- msd killed with SIGKILL within a copy's 30 s leaves the value on the pasteboard (a normal exit
  clears it, review N4).

## Revert

Revert the merge commit. The new IPC requests disappear with it (older `ms` never sends them);
nothing persistent changes shape: alerts are in memory, receipts keep their format, project
records keep version 3 (Undo only removes entries). Keys deleted or replaced through L33 stay as
they are.
