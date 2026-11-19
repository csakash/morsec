# SPEC: L35 `dash-connect` (Connect, Disconnect and Add project from the dashboard)

Source: `docs/design/guided-setup-dashboard.md` §4.3 (refinement), §6.4, §6.5, §8, §9; the L33 SPEC
(PR csakash/morsec#35, first comment): D-16, D-17, D-26 and its "Deferred" section. Builds on L31
(`ms-projects`, `ProjectSave`), L32 (the envelope) and L33 (the confirm path, `DashActions`,
receipts, `ms_rules::edit`).

L33 left four things as commands with a Copy button, because running them from msd needed their
own Touch ID flow: **Connect** and **Disconnect** an agent (`ms connect`, `ms disconnect`), and
**Add project** / **re-scan** (the `ms init` import). This loop runs them from the dashboard,
inside msd, behind msd's own Touch ID, and adds the rules edits L33 deferred (git hosts,
variables, SSH host keys).

## Goal

A user who never opens a terminal after installing can connect Claude Code or Codex, disconnect
one, set up a project folder and re-scan it from the dashboard. Each of these shows exactly what
will change first (the same redacted diff `ms connect` prints; the files, secrets and websites
`ms init` would touch), then asks Touch ID once with a reason that names those changes, then does
precisely what was shown or nothing. An agent driving the browser cannot do any of them without
the person's finger on the sheet, and an agent process can't reach them at all.

## Decisions

### Connect and Disconnect (replaces L33 D-16's "commands with Copy")

- **D-1 Two steps: preview, then apply.**
  - `POST /api/agents/{agent}/connect/preview` and `POST /api/agents/{agent}/disconnect/preview`
    (`{agent}` is `claude-code` or `codex`; no Touch ID, no mutation, no receipt, as Re-check):
    msd builds the connector and plans, exactly as `ms connect <agent>` / `ms disconnect <agent>`
    with no flags would. Answer: `{ "plan": "<hex sha256>", "nothing_to_do": bool, "files":
    [{ "path", "verb": "create|change|remove|write", "lines": [{ "sign": "+|-", "n", "text" }] }],
    "notes": [..] }`. `lines` are the redacted changed lines the terminal prints
    (`changed_lines` + `significant` + `redact` / `redact_line`, against `display_safe`), so a
    value of the user's own (a token in an env entry or hook) never reaches the page. Files that
    only `ms connect` writes whole (state, CA bundle) appear as `write <path>` with no lines.
  - `POST /api/agents/{agent}/connect` and `/disconnect` with `{ "plan": "<hex>" }`: msd plans
    again, refuses with 409 `changed` ("The agent's settings changed since you looked. Review the
    changes again") when the new plan's digest differs, then raises Touch ID, then **re-plans and
    re-checks the digest once more right after the sheet** (a file edited while the sheet was up
    is not overwritten), then applies.
  - The digest is SHA-256 over the agent id, the action, and for every change in order: path,
    before (or a marker for "absent"), after (or "absent"). It binds the click to the full
    content, not only the redacted lines shown.
- **D-2 Touch ID for both.** Connect edits an agent's configuration and adds hooks that run outside
  its sandbox at every session start (SDLC-4: a person consents to every agent configuration
  change); Disconnect removes the agent's sandbox and proxy settings (a loosening, T-69). The
  reason, built by msd and inert: "connect Claude Code to morsec: change ~/.claude/settings.json,
  ~/.claude.json (sandbox on, its requests through morsec)" / "disconnect Codex from morsec:
  restore ~/.codex/config.toml; its requests stop going through morsec". The request is an admin
  request (`admin_request`, key `morsec/daemon`, tier production, argv `["dashboard", "connect" |
  "disconnect", <agent>, "plan <digest>"]`), so the once-token is bound to that agent, action and
  plan, and like every morsec request it is approved once only.
- **D-3 Stopped.** Disconnect is refused while stopped (409 `stopped`, like every loosening in
  L33). Connect is allowed while stopped (it only confines the agent); the answer says agents
  can't use keys until Start.
- **D-4 Options.** The dashboard runs a plain connect: no `--env`, `--mcp-env`, `--force`,
  `--with-mcp`, `--statusline`, `--wrap`. Opt-in parts an earlier terminal connect turned on
  (`with_mcp`, `statusline`) are carried as a plain re-run carries them, and `--env` refs an
  earlier connect wrote are kept (`previous_env_refs`, `previous_mcp_refs`). If the earlier
  connect used `--wrap` (Claude Code), the dashboard refuses Connect with the terminal command
  (the CLI refuses carried `--wrap` inside agent sessions for the same reason: it changes how
  every hook runs). Disconnect has no options.
- **D-5 Which files.** msd uses the default locations under its `HOME` (`~/.claude`,
  `~/.claude.json`, `~/.codex`), as the Agents screen already does (`Paths::for_home(h, None)`);
  msd can't see a terminal's `CLAUDE_CONFIG_DIR` or `CODEX_HOME`. The connector state file
  (`~/.morsec/connect/<agent>.json`) now records the config directory a connect used
  (`config_dir`, additive: older states read as the default). When the state names a directory
  other than the default, both previews refuse with "Connected from a terminal with
  CLAUDE_CONFIG_DIR set. Use: ms disconnect claude-code" (and the command with Copy).
- **D-6 The `ms` path written into settings.** The connectors write the absolute path of `ms` into
  hooks and MCP entries, run outside the sandbox at every session start. msd uses the `ms` next to
  its own executable (`current_exe()` as launched, not canonicalised, so the Homebrew `opt` link
  survives upgrades): it must exist, be a regular file after resolving, sit in the same canonical
  directory as msd itself, and the directory as launched must pass the CLI's stable-directory
  test (`ms_path`: not under `HOME` or a group/world-writable directory, owned by the user or
  root). Debug builds skip the `HOME` part (dev msd runs from `target/debug`). If no such `ms`
  exists, the previews refuse with "morsec can't find the ms command next to msd; connect from a
  terminal". The stable-directory test moves into one shared function used by the CLI and msd.
- **D-7 Socket and CA.** msd fills what the CLI asks msd for: the proxy port, the CA PEM it holds
  in memory, every host in the MAC-verified rules (`allowedDomains`), and its own socket path;
  `socket_env` is set only when msd listens on a non-default socket (dev msd), as the CLI sets it
  from `MORSEC_SOCKET`.
- **D-8 msd's own writes are not drift.** msd watches the agents' settings files and raises
  "settings changed" when they change (`drift.rs`). After a dashboard Connect or Disconnect, msd
  records the fingerprint of each watched file it wrote; the watch loop skips an alert whose new
  fingerprint is exactly one msd recorded (and forgets it). Any later change alerts as before.
- **D-9 Where the code lives.** `ms-connect` keeps the connectors (the frozen `Connector` trait is
  unchanged). New `ms_connect::view` renders a plan or remove-plan as the preview's files and lines
  for both agents (the CLI's `show_file` / `show_config` print from the same function, so the
  terminal and the page can't disagree) and computes the digest. msd's glue is
  `crates/msd/src/daemon/dash_connect.rs`.

### Add project and re-scan (replaces L33 D-17's "command with Copy")

- **D-10 The setup moves into a library both sides call.** L31's project steps (name, walk, plan,
  store, rewrite, hint block, record, first rules) move from `crates/ms-cli/src/init_project.rs`
  into `ms_projects::setup`, split in two:
  - `prepare(host, catalog, root, name) -> Prepared`: name the project, read the earlier record,
    walk, read and plan every env file, find adoptable refs. **Reads only.** `Prepared::digest()`
    is SHA-256 over slug, display name, root, and per env file its path and every planned row
    (variable, line, action, key, provider, mode, tier) or its error, plus the adopted refs and
    the proposed first rules (D-11).
  - `execute(host, prepared) -> Report`: everything that writes, unchanged in order and checks
    (review R1 to R7 of L31 still hold: record saved first with no rules, then the rules).
  - A `Host` trait gives it what it needs: the projects (slug, root), one record, the key store
    (`ms_import::KeyStore`), the current rules, "save the record (no rules)" and "save the record
    with these first rules". `ms init` implements `Host` over IPC exactly as today
    (`ProjectList`, `ProjectGet`, `IpcStore`/`PutKey`, `RulesGet`, `ProjectSave`), so its
    behaviour and output don't change; msd implements it directly (its vault store through
    `put_key_as`, its `project_save` core).
- **D-11 Two steps: preview, then add.**
  - `POST /api/projects/preview { "path" }`: the L33 folder check first (canonical folder,
    refused roots, machine mode: same reasons), then `prepare`. Answer (no value, no masked
    value): `{ "plan", "slug", "display", "root", "existing": bool, "files": [{ "path",
    "secrets", "new_keys", "reused", "error"? }], "keys": [{ "key", "provider"?, "reaches":
    [hosts] | "runs_in": [folders] | "needs": "website|command" }], "findings": n,
    "stopped_early"?, "too_large": [..], "nothing_to_do": bool }`. The proposed first rules are
    computed as `initial_rules` would give them once the keys are stored with a fresh rule
    (`catalog_rule` against a fresh rule of the key's mode and tier); they are in the digest.
  - `POST /api/projects/add { "path", "plan" }`: refused while stopped (it gives new keys their
    first rules: a loosening) and while the project records are unreadable; `prepare` again and
    409 `changed` if the digest differs; then Touch ID: "set up project shop in ~/code/shop: move
    12 secrets from .env, .env.local into morsec; 9 keys may reach api.stripe.com, api.openai.com
    …; 1 database key may run in ~/code/shop" (inert, every file and host named; long lists are
    not cut, as the approval card). Then `execute` with that same `Prepared`, so what runs is what
    was digested.
  - Re-scan on the Project screen is the same two calls with the project's root.
- **D-12 One approval, bound to what was shown.** The dashboard's confirm token covers both the
  import and the first rules (the CLI asks twice: the review in the terminal, then the
  `ProjectSave` approval). In msd's `Host`, "save with these first rules" goes through
  `project_save`'s core with the token already given, and refuses the rules (keys stored, inert,
  listed as "not approved", exactly as a declined `ms init`) when the rules to save don't hash to
  the previewed rules, or when an existing key that already allows something would join the
  project (L34 S2 adoption: that case stays a terminal `ms init`, which asks for it by name).
  Every first rule gets an `approved` receipt with the token, as `ms init`'s do.
- **D-13 msd reads the folder.** The walk, the env-file reads, the rewrite and the hint block now
  run in msd under its own macOS identity. macOS may ask once whether msd may access a protected
  folder (`~/Documents`, `~/Desktop`, `~/Downloads`); if refused, the preview says "macOS did not
  let morsec read this folder. Allow it in System Settings → Privacy & Security → Files and
  Folders, or run ms init in a terminal" (the command with Copy stays on the screen as the
  fallback). The git-history check (`git log` for each env file) runs in `execute` only, after
  Touch ID, with the same hardening flags as the CLI.
- **D-14 Receipts.** `dashboard: add project <slug>` (key `morsec/daemon`) for the add, done or
  refused, with the token; the first rules' `approved` receipts; `PutKey`'s own receipts per new
  key (as `ms init`). Previews write none (they change nothing), like Re-check and Check folder.

### Rules edits L33 deferred

- **D-15 Git hosts, variables, SSH host keys.** `RuleEdit` gains `add_git_host`,
  `remove_git_host`, `add_env`, `remove_env`, `add_ssh_host_key`, `remove_ssh_host_key`, mapped
  to the existing `ms_rules::edit::Edit` variants, so validation and normalisation are those of
  `ms rules`. The variable-name check `ms rules --add-env` does (names morsec sets itself or that
  change how programs load code are refused) moves into one shared function (`ms_run::input`)
  called by both. Loosening (adding any of them) needs Touch ID and is refused while stopped;
  removing needs none (`classify_rule` decides, unchanged). The Secret screen shows each list with
  remove buttons and one labelled add field per list, with a hint line under it.
- **D-16 Mint scopes and quoted command words stay CLI only.** `ms rules` has no flag to edit mint
  scopes (they are set when a mint key is added), so the dashboard shows them read-only (the
  parity rule: the dashboard does what the CLI does). Commands whose words hold a space or a quote
  keep the `ms rules --add-command '<JSON>'` hint.

### Envelope, parity, page

- **D-17 New routes and the envelope.** The six routes join `ACTION_ROUTES`: the four
  connect/disconnect routes, `/api/projects/preview`, `/api/projects/add`. Every one passes the
  L32 envelope and L33's action checks (30/min bucket, request-time process re-check). The two
  applying routes (connect, disconnect, add) and the two project/agent previews are `sensitive`
  (`Sec-Fetch-Site: same-origin` must be present): the previews read agent settings and project
  folders. `/api/projects/check-path` stays as it is.
- **D-18 Parity.** `connect`, `disconnect` become Screen `/agents`; `init`, `import` become Screen
  `/projects` (`init`: project mode; the machine steps stay CLI only, because they install the
  daemon that serves the page; `import`: one file at a time with custom names stays CLI, the
  dashboard's Add project / re-scan covers the import a project needs). `parity_routes_exist`
  checks their routes exist.
- **D-19 The page.** Agents card: **Connect** (solid) or **Disconnect** (danger) → a panel with the
  preview (file by file, `+`/`-` lines in mono, notes) and **Apply with Touch ID** / Cancel; while
  the sheet is up the screen's buttons are disabled ("Confirm with Touch ID on this Mac…", as L33);
  `changed` re-fetches the preview. The terminal command stays under the panel as a fallback with
  Copy. Projects: **Add project** keeps the labelled path field; **Check** now shows the preview
  (files, counts, the websites the keys will reach, keys that will need a website) and **Set up
  with Touch ID**; the result shows the same rows as `ms init`'s summary. Project screen: **Re-scan**
  (same panel). Every string from a file, agent or path goes in with `textContent`. 375 px works.

## Acceptance criteria

1. **Connect preview** returns the same changes `ms connect <agent>` would make with the same
   inputs, the lines redacted exactly as the terminal shows them, and no value of the user's own;
   nothing is written.
2. **Connect** needs Touch ID, writes exactly the previewed plan, refuses (409, nothing written)
   when the plan changed before or during the sheet, and refuses carried `--wrap`.
3. **Disconnect** likewise, plus refused while stopped; the agent's files end byte-identical to
   what `ms disconnect` leaves.
4. **Paths and ms**: default config dirs only; a state naming another directory is refused; the
   `ms` written is msd's checked sibling and nothing else.
5. **Drift**: msd's own connect/disconnect writes raise no "settings changed" alert; a later edit
   by anyone else does.
6. **Setup library**: `ms init` in a project behaves and prints as before (L31's tests pass over
   `ms_projects::setup`).
7. **Add project preview** names the slug, files, counts and the hosts the new keys will reach,
   with no value or masked value; refused roots answer the L33 reasons; nothing is written.
8. **Add project** needs Touch ID, refuses while stopped or when the plan changed, imports exactly
   the previewed plan, gives the keys exactly the previewed first rules (or none, keys inert, when
   they differ), refuses adoption of keys that already allow something, and leaves the same files,
   record and rules as `ms init` would.
9. **Re-scan** of an existing project imports only new values and keeps the record's earlier
   entries.
10. **Rules edits**: git hosts, variables, SSH host keys added and removed from the Secret screen
    with `ms rules`' validation and messages; adding needs Touch ID, removing none.
11. **Envelope**: every new route refused without cookie, without CSRF, with a foreign Origin,
    cross-site, without `Sec-Fetch-Site`, and from an agent process tree.
12. **Receipts**: one per connect, disconnect and add, done or refused; none for previews; none
    carries a value.
13. **No value leaks**: canary values in the project's env files and in the agent settings never
    appear in any preview, answer, receipt, approval reason or msd log.
14. **Parity**: `connect`, `disconnect`, `init`, `import` are screens; the parity test passes.
15. **Docs**: threat-model rows T-104 to T-111 with tests (gate-checked); `ARI42.md` rows and
    change-log line; README/docs say the dashboard can connect and set up projects; the gate
    passes.
16. **Browser QA** as below, with screenshots.

## Tests per criterion

Every new test carries a `// protects=…; fails_when=…; no_claim=…` card.

| # | Tests |
|---|---|
| 1 | `crates/ms-connect/src/view.rs::preview_matches_terminal_lines`, `crates/ms-connect/src/view.rs::preview_redacts_user_values`, `crates/msd/src/daemon/dash_connect.rs::connect_preview_writes_nothing` |
| 2 | `crates/msd/src/daemon/dash_connect.rs::connect_needs_touch_id`, `crates/msd/src/daemon/dash_connect.rs::connect_refuses_changed_plan`, `crates/msd/src/daemon/dash_connect.rs::connect_refuses_carried_wrap`, `crates/ms-connect/src/view.rs::digest_covers_full_content` |
| 3 | `crates/msd/src/daemon/dash_connect.rs::disconnect_needs_touch_id_and_restores`, `crates/msd/src/daemon/dash_connect.rs::disconnect_refused_while_stopped` |
| 4 | `crates/msd/src/daemon/dash_connect.rs::custom_config_dir_refused`, `crates/msd/src/daemon/dash_connect.rs::ms_path_is_checked_sibling`, `crates/ms-connect/src/claude/mod.rs::state_records_config_dir` |
| 5 | `crates/msd/src/drift.rs::own_writes_are_not_drift` |
| 6 | `crates/ms-cli/tests/init_project.rs` (existing, unchanged), `crates/ms-projects/src/setup.rs::prepare_reads_only`, `crates/ms-projects/src/setup.rs::digest_changes_with_plan` |
| 7 | `crates/msd/src/daemon/dash_connect.rs::project_preview_has_no_values`, `crates/msd/src/daemon/dash_actions.rs::check_path_refuses_machine_roots` (existing) |
| 8 | `crates/msd/src/daemon/dash_connect.rs::add_project_needs_touch_id`, `crates/msd/src/daemon/dash_connect.rs::add_project_refuses_changed_plan`, `crates/msd/src/daemon/dash_connect.rs::add_project_refused_while_stopped`, `crates/msd/src/daemon/dash_connect.rs::add_project_rules_bound_to_preview`, `crates/msd/src/daemon/dash_connect.rs::add_project_refuses_adoption` |
| 9 | `crates/msd/src/daemon/dash_connect.rs::rescan_imports_only_new` |
| 10 | `crates/msd/src/daemon/dash_actions.rs::rules_edit_git_env_ssh`, `crates/ms-run/src/input.rs::env_carrier_names_shared` |
| 11 | `crates/ms-dash/tests/actions.rs::every_action_route_checks_envelope` (iterates the route table, so it covers the new routes), `crates/ms-dash/tests/actions.rs::connect_routes_are_sensitive` |
| 12 | `crates/msd/src/daemon/dash_connect.rs::connect_actions_write_receipts` |
| 13 | `crates/msd/src/daemon/dash_connect.rs::dash_connect_never_leaks_canary` |
| 14 | `crates/ms-cli/src/main.rs::dash_parity_covers_every_subcommand`, `crates/ms-dash/src/parity.rs::parity_routes_exist` |
| 15 | `scripts/threat_model_check.py` (gate), ARI-42 scan (gate), `npm run build` |
| 16 | Browser QA (PROOF.md) |

## Browser QA (required, with proof)

Against a **throwaway dev msd only**, as L33's QA (one fresh `0700` `$Q`, `HOME=$Q/home` for msd,
`--vault memory`, own socket and state dir, `--test-touch-id allow`/`deny`, CA variables unset,
guards on the real `~/Library/Application Support/morsec` and keychain before and after, detached
headless Chrome with `--use-mock-keychain --password-store=basic`). The dev msd's `HOME` holds a
fake `~/.claude/settings.json` (with a canary token in an env entry) and `~/.codex/config.toml`;
the real ones are never touched (their fingerprints are recorded before and compared after).

1. Agents: preview Connect for Claude Code (screenshot of the diff), apply, `settings.json` now
   has the sandbox and proxy; Disconnect preview and apply, file byte-identical to before. Codex
   the same. A `--test-touch-id deny` run shows the error and writes nothing. No settings-changed
   warning appears after msd's own writes.
2. Projects: Add project on `$Q/home/code/shop` (canary `.env`): preview, set up, the summary,
   the `.env` now holds refs, the Project screen lists the keys; re-scan after adding a line
   imports only it; Add project on `$Q/home` refuses.
3. Secret: add and remove a git host, a variable, an SSH host key.
4. Screens at 1280 and 375 px, light and dark, for the Agents panel and the Add project preview.
5. `ms log` against the dev msd shows the receipts; the canaries appear nowhere in the answers,
   receipts or msd's log.

Manual (recorded as not verified unless a person does it): the real Touch ID sheets' text; macOS's
folder-access prompt for msd on `~/Documents`.

## Threat model (`docs/threat-model.md`, new section "Dashboard connect and setup (L35)")

| ID | Threat | Control | Tests | Status |
|---|---|---|---|---|
| T-104 | An agent driving the browser disconnects itself (removes its own sandbox and proxy) | Touch ID raised by msd with the agent named; refused while stopped; process check per connection and per action; `Sec-Fetch-Site` required; receipt | `disconnect_needs_touch_id_and_restores`, `disconnect_refused_while_stopped`, `every_action_route_checks_envelope` | partial (T-69: the person may approve a sheet an agent caused) |
| T-105 | The person approves one change and msd writes another (settings edited between preview and apply, or during the sheet) | Digest over the full before/after of every file, checked before the sheet and again after it; 409 and nothing written on a mismatch | `connect_refuses_changed_plan`, `digest_covers_full_content` | mitigated |
| T-106 | Connect writes a hook that runs a planted program outside the sandbox (msd's idea of where `ms` is) | Only msd's own sibling `ms`, same canonical directory, stable-directory test; refused otherwise | `ms_path_is_checked_sibling` | mitigated |
| T-107 | A value of the user's (a token in an agent settings env entry) reaches the page through the preview | The terminal's redaction (`display_safe`, `redact`) on every line; the full content only in the digest | `preview_redacts_user_values`, `dash_connect_never_leaks_canary` | mitigated |
| T-108 | An agent makes msd import a folder and loosen new keys' rules without the person | Touch ID naming the folder, files and every host; refused while stopped; first rules bound to the previewed rules hash; adoption of loose keys refused | `add_project_needs_touch_id`, `add_project_rules_bound_to_preview`, `add_project_refuses_adoption`, `add_project_refused_while_stopped` | partial (as T-104) |
| T-109 | The folder changes between preview and import (a swapped env file, a new file) | Plan digest re-checked before the sheet; `execute` runs the digested `Prepared`; `envfile::commit` refuses a file changed since it was read; per-component `openat(O_NOFOLLOW)` walk | `add_project_refuses_changed_plan`, `prepare_reads_only`, `digest_changes_with_plan` | mitigated |
| T-110 | msd, outside every sandbox, runs `git` in an agent-writable repository (Add project's history check) | Runs only after Touch ID; `core.fsmonitor=false`, no pager, no signatures, no prompts, no transport or lazy fetch (`protocol.allow=never`, `GIT_NO_LAZY_FETCH`), no replace objects, no system config | `git_history_detects_commits`, `git_history_runs_no_configured_program` | mitigated (security review S1) |
| T-111 | msd's own settings write hides a later malicious edit (drift alert suppressed) | Only the exact fingerprint msd wrote is skipped, once | `own_writes_are_not_drift` | mitigated |

## ARI-42 (`ARI42.md`)

| ID | Change | Status after |
|---|---|---|
| SDLC-4 | Agent configuration edited from the dashboard only after a preview of the redacted diff and Touch ID bound to the full plan; `ms` path checked | Partial (strengthened) |
| AUTH-3 | Touch ID for connect, disconnect, add project / re-scan, and the new rules loosenings | Partial (strengthened) |
| MCP-3 | Six new routes behind the full envelope, all `sensitive` | Met (evidence added) |
| OUT-1 | Add project paths through the L33 folder check and `ms-projects`' walk; plan digests | Partial (strengthened) |
| LOG-1 | Receipts for connect, disconnect, add project | Partial (strengthened) |
| INJ-3 | Preview lines and paths rendered with `textContent`; reasons inert | Partial (unchanged) |
| GW-1 | No new path for a value to reach the page: previews carry names and redacted lines only | Partial (unchanged) |

## Deferred

- Connect for Cursor and Gemini (L22: their connectors don't exist yet).
- Connecting from the dashboard with a custom `CLAUDE_CONFIG_DIR` / `CODEX_HOME` (msd can't know
  the terminal's environment).
- The connect options (`--env`, `--mcp-env`, `--with-mcp`, `--statusline`, `--wrap`, `--force`) in
  the page.
- Machine-mode `ms init` (it installs the daemon that serves the page).
- Editing mint scopes (no CLI edit exists).

## Out of scope

- Changing the frozen interfaces (`Connector`, `ms-core` types, `Vault`, `Approver`, IPC v1):
  everything is additive; no IPC request is added.

## Residuals (for PROOF.md)

- T-69 / T-104 / T-108: an agent the user has given Automation over the browser can cause a sheet;
  each names the agent or folder and every host.
- macOS folder-access prompts for msd; a refusal makes the preview fail with the terminal fallback.
- msd runs `git log` in the project folder after Touch ID, with no transport, lazy fetch, replace objects or system config (T-110, security review S1).
- A terminal connect with `CLAUDE_CONFIG_DIR` before this loop left a state without `config_dir`:
  msd reads it as the default directory.

## Revert

Revert the merge commit. Nothing persistent changes shape except the optional `config_dir` field
in the connector state file, which older builds ignore (unknown fields are accepted: checked in
the build). Agents connected or projects set up from the dashboard stay as they are.
