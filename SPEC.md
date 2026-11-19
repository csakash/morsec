# SPEC: L34 ms-dev

Source: `docs/design/guided-setup-dashboard.md` §7, §5.3 (`DevStart` row), §8 (L34 row), §9;
card L34 in `docs/PLAN.md` Wave 7. Builds on L31 (`crates/ms-projects`, `ProjectSave` /
`ProjectList` / `ProjectGet`, PR #32). Where reading the code changed the design, the entry is
marked **Refinement**.

## Goal

After `ms init`, a project's `.env` holds `ms://` refs. Agents' commands work through msd's
proxy, but the user's own `npm run dev` sends the refs to Stripe and fails, because msd swaps only
for agent sessions. `ms dev -- <cmd…>` runs the user's own command so that it works:

```
cd ~/code/shop
ms dev -- npm run dev
```

## Current state (verified on `main` 7ebc849)

- msd's proxy session lookup (`crates/msd/src/proxy.rs` `Sessions::resolve`): loopback source
  port → PID (`ms_session::PortResolver`), walk to the outermost agent; an unattributed caller
  has no session and is refused (`403`). The proxy username is only a cross-check against the
  agent kind (`ms_session::cross_check`).
- Policy (`ms_rules::decide`): test-tier swap = allow, production = `NeedsApproval`, which the
  proxy hands to msd's approver (one Touch ID per request).
- Egress: hosts no key is bound to are refused (the allowlist is empty until L29).
- IPC v1 is frozen and additive; no response carries a value (`PutKey` sends its value as a raw
  frame the other way).
- Project records: `projects.toml` (MAC'd) lists each project's canonical root and, per env file,
  `var → key`. Run-mode keys (database URLs) get the project root as their only run root.

## Decisions

- **D-1 Where the credential is checked: msd, against the process tree (Refinement of §7.4).**
  `DevStart` mints a random 32-byte credential and binds the dev session to the **`ms dev`
  process itself** (the kernel peer of the `DevStart` connection: PID + start time, never a PID
  the client names). `ms` then spawns the command as its own child. A proxy connection is served
  as the dev session only when (a) its proxy username is that credential, and (b) the process
  holding the connection (port → PID) has the `ms dev` process, with the same start time, on its
  parent chain, and (c) no agent is on that chain. A credential copied to a process outside the
  tree is refused (`403`, like any unattributed caller); a process in the tree without the
  credential is refused too. Binding to `ms dev` rather than to the child's PID is the same tree
  (`ms dev` has exactly one child) and needs no second request naming a PID, so there is no
  spawn-then-bind race and nothing client-claimed. `ms dev` waits for its child and exits right
  after it, so the session ends with the child (D-6).
- **D-2 Agents inside the tree stay agents.** The existing outermost-agent walk runs first. If an
  agent (`claude`, `codex`, `cursor-agent`, `gemini`) is anywhere on the chain, the connection is
  that agent's session under agent rules, whatever username it sends; a dev credential never
  turns an agent connection into a dev session.
- **D-3 Run-mode values reach `ms` as raw value frames (Refinement of §5.3).** The reply
  `DevStarted` lists only variable **names**; each value follows as its own raw frame (the
  `PutKey` frame format, in the other direction), read straight into `SecretBytes`. No JSON
  variant holds a value. Only values of run-mode keys of **this** project whose rule names a root
  containing the canonical cwd are sent (L31 gives a database URL the project root and no
  commands, so "names a root" is the test, not "allows a command"); the variable names come from the project
  record (`var → key`). A variable recorded with two different keys takes the root `.env`'s key,
  else it is skipped with a note. ms-ipc gets an additive `Handler::handle_with_values` (default:
  no values) and `Client::request_with_values`; the server sends values only after a `DevStarted`
  whose name list has the same length.
- **D-4 One Touch ID for every run (§7.2; review D-A, stricter than the design).** Every
  `DevStart` calls `approve_exact` once, whatever the tiers. The request is bound to the argv
  `["ms","dev","--project",<slug>,"--command(<n> args)",<argv…>,"--root",<root>,"--swap",<swap
  keys…>,"--env",<VAR=key…>,"--production",<production keys…>,"--other-websites","allowed"]` and
  the canonical cwd. The command comes right after the project because the Touch ID reason is
  capped at 480 characters (round 2 F1); a command longer than about 160 sheet characters is cut
  there with "…(command cut: N more characters)" and the argv ends with
  `--full-command-sha256 <hex>`, so the approval still binds it exactly. Only a once-scope token
  is accepted (round 2 F2): `ms dev`'s inline review offers only "once", and an `s` answered in
  `ms approve` is refused, so the production window (D-4b) stays at the once token's 60 s. so the sheet shows the real command, the keys it may use, each variable that will
  get a value and that other websites are reachable. Values go out only for keys whose rule is
  still exactly the one the sheet was built from (review R1). Why every run: a prompt-injected,
  sandboxed agent can double-fork out of its tree; msd then sees an unattributed process, and
  without a person it could start a dev session for itself and get open egress (D-7), project
  swaps and run-mode values. A tty check would not stop it (`script -q /dev/null …`).
- **D-4b Production swaps ride on the run's approval only briefly (review D-B).** The proxy's
  approver answers a production swap of a key the sheet listed as production, from this dev
  session, with the run's token (its id on every receipt) only while the token is live (not
  revoked by `ms stop`) and for at most `min(token expiry, the key's session_ttl_secs)` after the
  approval. The token is a once token, so its expiry (60 s) is usually the limit; afterwards each
  production swap asks a person as for an agent. Within the window, code in the dev tree
  (including agent-edited code a dev server hot-reloads) can use those production keys, to their
  bound hosts only.
- **D-4c Sandboxed callers are refused (review D-A).** msd refuses `DevStart` from a process for
  which `sandbox_check(pid, NULL, 0)` (libsystem_sandbox, declared in `ms-session`'s only unsafe
  module) says it is sandboxed, or when the check fails: an agent command that left its tree is
  still in the agent's Seatbelt sandbox. An agent without a sandbox is not caught by this; the
  approval is the gate then.
- **D-5 Dev sessions use only their project's keys.** Policy for a dev session denies any key not
  in the project record (`NoSuchKey`); hosts, tiers and receipts are otherwise the agents' rules.
  Receipts name the session `other("ms-dev")` with the `ms dev` PID.
- **D-6 Session end.** `ms` sends `DevEnd` when the child exits (refused unless the peer is the
  same `ms dev` process); msd also drops a dev session once its `ms dev` process is gone (checked
  every 2 s and on every lookup); `ms stop` drops all; sessions live in msd memory, so a restart
  ends them.
- **D-7 Egress for dev sessions (Refinement).** A dev session may reach hosts no key is bound to
  through a plain tunnel (no TLS interception, SSRF guard unchanged): the user's own process is
  not sandboxed and could connect directly, so refusing would only break the app. This would
  bypass an agent's network sandbox if an agent could get a dev session, which is why every run
  needs the person (D-4, shown on the sheet as "other websites allowed") and sandboxed callers
  are refused (D-4c). Agents are unchanged. ms-proxy gets an additive `SessionResolver::open_egress(session)` (default `false`).
  `NO_PROXY` gets `localhost,127.0.0.1,::1` added so local services are not sent to the proxy.
- **D-8 Refusals.** Refused inside an agent session (`ms` checks its own tree before contacting
  msd; msd checks the caller, and refuses sandboxed callers: D-4c) and when `argv[0]` names a
  known agent binary: `ms` checks the given name, the name after resolving it on `PATH` and
  following symlinks, and both paths against agents' install paths (`…/claude/versions/<v>`, the
  `@anthropic-ai/claude-code`, `@openai/codex`, `@google/gemini-cli` packages, review N2); msd
  checks the basename and install path of the `argv[0]` it receives. Refused while stopped, and when cwd is in no recorded project root (the
  deepest matching root wins).
- **D-9 CA variables as connectors set them.** `ms` writes `~/.morsec/dev-ca-bundle.pem`
  (system roots + the CA certificate msd returns; public, atomic, 0644) and points
  `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` at it. No CA (no
  host bound): the variables are left alone.
- **D-10 Node.** `NODE_USE_ENV_PROXY=1` is always set. When `argv[0]` is `node`, `npm`, `npx`,
  `pnpm` or `yarn`, `ms dev` runs `node --version` (2 s budget) and warns when it is older than
  24 or unknown (best effort).

- **D-11 Inline review (build).** Like `ms init` and `ms start`, `ms dev` reviews its own
  approval on the terminal it runs in (`approve::inline_review`); `ms approve` works too.
- **D-12 Project keys must be bound by the proxy (found while building).** msd's proxy found a
  key's credential location only through catalog key names (`stripe/test`) or a first segment
  that is a provider id, so L31's project keys (`shop/stripe-secret-key`) were never swapped. The
  proxy now takes the provider from the MAC'd project record (`bindings_with`), and a project save
  rebuilds the proxy. A recorded provider counts only when its catalog hosts cover every host of
  the key's rule (review N1); a key any project record lists never falls back to the
  first-segment guess (round 2), so a project slugged `stripe` lends Stripe's location to none of
  its keys; keys in no record keep the old lookup. Test
  `crates/msd/src/proxy.rs::project_keys_bind_with_their_recorded_provider`.
- **D-13 What ms dev hands out depends on the record and the rule's shape (review S2).** Run
  values go out only for rules shaped exactly as `ms init` makes a database URL's: the project
  root as the only root, no commands, not read-only, no `env` names or the variable among them;
  any other run rule is skipped with a note. `ProjectSave` asks the person when the record adds a
  key that the stored record didn't list and whose rule already allows something (a key made by
  hand being adopted); the sheet names it ("joins the project") and each adopted key gets an
  approved receipt. `ProjectSave` from a sandboxed process is refused like `DevStart` (round 2
  F3). Adoption is decided by the key's current rule, not by record membership: deciding by
  membership would make every new key of an unknown service ask (L31's no-prompt cases), so the
  two-step case stays a residual (a key joins while it allows nothing, then is loosened with
  `ms rules`, which needs its own approval; every `ms dev` sheet then lists it again). Fresh keys (allowing nothing)
  join without a prompt; re-saving the same keys asks nothing, so `reinit_is_idempotent` is
  unchanged, and `orphaned_keys_are_adopted_on_reinit` is unchanged too (orphans are fresh and get
  their first rules in the same approval).
- **D-14 Robustness (review R2-R4, R6, R7, R9).** The stop check and the session insert share the
  session lock; capacity is checked before anything is asked, read or recorded; an empty or
  oversized value is skipped with a note; `ms dev` lists only variables it really set; signals are
  forwarded only to a child that is not reaped (polled with `try_wait`); value receipts carry the
  rules version in force after the approval. A session's end (`DevEnd`, reaper) leaves a receipt.
  Round 2: a stop check also runs right after the approval, before any value is read (F4); the
  reaper decides liveness once per session, so each removed session gets its end receipt (F5).

## Behaviour

`ms dev [--] <cmd> [args…]`

1. Refusals in D-8 (exit 77; usage 64; daemon down 69).
2. `DevStart { argv, cwd }` (waits up to 150 s for an approval).
3. Spawn `<cmd>` as a child in the same process group (keeps the terminal and Ctrl-C), with the
   user's environment plus: `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy` =
   `http://<credential>@127.0.0.1:<port>`; `NO_PROXY`/`no_proxy` with loopback added;
   `NODE_USE_ENV_PROXY=1`; the CA variables (D-9); each run-mode variable from D-3, unless the
   user's environment already sets it to something that is not an `ms://` ref (kept, noted).
4. `SIGTERM` and `SIGHUP` to `ms dev` are forwarded to the child; `SIGINT`/`SIGQUIT` are left to
   the terminal (they already reach the child's process group).
5. One status block on stderr: project, keys swapped, variable names given values (never
   values), Node warning. Exit status is the child's (128 + signal when killed).
6. `DevEnd` (best effort), then exit.

### IPC (protocol version stays 1, additive)

| Request | Refused in agent session | Approval | Reply |
|---|---|---|---|
| `DevStart { argv, cwd }` | yes | Touch ID once if any project key is production | `DevStarted { session, credential, proxy_port, project, root, ca_pem?, env: [names], notes }` + one raw frame per name |
| `DevEnd { session }` | yes | none | `Ok` (only from the `ms dev` process that started it) |

## Acceptance criteria and tests

| # | Criterion | Test(s) |
|---|---|---|
| 1 | `DevStart` is refused (no value, no session, no approval asked) from an agent session and from a sandboxed process; `ms dev` refuses inside an agent session before contacting msd | `crates/msd/src/daemon/dev_tests.rs::dev_refused_in_agent_session`, `crates/ms-cli/tests/dev_cli.rs::dev_refused_in_agent_session`, `crates/ms-session/tests/live.rs::sandboxed_process_is_detected` |
| 2 | `ms dev` and msd refuse when `argv[0]` is an agent binary (`claude`, `codex`, `cursor-agent`, `gemini`; by name, path, symlink or install path) | `crates/ms-cli/src/dev.rs::dev_refused_for_agent_binary`, `crates/msd/src/daemon/dev_tests.rs::dev_refused_for_agent_binary`, `crates/ms-session/src/walk.rs::install_paths` |
| 3 | A connection from the `ms dev` tree with the credential is a dev session; the credential from outside the tree, the tree without the credential, a dead `ms dev` or a reused PID are refused; an agent inside the tree stays an agent session | `crates/msd/src/proxy.rs::dev_swaps_refs_for_child_tree`, `crates/ms-session/src/walk.rs::within_checks_the_chain` |
| 4 | Dev sessions swap only their project's keys, to the keys' hosts, with receipts | `crates/msd/src/daemon/dev_tests.rs::dev_swaps_refs_for_child_tree` |
| 5 | The session ends when the child exits (`DevEnd`, reaper), on `ms stop` (also while the approval is pending) and on msd restart; each end leaves a receipt | `crates/msd/src/daemon/dev_tests.rs::dev_session_ends_with_child` |
| 6 | Values are returned only for run-mode keys of the cwd's project whose rule is shaped as `ms init` makes it; never for swap keys, other projects' keys, hand-changed run rules, empty values or outside a project; never in a JSON frame | `crates/msd/src/daemon/dev_tests.rs::dev_run_mode_values_only_for_project_keys`, `crates/ms-ipc/tests/ipc.rs::values_follow_dev_started_as_raw_frames` |
| 7 | Every `ms dev` run asks one Touch ID, bound to the command, keys, variables and open egress; production swaps of that run use it without another prompt only while it is live and within the key's session length; a key outside the project is denied; denial starts nothing | `crates/msd/src/daemon/dev_tests.rs::dev_production_needs_one_approval`, `crates/ms-approve/src/broker.rs::is_live_after_use_until_revoked` |
| 7b | A key whose rule changes while the sheet is up gets no value | `crates/msd/src/daemon/dev_tests.rs::dev_values_follow_the_rules_the_person_saw` |
| 7d | The sheet shows the command first, a huge command cut with a marker and bound by its hash; a session-scope (`s`) approval starts nothing | `crates/msd/src/daemon/dev_tests.rs::dev_sheet_shows_the_command_first`, `crates/msd/src/daemon/dev_tests.rs::dev_refuses_a_session_scope_approval`, `crates/ms-cli/src/approve.rs::once_only_review_never_approves_a_session` |
| 7c | `ProjectSave` asks the person to adopt a key that already allows something; refused from a sandboxed process | `crates/msd/src/daemon/dev_tests.rs::project_save_asks_to_adopt_a_key_that_allows_something` |
| 8 | End to end: a child of `ms dev` calls a fake Stripe upstream over HTTPS with an `ms://` ref through `HTTPS_PROXY`, and the upstream receives the canary; the child gets the run-mode value in its environment; the canary is in none of `ms dev`'s output, receipts, msd's log or IPC replies; the session's end is recorded when the command exits and its credential is refused afterwards | `tests/e2e/tests/canary.rs::dev_swaps_for_the_users_own_command` |
| 9 | Node older than 24 is warned about; env names and output never carry a value | `crates/ms-cli/src/dev.rs::node_version_warning`, `crates/ms-cli/src/dev.rs::child_env_is_built_from_names` |
| 10 | Dev sessions may tunnel to unbound hosts; agents still can't | `crates/ms-proxy/src/itests.rs::open_egress_only_for_sessions_that_have_it` |
| 11 | A project key is bound with its recorded provider only when that provider's hosts cover the rule | `crates/msd/src/proxy.rs::project_keys_bind_with_their_recorded_provider` |

Every new test carries a `// protects=…; fails_when=…; no_claim=…` card. The e2e uses `curl`
with `HTTPS_PROXY` (no Node 24 in the gate; noted in PROOF).

## Residual risks (go into PROOF.md)

- Run-mode values in the child's environment can be read by any same-user process (as run mode
  before L23) and are inherited by every grandchild, an agent the dev server starts included.
- A detached, unsandboxed same-user process is not an agent session: it can ask for `DevStart`,
  but every run needs the person's approval, whose sheet names the command, keys and variables
  (the gate is then the person reading it, as T-04).
- Within the run's approval window (D-4b), code in the dev tree, including agent-edited code a
  dev server hot-reloads, can use the project's production keys, to their bound hosts only.
- Node older than 24 ignores `HTTPS_PROXY`; refs then go out unswapped and fail (fail closed).
- Agents started through a wrapper are not recognised, by `ms dev` or by the proxy's session
  walk (which goes by process name): `npx claude`, a `#!/usr/bin/env node` script, or Claude
  Code's native binary started by its versioned path (`~/.local/share/claude/versions/<v>`, whose
  process name is the version). `ms dev` catches the install paths it knows (D-8); anything else
  in the dev tree gets the run-mode values in its environment and, if not named like an agent,
  is served as the dev session.
- At most 64 dev sessions at once (global); filling them needs an approval per session (review N3).
- Two-step adoption: a key can join a project's record while it allows nothing (no prompt) and be
  loosened later with `ms rules` (its own approval); each `ms dev` sheet then lists it.

## Out of scope

- `ms doctor` checking a project's Node version (design §7 residual note; separate change).
- The dashboard's copy button (L32/L33).
- Database-protocol swap for agents (design §10).
- Linux.
