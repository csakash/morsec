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
  variant holds a value. Only values of run-mode keys of **this** project, whose rule is ready and
  names a root containing the canonical cwd, are sent; the variable names come from the project
  record (`var → key`). A variable recorded with two different keys takes the root `.env`'s key,
  else it is skipped with a note. ms-ipc gets an additive `Handler::handle_with_values` (default:
  no values) and `Client::request_with_values`; the server sends values only after a `DevStarted`
  whose name list has the same length.
- **D-4 One Touch ID per run, for production (§7.2).** If any key of the project (by its rule in
  force) is production tier, `DevStart` calls `approve_exact` once. The request is bound to the
  argv `["ms","dev","--project",<slug>,"--root",<root>,"--keys",<production keys…>,"--",<argv…>]`
  and the canonical cwd, so the sheet shows the real command and keys. The token covers this dev
  session only: the proxy's approver answers a production swap of a key of this project from this
  session with that token (its id is on every receipt) and asks a person as usual for anything
  else. `ms stop` ends every dev session.
- **D-5 Dev sessions use only their project's keys.** Policy for a dev session denies any key not
  in the project record (`NoSuchKey`); hosts, tiers and receipts are otherwise the agents' rules.
  Receipts name the session `other("ms-dev")` with the `ms dev` PID.
- **D-6 Session end.** `ms` sends `DevEnd` when the child exits (refused unless the peer is the
  same `ms dev` process); msd also drops a dev session once its `ms dev` process is gone (checked
  every 2 s and on every lookup); `ms stop` drops all; sessions live in msd memory, so a restart
  ends them.
- **D-7 Egress for dev sessions (Refinement).** A dev session may reach hosts no key is bound to
  through a plain tunnel (no TLS interception, SSRF guard unchanged): the user's own process is
  not sandboxed and could connect directly, so refusing would only break the app. Agents are
  unchanged. ms-proxy gets an additive `SessionResolver::open_egress(session)` (default `false`).
  `NO_PROXY` gets `localhost,127.0.0.1,::1` added so local services are not sent to the proxy.
- **D-8 Refusals.** Refused inside an agent session (`ms` checks its own tree before contacting
  msd; msd checks the caller) and when `argv[0]` names a known agent binary: `ms` checks the
  given name and the name after resolving it on `PATH` and following symlinks; msd checks the
  basename it receives. Refused while stopped, and when cwd is in no recorded project root (the
  deepest matching root wins).
- **D-9 CA variables as connectors set them.** `ms` writes `~/.morsec/dev-ca-bundle.pem`
  (system roots + the CA certificate msd returns; public, atomic, 0644) and points
  `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` at it. No CA (no
  host bound): the variables are left alone.
- **D-10 Node.** `NODE_USE_ENV_PROXY=1` is always set. When `argv[0]` is `node`, `npm`, `npx`,
  `pnpm` or `yarn`, `ms dev` runs `node --version` (2 s budget) and warns when it is older than
  24 or unknown (best effort).

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
| 1 | `DevStart` is refused (no value, no session, no approval asked) from an agent session; `ms dev` refuses inside an agent session before contacting msd | `crates/msd/src/daemon/dev.rs::dev_refused_in_agent_session`, `crates/ms-cli/tests/dev_cli.rs::dev_refused_in_agent_session` |
| 2 | `ms dev` and msd refuse when `argv[0]` is an agent binary (`claude`, `codex`, `cursor-agent`, `gemini`; by name, path or symlink) | `crates/ms-cli/src/dev.rs::dev_refused_for_agent_binary`, `crates/msd/src/daemon/dev.rs::dev_refused_for_agent_binary` |
| 3 | A connection from the `ms dev` tree with the credential is a dev session; the credential from outside the tree, the tree without the credential, a dead `ms dev` or a reused PID are refused; an agent inside the tree stays an agent session | `crates/msd/src/proxy.rs::dev_swaps_refs_for_child_tree`, `crates/ms-session/src/walk.rs::within_checks_the_chain` |
| 4 | Dev sessions swap only their project's keys, to the keys' hosts, with receipts | `crates/msd/src/daemon/dev.rs::dev_swaps_refs_for_child_tree` |
| 5 | The session ends when the child exits (`DevEnd`, reaper), on `ms stop` and on msd restart | `crates/msd/src/daemon/dev.rs::dev_session_ends_with_child` |
| 6 | Values are returned only for run-mode keys of the cwd's project whose rule is ready and whose root holds the cwd; never for swap keys, other projects' keys or outside a project; never in a JSON frame | `crates/msd/src/daemon/dev.rs::dev_run_mode_values_only_for_project_keys`, `crates/ms-ipc/tests/ipc.rs::values_follow_dev_started_as_raw_frames` |
| 7 | A project with a production key asks one Touch ID per `ms dev` run, bound to the command; every production swap of that run uses it without another prompt; denial starts nothing | `crates/msd/src/daemon/dev.rs::dev_production_needs_one_approval` |
| 8 | End to end: a child of `ms dev` calls a fake Stripe upstream over HTTPS with an `ms://` ref through `HTTPS_PROXY`, and the upstream receives the canary; the child gets the run-mode value in its environment; the canary is in none of `ms dev`'s output, receipts, msd's log or IPC replies; after `ms dev` exits its credential is refused | `tests/e2e/tests/canary.rs::dev_swaps_for_the_users_own_command` |
| 9 | Node older than 24 is warned about; env names and output never carry a value | `crates/ms-cli/src/dev.rs::node_version_warning`, `crates/ms-cli/src/dev.rs::child_env_is_built_from_names` |
| 10 | Dev sessions may tunnel to unbound hosts; agents still can't | `crates/ms-proxy/src/itests.rs::open_egress_only_for_sessions_that_have_it` |

Every new test carries a `// protects=…; fails_when=…; no_claim=…` card. The e2e uses `curl`
with `HTTPS_PROXY` (no Node 24 in the gate; noted in PROOF).

## Residual risks (go into PROOF.md)

- Run-mode values in the child's environment can be read by any same-user process (as run mode
  before L23) and are inherited by every grandchild, an agent the dev server starts included.
- A detached same-user process is not an agent session: it can send `DevStart` and receive a
  project's test-tier run-mode values (production needs Touch ID). Same class as T-04 / T-40.
- Node older than 24 ignores `HTTPS_PROXY`; refs then go out unswapped and fail (fail closed).
- An agent started through a wrapper `ms dev` doesn't recognise (`npx claude`, a shell script)
  still gets the run-mode values in its environment; its own proxy traffic is an agent session.

## Out of scope

- `ms doctor` checking a project's Node version (design §7 residual note; separate change).
- The dashboard's copy button (L32/L33).
- Database-protocol swap for agents (design §10).
- Linux.
