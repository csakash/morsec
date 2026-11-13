# SPEC: L07 `daemon`

Loop card: `docs/PLAN.md` §5, "L07 `daemon`". Branch `feat/daemon`, dev port 4100.
Integrates wave 1 (L01 vault, L02 receipts, L03 rules, L05 proxy, L06 session), all on main at
`78e5e9a`.

## Goal

Turn the `msd` dev stub into the real broker daemon: one process that owns the vault, the rules,
the receipts, the swap proxy and the socket, identifies every caller, fails closed, and has a kill
switch that a misbehaving same-user process can't starve or undo. Give the CLI the replies it is
missing (`ms add`, `ms import`, `ms rules`, `ms status`, `ms stop`, `ms start`, `ms init`).

## Decisions taken for this loop

- **D-A (user, 2026-11-13): approvals before L11 are a deny stub plus a recovery path.** msd's
  `Approver` is `DenyApprover`: every approval it is asked for is denied with "approvals with
  Touch ID arrive in L11". Production-tier key use is therefore refused until L11. For the two
  administrative actions that would otherwise be impossible before L11, **resuming after
  `ms stop`** and **loosening a rule**, there is a pre-L11 recovery path: the user runs the
  command at their own terminal with `--at-terminal` (`ms init --resume`, `ms rules … --at-terminal`),
  `ms` asks for a typed confirmation on `/dev/tty`, and msd accepts it only from a caller that
  is not inside any agent's process tree (`Caller::Unattributed`). This is weaker than Touch ID
  (an agent that fully detaches from its tree and drives a pty could pass it) and is recorded
  as Partial in `ARI42.md`. It is never used for production-key use. L11 replaces it.
  (The `/dev/tty` confirmation happens in `ms`; msd itself checks only that the caller is
  outside every agent tree, so any detached same-user process passes the msd side. That is the
  residual.)
- **D-B: the rules MAC key is `morsec/rules-hmac`** (what L01's `ensure_internal_keys` creates),
  passed explicitly to `RulesStore::new`. L03's default `morsec/rules-mac` is not used by msd.
- **D-C: daemon state that must survive a restart and resist rollback lives in the vault**, not in
  a file: the kill-switch flag (`morsec/daemon-state`) and the CA private key (`morsec/ca`).
  An agent can delete or replace a file in the state directory, but cannot write or delete
  msd's keychain items (L01). A small `KeychainVault::put_internal` is added for these two
  names only.
- **D-D: the CA is created lazily.** `Ca::generate` needs at least one host. msd (re)issues the
  CA when the set of bound swap hosts is not covered by the stored CA, stores its key in the
  vault, and writes `ca.pem` and `ca-bundle.pem` to the state directory. With no bound hosts the
  proxy runs with an in-memory CA limited to `morsec.invalid` (never written, never trusted), so
  it still listens and refuses.
- **D-E: IPC stays v1 and changes only additively.** New request fields are optional
  (`#[serde(default)]`); new reply variants are added. `docs/PLAN.md` §4 is updated.

## In scope

### 1. IPC hardening (`crates/ms-ipc`) — open items S3 and S6 from L00

1. **S3, socket bind TOCTOU.** `Server::bind` opens the socket directory with
   `O_DIRECTORY|O_NOFOLLOW`, checks owner uid and mode with `fstat` on that descriptor, binds
   under a `0077` umask, then `lstat`s the socket path and checks it is a socket owned by us with
   mode 0600, and re-checks the directory descriptor. A symlinked directory, a directory owned by
   another uid, or a group/other-accessible directory is refused. Existing behaviour (stale socket
   removal, "another msd is running", non-socket refusal) is kept.
2. **S6, kill-switch starvation.** The server no longer blocks `accept` on a 64-slot semaphore.
   - General pool of 64 connections, **plus 8 reserved control slots** used only when the general
     pool is full. A connection in a reserved slot may send only `Status` or `Stop`; anything else
     gets `busy` and is closed.
   - **Per-peer cap**: at most 8 open connections per peer PID (after the peer check).
   - **Per-connection caps**: a total lifetime of 10 minutes and at most 1024 requests, on top of
     the existing 30 s idle timeout.
   - Limits are a `ServerLimits` struct with these defaults, so tests can change them.
   - Test: with 64 connections held open (and the per-peer cap raised for the test), `Stop` and
     `Status` still answer within 1 s.

### 2. IPC v1 additions (`crates/ms-ipc`), backwards-compatible

- `ResponseBody::Ok { message }` — success with a human-readable line (`PutKey`, `Stop`, `Start`,
  saved rules).
- `ResponseBody::Keys { keys: Vec<KeyMeta> }` — `ListKeys`. Reserved `morsec/` keys are never
  listed.
- `ResponseBody::Rules { version, toml, notes }` — `RulesGet`; the effective rules as TOML text
  (ms-ipc does not depend on ms-rules).
- `ResponseBody::Status` gains optional `running: Option<bool>`, `keys: Option<u32>`,
  `proxy_port: Option<u16>`, `alerts: Vec<String>` (all `#[serde(default)]`).
- `RequestBody::RulesProposeLoosen` gains `rule: Option<String>` (the proposed rule for that key
  as TOML, absent = remove the key) and `at_terminal: bool`.
- `RequestBody::RulesGet` gains `cwd: Option<PathBuf>` (merge that project's `.morsec.toml`).
- `RequestBody::Start` becomes `Start { at_terminal: bool }` with a default, so `{"type":"start"}`
  still parses.
- New `ErrorCode`s: `Busy`, `Denied`, `NeedsApproval`, `NotInitialized`, `Invalid`.

### 3. The daemon (`crates/msd`)

- **Services assembled at start**: vault, receipts store, rules, session identity, proxy, socket
  server with `SessionPeerCheck` (L06) as the peer check.
- **Vault backend**: `--vault keychain` (macOS default) or `--vault memory` (dev and tests;
  ephemeral; HMAC keys generated at start; status mode `dev-memory`). `--vault memory` is refused
  for the platform state directory.
- **State directory**: `~/Library/Application Support/morsec/` (rules, receipts, CA files);
  `--state-dir` overrides; `--port` alone selects the per-port dev directory
  `$TMPDIR/morsec-dev-<port>/` as it already does for the socket.
- **Rules wiring (open from L03)**:
  - Start: `RulesStore::load(min_version)`, `min_version` = the highest `rule_version` in the
    receipt chain. Any error → `Rules::tampered()` (everything denied, `ms status` says why).
    A missing rules file before any version was seen is `NotInitialized` (keychain mode refuses
    to start: "run ms init"; memory mode creates an empty v1 file).
  - `stopped` is set from the vault state at start and by `Stop`/`Start`.
  - `RulesGet` returns `ms_rules::effective(&rules, project_text, file)` for the given `cwd`'s
    `.morsec.toml` (read with a size cap; unreadable or invalid → every key disabled, as L03
    does).
  - `RulesProposeLoosen{key, rule}`: build the new rules, `ms_rules::classify`; tightening is
    saved with `RulesStore::save(new, false, min_version)`; loosening needs an approval
    (`DenyApprover`, so: refused) or the pre-L11 terminal path (D-A). Reserved keys refused.
    After a save the live rules are reloaded and the proxy is rebuilt.
  - Run requests stay `not_implemented` (L12) and say so; `decide_run` is used by L12.
- **Keys**: `PutKey` refuses reserved `morsec/` names, stores the value through the vault, and
  if the key has no rule yet adds one that allows nothing (`KeyRule::new(mode, tier)`, no hosts
  or commands), which is a tightening-or-equal change. Replies `Ok`. `ListKeys` replies `Keys`.
- **Swap proxy (L05)**: bound on `127.0.0.1:<proxy port>` (`--proxy-port`, default 7277; dev:
  `--port` + 1). Bindings come from swap rules with hosts, plus the L04 catalog's credential
  location for the key's provider (`<provider>/<tier>` naming); a key with no catalog match is
  not bound (logged). `Policy` = `ms_rules::decide` over the live rules; `SessionResolver` =
  L06 `PortResolver` + `cross_check`, returning `None` while stopped or for a session stopped
  by a LOG-2 alert; refusals with no key are logged through `EgressObserver`. Runs in
  `spawn_blocking` with a concurrency cap of 8 scans. msd refuses to start when
  `SSL_CERT_FILE`/`SSL_CERT_DIR` are set (L05 must-do).
- **Kill switch**:
  - `Stop` (no approval): sets `stopped` in the live rules, persists `stopped` to the vault,
    rebuilds the proxy so new connections are refused, records a receipt. Idempotent.
  - `Start`: needs an approval → `DenyApprover` refuses with the D-A recovery hint; with
    `at_terminal` from an unattributed caller it resumes, persists, records a receipt with
    approval method `terminal-pre-l11`.
  - Restarting msd (an agent kills it) keeps it stopped: the flag is read from the vault.
    An unreadable flag fails closed (stopped).
- **Receipts (L02)**: one `ReceiptStore` in `<state>/receipts`; daemon events (stop, start,
  rules change) are receipts on the reserved key `morsec/daemon`. LOG-2 `AlertHandler` stops the
  alerting session (no more swaps or socket requests from it until msd restarts).
- **Connector drift watch**: a poller (every 10 s) hashes the connector settings files that exist
  (`~/.claude/settings.json`, `~/.codex/config.toml`); a change after start raises a `warn` log
  and an entry in `Status.alerts`. L08/L13 refine what is watched.
- **Hardened runtime**: `crates/msd/msd.entitlements` (no `get-task-allow`, no JIT, no
  library-validation exemption) for L10's signing step.
- **LaunchAgent**: `crates/msd/launchd/cc.morsec.msd.plist` template (`RunAtLoad`, `KeepAlive`,
  no environment variables, absolute path to `msd`), installed by `ms init`.

### 4. CLI (`crates/ms-cli`)

- `ms status`: "morsec on · N secrets protected" / "morsec stopped · N secrets protected (resume
  with: ms start)" / "morsec off: daemon not running …"; rules-tampered and drift alerts shown.
- `ms stop`: sends `Stop`, prints the result. Exit 0 on success.
- `ms start`: sends `Start`; until L11 prints the D-A recovery hint and exits 1.
- `ms init`: runs `msd --init` (the same signed binary that will own the keychain items) to create
  the internal keys, the empty rules file and the receipts store; refuses when already initialized
  unless `--force` (which warns that old receipts stop verifying); then installs the LaunchAgent
  (`--no-launchd` skips; `launchctl bootstrap gui/<uid>`) and waits for the socket. `--trust` adds
  the current `ca.pem` to the login keychain trust settings (`security add-trusted-cert`, macOS asks).
  `ms init --resume` is the D-A terminal resume.
- `ms add` / `ms import`: accept the new `Ok` and `Keys` replies (they store end to end).
- `ms rules`: reads through `RulesGet` (MAC-verified by msd); edits send `RulesProposeLoosen` with
  the proposed rule; `--at-terminal` for the D-A path. The local unverified read is kept only as a
  fallback when the daemon is down, labelled as such.

## Amendments made during the build

- `RulesGet` has no `cwd`: msd returns the verified user rules and `ms` merges the project
  `.morsec.toml` itself, so msd never reads a path a client names (no file-read oracle for a
  sandboxed agent).
- The proposed rule travels as a one-key rules file, not a table body.
- S3: a descriptor check plus a post-bind inode check replace the process-wide `umask` (the
  workspace forbids `unsafe`; the verified-private directory keeps the socket unreachable until
  the `chmod`).
- Only `ca.pem` and `ca-hosts.json` are written; the trust bundle with system roots is L08's.
  `Status` carries the CA certificate msd verified, and `ms init --trust` trusts that, not the file.
- The rules rollback floor is also kept in the vault state item (`running v=<n>`), so deleting the
  receipts can't lower it (security review S3).
- `msd --init` refuses inside an agent tree, asks on `/dev/tty`, only uses the real state
  directory, and never clears `ms stop` (security review S2).
- AC4's restart persistence is proven at the daemon level over a shared vault; the dev memory vault
  is ephemeral, so the binary-level test can't restart msd.
- `Start` clears LOG-2 session stops as well (a person resuming morsec resets them).

## Out of scope (named follow-ups)

- Real Touch ID approvals and approval tokens (L11). Run requests and `decide_run` wiring (L12).
- `LogQuery` / `ms log --verify` over IPC (stays local, L02's current behaviour).
- Anchoring the receipts `(seq, head)` in the vault against tail truncation (L02 note) — L24.
- Using L01's non-extractable `CaKey` for the CA instead of a sealed software key (needs an
  rcgen remote-key path in ms-proxy) — L24.
- Linux service unit (L21). Signing and notarizing with the entitlements (L10).

## Acceptance criteria

1. `npm run build` (`scripts/check.sh`) exits 0.
2. S3: bind refuses a symlinked socket directory, a group-writable directory and another user's
   directory; the socket ends up 0600 (tests).
3. S6: 64 held connections do not delay `Stop`/`Status` (answer < 1 s); per-peer cap enforced;
   reserved slots refuse non-control requests with `busy` (tests).
4. AUTH-4: "flip the flag mid-run, the next request refuses": after `Stop`, the next proxy request
   through msd is refused and `PutKey`/`RulesGet` still work; after restarting msd it is still
   stopped (integration test with the real binary).
5. Fail closed: with msd down, the proxy port refuses connections and `ms status`/`ms add` fail
   with the `ms start` hint; tampered rules → everything denied and `ms status` says so (tests).
6. MCP-3 socket auth: a peer with another uid is rejected (peer-check unit test, as live
   two-uid tests need root), and an agent-attributed caller can't use the D-A terminal path.
7. `ms add` stores end to end against a running msd (memory vault) and `ms rules` shows the new
   key; `ms import` stores end to end (integration tests).
8. Rules over IPC: a tightening change is saved and reloaded; a loosening change is refused
   without approval and accepted through the terminal path from an unattributed caller; reserved
   keys refused (tests).
9. Swap through the daemon: with a test-tier swap key bound to a host, a request carrying the
   placeholder to an unbound host is refused (403) and recorded; with `Stop` it is refused.
10. Reviews converged, `/qa` run, `PROOF.md` and `docs/evidence/daemon.md` written, `ARI42.md`
    AUTH-4 and MCP-3 rows updated.

## ARI-42

AUTH-4 (kill switch), MCP-3 (socket auth). Touched: AUTH-1 (session from peer, wired), AUTH-3
(approvals: D-A stub, Partial), LOG-2 (alert stops a session).
