---
loop: foundation
plan_card: L00 (docs/PLAN.md §5)
branch: feat/foundation
status: confirmed 2026-11-13
---

# SPEC: L00 `foundation`: Rust workspace, frozen interfaces, `ms`/`mors` skeleton, local check gate

## Context

morsec has a plan (docs/PLAN.md, 29 loops in 6 waves) and no code. Every one of the 28 later loops
builds against the crates, types and traits this loop creates, and wave 1 runs 6 loops in
parallel. If the interfaces are wrong or missing, those loops collide on the same files or
diverge. This loop is the only one in wave 0 and blocks everything else.

Decisions already made: Rust core (PLAN D4); solo maintainer who merges their own PRs; **no
GitHub Actions for v1** (user, 2026-11-13). All checks run locally, behind gloop's build gate.

## Current State (verified 2026-11-13, worktree `worktrees/foundation/morsec`, base `b6a1cb6`)

| Item | State |
|---|---|
| Rust code | None. No `Cargo.toml`, no `crates/`. |
| Toolchain on the dev machine | rustc/cargo 1.93.1, clippy, rustfmt, miri present; `cargo-deny`, `cargo-audit` **not installed** |
| `loops.json` `repos[0].dev` | `["npm","run","dev"]`, a placeholder that cannot run |
| gloop build gate | `~/.claude/skills/gstack-loops/lib/pipeline.js:312-328` runs `npm run build` and **skips (passes) when there is no `package.json`**. On this Rust repo the hard gate is currently a no-op. |
| `REVIEW.md` | ARI-42 failure modes for morsec; nothing Rust-specific |
| CI | None, and none is wanted for v1 |

## Proposed Change

### 1. Workspace

- Root `Cargo.toml`: `[workspace]`, `resolver = "3"`, members = the 15 crates below,
  `[workspace.package]` (edition 2024, `rust-version = "1.93"`, `license = "LicenseRef-Proprietary"`,
  `publish = false`), `[workspace.lints]`, `[workspace.dependencies]`.
- `rust-toolchain.toml`: `channel = "1.93.1"`, components `rustfmt`, `clippy`.
- `Cargo.lock` committed. All builds and tests use `--locked`.
- `[workspace.lints.rust]`: `unsafe_code = "deny"`, `missing_debug_implementations = "warn"`.
  `[workspace.lints.clippy]`: `all = "warn"` (promoted to errors by `-D warnings` in the check
  script), `dbg_macro = "deny"`, `print_stdout = "deny"` except in `ms-cli` and `msd` (crate-level
  `#![allow]` with a comment). A later loop that needs `unsafe` opts out explicitly in its crate,
  with a justification comment. `crates/**` is a sensitive path, so that change gets reviewed.
- `[workspace.dependencies]`, declared now so later loops add to their crate's `Cargo.toml`
  without editing the root:
  `tokio = "1"` (features: rt-multi-thread, macros, net, io-util, sync, time, signal, fs),
  `serde = "1"` (derive), `serde_json = "1"`, `thiserror = "2"`, `clap = "4"` (derive),
  `zeroize = "1"` (derive), `toml = "0.8"`, `tracing = "0.1"`, `tracing-subscriber = "0.3"`,
  `sha2 = "0.10"`, `hmac = "0.12"`, `hex = "0.4"`, `base64 = "0.22"`, `tempfile = "3"`,
  `proptest = "1"`, `assert_cmd = "2"`, `predicates = "3"`, `libc = "0.2"`.
  Heavy crates (hyper, rustls, rcgen, security-framework, rmcp, aws-sdk-*) are **not** declared
  here; the owning loop adds them, to keep this lockfile small and audited.

### 2. Crates (all compile; stubs contain only a crate doc comment unless listed)

| Crate | Kind | This loop delivers |
|---|---|---|
| `crates/ms-core` | lib | `KeyName`, `SecretRef`, `SecretBytes`, `Mode`, `Tier`, `AgentKind`, `SessionId`, `KeyMeta`, `Request`, `Decision`, `ApprovalRequest`, `ReceiptEvent`, `Error` (§3) |
| `crates/ms-ipc` | lib | framing, `Request`/`Response` protocol v1, `Client`, `Server` skeleton with a peer-check hook, default peer check = same UID (§5) |
| `crates/ms-vault` | lib | `Vault` trait + `VaultExt`; `memory::MemoryVault` |
| `crates/ms-approve` | lib | `Approver` trait; `fake::FakeApprover` (scripted outcomes) |
| `crates/ms-mint` | lib | `Minter` trait; `fake::FakeMinter` |
| `crates/ms-connect` | lib | `Connector` trait; `fake::FakeConnector` |
| `crates/ms-receipts` | lib | `ReceiptSink` trait; `memory::MemorySink` |
| `crates/ms-run` | lib | `RunAdapter`, `RunCall`, `ExecPlan`, `EffectPreview` types and trait |
| `crates/ms-rules` | lib | `Rules` placeholder struct + `decide()` signature returning `Decision::Deny(Reason::NotImplemented)` (deny-by-default stub) |
| `crates/ms-session`, `ms-import`, `ms-proxy`, `ms-mcp` | lib | stub only |
| `crates/msd` | bin `msd` | dev daemon: `--foreground`, `--port <n>` (accepted, unused until L05), `--socket <path>`; serves IPC `Status` only |
| `crates/ms-cli` | bin `ms` | every PRD command stubbed (§6) |

### 3. `ms-core` types (frozen)

- **`KeyName`**: segments joined by `/`. Each segment matches `[a-z0-9][a-z0-9-]{0,62}`; 1–8
  segments; total ≤ 255 bytes. Rejects empty, uppercase, `.`/`..`, leading or trailing `/`,
  `//`, whitespace and non-ASCII. `TryFrom<&str>`, `Display`, `Serialize`/`Deserialize` (via a
  validated string).
- **`SecretRef`**: `ms://<KeyName>`. `SecretRef::parse(&str)` accepts exactly that form; it
  rejects other schemes, query, fragment, userinfo and port. `SecretRef::find_all(&str) ->
  Vec<(Range<usize>, SecretRef)>` finds refs embedded in strings like
  `postgres://u@h/db?x=ms://pg/staging` (used later by the shim and proxy).
- **`SecretBytes`**: owns `Zeroizing<Vec<u8>>`. **No** `Clone`, `Serialize`, `Deserialize`,
  `Display` or `PartialEq`. `Debug` prints `SecretBytes([redacted; N bytes])`. The only access is
  `expose(&self) -> &[u8]`, documented as broker-internal.
- **`Mode { Swap, Run, Mint }`**, **`Tier { Test, Production }`**,
  **`AgentKind { ClaudeCode, Codex, Cursor, GeminiCli, Other(String) }`**,
  **`SessionId { agent, pid: u32, started_unix_ms: u64 }`**.
- **`KeyMeta { name, mode, tier, created_unix_ms }`**: metadata only.
- **`Request`**: `Swap { key, host }`, `Run { key, argv_hash: [u8;32], cwd: PathBuf }`,
  `Mint { key, scope: String }`.
- **`Decision`**: `Allow`, `Deny(Reason)`, `NeedsApproval(ApprovalRequest)`.
  `Reason`: `NotImplemented`, `HostNotAllowed`, `CommandNotAllowed`, `Stopped`, `NoSuchKey`,
  `RulesTampered`.
- **`ApprovalRequest { session, key, tier, argv_display: Vec<String>, argv_hash: [u8;32], cwd,
  effect: Option<String> }`**.
- **`ReceiptEvent`**: time, session, key, mode, target (host or argv_display), argv_hash,
  rule_version, approval id, result.
- **`Error`** (thiserror): every variant's `Display` states what happened **and the fix**, for
  example `morsec: daemon not running. Start it with: ms start`. Variants include
  `DaemonUnavailable`, `InvalidKeyName`, `InvalidRef`, `Protocol`, `PeerRejected`,
  `NotImplemented { command, loop_id }`.

### 4. Traits (frozen; §4 of the plan, with one correction)

`Vault` must be object-safe because `RunAdapter::plan` takes `&dyn Vault`. The plan's generic
`with_secret<R>` is not. Frozen form:

```rust
pub trait Vault: Send + Sync {
    fn put(&self, name: &KeyName, value: SecretBytes, meta: KeyMeta) -> Result<()>;
    fn with_secret(&self, name: &KeyName, f: &mut dyn FnMut(&[u8])) -> Result<()>;
    fn delete(&self, name: &KeyName) -> Result<()>;
    fn list(&self) -> Result<Vec<KeyMeta>>;
}
pub trait VaultExt: Vault {                     // blanket impl for every Vault
    fn read_with<R>(&self, name: &KeyName, f: impl FnOnce(&[u8]) -> R) -> Result<R>;
}
pub trait Approver: Send + Sync { fn ask(&self, req: &ApprovalRequest, timeout: Duration) -> ApprovalOutcome; }
pub enum ApprovalOutcome { Approved(ApprovalToken), Denied, TimedOut }
pub trait ReceiptSink: Send + Sync { fn append(&self, e: ReceiptEvent) -> Result<ReceiptId>; }
pub trait RunAdapter: Send + Sync {
    fn matches(&self, argv: &[OsString]) -> bool;
    fn plan(&self, call: &RunCall, v: &dyn Vault) -> Result<ExecPlan>;
    fn preview(&self, call: &RunCall) -> Option<EffectPreview>;
}
pub trait Minter: Send + Sync {
    fn mint(&self, key: &KeyName, s: &SessionId, scope: &str) -> Result<MintedCred>;
    fn revoke_all(&self) -> Result<()>;
}
pub trait Connector: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self) -> Detection;
    fn plan(&self, cfg: &ConnectCfg) -> ConfigDiff;
    fn apply(&self, d: &ConfigDiff) -> Result<()>;
    fn remove(&self) -> Result<()>;
    fn verify(&self) -> Vec<Check>;
}
```

`MemoryVault` zeroizes values on delete and drop, and the closure receives a borrowed slice
(no copy escapes).

### 5. IPC protocol v1 (`ms-ipc`)

- Frame: 4-byte big-endian length, then UTF-8 JSON. Max frame 1 MiB; a larger frame gets
  `Error::Protocol` and the connection closes. Zero-length frames are rejected.
- Envelope: `{"v":1,"id":<u64>,"body":{...}}`. An unknown `v` gets an error response
  `unsupported_version` and the connection closes.
- `Request` bodies: `Status`, `PutKey { name, meta }`, `ListKeys`, `Run(RunCall)`, `Mint`,
  `RulesGet`, `RulesProposeLoosen`, `Stop`, `Start`, `LogQuery`, `DoctorProbe`. **Only `Status`
  is handled in this loop**; the rest return `not_implemented` with the owning loop id.
  `PutKey`'s value travels in a **separate follow-up frame** that the server reads straight into
  `SecretBytes`, so a value is never part of a serde-derived message.
- `Response` bodies contain no `SecretBytes`, which is enforced by the type (`SecretBytes` has no
  `Serialize`). There is deliberately no request that returns a value.
- `Server`: tokio `UnixListener`. The socket directory is created 0700 and the socket chmod'd
  0600. A `PeerCheck` trait runs on accept; the default `SameUid` uses tokio
  `UnixStream::peer_cred()` and rejects other UIDs. L06 replaces it with session identity.
- `Client`: connect with a 2 s timeout. When the socket is missing, it returns
  `Error::DaemonUnavailable` (fail closed, with the fix in the message).
- Default socket path: macOS `~/Library/Application Support/morsec/msd.sock`, Linux
  `$XDG_RUNTIME_DIR/morsec/msd.sock`. `MORSEC_SOCKET` overrides it, for dev loops.

### 6. `ms` binary (`ms-cli`)

- clap derive. Subcommands: `init`, `add`, `import`, `connect`, `disconnect`, `run`, `rules`,
  `log`, `stop`, `start`, `status`, `doctor`, `mcp`, `scan`, `stats`.
- `status` is real: it asks `msd` over IPC and prints `morsec on · daemon <version>`. If the
  daemon is unreachable it prints the `DaemonUnavailable` message and exits 1.
- Every other subcommand prints to stderr
  `morsec: '<name> <cmd>' is not built yet (planned in loop Lxx <slug>).` and exits **69**
  (EX_UNAVAILABLE). `<name>` is the invoked name (`ms` or `mors`, from `argv[0]`'s file name).
- `--version` prints `morsec <version> (<git short sha or "unknown">)`.
- The `mors` name: `ms` reads `argv[0]`. Install creates `mors` as a symlink to `ms`.
  `scripts/install-dev.sh` builds a release binary and links `ms` and `mors` into
  `~/.local/bin` (it refuses to overwrite a non-morsec file there).

### 7. `msd` dev daemon

- `msd --foreground [--port N] [--socket PATH]`. It binds the IPC server, handles `Status`
  (`{"daemon":"msd","version":..,"mode":"dev-stub"}`), logs to stderr with `tracing`, and shuts
  down cleanly on SIGINT/SIGTERM, removing its socket.
- With `--port` it records the port (no listener until L05). A dev socket defaults to
  `$TMPDIR/morsec-dev-<port>/msd.sock` when `--port` is given and `--socket` is not.

### 8. Local check gate (replaces CI)

- `scripts/check.sh` (bash, `set -euo pipefail`) runs, in order, and stops at the first failure:
  1. `cargo fmt --all --check`
  2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
  3. `cargo test --workspace --locked`
  4. `cargo deny --locked check` (licenses, bans, advisories, sources)
  5. `cargo audit --deny warnings`
  6. `python3 .claude/skills/ari42/scripts/ari42_scan.py check . --fail-on high`
  If `cargo-deny` or `cargo-audit` is missing, it **fails** with the install command (fail
  closed; it never skips).
- `package.json` (root, `"private": true`, no dependencies): `"scripts": {"build":
  "scripts/check.sh"}`. This makes gloop's existing build gate run the Rust checks. Without it the
  gate silently passes.
- `deny.toml`: allowed licenses MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause,
  BSD-3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0. Advisories: deny vulnerability, unmaintained
  and yanked. Sources: crates.io only; `unknown-git = "deny"`, `unknown-registry = "deny"`.
  Bans: `multiple-versions = "warn"`, `wildcards = "deny"`.
- Install `cargo-deny` and `cargo-audit` on this machine with `cargo install --locked`, and
  document the command in `README.md`.

### 9. Repo config and docs

- `loops.json`: `repos[0].dev` = `["cargo","run","-q","-p","msd","--","--foreground","--port","{{port}}"]`.
  Append to `review.sensitivePaths`: `crates/ms-vault/**`, `crates/ms-proxy/**`,
  `crates/ms-run/**`, `crates/ms-approve/**`, `crates/ms-rules/**`, `crates/ms-ipc/**`,
  `apps/MorsecApprove/**`, `deny.toml`, `rust-toolchain.toml`, `scripts/check.sh`, `package.json`.
- `REVIEW.md`, "What failure looks like here" gains:
  - no `Debug`/`Display`/`tracing` of secret material, and no `SecretBytes` in serde types;
  - `unsafe` only with a `// SAFETY:` comment and an explicit crate-level opt-out;
  - no new dependency without `cargo deny` passing, and no git or path dependency outside the workspace.
- `README.md`: build, test, and run `scripts/check.sh`; install the dev tools; `install-dev.sh`.
- `docs/PLAN.md`, updated for the no-CI decision: L00 (local gate instead of CI), L09 (the
  `security-evals` step runs inside `scripts/check.sh` instead of a required CI job), L10 (a
  local release script instead of `.github/workflows/release.yml`), §6 and §7 wording, and a
  decision row D7 "No GitHub Actions in v1".
- `ARI42.md`: GW-2 → Partial (lockfile, `--locked`, cargo-deny and cargo-audit in the local
  gate). SDLC-6 → Met (lockfile for the only manifest, sources restricted to crates.io, checked by
  `cargo deny`). EVAL-1 stays Gap (no security evals yet; L09). Add a change-log row.
- `docs/evidence/foundation.md`: the commands run and their results.

## Acceptance Criteria

1. `scripts/check.sh` exits 0 on the branch. Its output is saved to `proof/build-morsec.txt` by
   gloop's build gate, through `npm run build`.
2. `cargo build --workspace --locked` builds 13 libs and 2 bins (`ms`, `msd`) with 0 warnings.
3. `ms --version` and `mors --version` (symlink) both print `morsec 0.0.0 (<sha>)`;
   `mors import` prints `morsec: 'mors import' is not built yet (planned in loop L04 import-env).`
   and exits 69.
4. With `msd --foreground --socket <tmp>/msd.sock` running, `MORSEC_SOCKET=<tmp>/msd.sock ms status`
   prints `morsec on · daemon 0.0.0` and exits 0. With no daemon, it prints the
   `DaemonUnavailable` message containing `ms start` and exits 1.
5. The socket file is mode 0600 and its directory 0700 (asserted in a test).
6. A 1 MiB + 1 byte frame is rejected and the connection closed; an unknown `v` gets
   `unsupported_version`; a zero-length frame is rejected (tests).
7. `format!("{:?}", SecretBytes::from(canary))` contains no byte sequence of the canary; a
   `MemoryVault` value is zeroized after `delete` (tests).
8. `SecretRef`/`KeyName` property tests: every generated valid name round-trips; listed invalid
   forms are rejected (uppercase, `..`, `//`, trailing `/`, whitespace, non-ASCII, query,
   fragment, a 256-byte name).
9. `dyn Vault`, `dyn Approver`, `dyn ReceiptSink`, `dyn RunAdapter`, `dyn Minter` and
   `dyn Connector` all compile (object-safety test).
10. `ms-rules::decide()` returns `Deny(NotImplemented)` for every request (deny by default
    until L03).
11. A test serializes one instance of every IPC `Request` and `Response` variant after
    deserializing a canary-bearing `PutKey` exchange, and asserts the canary is absent from all
    JSON.
12. `scripts/check.sh` fails with a clear message when `cargo-deny` is missing (tested by running
    it with a `PATH` that hides `cargo-deny`).
13. Each test in the Testing Plan states its card:
    `protects=<observable>; fails_when=<wrong result>; no_claim=<what green does not prove>`.
14. No existing file other than those listed in the Files Reference is changed.

## Testing Plan

| Layer | What | Count |
|---|---|---|
| Unit: ms-core | KeyName/SecretRef valid and invalid tables, `find_all`, SecretBytes Debug redaction, Error messages contain a fix | +12 |
| Property: ms-core | proptest round-trip for KeyName/SecretRef | +2 |
| Unit: ms-vault | MemoryVault put/read/delete/list, zeroize on delete, VaultExt | +5 |
| Unit: traits | object-safety compile test for the 6 traits; FakeApprover scripted outcomes | +3 |
| Unit: ms-rules | deny-by-default stub | +1 |
| Integration: ms-ipc | round trip, max frame, zero frame, unknown version, socket perms, missing socket gives DaemonUnavailable, canary absent from all messages | +7 |
| Integration: binaries (assert_cmd) | `ms --version`, `mors` symlink naming, stub exit 69 for each of 14 subcommands (table-driven, 1 test), `ms status` with and without msd | +4 |
| Script | check.sh fails closed without cargo-deny | +1 |

## Rules for the implementing agent

1. Acceptance criteria are the `protects / fails_when / no_claim` profile of each test: the
   observable it protects, the wrong result it rejects, and what green does not prove. Never
   "make the tests pass".
2. Real code and real tests land in the same change. A placeholder, a stub assertion or a
   deferred test is not done. (Stub *commands* are the deliverable here; stub *tests* are not
   allowed.)
3. Any change to a test, validator, check step, timeout, tolerance, threshold or lint
   suppression is reported on its own line in the summary with its justification, before any
   other result.
4. A reported command names the command and its observed result (exit status, counts, the
   failing line). A command you did not run is not reported, and stderr is never silenced in a
   command you cite.
5. Your report is a claim until the parent re-runs it: say what you verified, what you reused,
   and what you could not check.

## Rollback Plan

Revert the merge commit. Nothing outside the repo changes except the dev tools installed by
`cargo install` (`cargo uninstall cargo-deny cargo-audit`) and the optional `~/.local/bin`
links from `install-dev.sh` (`rm ~/.local/bin/{ms,mors}`).

## Effort Estimate

Workspace and lints 1h · ms-core types and tests 3h · traits and fakes 2h · ms-ipc and tests 3h
· ms-cli and msd 2h · check gate, deny.toml, package.json 1h · docs (PLAN, ARI42, README,
REVIEW, evidence) 1h · review and fix cycles 2h. Total about 15h of agent time (≈ 1 loop-day).

## Files Reference

| File | Change |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml` | new |
| `crates/{ms-core,ms-ipc,ms-session,ms-vault,ms-rules,ms-receipts,ms-import,ms-proxy,ms-run,ms-mint,ms-approve,ms-connect,ms-mcp,msd,ms-cli}/` | new |
| `scripts/check.sh`, `scripts/install-dev.sh`, `package.json` | new |
| `loops.json` | dev command; sensitivePaths |
| `REVIEW.md` | Rust-specific failure modes |
| `README.md` | dev setup and commands |
| `docs/PLAN.md` | no-CI decision (L00, L09, L10, §6, §7, D7) |
| `ARI42.md` | GW-2, SDLC-6 rows; change log |
| `docs/evidence/foundation.md` | new |
| `.gitignore` | add `target/`, `proof/` |

## Out of Scope

- Any real vault, proxy, runner, minter, connector, receipts, rules or session logic (wave 1+).
- launchd/systemd units, signing, notarization, Homebrew (L07, L10).
- Swift apps (`apps/`), which are created by L11 and L25.
- GitHub Actions or any hosted CI (user decision for v1).
- Changing gloop itself to support non-npm build commands (possible upstream change to
  csakash/gstack-loops; `package.json` bridges it here).

## Related

- docs/PLAN.md §3.5, §3.7, §4, §5 L00; ARI42.md GW-2, SDLC-6, EVAL-1.
