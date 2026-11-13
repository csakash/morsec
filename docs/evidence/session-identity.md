# Evidence: L06 `session-identity`

Commands run on the loop branch `feat/session-identity`, 2026-11-13, macOS (Darwin 25.2, arm64),
rustc 1.93.1, cargo-deny 0.20.2. Inside a Claude Desktop session, so the test runner itself is in
a real `claude` session.

## Gate

`npm run build` → `bash scripts/check.sh`, exit 0, all 8 steps:

| Step | Result |
|---|---|
| 1 fmt | clean |
| 2 build (all targets, `--locked`) | 0 warnings |
| 3 clippy `-D warnings` | 0 warnings |
| 4 test | workspace 75 unit/integration tests passed + `ms-session` live harness 9/9 |
| 5 cargo deny | ok (new deps: `libc` macOS-only, `rustix` Linux-only, both already in the lockfile) |
| 6 cargo audit | 0 vulnerabilities |
| 7 supply-chain check | no patches or overrides |
| 8 ARI-42 scan | no findings |

Linux code path: `cargo clippy -p ms-session --all-targets --locked --target x86_64-unknown-linux-gnu -- -D warnings`
is clean. It was **not run** on Linux (no Linux host here); `/proc` parsers are unit-tested on
macOS with fixture text.

## Acceptance (SPEC.md)

| Criterion | Evidence |
|---|---|
| Nested fake-agent trees resolve to the right `SessionId` | `tests/live.rs`: `nested_fake_agents_resolve_to_the_outermost` (claude → helper → codex → helper; every level resolves to the outer `claude` PID and start time), `codex_tree_resolves_to_codex`, `detached_helper_is_unattributed` |
| Outermost rule (impostor `codex` inside `claude`) | same live test (inner process really is named `codex`); unit `impostor_inside_a_session_resolves_to_the_outer_agent` |
| PID reuse = new session | unit `reused_pid_is_a_new_session`, `parent_started_after_child_breaks_the_chain`, `cached_pid_with_new_start_time_is_not_trusted`, `started_after_accept_is_refused`; live `sessions_differ_by_start_time` |
| Fail closed on unreadable ancestors | unit `unreadable_parent_fails_closed_but_gone_parent_ends_chain`, `deep_chains_fail_closed`, `unreadable_caller_is_an_error`; live `reads_root_owned_processes` (so `login` / `launchd` don't trip it) |
| Port → PID, cache re-verified | live `socket_table_live` (exact address pair, reversed orientation, `127.0.0.2` same port does not match, own PID never an owner), `proxy_client_in_fake_agent_tree` (fake `claude` tree's connection → that session; after the client exits the cached answer is refused); unit `same_port_on_another_loopback_address_is_a_different_connection`, `port_reused_by_another_process_is_rechecked`, `socket_shared_across_sessions_is_ambiguous`, `own_process_is_never_an_owner` |
| Proxy username cross-check | unit `cross_check_cases` (match, mismatch, unknown, unattributed, control characters escaped), `names_round_trip`; live `proxy_client_in_fake_agent_tree` |
| Unix peer check (drop-in for `SameUid`) | unit `peer_check_cases`, `uid_changed_since_connect_is_refused` |

### Mutation checks

Each was applied, shown to fail the named test, then reverted:

| Mutation | Caught by |
|---|---|
| drop the cached start-time comparison (`port.rs`) | `cached_pid_with_new_start_time_is_not_trusted` |
| match sockets on ports only (`table.rs`) | live `socket_table_live` |
| treat every unreadable parent as "end of chain" (`walk.rs`) | `unreadable_parent_fails_closed_but_gone_parent_ends_chain` |

### Kernel struct offsets (macOS, LP64)

From `clang` `offsetof` on the SDK headers. They are confirmed against live data by
`reads_this_process`, `reads_root_owned_processes` and `socket_table_live`.

- `struct kinfo_proc`: size 648. `p_starttime` at 0 (`tv_sec` i64, `tv_usec` i32 at +8),
  `p_pid` 40, `p_comm` 243 (17 bytes), `e_ucred.cr_uid` 420, `e_ppid` 560.
- `struct socket_fdinfo`: size 792. `soi_kind` 256, `insi_fport` 264, `insi_lport` 268,
  `insi_vflag` 288, `insi_faddr` 296, `insi_laddr` 312. Constants: `SOCKINFO_TCP` = 2,
  `PROC_PIDFDSOCKETINFO` = 3.

## QA on this machine (real Claude Desktop)

The QA program used the crate from a scratch project outside the repo.

- This shell resolves to `ClaudeCode` with the `claude` PID. The chain is
  `zsh → claude(466) → disclaimer → Claude(85147) → launchd(1)`. The walk passes the
  root-owned `launchd`.
- The peer check on this process gives `Agent(ClaudeCode, 466)`. A peer with uid 0 gives
  `WrongUser`.
- Proxy path: an `nc` child connects to a loopback listener and resolves to
  `Agent(ClaudeCode, 466)` in 5.2 ms (full scan). The same source port on `127.0.0.2`
  gives `NoSocketOwner`.
- Cross-check: `claude-code` is accepted. `codex` is refused with
  ``proxy user "codex" does not match the calling process (ClaudeCode session 466)``.
- Seven concurrent Desktop sessions under one `Claude` app (claude PIDs 174, 238, 9258,
  25767, 86273, 87616, 466) each resolve to their own `claude` PID. The host app never
  merges them.
- Timings from the live tests:

  | Lookup | Time |
  |---|---|
  | Full socket scan | 2–5 ms |
  | Cached and re-verified | about 30 µs |

- Not covered: a Terminal.app `login` chain, because none was running. Root-owned reads
  are covered by the `pid 1` test.

## Review record

Two fresh-context reviewers looked at commit `36c651a`: one for code, one for security.

**Code review: 6 findings, all fixed in `cf45bf2`.**

1. Proxy connections were matched on ports only.
2. An unreadable parent ended the walk silently.
3. The Linux `btime` drifts.
4. The depth cap did not match the SPEC.
5. The cache test did not prove its claim.
6. Some comment references were stale.

**Security review: 1 high, 1 medium, 2 low.**

- The high was the same port-only matching, plus a `client == proxy` variant that could
  resolve to the daemon's own ancestry. Fixed: the full address pair is matched and the
  daemon's own PID is excluded.
- The medium was same-uid peer PID reuse. The accept-time check was added. Reuse before
  accept is documented as a residual risk.
- The lows were DoS from full scans (documented; L07 to use `spawn_blocking` and cap
  scans) and two SPEC wording errors (fixed).
- The audit of `sys/macos.rs` and the parsers found no issues.

Both reviewers re-reviewed `cf45bf2`, and both converged: every earlier finding was verified
fixed, and the new `sysctl` unsafe block and the `kinfo` offsets were checked independently.
The re-reviews raised three new minor findings, all Linux-only:

- Start-time precision is about 1 s. Recorded as a residual risk for L21.
- Clock drift could refuse real clients. Fixed with a 2 s Linux-only slack.
- A `hidepid=invisible` mount hides other users' ancestors. Recorded as a residual risk for L21.
