# socket-peer-verify: `ms` verifies msd before talking to it (T-03)

Before this change, `ms` trusted any process serving the msd socket as long as it ran as the
same user. The agent runs as that user, so it could take over the socket path and receive
values from `ms add` / `ms import`.

Now every client (`ms`, `ms-shim`, `ms mcp`, `ms doctor`) does three things in
`Client::connect`, before it writes a single frame:

1. **Signature check.** It reads the peer's audit token from the connected socket
   (`LOCAL_PEERTOKEN`) and checks that code against msd's Developer ID designated requirement:
   identifier `cc.morsec.msd`, Apple Developer ID chain, and the client's own Team ID.
2. **Sole-owner check.** The verified process must hold the server end of this connection
   alone, and that end must be close-on-exec. This is read with `proc_pidfdinfo`: the socket
   must not be shared, in flight or inherited.
3. **Second token lookup.** It looks the token up again, so the image can't have changed
   during the check.

Dev builds and failures:
- A client with no Team ID (every `cargo build`) refuses unless `MORSEC_DEV_UNVERIFIED_DAEMON=1`
  is set. With it set, the client warns once on stderr. A signed client ignores the variable.
- Failures raise the new `DaemonNotVerified` error. Fallbacks meant for "daemon down" (the local
  rules file, launchd kickstart) don't run on it.
- `ms doctor` shows a line with the msd identity.

The threat model moves T-03 from `open` to `partial`. `ARI42.md` is updated in AUTH-1, in GW-1
and in the change log.

## Testing

Evidence is saved under `.loops/runs/socket-peer-verify/interactive/proof/`: `tests.txt`,
`qa.md` and `build-morsec.txt`.

### Gate
`npm run build` (scripts/check.sh) passes on the final head. All steps ran: fmt, build, clippy,
tests, deny, audit, supply chain, packaging tests, the fuzz step, the threat-model test-name
check, the ARI-42 scan and the security evals. Output is in `build-morsec.txt`.

### Impostor
`crates/msd/tests/peer_verify.rs::impostor_gets_nothing_and_a_clear_error`:
- A listener on a temp socket path receives **0 bytes** from `ms add`.
- `ms` exits non-zero with "not a verified msd … Nothing was sent to it. Run: ms doctor".
- `ms doctor` reports "msd identity not verified" rather than "not running".

### Real msd passes
`real_msd_passes_the_signature_check`:
- The live check (audit token → `SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity`) plus
  the sole-owner check accepts the real `target/debug/msd`, pinned by its cdhash.
- It refuses an impostor under the same pin.
- It refuses that ad-hoc msd under the Developer ID requirement.

### Exec bypass (found in code review R1, reproduced, then fixed)
A same-user process listens on the path and then execs the genuine msd at the same PID, so the
token names msd. Each variant is refused, and the attacker's child reads 0 bytes:
- **Forked child keeps the listener:** "did not accept".
- **Attacker accepts and keeps a copy:** "another process also holds this connection".
- **Attacker accepts and msd inherits the only copy:** "not close-on-exec".

Tests: `exec_msd_behind_a_forked_listener_is_refused` and
`exec_msd_with_an_inherited_connection_is_refused`. With the sole-owner step disabled, both
tests **fail** (mutation check). With it, they pass.

### Release can't skip
`peer_verify::tests::release_signature_ignores_the_dev_opt_out`:
- A client with a Team ID always gets `Verify`, with or without the opt-out, in any build
  profile.
- Unsigned, unreadable and malformed-team cases refuse (`dev_builds_need_the_explicit_opt_out`,
  `requirement_rejects_malformed_team_ids`).
- The Developer ID requirement compiles in Security.framework (`requirement_compiles`).

### Kernel facts the check relies on
Checked live in `unix_records_identify_the_accepted_end`:
- Our socket's `unsi_conn_so` equals the accepted socket's `soi_so`.
- A fresh accepted socket is close-on-exec and unshared.
- A dup marks it shared.

The offsets come from clang `offsetof`.

### No false refusals of the real msd (review R6)
msd's own brief states are waited out, not refused: shared while a forked `ms run` child hasn't
exec'd yet, and not close-on-exec just after accept (`transient_states_are_waited_out`). A
connection msd closes early gets its own error (`closed_connection_is_reported_as_closed`).

### Existing suites
The cargo-run test suites run with the opt-out from `.cargo/config.toml`. The e2e harnesses,
the install test and the real-agent job clear the environment, so they now set it explicitly.
All pass in the gate.

### Hands-on CLI QA (`qa.md`)
Real `ms` against a real debug msd and a Python impostor, with a temp HOME and a memory vault:
- An unsigned `ms` refuses.
- With the opt-out it works and prints the DEV BUILD notice.
- The impostor receives 0 bytes, and `ms doctor` says "this ms can't verify msd; nothing was
  sent".

### Not run
**A Developer ID-signed `ms` against a Developer ID-signed `msd`.** This needs the release
identity, and Developer ID credentials are never entered by the agent. Manual check after
signing the first release:

```bash
ms doctor
```

Expect `✓ msd identity verified · cc.morsec.msd · team <TEAMID>`.

### Isolation
- The real `~/.claude`, `~/.codex` and `~/.ssh` were never touched: temp HOME everywhere.
- No keychain vault was used in these tests, and no keychain dialog appeared.

## Risk

### Sensitive paths (`gloop risk`)
These need a human reviewer:
- `.cargo/config.toml`
- `Cargo.lock`
- `crates/ms-cli/src/doctor.rs`
- `crates/ms-core/src/error.rs`
- `crates/ms-ipc/Cargo.toml`
- `crates/ms-ipc/src/client.rs`
- `crates/ms-ipc/src/lib.rs`
- `crates/ms-ipc/src/peer_verify.rs`
- `crates/ms-ipc/src/peer_verify/macos.rs` (new `unsafe`: getsockopt, proc_pidinfo,
  proc_pidfdinfo, SecCodeCopySigningInformation)
- `crates/ms-run/src/client.rs`
- `crates/msd/tests/peer_verify.rs`

### Behaviour change for developers
A cargo-built `ms` run outside cargo, such as `target/debug/ms` from a shell, now refuses to
talk to msd unless `MORSEC_DEV_UNVERIFIED_DAEMON=1` is set. This is intended and the message
says what to do. A signed release ignores the variable. `.cargo/config.toml` sets it only for
`cargo run` and `cargo test` processes in this repo. It is a runtime variable, so nothing
reads it at build time.

### Release dependency
Verification requires `ms` and `msd` from the **same** Developer ID team, which
`scripts/release.sh` already pins. A release where `ms` has a Team ID but `msd` doesn't verify
fails closed, so every command refuses. Run `ms doctor` on the first signed build before
publishing the tap.

### Residual risk (threat model T-03 stays `partial`)
- **Agent-started genuine msd.** A genuine signed msd that the agent starts itself, with its own
  `--socket`, `--state-dir` or `--vault memory`, or via its own launchd job, passes the check.
- **Downgrade.** Any older release of msd from the same team also passes.
- **Follow-up for both:** release msd refuses a non-default socket, state directory and memory
  vault, or `ms` checks that msd is the launchd job; plus a version floor.
- **Linux (L21).** No peer check yet. It needs `SO_PEERCRED` plus a pidfd, and either msd as its
  own user (L23 `_morsec`) or a root-owned install path checked through `/proc/<pid>/exe`.
- **Replaced binary (pre-existing, out of scope).** An agent that replaces `ms` in a
  user-writable prefix, or puts a fake `ms` first on PATH, gets past any client-side check.
- **Cancelled connect (R10, accepted).** A cancelled connect leaves its check running for up to
  2 s while holding the connection. Nothing is sent on it.
- **Invariant.** The sole-owner check assumes msd never receives descriptors (it has no
  `SCM_RIGHTS` or `recvmsg`) and never sets close-on-exec on descriptors it didn't create (it
  has no fd sweep). Keep it that way.

### Reviews
- **Code review:** 3 cycles, converged.
  - R1 (important, exec bypass): fixed with the sole-owner check.
  - R6 (important, false refusals of the real msd while it forks or accepts): fixed by waiting
    out transient states.
  - Nits: R3, R4, R5, R7 and R8 fixed; R2 covered by the attack tests; R9 noted; R10
    documented.
- **Security review:** converged with no important findings.
  - S1 (a test flake) fixed.
  - S2 (fd-count bound) noted.
  - S3 (downgrade) recorded as residual risk.
  - S4 is pre-existing.

## How to revert

- **Whole change:** `git revert -m 1 <merge commit>`. This removes the check, the new error
  variant, the doctor line, `.cargo/config.toml` and the test-harness opt-outs together. The
  threat model's T-03 goes back to `open` with the revert. Nothing persistent changes: there
  is no on-disk format, IPC protocol or vault change, so msd and stored keys are unaffected.
- **Emergency on a signed release** (e.g. a team mismatch makes every command refuse): there is
  deliberately no runtime switch. Ship a fixed build, or re-sign `ms` and `msd` with the same
  team.
