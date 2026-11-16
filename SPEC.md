# SPEC: socket-peer-verify (threat T-03)

## Problem

`ms` (and `ms-shim`, `ms mcp`) trust whatever process serves the msd socket if it runs as the
same uid (`crates/ms-ipc/src/client.rs`, `check_server_uid`). The agent morsec protects against
runs as the user. A same-uid process that takes over the socket path (it starts first, unlinks
the socket and listens there, or sets `MORSEC_SOCKET` in the user's shell config) receives the
values from `ms add` / `ms import`, and can fake approvals, receipts, `ms doctor` answers and
run results.

## Goal

Before a client sends any request (so before any value, and before acting on any reply), it
proves that the process on the other end of the connected socket is the signed `msd` from the
same Developer ID team as the client itself. It fails closed, with a message that says what to
do, and `ms doctor` reports the same verdict.

## Behaviour

1. **Where:** `ms_ipc::Client::connect`, after the existing uid check and before the `Client` is
   returned. Every production client (ms, ms-shim, ms mcp, ms doctor) goes through it, so no
   frame is ever written to an unverified peer.
2. **Peer identity from the kernel, not the path:** read the peer's audit token from the
   connected socket (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`). Look the code up with
   `SecCodeCopyGuestWithAttributes` (audit token attribute) and check it with
   `SecCodeCheckValidity` against the requirement. The audit token carries the PID version, so a
   PID that exited and was reused fails the lookup instead of matching the new process. Because
   the connected socket itself is checked, swapping the path between "check" and "connect" can't
   win: there is no separate check of the path.
3. **Requirement (release):** the client reads its own signing information
   (`SecCodeCopySigningInformation` on `SecCodeCopySelf`). If it has a Team ID `T`, the peer must
   satisfy the Developer ID designated requirement for msd:
   `identifier "cc.morsec.msd" and anchor apple generic and
   certificate 1[field.1.2.840.113635.100.6.2.6] exists and
   certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "T"`.
   The opt-out below is ignored (and says so) whenever the client has a Team ID.
4. **Dev builds:** a client with no Team ID (unsigned, ad-hoc or linker-signed: every
   `cargo build`) can't name a team, so by default it **refuses** to talk to msd, with a message
   naming the opt-out. The opt-out is the environment variable
   `MORSEC_DEV_UNVERIFIED_DAEMON=1`. It is honoured only by a client with no Team ID, and when
   used it prints a `morsec: DEV BUILD:` warning to stderr once per process. A signed release
   can never take this path, whatever the environment says. Any failure to read the client's
   own signature also refuses (fail closed).
5. **Errors:** a new `ms_core::Error::DaemonNotVerified { detail }`, rendered as
   `morsec: the process serving the msd socket is not a verified msd (<detail>). Nothing was
   sent to it. Run: ms doctor`. It is distinct from `DaemonUnavailable`, so fallbacks that run
   on "daemon down" (`ms rules` reading the local file, `ms start`/`ms stop` kickstarting
   launchd) do not run when an impostor answers.
6. **`ms doctor`:** the morsec section shows a pass line for a verified peer
   (`msd identity verified · cc.morsec.msd · team T`), a warning for the dev opt-out
   (`msd identity NOT verified · dev opt-out MORSEC_DEV_UNVERIFIED_DAEMON with an unsigned ms`)
   and a failure that names the verification error instead of "msd not running".
7. **Linux:** there are no code signatures. The client reports itself as having no Team ID, so
   Linux dev builds need the opt-out, as on macOS. What L21 needs is recorded in the threat
   model and `ARI42.md` (see below), not built here.

## Socket directory and TOCTOU (analysis, recorded in the threat model)

- msd's bind already refuses a symlinked or non-private directory, a live socket or a
  non-socket file, and re-checks the inode after bind (T-02). These stop other users, not the
  same user, who owns the directory and can always replace the path.
- So the fix does not rely on the path at all; it authenticates the peer of the connected
  socket. A client-side path or directory check would add nothing against a same-uid attacker.
- `LOCAL_PEERTOKEN` reports the credentials of the process that called `listen()`. msd only
  listens on sockets it binds itself, and the audit token's PID version changes on exec, so an
  attacker that listens and then execs msd (or hands msd a socket) presents a stale token, which
  fails.

## Out of scope (recorded as residual risk)

- A genuine signed msd that the agent starts itself with its own flags (`--socket`,
  `--state-dir`, `--vault memory`). The value then reaches real msd code, but with
  agent-chosen state. Follow-up: release msd refuses non-default socket, state and memory vault
  unless in a dev build, or `ms` also checks msd's launch origin (launchd job).
- Linux peer verification (L21): `SO_PEERCRED` + pidfd, and either msd as a dedicated user
  (L23 `_morsec`, then a uid check is enough) or a root-owned install path for `/proc/<pid>/exe`.

## Tests

- Impostor: a plain listener on a temp socket path, `ms add` run against it with the opt-out
  removed. `ms` exits non-zero, stderr carries the `DaemonNotVerified` message, and the impostor
  read zero bytes (no frame, no value).
- Opt-out visible: same impostor with `MORSEC_DEV_UNVERIFIED_DAEMON=1` on this unsigned build:
  the warning is on stderr (proves the dev path is the only way past, and is loud).
- Real msd passes: start the real `target/debug/msd` (memory vault, temp HOME, temp socket);
  the verification API accepts it against a requirement that pins its cdhash, and refuses an
  impostor and the Developer ID requirement (an ad-hoc msd is not a release).
- Release can't skip: the policy function returns "verify" for any client with a Team ID,
  with or without the opt-out, in every build profile; the Developer ID requirement string
  compiles (`SecRequirementCreateWithString`).
- Never touch the real `~/.claude`, `~/.codex`, `~/.ssh`; temp HOME everywhere; no keychain
  vault in these tests (memory vault only).

## Done

- `npm run build` green.
- Fresh-context code review and security review converged.
- Threat model T-03 status updated (or, if the threat model isn't on this branch, the update is
  written as a hand-over note for the hardening loop), `ARI42.md` updated.
- `PROOF.md` with Testing, Risk, How to revert.
