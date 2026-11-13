# L06 `session-identity`: who is calling `msd`

This PR builds `crates/ms-session/`. The daemon can now derive the caller's agent session from
the kernel, never from what the client says. That is ARI-42 AUTH-1, now Partial: wiring into
`msd` lands in L07.

- **Unix-socket peers.** The kernel gives the peer PID. The crate walks the process tree to the
  **outermost** agent process (`claude`, `codex`, `cursor-agent`, `gemini`). The result is
  `SessionId {agent, pid, start time}`, so a reused PID is a new session. `SessionPeerCheck` is
  a drop-in replacement for `ms_ipc::SameUid`.
- **Proxy clients.** The loopback connection's exact address pair maps to its owning PID. That
  lookup uses libproc on macOS and `/proc/net/tcp` on Linux, with a cache that is re-checked on
  every use. The per-connector proxy username is then cross-checked against the session.
- **Callers outside any agent.** These come back as `Caller::Unattributed`. That is documented
  as *not* proof of a person, and it never gets more rights than an agent session.

No frozen interface changed. Only `crates/ms-session/`, `Cargo.lock` (target-specific `libc` and
`rustix` entries, both already in the lockfile), my `ARI42.md` row and
`docs/evidence/session-identity.md` were touched.

## Testing

- **Gate.** `npm run build` (`scripts/check.sh`) exits 0 and all 8 steps pass: fmt, build,
  clippy `-D warnings`, test, deny, audit, supply-chain and ARI-42 scan.
- **Test counts.** `ms-session` has 30 unit tests and a 9-test live harness.
  `tests/live.rs` is `harness = false`: it copies its own binary as `claude`, `codex` and
  `helper`, then launches **nested fake-agent process trees**, detached to PID 1.
- **What the live tests show:**
  - claude → helper → codex → helper resolves to the outer `claude` at every level.
  - Two agent processes differ by start time.
  - `launchd` and other root-owned processes are readable.
  - A real socket table lookup matches on the exact address pair. `127.0.0.2` with the same
    port doesn't match. The daemon's own PID is never an owner.
  - A fake `claude` tree's proxy connection resolves to that session. The `codex` username
    fails the cross-check, and a cached answer is refused once the client exits.
- **PID reuse** has unit tests: the same PID with a new start time, a parent that started after
  its child, a cached PID with a new start time, and a peer that started after accept.
- **Mutation checks.** Dropping the cached start-time check, matching on ports only, or ending
  the walk on any unreadable parent each fails a named test.
- **QA on this Mac, inside Claude Desktop:**
  - This session resolves to its `claude` process (466) through
    `zsh → claude → disclaimer → Claude → launchd`.
  - Seven concurrent Desktop sessions under one `Claude` app stay distinct.
  - An `nc` proxy client resolves in about 5 ms.
  - Root-owned `launchd` is read through `sysctl`.
- **Not covered:**
  - The Linux code path is clippy-clean for `x86_64-unknown-linux-gnu` but has **not run** on
    Linux. Its `/proc` parsers are unit-tested with fixtures.
  - No Terminal `login` chain was available to try live.
- **Review.** A fresh-context code review and a fresh-context security review ran, then a
  re-review of the fixes. Both converged:
  - The two important/high findings are fixed: port-only matching allowed connection
    borrowing, and an unreadable ancestor silently ended the walk.
  - Every other finding is fixed or recorded as a residual risk with a reason.

Details: `docs/evidence/session-identity.md`.

## Risk

**Sensitive paths for human review:**
- `crates/ms-session/src/sys/macos.rs` is the only `unsafe` in the crate. It covers
  `sysctl(KERN_PROC_PID)`, `proc_listallpids`, `proc_pidinfo(PROC_PIDLISTFDS)`,
  `proc_pidfdinfo` and `proc_pidpath`. Every block has a `// SAFETY:` comment and the opt-out
  is scoped to that module.
- `src/kinfo.rs` and `src/sockparse.rs` parse kernel structs from bytes at hard-coded offsets.
  The offsets come from `clang` `offsetof`, and the live tests check them.
- `src/walk.rs`, `src/port.rs` and `src/peer.rs` are the identity decisions themselves (AUTH-1).

**Residual risks** (inherent to the same-user design; listed in SPEC.md):
- A process can detach from its agent, which makes it Unattributed. It can also exec or rename
  itself as `claude` outside any session to get a fresh session. **L07 must give a never-seen
  session no standing grants.**
- A Unix peer PID reused by the same uid before accept passes the checks.
- On Linux, start-time precision is about 1 s, and there is a 2 s slack.
- On Linux, a `hidepid=invisible` mount hides other users' ancestors.
- Full scans take about 2–5 ms each, so L07 should call the lookup off the runtime and cap
  scans.

**Behavior risk is low.** Nothing calls this crate yet. `msd` adopts it in L07.

## How to revert

`git revert` this PR's merge commit. Nothing outside `crates/ms-session/` depends on it yet. The
`Cargo.lock` lines and the `ARI42.md` AUTH-1 row revert with it, and AUTH-1 goes back to Gap.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
