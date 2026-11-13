# SPEC: L06 `session-identity`

Card: `docs/PLAN.md` §5, "L06 `session-identity`". Owns `crates/ms-session/` only. ARI-42: AUTH-1.

## Problem

`msd` has to know *which agent session* is talking to it, without trusting anything the client
says. Unix-socket clients (`ms`, the shim, `ms mcp`) arrive with a kernel-reported peer PID; proxy
clients arrive over loopback TCP with only a source port. This crate turns either into a
`ms_core::SessionId { agent, pid, started_unix_ms }` (frozen in §4), which policy, receipts and
minting key on. A reused PID must be a new session.

## What gets built

All in `crates/ms-session/`. No frozen interface changes.

1. **Process table** (`ProcessTable` trait + `OsProcessTable`). For a PID: parent PID, uid,
   start time (Unix ms), short name (`p_comm` / `comm`), executable path when readable.
   - macOS: `sysctl(KERN_PROC_PID)` (`kinfo_proc`, parsed from bytes at checked offsets; unlike
     `proc_pidinfo` it can read root-owned processes such as `login` and `launchd`, so the walk
     can pass them) and `proc_pidpath` for diagnostics.
   - Linux: `/proc/<pid>/stat` (ppid, start ticks), `/proc/<pid>/status` (uid), `/proc/stat`
     (`btime`, read once per daemon because the kernel recomputes it from the wall clock),
     `/proc/<pid>/exe`; tick rate from `rustix` (safe). No unsafe on Linux.
2. **Agent classification.** Exact, case-sensitive match on the process short name (set by the
   kernel at exec from the file name; on Linux a process can also rename itself with
   `prctl(PR_SET_NAME)`; the executable path is diagnostics only): `claude` → `ClaudeCode`, `codex` → `Codex`, `cursor-agent` → `Cursor`,
   `gemini` → `GeminiCli`. Desktop and IDE *hosts* (`Claude`, `Code`, `Cursor`, `Electron` …) are
   never session roots: Claude Desktop runs one `claude` process per session under the `Claude`
   app, so the app must not merge them.
3. **Process-tree walk → `Caller`.** From the peer PID, walk parent links up to PID 1 (depth cap
   64; deeper is an error). The session root is the **outermost** agent process on that chain.
   - Outermost, not nearest: a process inside a Claude Code session that names itself `codex` (or
     `claude`) must not become a fresh session or change agent kind. Authority comes from the
     real outer agent. A Claude session that runs `codex` attributes to the Claude session.
   - Every hop checks `parent.started <= child.started`. If not, the parent PID was reused after
     the real parent died, and the walk stops there (treated as reparented).
   - Result is `Caller::Agent(SessionId)` or `Caller::Unattributed { pid, started_unix_ms }` (no
     agent ancestor, e.g. a person running `ms` in a plain terminal, or a daemonized process).
     `Unattributed` is **not** proof of a human and must never get more rights than an agent
     session; that is documented on the type.
   - The caller or any ancestor that exists but cannot be read is an error: fail closed (an
     unreadable middle process could hide the real outer agent). An ancestor that no longer
     exists ends the chain, like a detach.
4. **Unix-socket peers.** `resolve_peer(&resolver, &ms_ipc::PeerInfo, accepted_unix_ms)`
   (requires a PID; `None` is an error; a process whose uid differs from the kernel's peer uid,
   or that started after the accept time, is a reused PID and is refused) and `SessionPeerCheck` implementing `ms_ipc::PeerCheck`: same uid as the
   daemon, PID present, PID's uid matches, and the walk succeeds. Drop-in for `SameUid` in L07.
5. **TCP loopback connection → PID** (`PortResolver`). Given the accepted stream's
   `peer_addr()` (client) and `local_addr()` (proxy), find the process whose socket is exactly
   `local = client`, `remote = proxy` (full address pair, IPv4-mapped compared as IPv4, both
   loopback). Ports alone are not enough: on Linux any 127/8 address is bindable, so another
   process could hold the same source port on `127.0.0.2`. The daemon's own PID is never an
   owner.
   - macOS: `proc_listallpids` → `proc_pidinfo(PROC_PIDLISTFDS)` → `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`.
     The socket record is read into a byte buffer and parsed in safe code at offsets verified by
     a self-test against a real socket.
   - Linux: `/proc/net/tcp{,6}` row → inode → scan `/proc/<pid>/fd` links for `socket:[inode]`.
   - Cache: recent owner PIDs are probed first (agents open many connections), with a short TTL
     on `(client, proxy) → owner`; every cache hit is re-verified against the live socket and the
     owner's start time before use.
   - Several processes sharing the socket (fork) must all resolve to the same `Caller` on a full
     scan, otherwise error. The cached / recent-owner paths return the first verified holder: a
     socket only reaches a second process by inheritance (same session) or by its holder
     passing it on, so this cannot pull another session's identity onto a connection without
     that session's cooperation. Not found → error.
6. **Proxy username cross-check.** `cross_check(&Caller, username)`: the per-connector proxy
   username (`claude-code`, `codex`, `cursor`, `gemini-cli`) must name the same agent kind as the
   resolved session. Mismatch, unknown username, or an `Unattributed` caller presenting an agent
   username → error.

## Unsafe

One module, `src/sys/macos.rs`, with `#[allow(unsafe_code)]` scoped to it (REVIEW.md: explicit
opt-out plus `// SAFETY:` on every block). It only calls `sysctl(KERN_PROC_PID)` and four libproc functions into
correctly sized, owned buffers and returns owned Rust values. All parsing is safe code.
Rejected alternatives: the `libproc` crate (bindgen + libclang at build time, large build-time
supply chain), `sysinfo` (no socket→PID, start time only in seconds), shelling out to `lsof`
(slow per connection, output parsing).

## Residual risks (same-user design, documented not fixed)

- A process can detach from its agent (`Caller::Unattributed`, never more rights than an agent)
  or exec / rename itself as `claude` outside any session and get a fresh `SessionId`. L07 must
  give a never-seen session no standing grants, and must not let a fresh session escape a
  revoked or capped one; sensitive actions still need approval (AUTH-3).
- Unix peer PID reused by a same-uid process before accept passes the checks (needs audit
  token / pidfd, an ms-ipc change). On Linux the post-accept check is also coarse: start time
  is `btime` (whole seconds) plus 10 ms ticks, up to ~1 s early, so reuse within ~1 s of accept
  can pass, and a 2 s slack (so clock drift can't refuse real clients) widens that to ~3 s.
  Fix in L21 by comparing boot-relative ticks (`CLOCK_BOOTTIME`) or a pidfd.
- Linux with `/proc` mounted `hidepid=invisible`: another user's ancestor reads as gone, not
  unreadable, so the walk ends there instead of failing closed. Only matters if an agent's
  descendant chain passes through another user's process. L21 to detect hidepid at startup.
- Full scans cost ~2–5 ms and every distinct new connection can force one; an agent could load
  the daemon this way. L07 should run lookups off the async runtime (`spawn_blocking`) and cap
  concurrent scans. The same agent could also just `kill msd`.

## Out of scope

Wiring into `msd` (L07), the proxy's Proxy-Authorization parsing (L05), per-session grants and
caps (L07/L08), node-launched `claude` detection via argv (open item), macOS audit-token PID
versions (needs ms-ipc change; residual risk).

## Acceptance (verify)

- Tests launch **nested fake-agent process trees** and resolve the leaf to the right
  `SessionId`. The live test binary (`tests/live.rs`, `harness = false`) copies itself as
  `claude` / `codex` / `helper` (macOS kills renamed copies of system binaries, and a symlink
  keeps the target's name), and starts each tree detached (reparented to PID 1) so the real
  agent running the tests doesn't, correctly, absorb it.
- Outermost rule: a fake `codex` inside a fake `claude` resolves to the `claude` session.
- **PID reuse:** same PID with a different start time is a different `SessionId`; a walk that
  meets a parent started after its child stops there (fake table).
- Port→PID: a test process connects to a local listener; the resolver returns that process's
  PID; cache hit is re-verified (after the client closes, lookup fails rather than returning
  stale data).
- Cross-check: match, mismatch, unknown username, unattributed caller.
- Live QA on this machine: the Claude Desktop chain (`zsh → claude → disclaimer → Claude`)
  resolves to `ClaudeCode` with the `claude` PID.
- `npm run build` (`scripts/check.sh`) green; `ARI42.md` AUTH-1 row updated.
