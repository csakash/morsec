# L17 `doctor` — SPEC

Card: `docs/PLAN.md` → "L17 `doctor`". Owns `crates/ms-cli/src/doctor.rs` (the `ms doctor` CLI
module), `crates/msd/src/doctor.rs` (the probe store) and `tests/e2e/doctor/`. ARI-42: INJ-4
(verify from inside the runtime), SDLC-2.

## Problem

`ms connect` writes settings that make an agent's sandboxed commands go through msd. Nothing
yet tells the user whether that is still true: a setting can be edited away, the daemon can be
down, the sandbox can have open internet. `ms doctor` answers "does every agent really route
through morsec, and is direct internet blocked?".

## Behaviour

### `ms doctor` (static, default)

Read-only. Talks to msd and reads connector files; changes nothing. Sections and checks:

- **morsec**
  - `msd running`: `Status` answers; shows mode (`keychain`/`dev-memory`), on/stopped, proxy port.
    Stopped (`ms stop`) is a problem.
  - `msd signed`: the daemon's PID comes from the socket's peer credentials, its executable from
    the process table; `codesign --verify --strict` must pass. Signed with a Team ID → pass;
    ad-hoc (a dev build) → warning; invalid or unsigned → problem.
  - `vault reachable`: `ListKeys` succeeds (shows the key count).
  - `CA trusted`: no CA yet (no key bound to a host) → info. Otherwise the CA PEM from msd's
    `Status` (never the file on disk) is checked with `security verify-cert -L` (local, no
    network); not trusted → warning with fix `ms init --trust` (agents themselves trust the CA
    through the connector's bundle, so this only affects tools that use the system store).
  - msd's `alerts` (rules tamper, connector drift) are shown as problems.
- **claude-code** and **codex**: each connector's `verify()` checks (L08, L13): marker, proxy
  settings, CA vars + bundle, hooks, MCP entry. Plus doctor's own cross-check: the proxy port
  the connector recorded equals msd's current proxy port. Not installed and not connected →
  skipped; installed but not connected → warning (`ms connect <agent>`); connected with a failed
  check → problem.
- **mcp**: `ms mcp` is L14 and not built: `ms mcp not installed (tool hashes are checked once
  it ships)`, as info, never a problem. A single function (`mcp_checks`) is the hook L14 fills.

### `ms doctor --live`

Opt-in only (spends tokens), never run by the gate. Refused inside an agent session (msd
attributes to the outermost agent, so a nested run would be mis-attributed; and an agent must
not spend the user's tokens on other agents). Requires msd running. For each agent that is
connected and on `PATH`:

1. A fresh nonce (16 random bytes, hex).
2. Runs the agent headless in a fresh empty temp directory, with a fixed prompt that contains
   only the absolute `ms` path and the nonce: run `<ms> doctor --probe --nonce <nonce>` and
   reply with its output.
   - Claude Code: `claude -p <prompt> --allowedTools "Bash(<ms> doctor --probe:*)"` (no
     permission bypass; the user's own sandbox settings apply).
   - Codex: `codex exec --skip-git-repo-check <prompt>` (the user's own sandbox and approval
     config apply; doctor adds no flag that loosens them).
   - Timeout 180 s, stdout/stderr capped at 64 KiB, stdin closed.
3. Asks msd what it saw for the nonce (`DoctorProbe { nonce }`).

Verdicts, per agent:
- **proxy path**: pass only when msd's proxy itself saw the canary CONNECT for this nonce from a
  session of the expected agent kind that started after the live run began. The agent's text
  is never trusted for a pass.
- **direct egress**: pass only when msd holds a probe report for the nonce, from a session of
  the expected agent kind, saying direct egress was blocked. If msd's report, **or the agent's
  own output**, says direct egress is open → loud failure (a claim of "open" is believed from
  any source; a claim of "blocked" only from msd).
- No report → problem ("the probe did not report: the agent did not run it, or its sandbox
  blocks the msd socket").

### `ms doctor --probe --nonce <hex>` (runs inside the agent's sandbox)

1. **Canary through the proxy**: takes the proxy from `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/
   `http_proxy`/`ALL_PROXY`/`all_proxy` (`http://host:port` only), sends
   `CONNECT <nonce>.doctor.morsec.invalid:443`. `.invalid` never resolves, nothing leaves the
   machine; msd refuses it (not allowlisted) and its egress observer records the sighting with
   the session. Reached = a `403` whose body starts with `morsec:`.
2. **Direct egress**: TCP connect, no proxy, 3 s timeout each, to `1.1.1.1:443`,
   `8.8.8.8:443` and `example.com:443`. Nothing is sent. Any connect succeeding = open.
   (Hidden `--direct-target host:port`, repeatable, replaces the list; used by tests.)
3. **Report** to msd (`DoctorProbe { nonce, report }`); failure to reach msd is printed.
4. Prints a human summary and one machine line `morsec-probe nonce=<n> proxy=<reached|no>
   direct=<blocked|OPEN>`. Exit 0 only when proxy reached and direct blocked. Direct open prints
   a loud `DIRECT INTERNET IS OPEN` banner to stderr.

### msd

- `DoctorProbe` grows optional fields (`nonce`, `report`), additive per PLAN §4 rules; a new
  `ResponseBody::Probe`.
  - With `report`: stores it under the nonce with the caller's session (first report wins, so a
    later "blocked" can't overwrite "open").
  - Without `report`: returns what msd holds for the nonce (canary sighting + report, each with
    agent kind and session start time).
- Canary sightings come from a proxy `EgressObserver` that wraps the logging one and records
  only hosts `^[0-9a-f]{32}\.doctor\.morsec\.invalid$`.
- Store bounded: 64 nonces, oldest dropped; nonce must be 32 lowercase hex; report detail
  ≤ 512 chars. No receipts (no key involved).

### Output (mockup format unavailable: the board needs a login; format chosen here)

```
morsec doctor

morsec
  ✓ msd running · keychain vault · proxy 127.0.0.1:7777
  ✓ msd signed · Developer ID (TEAMID)
  ✓ vault reachable · 3 secrets
  ! CA not trusted by macOS · fix: ms init --trust
claude-code
  ✓ Claude Code connected
  ✗ Claude Code sandbox uses the morsec proxy · sandbox.network.httpProxyPort no longer points at morsec; run: ms connect claude-code
codex
  - not installed
mcp
  - ms mcp not installed (tool hashes are checked once it ships)

1 problem, 1 warning. Fix them, then run: ms doctor
```

`✓` pass, `!` warning, `✗` problem, `-` info/skipped. All text that came from a file or msd
goes through `terminal_safe`. Exit codes: 0 no problems (warnings allowed), 1 at least one
problem, 2 usage. `--live` appends a `live` section per agent.

## Acceptance

1. Static doctor on a healthy temp-HOME setup (dev msd, both connectors applied) → no problems.
2. Removing the proxy setting (Claude: `sandbox.network.httpProxyPort`; Codex: the `HTTPS_PROXY`
   in `shell_environment_policy.set`) → doctor reports that check, exit 1.
3. msd down → `msd running` problem, exit 1, no hang.
4. `ms mcp` → reported "not installed" as info, exit unaffected.
5. Probe with direct egress open (a local listener as `--direct-target`) → loud banner, exit 1,
   msd holds a report saying open; through the dev msd proxy the canary is sighted.
6. `--live` with fake `claude`/`codex` on PATH: a "blocked" agent passes; an "open" agent fails
   loudly; an agent that claims success without running the probe fails (no sighting); an agent
   that only prints "direct=OPEN" fails loudly.
7. `--live` refused inside an agent session.
8. Tests use a temp HOME and never read or write the real `~/.claude` or `~/.codex`.
9. Real `--live` run once in QA if both agents are installed and signed in; otherwise recorded
   as not verified.

## Non-goals

- L29 egress allowlist (msd still refuses every unbound host; the canary needs no allowlist).
- Making Codex reach msd: under Codex's default sandbox network is off, so the live check will
  report the proxy path failing there; that's an honest finding, not a doctor bug.
- MCP tool hashes (L14).
- Running `--live` in the gate.
