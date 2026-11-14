# tests/e2e: canary security evals (L09)

`cargo test --locked -p ms-e2e` runs the suite; `scripts/check.sh` runs it as the
`security-evals` step, so the gloop build gate (`npm run build`) requires it (EVAL-1; no hosted
CI in v1, PLAN D7). It needs `ms` and `msd` built first (`cargo build --workspace`).

Each test starts a throwaway `msd --vault memory` with its own socket, state directory and
`HOME` in a temp dir, and makes fresh canary values from `/dev/urandom`. The login keychain is
never touched: the suite checks the daemon reports `dev-memory` before it stores anything.

| Test | What it proves |
|---|---|
| `canary_never_reaches_the_agent` | After `ms import`, a fake agent (`claude`) runs `env`, `cat .env`, `curl` (direct and through the swap proxy) and `psql`. No canary, in any encoding `ms-scan` knows, shows up in its output, the repo, what curl's target or psql got, msd's log or the receipts. A planted leak is caught. |
| `ms_scan_catches_a_leaky_transcript` | `ms scan` reports planted leaks in Claude Code and Codex transcripts by file:line, key and encoding, exits 3, prints no value; clean tree exits 0; symlinks not followed; refused inside an agent. |
| `mcp_tools_end_to_end` | (L14) A fake Claude Code starts the real `ms mcp`: `tools/list` matches `ms mcp --catalog` (same SHA-256); calls run with the value redacted; `$( )`, backticks, ESC and U+202E stay literal and come back escaped; an extra `key`, an `ms://` argument and an unknown tool are refused; receipts show each call under `claude_code`; no canary in output, receipts or msd's log. |
| `real_agent_job_skips_without_opt_in` | `real-agent.sh` does nothing (and spends nothing) without `MORSEC_REAL_AGENT=1`. |
| `gate_requires_security_evals` | `npm run build` → `scripts/check.sh` → this suite; no real agent in the gate. |

## `ms doctor` (L17): `doctor/main.rs`

Same throwaway msd and temp `HOME` (both connectors applied with `ms connect --yes`); the binary
is its own fake `claude` and `codex`, so `ms doctor --live` runs without spending tokens. The
suite checks the real `~/.claude/settings.json`, `~/.codex/config.toml` and morsec connector
state are unchanged when it ends.

| Test | What it proves |
|---|---|
| `healthy_setup_has_no_problems` | Static doctor: msd, vault, CA, both connectors and the port cross-check pass; the `ms mcp` catalog hash is "not checked yet" (info), exit 0. |
| `broken_connector_is_reported` | Removing Claude Code's `httpProxyPort` and Codex's `HTTPS_PROXY` is reported with the fix, exit 1. |
| `daemon_down_is_reported` | No daemon: `msd not running`, connectors still checked, exit 1, no hang. |
| `probe_open_egress_fails_loudly` | Inside an agent, open direct egress → banner, `direct=OPEN`, exit 1; msd holds the canary from that session and the report; a malformed target is refused. |
| `live_with_fake_agents` | `--live` passes a routed, blocked sandbox; fails loudly on open egress (from msd's report or the agent's output); fails an agent that only claims success. |
| `live_refused_inside_an_agent` | `--live` refuses to run inside an agent session. |

`ms doctor --live` with real agents spends tokens and is never in the gate; run it by hand from
your own terminal.

## Real agents (manual or nightly)

`real-agent.sh` runs `claude -p` and `codex exec` against a temp copy of `fixture/` with fresh
canaries in a throwaway msd, checks their output, then runs `ms scan` over your real transcript
directories. It spends model tokens, so it only runs when asked:

```bash
MORSEC_REAL_AGENT=1 tests/e2e/real-agent.sh
```

Run it from your own terminal (msd refuses `ms scan` inside an agent session). For a nightly
run, point a launchd agent or a cron entry at that line; nothing installs one for you.
