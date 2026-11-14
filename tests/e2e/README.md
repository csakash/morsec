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
| `real_agent_job_skips_without_opt_in` | `real-agent.sh` does nothing (and spends nothing) without `MORSEC_REAL_AGENT=1`. |
| `gate_requires_security_evals` | `npm run build` → `scripts/check.sh` → this suite; no real agent in the gate. |

## Real agents (manual or nightly)

`real-agent.sh` runs `claude -p` and `codex exec` against a temp copy of `fixture/` with fresh
canaries in a throwaway msd, checks their output, then runs `ms scan` over your real transcript
directories. It spends model tokens, so it only runs when asked:

```bash
MORSEC_REAL_AGENT=1 tests/e2e/real-agent.sh
```

Run it from your own terminal (msd refuses `ms scan` inside an agent session). For a nightly
run, point a launchd agent or a cron entry at that line; nothing installs one for you.
