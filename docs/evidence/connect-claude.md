# Evidence: L08 `connect-claude`

Loop branch `feat/connect-claude`, 2026-11-14, macOS (Darwin 25.2), Claude Code 2.1.318.
Full command outputs are kept outside the repo in `.loops/runs/connect-claude/interactive/proof/`.
Decisions D1–D12 are in `SPEC.md` (which becomes the PR body).

## Claude Code settings, verified against the docs (2026-11-14)

| Setting | What the docs say | Source |
|---|---|---|
| User settings | `~/.claude/settings.json`; `$CLAUDE_CONFIG_DIR` moves it; terminal, IDE extensions and the desktop app all read it; reloaded on save | https://code.claude.com/docs/en/settings |
| `env` | applied to Claude Code's own process and subprocesses; no `~`/`$VAR` expansion | https://code.claude.com/docs/en/env-vars |
| Proxy vars | Claude Code uses `HTTPS_PROXY` etc. for its own API traffic, also from `env` | https://code.claude.com/docs/en/network-config |
| `sandbox.enabled`, `sandbox.network.allowedDomains`, `httpProxyPort`, `socksProxyPort`, `allowUnixSockets` | names and scopes; with a custom port your proxy filters everything and `allowedDomains` no longer applies to it | https://code.claude.com/docs/en/settings-reference , https://code.claude.com/docs/en/sandboxing |
| MCP scopes | user and local scope in `~/.claude.json`, project scope in `.mcp.json`; stdio entry `type`/`command`/`args`/`env` | https://code.claude.com/docs/en/mcp |
| Hooks | `{event: [{matcher?, hooks: [{type: "command", command, args?, …}]}]}`; `args` = exec form, no shell; `SessionStart` gets `CLAUDE_ENV_FILE` | https://code.claude.com/docs/en/hooks |
| `statusLine` | `{type: "command", command, padding?}` | https://code.claude.com/docs/en/statusline |

Assumption not stated in the docs: with `CLAUDE_CONFIG_DIR` set, `.claude.json` lives in that
directory. The live check confirms it for 2.1.318 (`claude mcp get ms` finds the server there).

## Live check (Claude Code 2.1.318)

`MORSEC_LIVE_CLAUDE=1 cargo test -p ms-connect --test live_claude`: for the empty, typical and
complex goldens, `claude doctor` (which lists every settings entry Claude Code rejects) reports
no invalid settings, and `claude mcp get ms` reads the user-scope `ms` server as
`/usr/bin/env -i …`. Negative control: changing `httpProxyPort` to a string makes doctor report
"Invalid settings", so the check is able to fail. No sign-in or model call is needed.

Not verified live: the sandbox actually sending a Bash command's HTTPS through msd (needs a
signed-in session and a model call), and `--session-env` being run by a real `SessionStart`.

## ARI-42

| Req | Test |
|---|---|
| SDLC-2 | `ms-connect` `claude::sdlc2_sandbox_on_and_no_bypass`; live `claude_code_accepts_the_block` |
| SDLC-4 | `claude::{sdlc4_user_scope_only_and_drift_reported, refusals_change_nothing}`, `claude::tests::env_refs_only`, `ms-cli` `connect_cli::{agent_cannot_disconnect_or_force, refusals}` |
| MCP-4 | `claude::mcp4_server_gets_a_minimal_env` |

## Acceptance criteria (SPEC.md)

| AC | Test |
|---|---|
| 1 goldens | `claude::goldens` (`tests/golden/claude/{empty,typical,complex}`) |
| 2 round trip | `claude::round_trip_is_byte_identical` (goldens + 4-space, tab, compact, CRLF, leading whitespace, `{}`) |
| 3 idempotent | `claude::connect_is_idempotent` |
| 4 user edits | `claude::user_edits_survive_disconnect` |
| 5 refusals | `claude::refusals_change_nothing`, `apply_refuses_a_file_changed_since_plan`, `fsio::tests::*`, `json::tests::*` |
| 6 refs only | `claude::tests::env_refs_only`, `connect_cli::refusals` |
| 7 SDLC-2 | see above |
| 8 SDLC-4 | see above |
| 9 MCP-4 | see above |
| 10 CLI e2e | `connect_cli::connect_and_disconnect_end_to_end` (dev msd, temp HOME, canary in the user's env never printed) |
| 11 gate | `npm run build` (PROOF.md) |
