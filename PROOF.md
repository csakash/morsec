# PROOF: L14 `mcp-server`

`ms mcp` is a stdio MCP server that turns each run-mode command pattern in the user's rules into a typed tool (`pg/production` + `["psql","-c","*"]` → `pg_production__psql(arg1)`). msd enforces every call through a new `McpCall` IPC request: the key comes from the tool, the session from the kernel peer, arguments are checked against JSON Schema, the tool list is pinned to the rules version and hashed, and each call then takes L12's run path (roots, allowlist, L11 approver for production keys, receipts, redaction). Results come back as typed, inert JSON. Spec: `SPEC.md`.

## Testing

Evidence is in `.loops/runs/mcp-server/interactive/proof/` (not committed).

- **Gate:** `npm run build` (scripts/check.sh: fmt, build, clippy `-D warnings`, all tests, cargo deny, cargo audit, supply-chain check, packaging, ARI-42 scan, security evals). Green on a6f53ff, b497513 and 8eb4056 (`build-morsec-<sha>.txt`, `check.sh: all checks passed`), and on the final HEAD (see the report).
- **Unit tests** (`tests.txt`):
  - `ms-mcp` (14): `schema::{enforces_the_subset, unknown_keywords_fail_closed}`, `catalog::{tools_from_rules, calls_are_validated, hash_pins_the_catalog (golden hash), descriptions_are_escaped_and_bounded, names_unique_and_short}`, `result::{output_is_inert_data, failures_are_errors}`, `server::{protocol, unknown_protocol_version, queue_cap_and_unknown_tool_with_msd_down, malformed_notifications_are_dropped, a_client_that_does_not_read_is_bounded}`.
  - msd `daemon::mcp` (5):
    - `a_call_runs_with_the_tools_key_and_the_peers_session`: the receipt carries the agent session, the key and `mcp:<tool>`, and the value is redacted.
    - `schema_violations_and_other_keys_are_refused_and_recorded`: covers `ms://other`, extra `key`/`session`/`cwd`/`env`, wrong type, missing, too long and non-object arguments. Each one is refused and leaves a blocked receipt. `a; rm -rf /` stays literal.
    - `unknown_tools_and_stale_versions_are_refused`
    - `production_calls_go_through_the_approver`: approve and deny with L11's approver and a fake Touch ID.
    - `repeated_refusals_stop_the_session` (LOG-2)
- **End to end** (`tests/e2e` `mcp_tools_end_to_end`, part of the gate's security evals): a fake Claude Code starts the real `ms mcp` against a throwaway msd.
  - The tool list matches `ms mcp --catalog` (same SHA-256).
  - Calls run with the value redacted.
  - `$( )`, backticks, ESC and U+202E stay literal and come back escaped. No file is created.
  - An extra `key`, an `ms://` argument and an unknown tool are refused.
  - The receipts show each call under `claude_code`.
  - No canary value shows up in the output, receipts or msd's log.
- **QA** (`qa-transcript.txt`, script `qa_mcp.py`): 24/24 checks pass, driving the real `ms mcp` binary interactively against a dev msd (memory vault), with setup and approvals run from a detached "own terminal".
  - Handshake and the generated list.
  - A test-tier call and a value check.
  - Injection, with output that stays inert.
  - A production tool approved, then denied, in `ms approve`.
  - Rules changed mid-session: the list stays pinned and calls are refused with "rules changed". After a restart the new tool is listed with a new hash and runs.
  - Refusals for another key, another session or a schema violation. They stop the session through LOG-2.
  - Receipts for all of the above, with no value in any state file or log.
  - With msd down, the server still starts and lists no tools.
- **Reviews** (fresh-context subagents, read-only):
  - Code review converged in 4 cycles.
    - Cycle 1: R1–R6, all nits or pre-existing. R2–R6 fixed in e737eb3; R1 is pre-existing.
    - Cycle 2: R7–R10, all nits. R7–R9 fixed in 046390b; R10 accepted.
    - Cycle 3: R11, reported as important. It did not reproduce: a finished call holds its run permit while its answer waits, so the server stays bounded. It was made explicit anyway with `tx.reserve()` and a regression test (8eb4056). R12 fixed.
    - Cycle 4: no important findings. R13 test bound fixed (cbb1af3); R14 pre-existing.
  - Security review: no important findings.
    - S1 (stale-version calls rebuilt the catalog) and S2 (tampered rules could LOG-2-stop an honest agent) fixed in 046390b.
    - S3 (`*` matches options) is pre-existing.
    - The re-check of the fix commits found nothing exploitable. S4 (unlimited Failed receipts for stale calls) is the known receipt-volume class; S5 doc fixed.
- **ARI-42:** `ari42_scan.py check .` finds 0 high and 0 medium; the 5 lows are pre-existing test fixtures in `ms-connect`.
  - MCP-3: Partial → Met.
  - MCP-2: Partial, strengthened. It needs L17's doctor check to be Met.
  - AUTH-2 and OUT-1: Partial, strengthened.

**Not verified:**
- A real Claude Code or Codex client talking to `ms mcp`. Neither is signed in under a temp HOME, and I didn't touch the user's real config. In particular, I didn't check which cwd each client starts the server in, which decides which project roots apply.
- The real Touch ID sheet (stood in for by `--test-touch-id allow`, as in L11/L12).
- `ms doctor` comparing the hash. That is L17's, landing in parallel; the hand-over is in the notes folder.

## Risk

- **Sensitive paths (`gloop risk`):** a human reviewer must look at
  - the IPC protocol: `crates/ms-ipc/src/protocol.rs`, a new `McpCall`, additive and optional to old clients
  - msd's request dispatch: `crates/msd/src/daemon.rs` and the new `daemon/mcp.rs`
  - L12's run path: `crates/msd/src/daemon/run.rs`. `prepare_run`/`run_buffered` gained an optional `via` receipt-target prefix, and its test module helpers became `pub(crate)`.
  - the new crate `crates/ms-mcp`, plus `Cargo.toml`/`Cargo.lock` (new direct dependency `regex` 1.x, already in the lockfile through tracing-subscriber)
  - `crates/ms-cli/src/{main,mcp,connect}.rs`
  - `crates/msd/tests/cli.rs` (the stub table)
- **Security model:** msd is the authority, so a modified `ms mcp` (the agent can run any process) can't skip validation, receipts or the version pin. Going around `ms mcp` and sending `Run` straight to msd gives nothing beyond what `ms run` already allowed.
- **Residuals:**
  - A wildcard `*` also matches option arguments (`-f…`, `--config=…`). That comes from L12's pattern semantics (security S3), and the user's rule decides it.
  - A call refused because msd is at 8 runs (`Busy`), or because the session is already stopped, leaves no receipt. That is pre-existing in L12/L07 (review R1).
  - A call refused because the 32-call queue in `ms mcp` is full never reaches msd (review R10). After the client closes stdout, `ms mcp` keeps running calls until stdin closes, though each one is still recorded (R14).
  - Stale-version calls write unlimited `Failed` receipts (security S4). That is the same receipt-volume class as allowed runs.
  - Stale-version refusals don't count toward LOG-2, by design.
  - Tool names are positional (`arg1`) rather than the card's `db_query(sql)`. Friendly names need a rules field, which is a decision for the orchestrator.
- **Merge:** these touch the same files as L17 (msd/tests/cli.rs stub table, ms-ipc protocol.rs, msd daemon.rs, ms-cli main.rs, ARI42.md, tests/e2e). All the changes are small and additive.

## How to revert

`git revert` the L14 commits (or the merge commit). That removes `McpCall`, msd's `daemon/mcp.rs`, `ms mcp` (it goes back to the "not built yet" stub, exit 69) and the e2e test. No stored data or file formats change: rules, receipts and connector configs are untouched. A connector entry written with `--with-mcp` keeps pointing at `ms mcp`, which then exits 69 again, as before L14.
