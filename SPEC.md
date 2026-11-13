# SPEC: L09 `e2e-canary`

Loop L09 (`feat/e2e-canary`, port 4200). Card: `docs/PLAN.md` § "L09 `e2e-canary`".
Depends on L07 (msd) and L04 (`ms import`) on main at 9d18109. Built alongside L08/L10, so it
touches only its own paths plus small additive edits to shared files.

## Problem

morsec promises that a coding agent can use a secret without ever seeing it. Nothing yet proves
that end to end, and nothing tells a user whether a value already leaked into an agent
transcript. EVAL-1 (security evals gate the build), GW-1 ("agent runs `env`, no key") and INJ-5
(no secrets in prompts) are still Partial/Gap waiting on this loop.

## What gets built

1. **`ms scan`** — searches Claude Code (`~/.claude/projects/**`) and Codex (`~/.codex/sessions/**`)
   transcripts for any vault value in raw form and in its base64, base64url, URL-encoded, hex
   and JSON-escaped forms. Matching runs inside `msd`; `ms` only prints what msd reports:
   `file:line  key  (encoding)`. A value never crosses the socket and is never printed.
2. **`ms-scan` crate** — the matching engine (needle building, streaming matcher, file walk).
   Used by msd, and by the e2e suite to assert "no canary in any form" over its own captures.
3. **`tests/e2e` (`ms-e2e` crate)** — the canary suite, run by the gate:
   - a throwaway msd (`--vault memory`, temp state dir, temp `HOME`), canary values made fresh
     from `/dev/urandom` on every run;
   - a fixture repo whose `.env` holds the canaries, imported with the real `ms import --yes`;
   - a fake agent (the test binary copied as `claude`) whose process tree runs `env`,
     `cat .env`, `curl` through the swap proxy and `psql "$DATABASE_URL"`;
   - assertions that no canary, in any scanned encoding, shows up in the fake agent's stdout,
     stderr, env, any file in the fixture repo, what `curl`'s target and `psql` received, or the
     receipts;
   - an intentionally leaky fixture: canaries (raw, base64 at an odd offset, URL-encoded, hex)
     planted in fake Claude and Codex transcripts. `ms scan` must report each planted line by
     file:line, exit 3, and print no value in any encoding; a clean transcript tree exits 0;
   - `ms scan` from inside an agent session is refused.
4. **Real-agent job** — `tests/e2e/real-agent.sh`: `claude -p` and `codex exec` against a copy of
   the fixture repo with a throwaway msd, then `ms scan`. Manual or nightly only. Runs only when
   `MORSEC_REAL_AGENT=1`; otherwise it prints why it skipped and exits 0 without starting msd or
   any agent (no tokens spent). Not part of the gate.
5. **`security-evals` step in `scripts/check.sh`** — runs the `ms-e2e` suite (and msd's
   `agent_e2e`) as its own named step, so the gloop build gate requires it (D7: no hosted CI).

## Decisions (made in this loop; flagged for the orchestrator to check)

- **D-1 New IPC request `Scan` and reply `ScanReport`.** Additive to protocol v1 like L07's
  additions (PLAN §4 gets one line). `Scan` has no fields. `ScanReport { findings, files_scanned,
  bytes_scanned, skipped_keys, notes, complete }`; a finding is `{ file, line, key, encoding }`.
  No field can hold a value.
- **D-2 msd picks the roots; a client names no path.** `$CLAUDE_CONFIG_DIR/projects` (else
  `$HOME/.claude/projects`) and `$CODEX_HOME/sessions` (else `$HOME/.codex/sessions`), read from
  msd's own environment. Same rule as `RulesGet` (msd never reads a path a client names), so the
  scan can't be pointed at arbitrary files. Tests start msd with a temp `HOME`.
- **D-3 Refused inside an agent session.** A scan answers "is value X in a file I can write?",
  which is a guessing oracle for low-entropy values. Only an unattributed caller (the user's own
  terminal) may scan; an agent gets `denied` with "run ms scan from your own terminal".
  Unidentified callers are already refused by msd.
- **D-4 Output: file, line, key name, encoding — never the value.** The card says "file:line
  only, never the value"; the key name is metadata (`ms list` shows it) and tells the user what
  to rotate, so it is included. File paths pass through `terminal_safe` (a file name can carry
  escape sequences).
- **D-5 Values shorter than 8 bytes are not scanned** (they'd match everywhere); their key names
  are listed as skipped. `morsec/` internal keys are not scanned (never listed).
- **D-6 Encodings:** raw; JSON-escaped; URL-encoded (upper- and lower-case `%XX`); hex (lower,
  upper); base64 and base64url at all three byte alignments, padding-agnostic, so a value inside
  a larger base64 blob is still found. Not covered (stated in `ms scan --help`): compressed or
  encrypted content, a value split across lines, partial values, other encodings.
- **D-7 Bounds:** one scan at a time (a second gets `busy`); symlinks never followed; depth ≤ 32;
  only regular `*.jsonl` / `*.json` files; files streamed in 1 MiB chunks with overlap, so memory
  stays flat on huge transcripts; a 240 s budget, after which the report says `complete: false`
  and `ms scan` says the scan was cut short (the client waits up to 300 s). Needles live in
  zeroizing buffers inside msd and are dropped when the scan ends. Findings are capped at 1000.
- **D-8 Exit codes:** 0 no leak found; 1 error (daemon down, refused); 3 a leak was found.
  An incomplete scan with no finding exits 1, never 0.
- **D-9 Fake agent = self-copying test binary** (macOS SIGKILLs relocated system shells; same
  approach as `crates/msd/tests/agent_e2e.rs`). `psql` is a fake script on the agent's `PATH`
  that records the argv and env it got: no Postgres is needed, and until L12 `Run` exists, an
  agent's `psql` can only ever see the `ms://` reference. `curl` targets a local listener
  through the swap proxy; the request is refused (no bound host) and the listener must never
  receive anything. The positive swap path stays covered by the L05 proxy itests.
- **D-10 Canary vaults never touch the keychain.** msd always runs `--vault memory` with an
  explicit `--socket` and `--state-dir` in a temp dir; the suite asserts `Status.mode ==
  "dev-memory"` before storing anything, and `HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` point
  into the temp dir for msd and every `ms` call. The real-agent job does the same; only the real
  agent itself uses the user's own config (it needs the user's login), and its transcripts are
  what the follow-up `ms scan` reads.
- **D-11 Callers outside the agent tree.** When the gate itself runs under a coding agent, the
  test process is inside an agent session. Calls that must come "from the user's terminal"
  (`ms scan`, `ms import`) run detached (reparented to PID 1), like `agent_e2e`.
- **D-12 Shared-file edits are additive:** `Cargo.toml` (two members, one workspace dep),
  `ms-ipc` protocol (one request, one reply, its `owner_loop` arm) and client (a request with a
  longer timeout), msd (`mod scan;` plus one dispatch arm), `ms-cli` `main.rs` (`Scan` stops
  being a stub), `scripts/check.sh` (one step), `ARI42.md`, `docs/PLAN.md` §4 (one line).

## Acceptance

- `npm run build` (`scripts/check.sh`) green, including the new `security-evals` step.
- The e2e suite fails if a canary reaches the fake agent's output, env, files, curl target,
  psql capture or receipts (shown by the leaky-fixture cases, which plant one on purpose and
  must be caught).
- `ms scan` reports every planted line by file:line with the right key and encoding, prints no
  value in any encoding, exits 3; a clean tree exits 0; inside an agent session it is refused.
- `tests/e2e/real-agent.sh` without `MORSEC_REAL_AGENT=1` exits 0 and invokes no agent (tested).
- `ari42_scan.py check .` clean; ARI42.md updated for EVAL-1, GW-1, INJ-5 with test names.

## Out of scope

Real `claude -p` / `codex exec` runs in the gate (manual/nightly only); scheduling the nightly
job (documented, not installed); `ms run`/`Run` (L12); live swap to a real provider; `ms doctor`
(L17); a JSON output mode for `ms scan`.
