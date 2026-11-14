# L12 `run-core`: run mode (shim, runner, streaming redactor, generic adapter, `ms run`)

Spec: `SPEC.md` (decisions D0–D10; D1, D2 and D4 amended during build after review). An agent's
command that carries an `ms://` ref for a run-mode key now runs inside msd: the binary comes
from a trusted search path, the arguments travel as an array (never a shell), the environment is
built from nothing, the working directory must be inside the key's project roots, and output is
redacted in every encoding before it comes back. Without a ref, the shim runs the real tool
unchanged.

## Testing

`npm run build` (scripts/check.sh: fmt, build, clippy `-D warnings`, all tests including the
macOS keychain tests, cargo deny, cargo audit, supply-chain check, packaging tests, ARI-42 scan,
security-evals canary suite) passes on the final commit `40c75eb` with a clean tree: 376 tests.
No keychain dialog blocked it.

Card Verify list:

| Check | Test |
|---|---|
| Injection payloads in arguments never reach a shell (OUT-1) | `ms-run` `tests/runner.rs::injection_payloads_never_reach_a_shell` (`;`, `$( )`, backticks, `&&`, `\|`, newline stay literal single args; marker file never created); e2e `run_mode_through_shims` "inject" through the real shim and msd |
| Split-chunk redaction | `redact::tests::{split_at_every_offset, split_into_single_bytes, overlapping_values, random_chunking (proptest), hold_is_bounded, base64_boundaries_are_redacted}`: value and its raw, base64, base64url, hex and URL forms split at every byte offset, one byte at a time, overlapping values |
| The "agent runs `env`" test | `tests/runner.rs::agent_runs_env` (env is exactly PATH, HOME and the forwarded variable; the test process's CARGO_* vars absent; value redacted; base64 and hex copies redacted); e2e `run_mode_through_shims` "env" (fake `claude` agent → shim → real msd: only PATH/HOME/LANG/TMPDIR/USER/LOGNAME and the variable reach the child; the agent's own variables don't) |
| A non-allowlisted binary is refused | e2e "notallowed" (exit 77 and a `blocked` receipt); `resolve::tests::resolves_safely` (writable, non-executable, missing, shim-linked and relative programs refused) |
| A cwd outside the project roots is refused | `cwd::tests::roots_are_enforced` (outside, via a symlink, via `..`, a sibling sharing a prefix, a symlinked root); e2e "outside" |

Also covered: production keys ask the `Approver` with the request msd built and run only when
approved (`daemon::run::tests::production_runs_need_the_approver`, a fake approver: deny, then
approve); values only in rule-named variables as whole values
(`env_only_as_the_rule_names_it`, e2e `notwhole`/`othername`/`foreign`); `ms stop` kills a
running command (`stop_kills_a_running_command`; QA: killed within 1 s); exit codes and signals
pass through (`exit_codes_pass_through`); stdin forwarding (`stdin_and_stderr`; QA); a cancelled
run kills the whole process group (`cancel_kills_the_group`), as does the time limit
(`time_limit`); a slow client gets all output (`slow_reader_gets_all_output`); a `setsid`
descendant doesn't stall the run (`escaped_descendant_does_not_stall`); the IPC stream (`ms-ipc`
`tests/stream.rs`: round trip, refusal leaves stdin unread, disconnect cancels, including under
stdin backpressure); the shim passes through without a ref, doesn't loop through two shim
directories, and fails closed with exit 69 when msd is down (`ms-run` `tests/shim.rs`); an
idle open stdin doesn't hold the shim after the command ends (e2e "idle"); `roots`/`env`
round-trip and count as loosening (`ms-rules` tests). The regression tests for review R2, R3
and R4 were checked to fail on the code before the fix.

QA: real `ms`, `ms-shim` and a dev msd on port 4300, driven from a Claude Code session (so msd
attributes every call to a real agent session); the transcript and receipts are in the loop's
`proof/qa.md`. No value appeared in any output, log or receipt. QA found two issues, both fixed
in 5c255e7: base64 boundary characters left after a redaction, and a misleading `ms run`
message.

Review: a fresh-context code review ran 4 rounds (R1–R9; important: stdin read before msd
answered, a hang on an idle stdin, a 590 s stall when a descendant leaves the group, a missed
client disconnect under stdin backpressure, and output cut for slow readers by the first R3
fix). All are fixed and re-verified. Nits are fixed except R6 (wontfix: needs more than 64 KiB
of a self-overlapping value repeated back to back; recorded as a residual) and N2/N3 (follow-ups,
below). Security review: S1 (important, reproduced: agent-chosen variables such as
`CURL_HOME=…/ms://x` made an allowlisted curl read the agent's config and send the token to the
agent's listener) is fixed with per-key `env` names and whole-value refs. S2 (a symlinked root
classified as tightening) and S3 (`ms stop` didn't reach runs in progress) are fixed. The
re-review found no issues.

Not verified here: production keys with a real approver (L11 builds it; on main the deny-stub
refuses them, QA shows the message); Linux (built and tested on macOS only; the code is
portable, but there is no Linux run); real Claude Code or Codex sessions using the shims (the
fake-agent e2e and this session's own process tree stand in); `ms-shim` in a release build
(packaging doesn't ship it yet, see Risk).

## Risk

- **Sensitive paths (gloop risk: 35 files).** All are in the crates that handle secrets:
  - IPC protocol and server: `crates/ms-ipc/src/{protocol,server,client}.rs`. Additive to v1:
    `RunStream`, `RunInput`, `RunInputEnd`, `RunStarted`, `RunOutput`, `RunExit`, `RunResult`,
    optional `env` on `Run`, error code `not_run`, `Handler::handle_stream` with a default.
  - Rules model: `crates/ms-rules/src/{model,change,project}.rs`. New per-key `roots` and
    `env` fields; adding either is loosening; projects can't add them.
  - msd dispatch: `crates/msd/src/daemon.rs` and the new `daemon/run.rs`.
  - `ms run` and `ms rules`: `crates/ms-cli/src/{run,rules,main}.rs`.
  - `ms-scan`: `Needles::patterns()`, read-only.
  - `ms-core`: one test comment.
  - All of `crates/ms-run`.
  - `Cargo.lock`: no new crates. `aho-corasick` and `rustix` were already in the lock; new
    edges only.

  A human should review the env and roots policy in `crates/msd/src/daemon/run.rs` and the
  redactor in `crates/ms-run/src/redact.rs` with particular care.
- **Behaviour change for existing rules:** a run key now needs `roots` and `env` names before
  it can run anything (fail closed, with the fix in the error). Run mode was not built before, so
  no working setup breaks.
- **Residuals (ARI42 OUT-4 Partial until L23):**
  - Children run as the same user, so a same-user process can read their environment or race
    the cwd check.
  - A descendant that calls `setsid` leaves the process group: it isn't killed, though it no
    longer holds the run.
  - The redactor's automaton and std `Command`'s copy of the environment are not zeroized.
  - Output transformed in ways the encoders don't cover (compressed, split by the program) is
    not caught.
- **Packaging:** `scripts/release.sh`, the signing targets and the Homebrew formula (L10's
  files) don't ship `ms-shim` yet. Until they do, `ms run --link-shims` in an installed build
  says ms-shim is missing. `ms run` itself works.

## How to revert

`git revert` the loop's commits (SPEC.md commit `9f64b8d`, then `5bdf0a8`, `1866c55`,
`a6d5001`, `5c255e7`, `40c75eb`), or revert the merge commit. Rules files written with the new
`roots`/`env` fields would then fail to load: the old `deny_unknown_fields` parser marks the
rules tampered and refuses everything, which fails closed. Remove those two fields (or run
`ms init --force` on a dev setup) after reverting. Shim links in `~/.morsec/shims` can be
deleted; without them agents' PATH falls through to the real tools.
