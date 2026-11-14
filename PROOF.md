L11 `approvals-macos`, CLI only (no Swift app). The deny-stub approver is replaced by a real one behind the frozen `Approver` trait:

- A request that needs approval waits in msd, one at a time.
- A person reviews it with `ms approve` in their own terminal. `ms start`, `ms rules` and `ms scan` show the same review inline.
- msd itself raises the Touch ID sheet (LocalAuthentication, with a password fallback) before approving.
- The approval is an HMAC token bound to the session, key, argv hash, cwd, scope and expiry. It is checked against the exact request before anything acts on it.
- `Scan` now goes through the approver too.
- The pre-L11 `--at-terminal` path is removed.

See `SPEC.md` for the design decisions (D1–D10).

## Testing

- **Gate:** `npm run build` (`scripts/check.sh`: fmt, build, clippy `-D warnings`, all tests including the keychain ACL tests, cargo-deny, cargo-audit, supply-chain check, shellcheck, ARI-42 scan, canary security-evals). It passed at 750c552 and again after the review fixes; see `proof/build-morsec.txt`. No keychain dialog blocked it.
- **Changing one argument after approval makes the executor refuse:**
  - `ms-approve` `token::any_change_after_approval_is_refused` covers argv, cwd, key, session pid, session start and agent, plus forged expiry, scope, MAC and another daemon's key.
  - `broker::approve_then_one_argument_changes` covers the person approving and then `verify` with one argument changed.
  - `msd` `Daemon::approve_exact` and the swap proxy's `VerifyingApprover` verify against the exact request before acting.
- **A timeout is rejected:**
  - `broker::timeout_is_rejected` (and nothing is approved late).
  - `broker::touch_id_finishing_late_approves_nothing`.
  - `daemon::tests::start_needs_touch_id_approval` covers an unanswered request.
- **ANSI, RTL-override and newline payloads render inert:**
  - `render::payloads_render_inert` covers ANSI/OSC, U+202E, CR/LF, NUL, zero-width, isolates, C1 and backslash, in both `ms approve` and the Touch ID reason.
  - `render::long_commands_are_never_silently_cut`.
  - `ms-cli` `approve::screen_is_inert`.
- **An agent-tree caller cannot approve:**
  - `daemon::tests::approvals_ipc_rules`: an agent can't list or decide.
  - Real binaries, `crates/msd/tests/agent_e2e.rs`: a fake `claude` tree's `ms approve` is refused even when it types `o` into its own pseudo-terminal. The person's `d` in their own terminal refuses the agent's loosening and its `ms start`. `o` from the user's terminal applies a loosening, recorded with `touch-id` and the token id.
- **One prompt at a time:**
  - `broker::one_prompt_at_a_time`: a second request is refused at once.
  - `approvals_ipc_rules`: `Busy` over IPC.
- **Scopes:**
  - `broker::session_scope_covers_only_the_same_request`.
  - `token::expiry_reuse_and_revocation`: once tokens are single-use, and `ms stop` revokes.
  - `broker::stop_during_touch_id_approves_nothing`: review finding R1, `ms stop` while the sheet is up.
- **Failed or cancelled Touch ID denies:** `broker::failed_touch_id_denies_and_deny_needs_none`, `daemon::tests::failed_touch_id_denies`.
- **Scan behind the approver:**
  - `daemon::tests::scan_refused_inside_agent`: unapproved scans time out or are denied, and the denial is recorded.
  - The e2e canary `ms_scan_catches_a_leaky_transcript` approves through the inline review on a pty.
- **QA:** the real `ms`/`msd` were driven from a detached "own terminal". See `proof/qa.md` and `proof/qa/qa-run.txt`.
- **Needs a human (not automated):** the real Touch ID sheet. On a Mac with Touch ID:
  1. `ms init`, then `ms stop`.
  2. Run `ms start` and answer `o`.
  3. Check that the system sheet appears from msd. Its text should name `morsec/daemon`, the scope and `"ms" "start"`, and show the same fingerprint as the terminal.
  4. Check that a finger approves.
  5. Check that "Use Password…" works with the login password.
  6. Check that Cancel denies ("Touch ID did not confirm").
  7. Leave the sheet up for more than 120 s and check that it is taken down and the request is rejected.

  Not yet done.

## Risk

- **Sensitive paths (need a human reviewer):**
  - `crates/ms-approve/**`: the approver, token, Touch ID and `unsafe` FFI to LocalAuthentication, each block with a SAFETY comment.
  - `crates/msd/src/daemon.rs` and `approve.rs`: approval wiring, stop/start, scan.
  - `crates/ms-ipc/src/protocol.rs`: two new messages, which are additive.
  - `crates/ms-cli/src/{approve,service,rules,scan}.rs`.
  - `Cargo.lock`: new dependencies `objc2`, `objc2-foundation`, `objc2-local-authentication` and `block2`. They are MIT/Zlib/Apache, pass cargo-deny and cargo-audit, and only msd enables the `touch-id` feature.
- **Residual risks (recorded in ARI42.md AUTH-3):**
  - A detached same-user process is not an agent session, so it can send a decision. The gate is then the Touch ID sheet, whose text msd writes, plus a person reading it.
  - A same-user process can write into the `ms approve` terminal. The sheet's text is the authoritative copy.
  - Run-mode executors (L12/L15/L16) must call `Daemon::approve_exact`.
- **Behaviour changes:**
  - `ms start`, a loosening `ms rules` and `ms scan` now need Touch ID.
  - `ms init --resume` is an alias of `ms start`. `ms rules --at-terminal` is hidden and ignored with a note.
  - msd ignores `at_terminal`.
  - Production-tier swap requests through the proxy can now be approved by a person, where before they were always denied.
- **Test-only flag:** msd has `--test-touch-id allow|deny`. It is refused unless the build is debug and the vault is `--vault memory`.

## How to revert

Revert the PR's merge commit (or `git revert` the L11 commits 54c1028..6a60e0d, excluding the merge of origin/main). This restores the L07 deny-stub, under which production keys are refused and `ms init --resume` / `--at-terminal` are the recovery path. No data migration is involved. Tokens and pending approvals live only in msd's memory, and the receipts format is unchanged (`approval_id` and `approval_method` were already fields).
