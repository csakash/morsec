# Evidence: L02 `receipts`

Commands run on the loop branch `feat/receipts`, 2026-11-13, macOS (Darwin 25.2), rustc 1.93.1.
Full outputs are kept outside the repo in `.loops/runs/receipts/interactive/proof/`
(`build-morsec.txt`, `qa-cli.txt`).

## Gate

`npm run build` → `bash scripts/check.sh`, exit 0. All 8 steps passed:

| Step | Result |
|---|---|
| 1 `cargo fmt --all --check` | clean |
| 2 `cargo build --workspace --all-targets --locked` | 0 warnings |
| 3 `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 warnings |
| 4 `cargo test --workspace --locked` | 74 passed, 0 failed (ms-receipts 12 unit + 13 integration incl. a property test; ms-cli `log_cli` 5) |
| 5 `cargo deny --locked check` | advisories ok, bans ok, licenses ok, sources ok |
| 6 `cargo audit --deny warnings` | 0 vulnerabilities (131 crates) |
| 7 `scripts/supply_chain_check.py` | no patches or overrides; all 15 path packages are workspace members |
| 8 ARI-42 scan | 0 high, 0 medium, 0 low |

New dependencies (all RustCrypto/mainstream, already declared in `[workspace.dependencies]` by
L00): `hmac 0.12`, `sha2 0.10`, `hex 0.4`; `serde_json` gains the `raw_value` feature.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 gate exits 0 | above |
| 2 multi-file store verifies with the key | `store.rs::rotation_checkpoints_and_permissions` (40 receipts, ≥ 3 files, ≥ 10 checkpoints) |
| 3 tampering fails verify at the right record | `tampering_fails_verify`: in-place edit and edit + re-chain (BadMac), delete (MissingRecords, line 3), swap (MissingRecords at line 2), duplicate (OutOfOrder), middle file removed, first file removed (BadGenesis), torn line, record MAC'd with another key, garbage line; chain-only check catches removal, reorder, duplication and torn lines. `bad_checkpoint_detected` (validly MAC'd checkpoint with wrong head). Property test `any_byte_flip_fails` (24 cases: any single bit flip in any line fails). QA: `ms log --verify` after deleting record 3 exits 1 naming line 3 |
| 4 every §3.4 field | `receipt_has_every_field` (absent fields written as `null`) |
| 5 canary never on disk | `canary_never_written` (value redactor + shape patterns across target, argv, failure message, approver, method, agent name); `redact::tests::*` incl. `_`-suffixed env names, quoted and escaped values, any `Authorization` scheme, cookies, `mysql -p…`, `--db-password`, and value forms: percent-, form-, JSON-escaped, base64/base64url at all 3 alignments, non-UTF-8. QA: `grep -c hunter2` = 0 in the seeded store |
| 6 LOG-2 alert | `alert_detector`: 4 blocks no alert; 5th (a denial) one alert with `stop_session`; 5 more in the same window no second alert; a new burst after the window alerts again; other sessions and spread-out attempts don't count |
| 7 reopen resumes; fail closed | `reopen_and_fail_closed` (resume seq/prev; wrong key, missing key, 16-byte key, torn tail) |
| 8 query filters | `query::tests::filters`, `counts`; CLI `log_table_and_filters` |
| 9 CSV/JSON export | `export::tests::csv_cells`; CLI `exports` (formula prefix `'`, controls as `\u{..}`, JSON round-trips the original string, `--out` 0600 and never overwrites) |
| 10 CLI end to end, `ms` = `mors` | `log_cli.rs` (5 tests) and `mors_alias_matches`; QA transcript `qa-cli.txt` |
| 11 dir 0700, files 0600, unsafe paths refused | `rotation_checkpoints_and_permissions`, `refuses_unsafe_paths` (0755 dir, symlinked dir, symlink at file name), `hard_link_at_next_name_refused`, `hostile_files_fail_closed` (FIFO, oversized file) |
| 12 test cards | every test carries `protects / fails_when / no_claim` |
| 13 only listed files changed | `git diff --stat main..HEAD`: `crates/ms-receipts/**`, `crates/ms-cli/{Cargo.toml,src/main.rs,src/log.rs,src/stats.rs,tests/log_cli.rs}`, `crates/msd/tests/cli.rs` (two stub rows removed), `Cargo.lock`, `ARI42.md` (LOG-1/2/4 + change log), this file, `PROOF.md`, `SPEC.md` |

## Deviations from SPEC.md, with reasons

- `ms log --verify` rejects filter flags (code review C2): it always checks the whole store.
- A seq gap caused by a swap is reported as `MissingRecords` at the first out-of-place line, not
  `OutOfOrder` (it can't be told apart without look-ahead).
- Redaction goes further than §2 listed (security review S1–S4), and reads are hardened against
  FIFOs, symlinks and files over 64 MiB (S6); `max_file_bytes` is capped at 32 MiB.
- `crates/msd/tests/cli.rs`: `log` and `stats` removed from the stub table, as SPEC allowed.

## Review record

- Code review (fresh context): 8 findings, all fixed with tests (R1–R4 redaction gaps, T1 panic
  on a multibyte time, A1 second alert in a window, C1 overstated `--verify` note, C2 filters
  ignored by `--verify`).
- Security review (fresh context): 13 findings, 0 critical, 0 high. Fixed with tests: S1–S8, S11.
  Recorded, not fixed here (outside L02's paths or accepted): S9 reserve `morsec/` key names (L03,
  L04), S10 tail truncation/rollback across a daemon restart (anchor head in the vault, L07; L23),
  S12 `hmac` pad state not zeroized (accepted), S13 `approval.token_id` must be an opaque id
  (L07, L11). See SPEC.md "Open items" and ARI42.md LOG-1.
- Convergence review of the fix commits (cycle 2): every earlier finding confirmed fixed. 5 new:
  N1 quoted `Authorization` credential and N2 values containing `%` / `\` / non-ASCII in encoded
  form (both important, fixed and tested; `match_at` now backtracks, iteratively and memoised);
  N3 `-pVALUE` behind `sudo`/`env`/`docker exec`, `sshpass -p`, `curl -u user:pw` (fixed, tested);
  N4 over-redaction of `key: …` and `--no-auth` (fixed, tested); N5 a failed rotation stops the
  store until restart (accepted: fail closed). Fixes that lacked tests now have them: symlink
  reads, hard-linked reopen, detector hard cap. Review loop stops here (`fixCycles` 2).
