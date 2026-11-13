# Evidence: L04 `import-env`

Commands run on the loop branch `feat/import-env`, 2026-11-13, macOS (Darwin 25.2), rustc 1.93.1.
Full outputs are kept outside the repo in `.loops/runs/import-env/interactive/proof/`
(`build-morsec.txt`, `qa.md`, `PROOF.md`).

## Gate

`npm run build` → `bash scripts/check.sh`, exit 0. All 8 steps passed: fmt; build; clippy
`-D warnings`; 86 tests passed, 0 failed (workspace); cargo deny (advisories, bans, licences,
sources ok); cargo audit (0 vulnerabilities); supply-chain check (15 path packages, all members);
ARI-42 scan (0 findings).

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 gate exits 0 | above |
| 2 parser golden tests and properties | `dotenv::tests::{golden, loader_compatible_forms, unknown_lines_refused, bare_cr_refused, errors_fail_closed, rewrite_splices}`; proptests `never_panics` (arbitrary `String`), `never_panics_ascii`, `untouched_rewrite_is_identity` (CR/CRLF/tab input) |
| 3 classifier table | `classify::tests::{provider_table, not_imported, unknown_scheme_not_shown}`, `plan::tests::naming_and_dedupe` (AWS pair, duplicate value → one key, unknown → swap with no hosts) |
| 4 catalog loads and validates | `catalog::tests::{builtin_is_valid_and_complete, validator_rejects, longest_prefix, env_names}` |
| 5 library end to end | `envfile::tests::import_leaves_only_refs` (refs only, mode kept, no file in the dir holds the canary, no temp left) |
| 6 fail closed | `envfile::tests::{store_failure_leaves_file, concurrent_change_aborts, refusals}`; `plan::tests::{repeated_variable, inline_comment_on_secret_refused}` |
| 7 CLI | `ms-cli/tests/import_add.rs` (6 tests, `ms` and `mors`), `hidden_input.rs` (4 pty tests, mutation-checked), `import::tests::table_is_masked` |
| 8 git warning | `envfile::tests::git_history_detects_commits`, `import_add::warns_when_committed` |
| 9 reviews, QA, proof, ARI-42 | below; `ARI42.md` INJ-5 and GW-1 rows |

## Review record

| Id | Finding | Resolution |
|---|---|---|
| S1 (important) | `KEY: value`, dashed names and junk lines skipped silently, leaving keys in plaintext; partial values left by ` #` | fixed 9e1bc2a (amendments A1, A2) |
| S2 (important) | `EnvFile` derived `Debug` printed the file | fixed 9e1bc2a |
| S3 (nit) | text before `://` shown as a scheme | fixed 9e1bc2a (A7) |
| R1 (important) | `--name` on a repeated variable lost a value | fixed 811cdeb (A5) |
| R2 (important) | public-name prefix beat a secret-looking name | fixed 811cdeb (A4) |
| R3 (important) | bare CR merged lines | fixed 811cdeb (A3) |
| R4 (important) | proptests never generated line breaks | fixed 811cdeb |
| R5 (nit) | same-value rule rewrites config values | decided, amendment A6 |
| R6 (nits) | prompt text, buffer growth, control keys, test wording | fixed 811cdeb (A8) |

Security re-review of the fixes: no issues.

## Not proven here

- Storing through msd: IPC v1 has no success reply for `ListKeys`/`PutKey` (L07). The CLI fails
  closed and is tested to; storing itself is proven against `MemoryVault`.
- The cargo-fuzz target (`crates/ms-import/fuzz`) was not run (no nightly or cargo-fuzz here).
- Keychain storage and canary scans of real agent transcripts: L01 and L09.
