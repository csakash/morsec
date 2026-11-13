# Evidence: L00 `foundation`

Commands run on the loop branch `feat/foundation`, 2026-11-13, macOS (Darwin 25.2), rustc 1.93.1.
Full outputs are kept outside the repo in `.loops/runs/foundation/interactive/proof/`.

## Gate

`npm run build` → `bash scripts/check.sh`, exit 0. All 8 steps passed:

| Step | Result |
|---|---|
| 1 `cargo fmt --all --check` | clean |
| 2 `cargo build --workspace --all-targets --locked` | 13 libs + 2 bins (`ms`, `msd`), 0 warnings |
| 3 `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 warnings |
| 4 `cargo test --workspace --locked` | 45 passed, 0 failed |
| 5 `cargo deny --locked check` | advisories ok, bans ok, licenses ok, sources ok |
| 6 `cargo audit --deny warnings` | 0 vulnerabilities (1490 advisories loaded) |
| 7 `scripts/supply_chain_check.py` | no patches or overrides; all 15 path packages are workspace members |
| 8 ARI-42 scan | 0 high, 0 medium, 0 low |

`crates/ms-cli/tests/check_script.rs` proves the gate fails closed (exit 1, install hint, no step
run) when `cargo-deny` is missing. Step 7 was shown to fail on `[ patch.crates-io ]`,
`["patch".crates-io]`, a root dotted `patch.crates-io.x` key, `[replace]`, and a non-member path
package.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 gate exits 0 | above |
| 2 build, 0 warnings | gate steps 2 and 3 |
| 3 `ms`/`mors` version and stub text, exit 69 | `msd/tests/cli.rs`: `version_under_both_names`, `stubs_exit_69_and_name_their_loop` (14 commands × 2 names) |
| 4 `ms status` with and without daemon | `status_with_and_without_daemon`, `port_beats_exported_socket` |
| 5 socket 0600, dir 0700 | `ms-ipc/tests/ipc.rs`: `socket_permissions`; QA step 1 |
| 6 oversized, unknown-version, zero frames | `oversized_frame_rejected`, `unknown_version_rejected`, `zero_frame_rejected`, `malformed_rejected`, `frame::tests::limits` |
| 7 `SecretBytes` Debug redacted; value gone after delete | `secret::tests::debug_is_redacted`, `memory::tests::put_read_list_delete` (memory wiping is zeroize-on-drop, not observed after free) |
| 8 KeyName/SecretRef properties and invalid forms | `key::tests::*` incl. proptests and `length_limit_is_exact` |
| 9 traits object-safe | each trait's test uses it as `dyn` |
| 10 `decide()` denies everything | `ms-rules`: `denies_everything` |
| 11 value never in JSON | `value_crosses_the_wire_only_as_raw_frame` (byte-recording relay, both directions) |
| 12 gate fails closed without cargo-deny | `check_script.rs` |
| 13 test cards | every test carries `protects / fails_when / no_claim` |
| 14 only listed files changed | plus `scripts/supply_chain_check.py` and `.gitignore` entries (`target/`, `proof/`, `.gstack/`, `.loops/`), from review and security fixes |

## Deviations from SPEC.md, with reasons

- `Decision::Deny { reason }` and `Decision::NeedsApproval { request }` are struct variants: serde
  internal tagging needs them.
- The IPC `Run` request is `{ argv, cwd }`, not a client-built `RunCall`: the session must come
  from the peer, never the client (AUTH-1). Recorded in `docs/PLAN.md` §4.
- `scripts/check.sh` has 8 steps, not 6: a build step (the integration tests run the built
  binaries, which `cargo test` does not relink) and a supply-chain step (security review S1/S5).
- New `Error::Socket` variant for socket setup failures (QA: `Protocol` told users to compare
  versions).
- `Client::connect` refuses a server running as another uid (security review S2).

## Review record

- Code review, 2 cycles: R1–R8 fixed (R8 is this file); cycle 2 found 0 important, R2 gap, R9 and
  R10 fixed or recorded (R9 is an open decision in the L12 card).
- Security review, 2 cycles: S1, S2, S4, S5 fixed; S3 (bind TOCTOU under an attacker-writable
  ancestor) and S6 (connection starvation of the kill switch) are carried into the L07 card with
  reasons.
