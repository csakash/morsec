# Evidence: L03 `rules-policy`

Commands were run on the loop branch `feat/rules-policy` on 2026-11-13: macOS (Darwin 25.2), rustc
1.93.1. Full outputs are kept outside the repo in `.loops/runs/rules-policy/interactive/proof/`
(`build-morsec.txt`, `qa.md`, `qa-transcript.txt`).

## Gate

`npm run build` runs `bash scripts/check.sh`, which exited 0. All 8 steps passed: fmt, build,
clippy `-D warnings`, test, cargo deny, cargo audit, the supply-chain check and the ARI-42 scan
(0 findings). The final numbers are in `PROOF.md`.

The lockfile gains crates.io crates through the workspace dependencies that L00 already declared:
`hmac` 0.12.1, `sha2` 0.10.9, `hex` 0.4.3, `toml` 0.8.23 and their RustCrypto and toml_edit
dependencies (`digest`, `block-buffer`, `crypto-common`, `generic-array`, `typenum`, `subtle`,
`cpufeatures`, `version_check`, `toml_edit`, `toml_datetime`, `toml_write`, `serde_spanned`,
`winnow`). ms-rules also uses `libc` (for `O_NONBLOCK`), and ms-cli uses `serde_json`; both were
already locked. cargo deny passes. The duplicate `syn` 2 and 3 warning was already on main.

## Canonical argv hash (for L02, L11 and L12)

`ms_rules::argv_hash(argv)` is SHA-256 over:
1. the bytes `morsec-argv-v1\0`;
2. then, for each argument in order, its UTF-8 byte length as a big-endian u64, followed by the
   argument's bytes.

The length prefixes make the hash unambiguous: `["a b"]`, `["a","b"]` and `["ab",""]` all differ.
`argv_hash(["psql","-c","select 1"])` is
`1119efc56811fc6451e14705348a585f933a037109bb6d5eed8510228209f8de`. The test
`argv_hash_is_unambiguous_and_pinned` pins this value, and it was checked independently with
Python `hashlib`. Every `ApprovalRequest` built by `decide` or `decide_run` sets
`argv_hash = argv_hash(argv_display)`, so the hashed argv is exactly the one shown. Swap approvals
use `["swap", host]` and mint approvals use `["mint", scope]`.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 gate passes | above |
| 2 a project file never widens | `project::tests::project_never_widens`: proptest, 2000 cases, every mode, both `decide` and `decide_run`; also checks TTL, tier, read_only and mode. The pattern proptests `host_intersection_is_exact` and `command_intersection_is_exact` show the intersection is exact. Further tests: `tightens_as_documented`, `disables_fail_closed`, `change::tests::merge_result_is_never_a_loosen`, CLI `project_file_tightens_and_broken_file_disables` |
| 3 tampering fails closed | `store::tests::tampering_fails_closed` covers: edited rules, whitespace-only edit, flipped, garbage, empty, oversized and missing MAC, a file MAC'd by another vault's key, a missing or short MAC key, rollback to v1 after v2, and a deleted file after a version was seen. Also `oversized_rules_file` (including a FIFO in place of the file) |
| 4 decision table | `policy::tests::decision_table`: 3 modes × 2 tiers × (allowed, not allowed, each wrong mechanism), plus unknown key, stopped, tampered (tampered beats stopped), `Rules::tampered()`, empty rules and reserved `morsec/` keys. Also `swap_host_edge_cases` |
| 5 production → NeedsApproval | proptest `production_always_needs_approval` (never `Allow`; always `NeedsApproval` when the rule matches) |
| 6 approval binding | `decide_run_binds_approval_to_argv`, `argv_hash_is_unambiguous_and_pinned` |
| 7 CLI | `ms-cli/tests/rules_cli.rs`: `list_and_show`, `project_file_tightens_and_broken_file_disables`, `check_project_file`, `proposals_are_classified_and_not_written`, `output_is_terminal_safe`, `missing_rules_file`; unit test `project_lookup_stops_at_git_root`; manual QA |
| 8 test cards | every new test has `protects / fails_when / no_claim` |

## Deviations from SPEC.md, with reasons

- **AC2 property restated (review R1).** The frozen `Request::Run` carries only a hash, so
  `decide` matches run requests only against wildcard-free patterns. A merge can narrow
  `["psql","*"]` to the literal `["psql","a"]`, which `decide` then matches. The user rule already
  allowed that argv, so this is not a widening. The property is now judged against the full
  request: `decide_run(u)` for run requests and `decide(u)` otherwise. `SPEC.md` records the
  original wording. The proptest found the case; its seed is in `proptest-regressions/`.
- **Reserved `morsec/` key namespace (security review S1).** No rule may name `morsec` or
  `morsec/*`, and policy denies them even if one gets into memory. This keeps the rules and
  receipts MAC keys from ever going to a host or a command through an approved loosening.
- **Project lookup outside a git repo finds nothing (review R6).** SPEC said "up to the git root".
  Outside a repository, nothing is picked up.
- **`save` validates what it writes (review R5).** It round-trips through the file format, so the
  limits match `load`, including the 1 MiB file size.

## Interfaces

No frozen interface changed. `decide` keeps its signature. These are new, additive and owned by
L03: `decide_run`, `argv_hash`, `permissiveness`, `is_reserved`, `RulesStore`, `effective`,
`merge`, `classify`, `classify_rule`, and the pattern types. Outside the owned paths, three files
changed:
- `crates/ms-cli/src/main.rs`: `mod rules;`, the `Rules` arms, and an
  `allow(clippy::large_enum_variant)` on `Command`;
- `crates/msd/tests/cli.rs`: the `rules` row is removed from the stub table;
- `docs/PLAN.md`: the L07 card carries the rules wiring and the IPC gap.

## Review record

- **Code review cycle 1:** 1 important (R1) and 6 nits (R2–R7), plus a FIFO hardening point. All
  were fixed in b6b2370.
- **Code review cycle 2:** 0 important. Nits on R5 (size limit), R7 (hex labels) and N1 (pipe
  message) were fixed in 45a575a.
- **Security review:** 0 important, 4 nits.
  - S1 (reserved MAC key names) and S3 (pairwise amplification) were fixed in 5980a0c.
  - S4 (empty hosts on run/mint keys must mean "no host") is documented on `KeyRule::hosts` and is
    an open item for L15 and L16.
  - S2: hmac 0.12 does not zeroize its inner state after the closure. Accepted: the threat model
    keeps msd memory out of the agent's reach. It is an open item.
- **QA:** three output bugs fixed in e813a00 (see `qa.md`).

## Open items

1. **IPC gap (L07 or a small IPC loop).** `RulesProposeLoosen` needs a field for the proposed rule
   and there is no `ResponseBody::Rules` reply. Until those exist, `ms rules` reads local files and
   labels them "MAC not checked by ms; msd verifies it". Edits are previewed and the command exits
   69. The L07 card in `docs/PLAN.md` has the wiring.
2. **L07 must pass a real `min_version`** (from the receipt chain) to `RulesStore::load` and
   `save`. Rollback protection depends on it.
3. **L01/L07 create the vault key `morsec/rules-mac`** (≥ 32 bytes). L02 uses a separate
   `morsec/receipts-hmac`.
4. **L11 and L12 use `ms_rules::argv_hash`.** L12 calls `decide_run` with the real argv.
   `argv[0]` is compared literally.
5. **S4 for L15 and L16:** an empty `hosts` list on a run key means no host.
6. **S2:** consider an hmac release with zeroize support when it is available.
7. `ARI42.md` totals line ("In scope: 27 (…)") was not edited, so parallel loops don't conflict.
   AUTH-2 and AUTH-3 moved from Gap to Partial. Recount at merge.
