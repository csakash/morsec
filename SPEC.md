# SPEC: L31 guided-init

Source: `docs/design/guided-setup-dashboard.md` §4 and §5 (merged in csakash/morsec#31), card L31
in `docs/PLAN.md` Wave 7. This SPEC refines the design where reading the code changed the plan
(marked **Refinement**).

## Context

Protecting one key takes five commands today, and imported keys sit unusable until the user runs
`ms rules --add-host` for each one, answering Touch ID for every key. A non-technical user should
type `ms init` in a project folder and be done: secrets found, moved into the vault, `.env`
rewritten, agents connected, keys able to reach their services after one fingerprint.

## Current state (verified on `main` 9567a5a)

- `ms init` (`crates/ms-cli/src/service.rs`, `InitArgs`: `--force`, `--no-launchd`, `--trust`,
  hidden `--resume`) creates the vault and LaunchAgent. It ignores the current directory.
- `ms import` (`crates/ms-cli/src/import.rs`) handles one file: `EnvFile::read` → `plan::plan`
  with the built-in catalog → table → confirm (or `--yes`) → `envfile::commit`, which stores each
  value through the `KeyStore` trait (`IpcStore` → `PutKey`) and then rewrites the file
  atomically.
- The plan computes catalog hosts per row (`Row::hosts`), but msd's `put_key`
  (`crates/msd/src/daemon.rs:882`) gives every new key a rule that allows nothing. That is
  deliberate and tested (`put_key_and_list`: "a new key is usable before the user allows a target"
  must fail): an agent may create keys, and they stay inert. So today every imported key needs its
  own `RulesProposeLoosen` and its own Touch ID.
- Rule loosening goes through `propose` (`daemon.rs:1007`): `classify_rule`, then
  `approve_exact` on an `admin_request` whose argv carries the exact rule text, so the approval is
  bound to it.
- Agent-session refusals are done in `Daemon::handle` by matching `in_agent`
  (`daemon.rs:625–660`).

## Decisions

- **D-1 (Refinement of design §4.3): orchestration in the CLI, logic in a library.** The design put
  scan and import inside msd. L31 runs them in `ms init` instead, through a new library crate
  `ms-projects` and the existing `KeyStore`/`PutKey` path that `ms import` already uses and
  tests. Values cross the peer-verified socket exactly as `ms import` sends them today. L33's
  dashboard Add project calls the same library inside msd with a direct vault `KeyStore`.
  The design doc is updated to say so.
- **D-2: one Touch ID for the whole project.** New request `ProjectSave` carries the project record
  and the initial rules for the project's new keys (catalog hosts for swap keys, the project root
  for run-mode keys). msd applies them only after one approval that is bound to the hash of the
  exact `(key, rule)` set. The approval sheet and `ms approve` list every key with its hosts or
  root. The per-key "new key allows nothing" rule in `put_key` is unchanged. Zero questions
  (design D2) still holds: a fingerprint is not a question. If the person declines or the approval
  times out, the keys stay stored and inert, and the summary says how to finish (`ms init` again).
- **D-3: no dashboard and no `ms dev` lines yet.** The summary points at `ms projects` until L32
  and L34 land.

## Behaviour

### Mode detection (design §4.1, unchanged)

`ms init [--machine | --project [PATH]] [--name NAME] [--no-connect]`; existing flags keep their
meaning. Project markers, the `$HOME` dotfiles-repo rule and the excluded roots are as in design
§4.1. `--force`, `--trust` and `--resume` behave as today and imply machine mode.

### Machine steps (both modes, each skipped when already done)

1. Vault, LaunchAgent, msd up (today's `ms init`).
2. CA trust (today's `ms init --trust`; macOS asks once). If the user declines, keep going and say
   swaps for Go tools will fail until `ms init --trust`.
3. Connect detected agents unless `--no-connect`: `claude-code` when `claude` is on `PATH` or
   `~/.claude` exists, `codex` likewise with `codex` / `~/.codex`. Uses `connect::run` with
   `yes = true` and no `--env`. A connector that fails is reported and doesn't stop init.
4. `ms doctor` static checks; failures are listed in the summary.

### Project steps

1. Slug and display name (design §4.4). Moved-project detection is out of scope for L31: a second
   root with the same basename gets the hash suffix.
2. Walk (design §4.5): `ms_projects::walk`, directory fd + `openat(O_NOFOLLOW)`, no symlinks, one
   device, the skip list, budgets (200,000 entries, 10 s, env files ≤ 1 MiB, source files ≤ 512 KiB,
   5,000 source files). The budgets are parameters so tests can make them small.
3. Classify files: env files (imported), example files (hints only), source files (code findings
   via `Catalog::match_prefix` only).
4. Plan per env file with `plan::plan`, then apply project naming (`<slug>/<var-slug>`, file
   segment on a value clash, tier raised by file name) through `Options::names` and
   `Options::tiers`. Example-file names are added to `Options::include` when the classifier
   called that variable "not secret" in a real file.
5. `envfile::commit` per file with the IPC store. A file that fails to parse or commit is
   listed and left untouched; the others go on.
6. `ProjectSave { record, rules }` (one approval, D-2).
7. Agent hint block (design §4.7) appended to `CLAUDE.md` and/or `AGENTS.md` at the root when
   they exist and don't already hold `<!-- morsec:begin -->`. Written atomically, mode kept.
8. Summary (plain English, every agent-influenced string through `terminal_safe`):

```
morsec is on.

Project    shop  (~/code/shop)
Found      14 secrets in 3 files
Protected  12, ready to use
Needs you  2 have no known service yet: ms rules shop/session-secret --add-host <host>
In code    1 key written straight into src/lib/stripe.ts:4 (move it into .env, then ms init)
Committed  .env is in 2 git commits: rotate those keys at each provider
Agents     Claude Code, Codex connected

See everything: ms projects shop
```

### `ms projects [SLUG]`

No slug: one line per project (slug, root, protected, needs-you, findings). With a slug: the
record as a table, values never shown (masked as the import table does).

### IPC (protocol version bump)

| Request | Refused in agent session | Approval | Reply |
|---|---|---|---|
| `ProjectSave { record: ProjectRecord, rules: Vec<(KeyName, KeyRule)> }` | yes | one, if any rule loosens; bound to the hash of the canonical TOML of all rules | `Ok { message }` with counts |
| `ProjectList` | no | none | `Projects { projects: Vec<ProjectSummary> }` |
| `ProjectGet { slug }` | no | none | `Project { record: ProjectRecord, keys: Vec<KeyStatus> }` |

`ProjectSave` checks, in msd: every key starts with `<slug>/`; every key exists in the vault;
every rule is for a key whose current rule allows nothing (new keys only; anything else is
refused with "use ms rules"); swap rules carry only hosts, run rules only `roots == [record.root]`
and the env/commands the catalog gives; the record's root is absolute and canonical; limits from
design §5.2. Refused while stopped.

### Project record

`crates/ms-projects` owns `ProjectRecord` (design §5.2 schema), its TOML form, and the MAC'd store
`projects.toml` + `projects.toml.mac` in msd's state dir, keyed by a new reserved vault key
`morsec/projects-hmac` (created on first use, never listed, never replaceable over IPC). A bad
MAC: `ProjectList`/`ProjectGet` return `Denied` with "the project records failed their integrity
check"; keys and rules keep working. The record never holds a value.

## Acceptance criteria

1. `ms init` in `$HOME`, `/`, or a `$HOME` that is a git repo with no project markers runs machine
   steps only and opens no file outside morsec's directories (test reads an audit of opened paths
   through the walk API: zero calls).
2. `ms init` in a fixture project with `.env`, `.env.production`, `apps/web/.env`, `.env.example`,
   a symlinked `.env.link → ../outside/.env`, `node_modules/x/.env` and `src/stripe.ts` holding a
   `sk_live_` canary:
   - imports the secrets of the three real env files and nothing from `.env.example`, the
     symlink target or `node_modules`;
   - names keys `<slug>/<var>`, `<slug>/production/<var>` (value clash) and keeps a shared value
     as one key;
   - stores `.env.production` keys as production;
   - rewrites the three files to refs only; the canary appears in no file, receipt, project record,
     stdout or stderr;
   - reports `src/stripe.ts:<line>` as a code finding and leaves that file byte-identical;
   - asks for exactly one approval; after it, catalog hosts are allowed for every known-provider
     swap key and unknown ones still allow nothing.
3. Declining the approval leaves the keys stored and inert, the files rewritten, and a summary
   line telling the user to run `ms init` again; running it again asks once more and finishes.
4. A second `ms init` with no new values imports nothing, asks no approval and prints
   "already protected".
5. `ProjectSave`, issued from an agent session, is `Denied`; one that names a key outside its
   slug, an existing key with a non-empty rule, a host on a run rule, or a non-canonical root is
   `Invalid`.
6. Walk: stops at the entry budget with `stopped_early = true`; never opens a path through a
   symlink (including a directory swapped for a symlink between `readdir` and `openat`); never
   crosses a mount point; skips every listed directory.
7. A tampered `projects.toml` (byte flip, foreign MAC, rollback to an older file) makes
   `ProjectList` `Denied`, and swaps for existing keys still work.
8. The hint block is appended once to an existing `CLAUDE.md`, never creates the file, and isn't
   duplicated on re-run.
9. `npm run build` passes; `docs/threat-model.md` gains the L31 threats from design §8 with the
   tests below, and `scripts/threat_model_check.py` passes.
10. Each test states its card: `protects=…; fails_when=…; no_claim=…`.

## Testing plan

| Layer | What | Count |
|---|---|---|
| Unit `ms-projects` | slug rules, collision suffix, mode detection table (incl. dotfiles repo), tier raise, file-segment naming, record TOML round trip, MAC store tamper table | +12 |
| Unit `ms-projects::walk` | budgets, skip list, symlink file, symlink dir, swap race (dir replaced by symlink), mount boundary (skipped when no second fs available, stated), example/env/source classification | +8 |
| Unit msd | `ProjectSave` checks (criterion 5), one approval bound to the rules hash (a changed set invalidates it), refused while stopped, `ProjectList`/`ProjectGet`, tamper fails closed (criterion 7) | +8 |
| Integration `ms-cli/tests/init_project.rs` | criteria 1 to 4 and 8 against a real msd with `--vault memory`, approvals answered by the test harness the way `connect_cli.rs` does | +6 |
| E2E canary | the fixture of criterion 2 added to the `security-evals` canary suite | +1 |

Named tests the threat model will reference: `init_in_home_is_machine_mode`,
`dotfiles_repo_in_home_is_machine_mode`, `scan_never_follows_symlinks`, `scan_budget_stops_early`,
`scan_skips_dependency_dirs`, `import_raises_tier_from_file_name`,
`same_var_two_values_gets_file_segment`, `code_finding_never_stored_or_rewritten`,
`project_requests_refused_in_agent_session`, `projects_toml_tamper_fails_closed`,
`reinit_is_idempotent`, `project_save_one_approval_bound_to_rules`.

## Rules for the implementing agent

1. Acceptance criteria are each test's `protects / fails_when / no_claim` card; never "make the
   tests pass".
2. Real code and real tests land together.
3. Any change to an existing test, gate step, threshold or suppression is reported on its own line
   with its reason. `put_key_and_list` must stay as it is.
4. Report commands with their observed results.
5. Run the gate as `env -u SSL_CERT_FILE -u NODE_EXTRA_CA_CERTS -u REQUESTS_CA_BUNDLE -u CURL_CA_BUNDLE npm run build`
   (this machine's Claude Code is connected to morsec; msd refuses to start with `SSL_CERT_FILE`).

## Out of scope

Dashboard (L32, L33), Undo (L33), `ms dev` (L34), moved-project detection, msd-side import,
docker-compose / Kubernetes / Terraform literals, rewriting code findings, Linux.

## Rollback

Revert the PR. Keys stored by `ms init` stay in the vault and keep working with `ms rules`;
`projects.toml` is then unused; rewritten `.env` files keep their refs (restore values with
`ms rules` + the provider, or wait for L33's Undo).

## Files

| File | Change |
|---|---|
| `crates/ms-projects/` (new) | mode detection, slug, walk, naming, record, MAC store |
| `crates/ms-cli/src/service.rs` | mode flags, machine and project steps, summary |
| `crates/ms-cli/src/projects.rs` (new), `main.rs` | `ms projects` |
| `crates/ms-cli/src/import.rs` | expose `IpcStore` for reuse (no behaviour change) |
| `crates/ms-ipc/src/protocol.rs` | `ProjectSave`, `ProjectList`, `ProjectGet`, replies, version bump |
| `crates/msd/src/daemon.rs` (+ `daemon/projects.rs`) | handlers, batch approval, record store |
| `crates/ms-vault` | reserve `morsec/projects-hmac` |
| `Cargo.toml` | add `ms-projects` to the workspace |
| `docs/threat-model.md`, `ARI42.md`, `CHANGELOG.md`, `docs/ONBOARDING.md` | threats, statuses, changelog, the new one-command start |
| `docs/design/guided-setup-dashboard.md` | D-1 refinement note |
