# SPEC: L03 `rules-policy`

Source: `docs/PLAN.md` §5 "L03 `rules-policy`" and §3.3. Owns `crates/ms-rules/` and the `ms rules`
CLI module (`crates/ms-cli/src/rules.rs`). Frozen interfaces (`docs/PLAN.md` §4, `ms-core`, IPC v1)
do not change.

## Problem

`decide()` denies everything (L00 stub). The broker needs a per-key rules model, a rules file the
agent can't loosen (same Unix user, §3.3), a project `.morsec.toml` that can only tighten, and the
policy function every mechanism calls.

## Behaviour

### Rules model (`ms_rules::model`)
- `Rules { version: u64, keys: BTreeMap<KeyName, KeyRule>, stopped: bool, tampered: bool }`.
  `stopped` and `tampered` are runtime state, never read from or written to a file.
- `KeyRule { mode, tier, hosts: Vec<HostPattern>, commands: Vec<CommandPattern>,
  mint_scopes: Vec<String>, session_ttl_secs: u64, read_only: bool }`.
- Host pattern: an exact host (`api.stripe.com`, an IPv4 literal, or a bracket-free IPv6 literal)
  or a suffix wildcard `*.example.com` (one or more labels before the suffix, never the apex).
  Lowercase; validated at parse time. A bare `*`, or `*` anywhere but the first label, is rejected.
- Command pattern: a non-empty argv array. A token `"*"` matches exactly one argument; a final
  token `"**"` matches zero or more remaining arguments (only allowed last); `"\*"`/`"\**"` and any
  token starting with `\` are literals with the backslash removed. `argv[0]` is compared literally
  (no PATH or basename normalisation: a mismatch denies).
- TOML file format (`rules.toml`): `version = N` and `[keys."<name>"]` tables; unknown fields are
  rejected. Default TTL 3600 s; `session_ttl_secs` must be 1..=86400.

### Policy (`decide`, frozen signature) — pure: no I/O, clock or vault
Order: `tampered` → `Deny(RulesTampered)`; `stopped` → `Deny(Stopped)`; unknown key →
`Deny(NoSuchKey)`; mode mismatch → `Deny(HostNotAllowed)` for swap, `Deny(CommandNotAllowed)` for
run and mint; target not allowed → same reasons; then `Tier::Test` → `Allow`,
`Tier::Production` → `NeedsApproval`. Deny by default everywhere.
- Swap: request host normalised (lowercase, one trailing dot removed); must match a host pattern.
  A host with a port, userinfo, path or invalid characters never matches.
- Run via `decide`: the frozen `Request::Run` carries only `argv_hash`, so it matches only
  wildcard-free command patterns, by `argv_hash()` of the pattern. Anything else is denied.
- Run via the additive `decide_run(rules, session, key, argv, cwd)`: full pattern matching; the
  `ApprovalRequest` carries the real `argv_display`, `argv_hash` and `cwd`.
- Mint: scope must be in `mint_scopes` exactly.
- `argv_hash(argv)`: SHA-256 over `"morsec-argv-v1\0"` then, per argument, its byte length as u64
  big-endian followed by its bytes. Unambiguous; the one encoding L11/L12 use.
- Approval requests for swap and mint use `argv_display = ["swap", host]` / `["mint", scope]`,
  hashed with `argv_hash`, and an empty `cwd`.
- Session TTL and read-only are exposed on the rule for the approver/token expiry (L11) and run
  adapters (L15); `decide` doesn't use the clock.

### MAC'd store (`ms_rules::store::RulesStore`)
- Files: `rules.toml` and `rules.toml.mac` (hex HMAC-SHA256). MAC input is
  `"morsec-rules-v1\0"` followed by the exact file bytes. The MAC key is read from the `Vault`
  under a configurable key name (default `morsec/rules-mac`) and never copied out of the closure
  except into a zeroized buffer.
- `load(min_version)`: fails closed (error, and `Rules::tampered()` for the daemon) on a missing
  or unreadable `.mac`, bad hex, wrong MAC (constant-time compare), missing vault key, parse
  error, or `version < min_version` (rollback of an older validly-MAC'd file). The daemon supplies
  `min_version` (from the receipt chain) in L07.
- `save(rules)`: writes `version = previous + 1`, atomically (temp file + rename, mode 0600) for
  both files. A crash between the two renames leaves a MAC mismatch, which fails closed.
- `classify_change(old, new) -> Change { Same, Tighten, Loosen }` per key; `apply(new, approved:
  bool)` refuses a `Loosen` unless `approved` (the approval is L07/L11's job: `RulesProposeLoosen`).

### Project rules (`.morsec.toml`, tighten-only merge)
- Same per-key fields, all optional, plus `disabled = true`. Unknown fields and invalid values are
  errors; a project file that fails to parse disables every key for that project (fail closed).
- `merge(user, project) -> Rules`, exact intersection: hosts and commands are intersected as
  pattern sets (a request matches the result iff it matches both), mint scopes intersected, TTL
  is the minimum, tier the maximum, `read_only` is OR. A project rule for a key the user rules do
  not have is ignored (it can't create keys). A different `mode` disables the key.
- Property: for all user rules, project files and requests, the merged rules are never more
  permissive than the user rules judged on the full request: `decide_run(u)` for run requests
  (argv known), `decide(u)` otherwise. (Amended in build after review R1: the hash-only
  `decide` path matches only literal patterns, so a merge that narrows `["psql", "*"]` to the
  literal `["psql", "a"]` lets `decide` match an argv the user rule already allowed.) Original
  wording: `decide(merge(u, p))` is never more
  permissive than `decide(u)` (order: Deny < NeedsApproval < Allow).

### `ms rules` CLI (module `ms-cli/src/rules.rs`)
IPC v1 has no rules response and `RulesProposeLoosen` carries no rule, so this loop's CLI works on
local files and does not write them (writing needs the vault MAC key, which only `msd` holds):
- `ms rules` lists keys; `ms rules <name>` shows one key's effective rule (user rules merged with
  the project `.morsec.toml` found from the current directory up to the git root), labelled
  "MAC not checked by ms; msd verifies it". `--rules <path>` overrides the rules file location.
- `ms rules --check <file>` validates a project file, exit 0 or 1 with the error.
- `ms rules <name> --add-host/--remove-host/--add-command/--remove-command/--tier/--ttl/
  --read-only/--writable`: prints the proposed rule and whether it tightens or loosens, then
  exits 69 saying the change is applied by `msd` (L07), loosening with an approval.
- All file-derived text is passed through the terminal-safe filter. Errors say what happened and
  the fix.

## Acceptance criteria
1. `npm run build` (`scripts/check.sh`) passes.
2. Property test: a project file never widens the effective rule (merge vs decide, all modes).
3. A tampered rules file, a tampered or missing `.mac`, a missing MAC key and a rolled-back version
   are each rejected (fail closed).
4. Decision-table test covering every mode × tier × allowed/not-allowed, plus stopped, tampered and
   unknown key.
5. A production key always yields `NeedsApproval` when otherwise allowed (property test).
6. `decide_run` approval binding: the `ApprovalRequest` argv hash equals `argv_hash(argv)`, and any
   changed argument changes it.
7. `ms rules`, `ms rules <name>`, `ms rules --check`, and a loosening proposal behave as above
   (integration tests on the built binary), with control characters stripped from output.
8. Every test carries a `protects / fails_when / no_claim` card.

## Out of scope
Daemon wiring (L07), approval UI and tokens (L11), applying `read_only` in adapters (L15), IPC
changes for rules (open item), receipts (L02).
