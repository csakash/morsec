---
loop: receipts
plan_card: L02 (docs/PLAN.md §5), §3.4
branch: feat/receipts
status: confirmed 2026-11-13 (from the card; no open questions needed the user)
---

# SPEC: L02 `receipts`: hash-chained, HMAC'd receipt store; `ms log`, `ms log --verify`, `ms log --export`, `ms stats`; LOG-2 alerts

## Context

Every use of a key (swap, run, mint), and every block or denial, must leave a receipt that an
agent running as the same user cannot rewrite unnoticed (PLAN §3.3 "Forge receipts", §3.4).
Receipts back three ARI-42 requirements: LOG-1 (log every agent run), LOG-2 (detect abnormal
behaviour) and LOG-4 (customer access to records). L07 wires the store into `msd`; L27 adds the
ARI-42 export bundle on top of this crate.

## Current State (verified 2026-11-13, base `c5a7d84`)

| Item | State |
|---|---|
| `crates/ms-receipts` | `ReceiptSink` trait (frozen), `ReceiptId`, `memory::MemorySink`. Deps: `ms-core` only. |
| `ms_core::ReceiptEvent` (frozen) | time, session, key, mode, target (host or redacted command), argv_hash, rule_version, approval_id, result. No approver identity/method, no redacted argv list, no chain fields. |
| `ms-vault` | `Vault` trait (object-safe, value only inside a closure) and `MemoryVault`. The macOS Keychain backend and the real HMAC key are L01, in parallel. |
| IPC v1 (frozen) | `LogQuery { limit }` request exists; **no response variant carries receipts**. |
| `ms log`, `ms stats` | stubs that exit 69 naming L02. |
| `Cargo.lock` | no `hmac`/`sha2` yet (declared in `[workspace.dependencies]`). |

## Proposed Change

### 1. Record format (one JSON object per line, `receipts-<first seq, 20 digits>.jsonl`)

```text
{"rec":{"v":1,"seq":N,"prev":"<hex sha256 of previous rec bytes | 64 zeros for seq 1>","time_unix_ms":…,"entry":{"kind":"receipt"|"checkpoint"|"alert",…}},"mac":"<hex hmac-sha256>"}
```

- `hash(N) = SHA-256(raw bytes of rec N)`, taken from the exact bytes on disk
  (`serde_json::value::RawValue`), so there is no canonicalisation step to get wrong.
- `mac(N) = HMAC-SHA-256(K, "morsec-receipt-v1\0" || raw rec bytes)`. `K` is the vault key
  `morsec/receipts-hmac`, read only inside `Vault::with_secret`; it is never copied out, logged
  or stored. Comparison is constant time (`hmac::Mac::verify_slice`).
- `receipt` entry (LOG-1, PLAN §3.4 fields): `agent`, `session {pid, started_unix_ms}`, `key`,
  `mechanism` (swap/run/mint), `target` (host or redacted command), `argv_hash` (hex, optional),
  `argv_redacted` (optional list), `rule_version`, `approval` (optional
  `{token_id, by, method}`), `result` (allowed/approved/blocked+reason/denied/failed+message).
- `checkpoint` entry, every `checkpoint_every` records (default 1000) and at every rotation:
  `{through_seq, head}` where `head` is the hash of record `through_seq`. It is itself chained
  and MAC'd.
- `alert` entry (LOG-2): `{session, agent, blocked_count, window_ms, first_seq, last_seq,
  action: "none"|"stop_session"}`.

### 2. `ReceiptStore` (`crates/ms-receipts/src/store.rs`)

- `ReceiptStore::open(dir, vault: Arc<dyn Vault>, StoreConfig) -> Result<Self>`. Creates `dir`
  0700 (refuses an existing dir that is group/world accessible, or a symlink) and files 0600,
  `O_APPEND`. On open it reads the newest file's last record, checks its MAC and resumes
  `seq`/`prev` from it. **Fails closed** when the key is missing, the tail MAC is wrong, or the
  last line is torn, with a message that says what to run (`ms log --verify`).
- Implements the frozen `ReceiptSink` (`append(ReceiptEvent)` → receipt with `approval.by/method`
  unset). An inherent `append_detailed(event, ReceiptDetail { argv_redacted, approval_by,
  approval_method })` carries the fields the frozen event lacks. No frozen type changes.
- Every write is one `write_all` of the full line plus `\n`, then `sync_data` when
  `StoreConfig::fsync` (default on). A mutex serialises appends.
- Rotation when the current file passes `max_file_bytes` (default 8 MiB): write a checkpoint,
  start `receipts-<next seq>.jsonl`; the chain continues across files.
- **Redaction before write**: all agent-supplied strings (`target`, `argv_redacted`, failure
  message, approver, `AgentKind::Other`) pass through a `Redactor` before the record is built.
  `Redactor` trait + `PatternRedactor` (default: URL userinfo passwords, `password=`/`token=`/
  `secret=`/`key=` query and assignment values, `Authorization`/bearer values, well-known
  token prefixes such as `sk_live_`, `sk_test_`, `ghp_`, `github_pat_`, `xox?-`, `AKIA…`, PEM
  private-key blocks) + `ValueRedactor` (exact values supplied by the broker as `SecretBytes`,
  replaced with `ms://<key>`). Each field is also capped (target 4 KiB, each argv element 1 KiB,
  64 argv elements) with a visible `…[truncated]` marker.
- **LOG-2 detector**: `blocked`/`denied` results per session within `alert_window` (default
  10 min); at `alert_threshold` (default 5) it appends one `alert` record and calls the
  configured `AlertHandler` (the daemon's hook to stop the session when
  `stop_session_on_alert` is set; L07 wires the real stop). One alert per window per session.

### 3. Reader, verify, query, stats, export (`read.rs`, `verify.rs`, `query.rs`, `stats.rs`, `export.rs`)

- `verify(dir, Option<&dyn Vault>) -> VerifyReport`: checks genesis (`seq 1`, zero `prev`),
  `seq` strictly +1 across lines and files, `prev` links, checkpoint heads, file names matching
  their first `seq`, no torn or malformed lines, and every MAC when a vault is given. Reports the
  first failure (file, line, seq, problem) and whether MACs were checked.
- `Query { since, until, agent, key, result, session_pid, limit }` → matching receipts, newest
  last; `limit` keeps the most recent N.
- `stats(records) -> Stats`: approval prompts per session (approved + denied), approvals,
  allowed, blocks per UTC day, denials, alerts.
- `export_json` (array of records with `seq`, `hash`) and `export_csv` (RFC 4180 quoting; cells
  that start with `= + - @ \t \r` get a leading `'` against formula injection).

### 4. CLI (`crates/ms-cli/src/log.rs`, `crates/ms-cli/src/stats.rs`; `main.rs` only dispatches)

- Receipts directory: `MORSEC_RECEIPTS_DIR`, else macOS `~/Library/Application Support/morsec/receipts`,
  Linux `/var/lib/morsec/receipts` (PLAN §3.5).
- `ms log [--since D] [--until D] [--agent A] [--key K] [--result R] [--pid P] [-n N]`: a table,
  every agent-supplied string passed through `terminal_safe` (INJ-3). `D` is `30m`, `2h`, `7d`,
  `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ`.
- `ms log --verify`: the CLI cannot read the HMAC key (on macOS it is bound to `msd`'s code
  signature, L01), and IPC v1 has no message that returns receipts or a verify result. So the CLI
  checks the **chain** and says plainly that record MACs are checked by the daemon, which lands
  with L07 (§ Open items). Exit 0 when the chain is intact, 1 on any failure.
- `ms log --export json|csv [--out FILE]` with the same filters; stdout by default; `--out`
  creates the file 0600 and refuses to overwrite.
- `ms stats [--since D] [--json]`.
- `ms` and `mors` behave identically (same binary).

### 5. Dev seed for QA

`crates/ms-receipts/examples/seed.rs`: writes sample receipts with `MemoryVault` and a fixed dev
key into a directory, for manual QA of `ms log`. Never used by `ms` or `msd`.

## Acceptance Criteria

1. `npm run build` (`scripts/check.sh`) exits 0.
2. With the right key, `verify` passes on a store of ≥ 3 files after rotation.
3. Each of these fails `verify` at the right seq: editing a field of any record (MAC), editing
   and re-chaining without the key (MAC), deleting a record, swapping two records, duplicating a
   record, deleting a whole middle or first file, a torn last line, a wrong checkpoint head.
   Removing, reordering or duplicating also fails the **chain-only** check (no key).
4. A sample receipt carries every §3.4 field: time, agent, session, key, mechanism, target,
   argv_hash, argv_redacted, rule_version, approval (token_id, by, method), result, prev (LOG-1).
5. A canary value placed in target, argv, failure message and approver is absent from every byte
   on disk, both through `ValueRedactor` (exact value) and `PatternRedactor` (shape) (LOG-1/INJ-5).
6. 5 blocked/denied results from one session within the window append exactly one alert and call
   the handler with `stop_session` when configured; 4 do not; another session's blocks don't
   count (LOG-2).
7. Reopening a store resumes `seq` and `prev`; reopening with a wrong key, a missing key or a
   torn tail fails closed with a fix in the message.
8. Query filters (time, agent, key, result, pid, limit) return exactly the expected records.
9. CSV export quotes commas, quotes and newlines and neutralises formula prefixes; JSON export
   round-trips (LOG-4).
10. `ms log`, `ms log --verify`, `ms log --export csv`, `ms stats` work end to end against a
    seeded directory under both `ms` and `mors`; `ms log` strips escape sequences from
    agent-supplied fields.
11. The receipts dir is 0700 and files 0600; a world-readable existing dir is refused.
12. Each test states `protects / fails_when / no_claim`.
13. Only files in the Files Reference change.

## Testing Plan

| Layer | What |
|---|---|
| Unit: redact | patterns, value redactor, caps |
| Unit/integration: store | append, reopen, rotation, checkpoint, fail-closed opens, perms, alert detector, concurrency (threads append, chain still verifies) |
| Integration: verify | the tamper table in AC 3, with and without key |
| Property | random sequences of appends verify; any single-byte flip in any record fails |
| Unit: query/stats/export | filters, per-session/per-day counts, CSV/JSON |
| Integration: CLI | assert_cmd against a seeded dir: log, verify (intact and tampered), export, stats, `mors`, escape stripping |

## Rules for the implementing agent

Same five rules as L00: tests are `protects / fails_when / no_claim` cards; real code and real
tests together; any change to a check, threshold or lint suppression reported on its own line;
report commands with their observed results; a report is a claim until re-run.

## Open items (for the user, not blocking this loop)

- **Full `ms log --verify` needs the daemon.** The library verifies MACs (tested here); the CLI
  can only check the chain until an IPC message returns a verify result or receipts. IPC v1 is
  frozen, so that addition belongs to L07 (or its own small loop). Recorded in `ARI42.md`.
- Tail truncation (dropping the last few records) and full rollback to an older consistent copy
  are not detectable from the files alone. The store's in-memory head does **not** close this:
  a same-user agent can restart the daemon (launchd restarts it) and roll the files back first,
  and `open()` trusts the last record that MACs. Fix proposed for L07: anchor `(seq, head)` in
  the vault at each checkpoint and refuse to open below it. L23's separate user closes it fully.
  (Security review S10.)
- **Reserve `morsec/` key names (L03, L04).** The HMAC key `morsec/receipts-hmac` lives in the
  ordinary key namespace. Policy must always deny `morsec/*` in every mode and `ms add` / `ms
  rules` must refuse it, or an agent could ask for `ms://morsec/receipts-hmac` and forge receipts.
  Outside L02's owned paths. (S9)
- `approval.token_id` is written to agent-readable receipts: L07/L11 must pass an opaque id,
  never the approval token itself. (S13)
- The `hmac` crate does not zeroize its key-derived pad state; accepted and recorded. (S12)
- The LOG-2 detector is per session and in memory: a daemon restart resets it, and attempts
  spread across sessions don't alert. L07 can rebuild it from recent receipts at open. (S11)
- A failed rotation (for example disk full) stops the store until the daemon restarts: fail
  closed by design. (Convergence review N5)
- Retention/pruning of old files is out of scope (deleting the first file fails verify by design).

## Rollback Plan

Revert the merge commit. Receipts written by a dev seed live only in temp dirs.

## Files Reference

| File | Change |
|---|---|
| `crates/ms-receipts/Cargo.toml`, `src/**`, `tests/**`, `examples/seed.rs` | new code (except `src/export/ari42/`, L27) |
| `crates/ms-cli/Cargo.toml`, `src/log.rs`, `src/stats.rs`, `src/main.rs` (dispatch only), `tests/log_cli.rs` | new / minimal |
| `crates/msd/tests/cli.rs` | drop `log`/`stats` from the stub table only, if it lists them |
| `Cargo.lock` | `hmac`, `sha2` and their deps |
| `ARI42.md` | LOG-1, LOG-2, LOG-4 rows and a change-log row only |
| `docs/evidence/receipts.md`, `PROOF.md` | new |

## Out of Scope

Wiring into `msd` (L07), `LogQuery` handling and new IPC messages (L07), the ARI-42 export
bundle (L27), the run-mode output redactor (L12), the real Keychain key (L01), retention.
