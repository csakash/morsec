# PROOF: L15 `run-postgres`

`psql` and `prisma` adapters for run mode (`crates/ms-run/src/adapters/pg/`), an additive
context-aware adapter hook (`crates/ms-run/src/context.rs`, `runner.rs`), and msd wiring
(`crates/msd/src/daemon/run.rs`). Spec: `SPEC.md` (D5 amended by the user after review cycle 3:
the preview counts rows without running the write).

## Testing

- **Gate:** `npm run build` (`scripts/check.sh`: fmt, clippy, tests, cargo deny, cargo audit,
  security evals) passes on `dde9fbf`.
- **Live Postgres** (`ms-run` `adapters::pg::live_tests::live_postgres`): a throwaway Postgres 17.9
  cluster (temp `initdb` from Postgres.app, loopback, scram-sha-256). The test prints
  `VERIFIED` when it ran and `NOT VERIFIED` when no server binaries are found.
  - **A write on a read-only rule fails.** `INSERT` hits "read-only transaction". `SET
    default_transaction_read_only = off` then `UPDATE` hits "permission denied". A writer role, a
    role that is a member of writer, and a role that can only write in another database are each
    refused before psql starts.
  - **The password is never in argv.** `ps -axww` sampled during the run: 26 samples saw psql
    with `postgres://writer@127.0.0.1…` and none held the password, raw or %-encoded. The agent's
    first `\! ls "$PGPASSFILE"` finds the file already gone. No passfile is left afterwards.
  - **The preview never writes.** It counts "2 rows in orders" and leaves the table unchanged.
    Tables with triggers, cascades or `SET DEFAULT` keys are counted with nothing run (the
    sequence is not advanced). A volatile function, a cast to a non-built-in type,
    `table_to_xml`, row security, or a database with a user operator or user cast gives
    "unknown". Filters that sneak in `COMMIT`, `UPDATE` or `nextval` are refused by the server,
    and the counters stay unchanged.
- **msd with L11's real `HumanApprover`** (fake Touch ID):
  - `production_psql_update_previews_then_runs_once`: the prompt shows the argv and "1 row in
    orders" while the table is still unchanged. A denial changes nothing. An approval runs the
    update exactly once (+1). A `read_only = true` rule with a writer URL is refused.
  - `prisma_migrate_always_needs_approval`: on a test-tier key, the prompt shows tier production
    and mentions the schema. A denial is refused and recorded; an approval's receipt carries
    touch-id.
- **Unit tests:**
  - URL split in libpq's order; refused URL shapes.
  - Passfile: 0600 in a 0700 dir, removed on first read and on drop, private parent.
  - psql getopt parsing (connection options, prefixes, pipes refused).
  - SQL filter check: WHERE extraction, implied operators, `!=`.
  - Prisma launcher shapes and classes, with a fake binary: approval on every call with a
    writable key; a mixed read-only/writable call refused.
  - `context::contextual_adapter_contract`: an adapter's own secrets are redacted, the guard is
    dropped at the end of the run, and the old entry point refuses (fail closed).
- **Reviews:**
  - Code review ran 7 cycles. It stopped at the 2-round budget twice and was re-scoped by the
    user (count-only preview, then one more round). It converged with no important findings
    left.
  - Security review: S1 (prisma "read-only" subcommands run agent-editable code with a writable
    URL) and S1-b (a read-only key in the call switched that approval off) are both fixed and
    re-checked: no issues. S2 (`noatime` mounts) is recorded as a residual.
- **ARI-42:** AUTH-2, AUTH-3 and OUT-1 rows updated (Partial, strengthened). The scanner finds
  no new issues; its 5 low findings are pre-existing, in ms-connect.
- **Not verified:** the real Touch ID sheet, real Prisma (not installed; a fake binary was used),
  Postgres versions other than 17, and TLS servers.

## Risk

- **Sensitive paths (`gloop risk`):** all of `crates/ms-run/src/adapters/pg/*`,
  `crates/ms-run/src/{context,runner,lib}.rs`, `crates/ms-run/Cargo.toml`,
  `crates/msd/Cargo.toml` and `crates/msd/src/daemon/run.rs`. These need a human reviewer.
- **Shared-file edits (additive):** `runner.rs` gains `register_contextual`, `plan_in`,
  `preview_in` and `needs_approval`, and `Prepared` keeps a guard. msd's run path passes rule
  facts and asks the approver when an adapter escalates. Expect small merge conflicts with L16
  (`adapters/mod.rs`, `lib.rs`, the runner registration in msd).
- **Behaviour changes for existing keys:**
  - A `read_only` key can no longer run through the generic adapter (it is refused).
  - Every prisma call with a writable key asks a person.
- **Residuals (ARI42.md):**
  - Same-user race inside the ~1 ms window before the passfile is removed.
  - `noatime` mounts, where the passfile lives up to 15 s.
  - The read-only role check doesn't cover SECURITY DEFINER functions, large objects, or
    `ALTER ROLE … SET`.
  - Prisma calls that name prisma nowhere in argv rely on the command rule alone.
  - An approved prisma call binds argv and cwd, not the migration files.
  - Previews are "unknown" in databases with extension casts or operators (citext, PostGIS).
- **Decisions to check:**
  - The context hook sits beside the frozen `RunAdapter` (D1).
  - Prisma gets the full URL through `DATABASE_URL`, because its engines don't read a passfile
    (D4).
  - The rule's `hosts` is not read; the target comes only from the stored URL (D6).

## How to revert

`git revert` this PR's merge commit. The adapters are only registered in `runner()` in
`crates/msd/src/daemon/run.rs`. Reverting removes them, and psql/prisma calls with a key go back
to L12's generic adapter, which refuses refs in argv. No data or rules format changes.
