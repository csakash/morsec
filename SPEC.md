# SPEC: L15 `run-postgres`

Card: `docs/PLAN.md` § "L15 `run-postgres`". Depends on L11 (approvals) and L12 (run-core), both
merged. Owns `crates/ms-run/src/adapters/pg/`. Shared files are touched only additively:

| File | Change |
|---|---|
| `crates/ms-run/src/lib.rs` | `pub mod adapters; pub mod context;` |
| `crates/ms-run/src/adapters/mod.rs` | `pub mod pg;` (L16 adds its own line) |
| `crates/ms-run/src/context.rs` (new) | per-call rule facts and the `ContextAdapter` trait (below) |
| `crates/ms-run/src/runner.rs` | `register_contextual`, `plan_in`, `preview_in`, `needs_approval`; `Prepared` keeps the adapter's guard alive for the run and redacts the adapter's extra secrets |
| `crates/ms-run/Cargo.toml` | `tempfile` as a normal dependency; rustix `fs` feature |
| `crates/msd/src/daemon/run.rs` | register the pg adapters; pass rule facts; ask the approver when an adapter escalates |
| `ARI42.md` | AUTH-2, AUTH-3, OUT-1 rows and a changelog line |

## Goal

`psql` and `prisma` run through morsec with a Postgres URL key without the password ever being
in argv, a read-only rule actually prevents writes, schema migrations always need a person, and
a production write shows how many rows it will change before anyone approves it.

## How an agent calls it

The key's value is the whole connection URI (`postgres://user:pw@host:5432/db?sslmode=require`),
which is what `ms import` already stores (L12 SPEC, "DSN userinfo refs").

- `psql ms://pg/prod -c "UPDATE orders SET …"` — the ref is psql's connection argument (the
  positional dbname or the value of `-d` / `--dbname`), as a whole argument.
- `DATABASE_URL=ms://pg/prod prisma migrate deploy` (also `npx|bunx|pnpx prisma …` and
  `npm|pnpm|yarn|bun exec|dlx|x prisma …`, with only `--yes`/`-y`/`--no-install`/`--quiet`/`--`
  between; any other shape that names prisma — a runner option, `yarn prisma` / `npm run prisma`
  (a package script), `npm install prisma`, `npx -p ./pkg prisma` — runs code morsec can't see
  into, so it always needs an approval) — Prisma reads its URL from the environment, through L12's
  env channel (the variable must be in the key's `env` rule).

## Decisions (made in this loop; flagged for the orchestrator)

- **D1 — a context-aware adapter hook, additive to the frozen `RunAdapter`.** The frozen trait
  gets no rule facts (read-only, tier), no vault in `preview`, and no way to clean up after the
  run or add redaction patterns. `ms_run::context` adds `ContextAdapter { matches, plan(call,
  ctx) -> AdapterPlan, preview(call, ctx), needs_approval(call, ctx) }` where `CallContext`
  carries the vault and `KeyFacts { tier, read_only }` for every run key of the call (from the
  **effective** rules, so a project file's `read_only = true` applies). `AdapterPlan` is the
  `ExecPlan` plus extra secrets to redact plus a guard dropped when the run ends. Contextual
  adapters are tried first, then frozen adapters, then the generic one. The old `Runner::plan` /
  `preview` keep working and give contextual adapters an empty context, which they refuse (fail
  closed). L16 can use the same hook.
- **D2 — psql: password out of argv, into a short-lived passfile.** The adapter reads the URL
  from the vault, parses it (URI form only; a keyword/value DSN is refused with a message), and
  replaces the ref argument with the URL **without** the password (userinfo password and
  `password=` removed; a `passfile=` parameter refused because it would override ours;
  `connect_timeout=10` added when absent). The password goes into a passfile: a fresh 0700
  directory under a 0700 `morsec-pg` parent in msd's temp dir (owner and mode checked, symlinks
  refused), file created `O_EXCL` with mode 0600, one line `host:*:*:user:password` (escaped;
  `host` is the URL's host for a single TCP host, else `*`; a password with a newline is refused).
  `PGPASSFILE` points at it. The file is overwritten and removed **as soon as it has been read**
  (its access time is set to the epoch after writing; a watcher removes it the moment that
  changes), else after 15 s, and in any case when the run ends (guard) — and stale ones are swept
  when msd first uses the adapter. The password is also added to the redaction patterns, so it is
  redacted on its own, not only as part of the URL. psql always gets `-X` (no `~/.psqlrc`, which
  the agent could write). Connection options from the agent (`-h`, `-p`, `-U`, a second
  positional, `-d` with anything but the ref) are refused; unknown options are refused; refs
  anywhere else in argv are refused; a ref forwarded through the environment is refused for psql.
- **D3 — read-only rules: GUC + role check.** For a key whose effective rule has `read_only`,
  the rewritten URL carries `options=-c default_transaction_read_only=on` (merged into an existing
  `options`), and before the command runs morsec connects with the same URL and passfile and runs
  a fixed check: the login role and every role it is a member of must not be superuser, have
  CREATEROLE/CREATEDB, be in `pg_write_all_data` / `pg_write_server_files` /
  `pg_execute_server_program`, have CREATE on the database or a non-system schema, or have
  INSERT/UPDATE/DELETE/TRUNCATE on any non-system table/view or UPDATE/USAGE on a sequence. If any
  holds, or the check can't run, the command is refused, saying which. The GUC alone can be
  turned off by the session (`SET default_transaction_read_only = off`); the role check is what
  makes a write fail. Residuals: SECURITY DEFINER functions, large objects, check constraints.
- **D4 — Prisma.** Prisma's engines don't read a passfile, so Prisma gets the URL through L12's
  env channel (a whole variable named by the rule, never argv). The adapter classifies the
  subcommand. `migrate deploy|dev|reset|resolve`, `db push|execute` **always need an approval
  (production tier), whatever the key's tier**: msd asks L11's approver with an `ApprovalRequest`
  built like `decide_run`'s, and the receipt says `approved`. On a read-only key, those plus
  `db seed`, `studio` and any subcommand not known to be read-only are refused, and the allowed
  ones (`migrate status|diff`, `db pull`, `generate`, `validate`, `format`, `version`, `--help`)
  run after the same role check as D3. Refs in argv are refused.
- **D5 — effect preview (amended after review cycle 3, approved by the user: count without
  writing).** Only when an approval is asked (production key, or D4). For psql with exactly one
  `-c` and no `-f`, whose command is a single simple `UPDATE` / `DELETE` (a strict token check: no
  comments, `$`, backslash, `:` variables, prefixed strings, `RETURNING`, `DEFAULT`, `WHERE
  CURRENT OF`, `WITH`, subqueries or other relations, dotted names, extra `;`), morsec counts the
  rows it would change **without executing the write**: on its own connection it runs `BEGIN READ
  ONLY`, timeouts (`statement_timeout` 5 s, `lock_timeout` 2 s), then a DO block that refuses
  unless the table has no row security, no child or partition that isn't a plain table, and only
  columns of built-in (`pg_catalog`) types, and in the `WHERE` clause every function is a
  built-in, non-volatile one that doesn't run SQL given as text (`*_to_xml*`, `ts_stat`), every
  operator (written or implied by `IN`, `BETWEEN`, `LIKE`, …) is built in and not volatile, and
  every cast is to a `pg_catalog` type, and then
  runs `SELECT count(*) FROM [ONLY] <table> WHERE <the statement's WHERE clause>` — then
  `ROLLBACK`. The `SET` list is never evaluated. Nothing is written, so no trigger, rule, cascade,
  default or constraint runs, and a read-only transaction refuses any write (and `nextval`) even
  if the filter text were misread. The clause reaches the server only as a quoted literal
  (`:'filter'`, `set_config`), never through psql's lexer. The summary is "3 rows in orders" (the
  rows the statement matches; row security for UPDATE/DELETE may differ from SELECT's); anything
  else is "rows changed: unknown (<why>)". Read-only keys and other forms preview as unknown.
  Prisma previews as unknown (the reason says what it does). This replaces the card's "simple
  DML runs inside `BEGIN … ROLLBACK`": executing the write kept running code the checks couldn't
  see (domain and CHECK constraints, cascades, inheritance children).
- **D6 — hosts.** The adapters don't read the rule's `hosts` (empty would have to mean "none",
  per the rules model): the connection target comes only from the user's stored URL, and the
  agent can't change host, port or user (D2). Flagged for the orchestrator.

## Verify (card) and how

1. A write on a read-only rule fails — throwaway Postgres (Postgres.app/`postgres` on this
   machine, temp `initdb`): with a read-only role an `INSERT` fails (GUC and privileges), and with
   a role that can write the run is refused by the role check before psql starts.
2. The password never appears in argv — `ps -axww -o args` sampled while the psql child runs
   (`SELECT pg_sleep`), plus the passfile is gone during the run and after.
3. A production `UPDATE` prompts and, once approved, runs exactly once — msd test with L11's real
   `HumanApprover` (fake Touch ID): the request shows the argv and "N rows in orders"; denied →
   nothing changed; approved → the counter column moved by exactly one.
4. The preview never commits — the table is unchanged while the approval is pending and after a
   denial; a statement that tries to smuggle `COMMIT` / a second statement is refused or rolled
   back.
5. `prisma migrate deploy` on a test-tier key asks the approver (fake `prisma` binary on a
   test-only resolver path; Prisma isn't installed here).

If no `postgres` server binary is found, the live tests print "not verified" and pass; PROOF.md
says which ran.

## Out of scope

Keyword/value DSNs; `pg_dump`/`pg_restore`/other libpq tools; TLS configuration beyond what the
URL says; INSERT previews (sequences and defaults have side effects ROLLBACK can't undo);
Prisma's own read-only enforcement beyond the role check.
