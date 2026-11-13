---
loop: import-env
plan_card: L04 (docs/PLAN.md §5)
branch: feat/import-env
status: confirmed 2026-11-13 (from the plan card; defaults below chosen by the loop, see "Decisions")
---

# SPEC: L04 `import-env`: dotenv parser, provider catalog, classifier, `ms import`, `ms add`

## Context

The first thing a new user does is move the secrets they already have into morsec: a `.env`
full of `sk_live_…`, `DATABASE_URL=postgres://…` and friends. `ms import .env` moves every value
into the vault and rewrites the file so it holds only `ms://` references, which makes the file
safe to `cat`, commit or show an agent (PRD: ".env safe to commit; `cat .env` shows only refs").
`ms add <name>` adds one secret by hand. This loop also owns the provider catalog, which the swap
proxy (L05) and the rules (L03) read to know a key's hosts and where the credential goes.

## Current state (verified 2026-11-13, base `c5a7d84`)

| Item | State |
|---|---|
| `crates/ms-import` | stub, no dependencies |
| `ms import`, `ms add` | stubs in `crates/ms-cli/src/main.rs`, exit 69 naming L04 |
| `Vault` trait, `MemoryVault` | frozen and built (L00) |
| IPC v1 `PutKey`, `ListKeys` | request side exists; **`ResponseBody` has only `Status` and `Error`**, so there is no success reply for either. msd answers both with `not_implemented` (L07). |
| Keychain vault | being built in parallel (L01); not on main |
| `catalog/` | does not exist |

## Owned paths

`crates/ms-import/**`, `catalog/providers.toml`, `crates/ms-cli/src/{import,add,tty}.rs` plus the
minimum wiring in `crates/ms-cli/src/main.rs` and `crates/ms-cli/Cargo.toml`, the two `add`/`import`
rows of the stub table in `crates/msd/tests/cli.rs` (they stop being stubs), this loop's evidence
file and its rows in `ARI42.md`. No frozen interface (PLAN §4) changes.

## Proposed change

### 1. dotenv parser and rewriter (`ms_import::dotenv`)

- Input: bytes, at most 1 MiB, UTF-8 (optional BOM kept). Lines end in `\n` or `\r\n`; endings
  are kept.
- Entry: optional `export `, a name `[A-Za-z_][A-Za-z0-9_.]*`, optional spaces, `=`, value.
- Values:
  - unquoted: up to end of line or ` #` (inline comment); surrounding spaces trimmed;
  - `'single'`: literal, may span lines;
  - `"double"`: `\n \r \t \" \\ \$` escapes decoded, others kept as written; may span lines;
  - `` `backtick` ``: literal, may span lines.
- Interpolation: an unquoted or double-quoted value containing `${…}` or `$NAME` is marked
  `interpolated` and is **never imported or changed** (the card: "left untouched").
- Comments, blank lines and lines that are not entries are kept byte for byte. An unterminated
  quote is a parse error naming the line, and the import stops before changing anything.
- Each entry records the byte span of its raw value (quotes included). Decoded values are held
  as `SecretBytes` only.
- Rewriter: splices `ms://<name>` into chosen spans and leaves every other byte alone. With no
  replacements the output equals the input exactly (property-tested).

### 2. Provider catalog (`catalog/providers.toml`, embedded with `include_str!`)

Per provider: `id`, `name`, `mode` (swap/run/mint), `hosts`, credential `location`
(`header` with name and prefix, `basic_user`, `basic_password`, `url_path`, `dsn`, `sigv4`),
value `prefixes` (each with optional tier hint and minimum length), `url_schemes`, `url_hosts`
and `env_names` (exact variable names that identify it when the value has no prefix).

Providers: Stripe, OpenAI, Anthropic, GitHub, Slack (tokens and webhook URLs), SendGrid, Twilio
(auth token and API key), Postgres URLs, MySQL URLs, AWS access key id and secret access key.
The catalog is validated when loaded (a test loads it): unique ids, valid key-name segment ids,
non-empty hosts for swap providers, no prefix shared by two providers.

### 3. Classifier (`ms_import::classify`)

For each entry, in order:

1. Value already `ms://…` → **already a ref**, skipped.
2. Interpolated or empty → **kept**, not imported.
3. Value matches a catalog prefix (longest prefix wins, so `sk-ant-` is Anthropic, not OpenAI),
   URL scheme or URL host, or the name is in a provider's `env_names` → **secret, provider X**.
4. Name contains `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `PWD`, `PASS`, `CREDENTIAL`,
   `AUTH`, `PRIVATE`, `DSN`, `SALT` or `COOKIE`; or the value is a URL with a password; or the
   value is ≥ 20 bytes with high entropy → **secret, unknown provider**.
5. Otherwise → **kept** (for example `PORT=3000`, `NODE_ENV=development`).

`--include VAR` forces a kept entry in; `--exclude VAR` keeps a secret out.

**Tier** (first hint wins): the prefix's hint (`sk_live_`/`rk_live_` → production, `sk_test_`/
`rk_test_` → test); for URLs, host contains `prod` → production, host is loopback or contains
`localhost`, `dev`, `staging`, `test` or `sandbox` → test; name contains `PROD` → production,
`TEST`, `DEV`, `STAGING` or `SANDBOX` → test. **No hint → production** (fails closed: it asks
before use). `--tier VAR=test|production` overrides.

**Mode and hosts** come from the catalog. Unknown values get mode `swap` and **no hosts**, so they
are unusable until `ms rules` adds one (fails closed).

**Key names:** `<provider>/<tier>` (`stripe/test`, `pg/production`); AWS pairs become
`aws/<tier>/access-key-id` and `aws/<tier>/secret-access-key`; unknown values become
`env/<var-name-lowercased-with-dashes>`. A name already used in the vault or earlier in the
file gets `-2`, `-3`, …; an existing vault key is never overwritten. The same value appearing
twice in one file becomes one key and two refs. `--name VAR=<key name>` overrides.

### 4. `ms import [PATH] [--dry-run] [--yes] [--include V]… [--exclude V]… [--tier V=T]… [--name V=N]…`

1. `PATH` defaults to `.env`. Refuse a symlink, a non-regular file or a file over 1 MiB.
2. Parse and classify; print the review table: variable, action (import / kept / already ref /
   interpolated), key, provider, mode, tier, hosts, and a **masked value**: the catalog prefix
   (e.g. `sk_live_…`) or `…`, plus the length. No other character of a value is ever printed.
3. Warn if the file was ever committed (`git log --all -- <file>` in the file's directory with
   `--no-pager -c core.fsmonitor=false`): "rotate these keys". Skipped quietly outside git.
4. `--dry-run` stops here (exit 0). Otherwise ask `Import N keys and rewrite <file>? [y/N]` on
   the terminal. With a non-TTY stdin and no `--yes`, refuse (exit 2).
5. Store: list existing keys, then `put` each key. Any failure stops the import **before the file
   is touched** and says which keys (if any) were already stored.
6. Rewrite atomically: write a temp file in the same directory with the original's permissions,
   `fsync`, check the original is unchanged since it was read (else abort), `rename` over it,
   `fsync` the directory. No plaintext backup is kept anywhere.
7. Print a summary and a note that hosts and commands are set with `ms rules` (L03 applies them).

Storage goes through a small `KeyStore` trait in `ms-import` (`list`, `put`). Every `Vault`
implements it. The CLI's implementation sends IPC `ListKeys`/`PutKey` to msd. **IPC v1 has no
success reply for either** (`ResponseBody` is `Status | Error`), and msd answers
`not_implemented` until L07. So today the CLI fails closed at step 5 with that message and the
file is never changed. The `ResponseBody` variants needed (`Ok`, `Keys`) are an interface change
for L07 or its own small loop; this loop does not make it.

### 5. `ms add <name> [--tier T] [--mode M] [--stdin]`

- `<name>` is a `KeyName`. Default tier production, mode swap.
- With a TTY stdin: prompt on stderr, read with echo **and** signals off (`ISIG` cleared, so
  Ctrl-C arrives as a byte and cancels cleanly with the terminal restored), restore the terminal
  in a drop guard. Enter twice to confirm; mismatch aborts.
- Without a TTY: refuse (exit 2) unless `--stdin`, which reads all of stdin (max 64 KiB) and
  strips one trailing newline.
- There is no flag that takes the value on the command line (it would show in `ps`).
- Empty value refused. Existing name refused (no silent overwrite). Stores through `KeyStore`.

### 6. Fuzz target

`crates/ms-import/fuzz/` (standalone cargo-fuzz crate, own `[workspace]`, not a workspace member)
with a `dotenv` target: parse never panics; rewrite-without-changes is the identity. The same
properties run on stable as proptests inside `cargo test`, so the gate covers them.

## Acceptance criteria

1. `npm run build` (`scripts/check.sh`) exits 0.
2. Parser golden tests cover quotes, `export`, multiline, comments, inline comments, CRLF, BOM,
   escapes, interpolation and unterminated quotes; proptests: no panic on arbitrary input,
   untouched rewrite is byte-identical.
3. Classifier table test: every catalog provider (incl. `sk_live_` → production, `sk_test_` → test,
   `prod` in a URL host → production), unknown secret → swap with no hosts, non-secrets kept,
   AWS pair named as a pair, duplicate value → one key.
4. Catalog loads and validates; a broken catalog is rejected by the validator (tests).
5. Library end to end against `MemoryVault` in a temp dir: after import the file holds only refs
   (non-secrets unchanged), the canary value is in the vault, and **no file anywhere in the temp
   dir contains the canary**; permissions of the file are kept.
6. Fail closed: a store failure on the 2nd key leaves the file byte-identical; a file changed
   between read and rename aborts; a symlink is refused.
7. CLI: `ms import --dry-run` prints the table with masked values only (canary absent from
   stdout and stderr) under both `ms` and `mors`; `ms import` without a TTY and without `--yes`
   exits 2 and leaves the file unchanged; `ms import --yes` with no daemon fails and leaves the
   file unchanged; `ms add` with a non-TTY stdin and no `--stdin` exits 2; `ms add --stdin`
   with no daemon fails closed.
8. Git warning shown for a `.env` that was committed in a temp repo, not shown otherwise.
9. Fresh-context code review and security review converged; `/qa` run; `PROOF.md` and
   `docs/evidence/import-env.md` written; `ARI42.md` rows INJ-5 and GW-1 updated for this loop.

## Decisions (made by the loop; change before ship if you disagree)

- D-a: an untiered secret defaults to **production** (asks before use) rather than test.
- D-b: per-key edits in review are flags (`--name`, `--tier`, `--include`, `--exclude`) and a
  rerun, not an in-terminal editor. Hosts and commands are edited with `ms rules` (L03).
- D-c: the review table never shows any character of a value beyond the catalog's public prefix.
- D-d: the cargo-fuzz target is written but run only where nightly and cargo-fuzz exist; the gate
  runs the same properties as proptests on stable.

## Out of scope

Keychain storage (L01), persisting hosts and commands as rules (L03), daemon `PutKey`/`ListKeys`
handlers and their reply variants (L07), 1Password/Bitwarden (L26), approval before replacing a
key (L07/L11).

## Amendments from review (2026-11-13)

Fresh-context code and security review found cases where the spec as written would leave a
secret in plaintext. Each change below makes the import stricter (fail closed); none loosens it.

- A1 (security S1): names are `[A-Za-z0-9_.-]+` and `NAME: value` is an entry, matching what
  Node's dotenv reads. Any other line that is not blank, a `#` comment or `export NAME` stops the
  import with its line number (never its text), instead of being kept silently.
- A2 (security S1): an imported unquoted value followed by ` #…` is refused (docker `env_file`
  reads the comment as part of the value). Quote it, move the comment, or `--exclude` it.
- A3 (code R3): a `\r` outside quotes that is not part of `\r\n` stops the import.
- A4 (code R2): "public by design" values are kept: Stripe publishable keys (`pk_live_`,
  `pk_test_`) and browser-bundled names (`NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`, …) **unless the name
  says secret** (`VITE_SECRET_TOKEN` is imported). The table labels them `keep: public`;
  `--include` overrides.
- A5 (code R1): `--name`/`--tier` on a variable defined more than once is refused, and no two
  different values may be stored under one key.
- A6 (code R5, decision D-e): a kept row whose value equals an imported secret gets that secret's
  reference (`import (same value)`), even for ordinary config such as `POSTGRES_USER=postgres`
  next to `POSTGRES_PASSWORD=postgres`. Leaving it would leave the secret readable under another
  name; `--exclude` keeps it.
- A7 (security S3): for unknown secrets only well-known URL schemes are shown in the table.
- A8 (code R6): hidden input refuses control keys instead of storing them; the confirm prompt
  reads `Import N key(s) and rewrite <file>? [y/N]`.
