# L02 `receipts`: tamper-evident receipts, `ms log`, `ms stats`

Adds the receipts store to `crates/ms-receipts`: append-only JSONL, each record hash-chained to
the one before and HMAC'd with the vault key `morsec/receipts-hmac`, checkpoints, rotation,
redaction before write, and a LOG-2 alert after N blocked or denied attempts by one session.
Adds `ms log` (filters, `--verify`, `--export json|csv`) and `ms stats` to `crates/ms-cli`.
No frozen interface changed (`ReceiptSink`, `ReceiptEvent`, `Vault`, IPC v1 are untouched; the
extra §3.4 fields come in through the inherent `ReceiptStore::append_detailed`).

## Testing

- `npm run build` (`scripts/check.sh`): exit 0, all 8 steps; 74 tests pass, 0 fail; cargo deny
  and audit clean; ARI-42 scan 0 findings.
- Tamper table: edit, edit + re-chain without the key, delete, swap, duplicate, remove a middle
  or the first file, torn line, foreign-key record, bad checkpoint: each fails `verify` at the
  right record. A property test flips any single bit of any line and verify fails every time.
- Canary: a value placed in every agent-supplied field never reaches disk, in raw, percent-,
  form-, JSON-escaped and base64 forms, and secret shapes are caught without the value.
- LOG-2: 5 blocked/denied in the window gives exactly one alert with `stop_session`.
- Fail closed: wrong, missing or short key, torn tail, world-readable dir, symlinks, a hard link
  or FIFO at a receipts name, files over 64 MiB.
- CLI end to end under `ms` and `mors`, plus a manual QA transcript (seeded store, filters,
  verify intact and tampered, CSV/JSON exports, stats, terminal-escape stripping).
- Fresh-context code review (8 findings) and security review (13 findings) fixed or recorded;
  a convergence review of the fixes found 5 more (fixed or accepted). Details: `docs/evidence/receipts.md`.

## Risk

- **Sensitive paths:** `crates/**`, `Cargo.lock` (new crates `hmac`, `sha2`, `hex`). Human
  review recommended for `crates/ms-receipts/src/redact.rs` (what reaches agent-readable disk)
  and `store.rs` / `verify.rs` (tamper evidence).
- **Accepted residual risks:** a same-user agent can drop the newest records or roll the files
  back to an older consistent copy (a fix for L07 is to anchor the head in the vault; L23's
  separate user closes it fully). `ms log --verify` in the CLI checks the chain only, since the
  HMAC key is daemon-only and IPC v1 has no verify message (L07). Pattern redaction is
  best-effort; the exact-value redactor relies on the daemon passing the value it used.
- **Cross-loop asks:** L03/L04 reserve `morsec/` key names (else the receipts key could be
  requested by ref); L07 wires the store, the alert handler, the head anchor, and passes only an
  opaque approval id.
- Not wired into `msd` yet, so nothing writes receipts in a running system until L07.

## How to revert

Revert the merge commit. Only `crates/ms-receipts`, the `ms log`/`ms stats` modules (which go
back to exit-69 stubs), two rows in `crates/msd/tests/cli.rs`, `Cargo.lock`, and the LOG-1/2/4
rows in `ARI42.md` change. Nothing outside the repo is touched.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
