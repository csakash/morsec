# L01 `vault-macos`: macOS Keychain vault

Adds `ms_vault::macos::KeychainVault`, the macOS backend of the frozen `Vault` trait, plus a
non-extractable CA signing key and morsec's internal HMAC keys. The spec is in `SPEC.md`. Full
evidence, including the day-one spike, is in `docs/evidence/vault-macos.md`.

**Spike outcome (decision D2):** the data-protection keychain needs a macOS provisioning profile,
which we don't have yet. Without one, a `keychain-access-groups` binary is killed at launch, and
app groups return `-34018`. This loop therefore ships the card's fallback: the legacy login
keychain, with each item ACL-bound to the signed `msd`. It is hardened by pinning, sealing and
planted-key checks, all added after the security review.

## Testing

- `npm run build` (`scripts/check.sh`) exits 0 and all 8 steps pass: fmt, build, clippy
  `-D warnings`, tests, cargo-deny, cargo-audit, the supply-chain check, and the ARI-42 scan
  (0 findings).
- `ms-vault` runs 18 tests against the real login keychain. Each test uses its own service name,
  cleans up after itself, and never raises a dialog. No test items remain afterwards
  (`security dump-keychain | grep -c cc.morsec.test` → 0).
  - `acl_other_binary_is_denied`: a copy of the test binary, re-signed ad hoc under another
    identifier, is denied get, delete, replace and CA signing. A byte-identical copy can read
    (positive control). Another binary's direct `SecItemUpdate` of the attributes changes nothing
    we trust. Its update of the data leaves the item unusable to everyone: fail closed, never
    leaked.
  - `acl_developer_id` (run with `MORSEC_SIGN_IDENTITY="Developer ID Application: Akash Munshi
    (554MCRUAKK)"`): an item written by a Developer ID-signed binary is readable by a re-signed
    build with the same identifier and team (an upgrade) and denied to an ad-hoc binary.
  - `planted_items_are_replaced`, `seal_failures_fail_closed`, `ca_rejects_planted_keys`:
    - Items planted with `security -A` or without a seal are replaced by `put` and `reset_*`, and
      are refused by reads.
    - A foreign CA key, or a second one, makes `ensure_ca_key` fail closed.
    - Without the seal key, nothing reads. Signing keys are pinned by a label-bound public-key
      hash, so a key planted under the label is ignored, even one this binary may sign with. A
      pin overwritten by another binary fails closed (`pin_overwrite_fails_closed`).
    - `home_env_is_ignored`: with `HOME` pointing at an attacker directory, the real login
      keychain is still used.
  - `ca_key`: the CA private key is non-extractable, its signatures verify, and it is reused.
  - `round_trip`, `put_replaces_value_and_meta`, `missing_key`, `meta_name_must_match`,
    `internal_keys`, `error_messages`: trait semantics, the reserved `morsec/` names, and error
    text that carries a fix and never the value.
- Not run: `core_dump_scan` (a canary core-dump scan, `#[ignore]`d). macOS writes cores only to
  root-owned `/cores`. Run it by hand after `sudo chmod 1777 /cores`.
- Not applicable on this backend: the manual check that production items need user presence.
  The Keychain can't enforce it here (SPEC S4).
- Reviews: one fresh-context correctness review and one security review, three rounds each.
  - Round 1: 15 findings (1 critical). Round 2: 10 (3 high). Round 3: 5, all low.
  - Every finding is fixed or recorded as a residual. Both reviews converged with no critical,
    high or medium findings left. Details are in `docs/evidence/vault-macos.md`.
- ARI-42: GW-1 moves from Gap to Partial; INJ-5 gets L01 evidence and stays Gap until L09.

## Risk

- **Sensitive paths (human review):**
  - `crates/ms-vault/src/macos/ffi.rs`: the only `unsafe`, with a module-level opt-out narrower
    than the crate.
  - `crates/ms-vault/src/macos/mod.rs`: ACL binding, sealing, signing keys.
  - `crates/ms-vault/Cargo.toml`: new dependencies `security-framework` 3.7,
    `security-framework-sys`, `core-foundation`, `sha2`, `serde_json`; macOS only.
- **Residual risks, documented and not fixed here:**
  - Security.framework copies the data into `CFData` it never wipes.
  - A same-user process can make items or key items unusable (denial of service, fail closed).
  - A user can click "Always Allow" on a dialog another binary raises.
  - `ensure_*` trusts keys that exist before `ms init`, so L07 must call `reset_*` at init.
  - No ACL audit yet (`ms doctor`).
  - Production user presence comes from the approval path, not the Keychain.
  - All of these close or shrink with the data-protection keychain once a provisioning profile
    exists.
- No frozen interface changed. Outside the owned path, only these changed: the
  `#[cfg(target_os = "macos")] pub mod macos;` line in `crates/ms-vault/src/lib.rs`,
  `crates/ms-vault/Cargo.toml`, `Cargo.lock`, my own `ARI42.md` rows and score line, and
  `docs/evidence/vault-macos.md`.
- **Wiring for L07:**
  - At `ms init`, call `reset_internal_keys()` and `reset_ca_key()`. Signing keys are created
    only there.
  - At start, call `ensure_internal_keys()` and `ensure_ca_key()`.
  - The resolver must refuse `ms://morsec/...` references from agents.
  - Disable keychain dialogs for the life of the process.
  - The HMAC key names are `morsec/receipts-hmac` (as L02 asked) and `morsec/rules-hmac` (L03).

## How to revert

`git revert` the merge commit. Nothing else uses `ms_vault::macos` yet: L07 wires it in. Items
an installed build wrote stay in the login keychain under service `cc.morsec.vault`, with keys
labelled `cc.morsec.vault.ca` and `cc.morsec.vault.seal`. Remove them in Keychain Access if
needed. Tests leave nothing behind.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
