# SPEC — L01 `vault-macos`

Loop card: `docs/PLAN.md` §5 "L01 `vault-macos`". Depends on L00 (merged). Branch `feat/vault-macos`.

## Goal

A macOS Keychain backend for the frozen `Vault` trait, so `msd` (L07) can store and use secret
values that no other binary of the same user can read silently.

## Decisions taken in this loop

| # | Decision | Why |
|---|---|---|
| S1 | **Legacy (file-based) login keychain, not the data-protection keychain.** | Day-one spike (2026-11-13, macOS 26.2, `docs/evidence/vault-macos.md`): the data-protection keychain needs a `keychain-access-groups` entitlement, which needs a macOS provisioning profile. Without one the binary is killed at launch (exit 137); `com.apple.security.application-groups` gives `-34018`. The user chose (D2) to use the existing Developer ID identity, and to fall back now and defer the profile. |
| S2 | Item access is bound to the creating binary's **designated requirement** via the keychain's default creator ACL. | Spike: an item written by a Developer ID-signed binary (identifier `cc.morsec.spike`, team `554MCRUAKK`) is readable by a re-signed copy with the same identifier and team, and denied (`-25293`) to ad-hoc, Apple Development-signed and same-team/other-identifier binaries when user interaction is disabled. |
| S3 | `msd` reads with **user interaction disabled**, so a broken ACL fails closed instead of popping a dialog. | A daemon must never block on a GUI prompt, and must never be the one that asks the user to grant itself access. |
| S4 | **Production-tier user presence is not enforced by the Keychain on this backend.** It is enforced by the approval path (`Approver`, L11; executor check, L07). | `SecAccessControl(.userPresence)` is data-protection-keychain only (spike: `-34018` on the legacy keychain). Recorded as an open item: when a provisioning profile exists, switch to the data-protection keychain and add `.userPresence`. |
| S5 | Internal HMAC keys are ordinary items under reserved names `morsec/receipts-hmac` (L02's agreed name) and `morsec/rules-hmac` (L03), 32 random bytes from `SecRandomCopyBytes`, created by `ensure_internal_keys()`. They are ACL-bound to `msd` and hidden from `list()`. Users cannot `put` or `delete` names under `morsec/`. | The Keychain has no HMAC primitive on keys we can use, so "non-exportable" for HMAC keys means: readable only by the signed `msd`, never listed, never writable from outside. |
| S6 | The CA private key is a **non-extractable** P-256 `SecKey` in the login keychain (`kSecAttrIsExtractable = false`). `msd` gets only `public_key()` and `sign()`; the private bytes never exist in process memory. | Card: "the CA private key, as non-exportable items". Spike: the default is extractable (`extr = 1`), so the attribute is set explicitly. |
| S7 | One small `ffi` module opts out of `unsafe_code` (module-level, narrower than crate-level) to read two Apple constants (`kSecAttrIsExtractable`, `kSecAttrIsSensitive`) that `security-framework-sys` does not export. | Every `unsafe` block reads an immutable `extern static`; each has a `// SAFETY:` comment. |

## Build

All code lives in `crates/ms-vault/src/macos/` (owned path). Outside it, only the minimum to wire
it in: `crates/ms-vault/Cargo.toml` (target-specific deps `security-framework`, `core-foundation`,
`serde_json`), one `#[cfg(target_os = "macos")] pub mod macos;` line in `crates/ms-vault/src/lib.rs`,
and `Cargo.lock`. No frozen interface changes.

- `KeychainVault` implements `Vault`:
  - service `cc.morsec.vault` (overridable only for tests), account = key name.
  - `put`: value comes in as `SecretBytes`; written with `KeyMeta` as JSON in the item's comment
    (metadata only). Replacing an item deletes the old one first. Reserved names refused.
  - `with_secret`: reads into a `SecretBytes` immediately (no extra copy), calls the closure with
    a borrow, drops (zeroizes). Missing item → `Error::NoSuchKey`. Never prompts.
  - `delete`, `list` (attributes only; no item data is requested; internal keys hidden).
  - All Keychain errors map to `ms_core::Error` with a fix in the message and the OSStatus code,
    never the value.
- `ensure_internal_keys()` and `CaKey` (`ensure_ca_key()`, `public_key_sec1()`, `sign_sha256()`).
- `Debug` for every type prints no value.

## Verify (acceptance criteria)

1. Round trip: put / with_secret / list / delete against the real login keychain under a
   per-test service name; list returns metadata, never the value.
2. **ACL test (automated, in the gate):** an item written by the test binary is denied to a copy
   of that binary re-signed with a different identifier (`codesign -s - -i …`). An optional run
   with a Developer ID identity (env `MORSEC_SIGN_IDENTITY`) checks a Developer ID-signed writer
   against an ad-hoc reader as well.
3. Reads never prompt: with interaction disabled, a denied read returns an error, not a dialog.
4. Reserved names: `put`/`delete` of `morsec/*` from the trait fail; internal keys exist after
   `ensure_internal_keys()`, are 32 bytes, are stable across calls, and are not listed.
5. CA key: non-extractable (no external representation of the private key), signature verifies
   with the public key, stable across `ensure_ca_key()` calls.
6. Memory: canary value; after `with_secret` returns, no `SecretBytes` copy of it remains alive
   in our code (structural test + `Debug` redaction). A core-dump scan is attempted where the OS
   allows it; if it needs admin (macOS writes cores to root-owned `/cores`), that is recorded in the
   evidence file rather than claimed.
7. User presence for production items: **not applicable on this backend** (S4); recorded as an
   open item, not claimed.
8. `npm run build` (`scripts/check.sh`) passes.

## Out of scope

Data-protection keychain + `.userPresence` (needs a provisioning profile), `ms init` and daemon
wiring (L07), the approval dialog (L11), CA certificate issuance with rcgen (L05).

## ARI-42

GW-1 (protect provider keys: values readable only by the signed broker), INJ-5 (no secrets in
prompts: values never leave a closure; nothing in `Debug`, errors or `list`).
