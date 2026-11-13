# Evidence: L01 `vault-macos`

Commands run on the loop branch `feat/vault-macos`, 2026-11-13, macOS 26.2 (Darwin 25.2.0,
build 25C56), rustc 1.93.1, Xcode at `/Applications/Xcode.app`. Signing identity:
`Developer ID Application: Akash Munshi (554MCRUAKK)` (decision D2: the user approved using it).

## Day-one spike: which keychain can a signed CLI daemon use?

Spike program: a 40-line Rust binary on `security-framework` 3.7.0 that puts, reads and deletes a
generic password, built once and copied/re-signed per case (kept outside the repo, in the session
scratchpad). Results:

| # | Binary | Keychain | Result |
|---|---|---|---|
| 1 | ad-hoc, no entitlements | data-protection | `-34018` errSecMissingEntitlement |
| 2 | Developer ID, hardened runtime, `com.apple.security.application-groups = [554MCRUAKK.cc.morsec]`, bare binary | data-protection, access group `554MCRUAKK.cc.morsec` | `-34018` |
| 3 | same as 2, inside a minimal `Spike.app` (Info.plist, `LSUIElement`) | data-protection | `-34018` |
| 4 | Developer ID, `keychain-access-groups = [554MCRUAKK.cc.morsec]`, **no provisioning profile** | — | killed at launch by AMFI, exit 137 (restricted entitlement without a profile) |
| 5 | Developer ID, identifier `cc.morsec.spike` | legacy login keychain | put ok, read ok |
| 6 | ad-hoc copy, interaction disabled | legacy, item from 5 | `-25293` errSecAuthFailed (denied, no dialog) |
| 7 | Developer ID copy, same identifier and team | legacy, item from 5 | read ok (an upgrade keeps access) |
| 8 | Developer ID, other identifier `cc.morsec.other` | legacy, item from 5 | `-25293` |
| 9 | Apple Development certificate, same identifier | legacy, item from 5 | `-25293` |
| 10 | Developer ID, `SecAccessControl(.userPresence)` | legacy | `-34018` (access control is data-protection only) |
| 11 | P-256 `SecKey` via `GenerateKeyOptions` | legacy | created, but `extr = 1` (extractable) by default |

Conclusions:

- **The data-protection keychain needs a macOS provisioning profile** for a Developer ID build
  (App ID with keychain sharing, embedded `embedded.provisionprofile`). There is none on this
  Mac (only two iOS team profiles). The user chose to fall back now and defer the profile.
- **Fallback taken: the legacy login keychain.** The creator's designated requirement (Developer
  ID identifier + team) is on each item's ACL. Every other binary we tried is denied, and a
  rebuilt `msd` with the same identifier and team keeps access.
- Production-tier user presence can't come from the Keychain on this backend (row 10). It stays
  with the approval path (L11 `Approver`, checked by the executor in L07).
- The CA key must set `kSecAttrIsExtractable = false` explicitly, and on the file-based keychain
  the attribute is honoured only at the top level of the `SecKeyCreateRandomKey` dictionary, not
  inside `kSecPrivateKeyAttrs` (found by the `ca_key` test: `extr = 1` until moved).

## Findings during the build (macOS 26.2)

- On the legacy keychain, any binary of the user can `SecItemUpdate` the **attributes and the
  data** of an item `msd` created (`acl_other_binary_is_denied`):
  - After an attribute update, `msd` still reads the item and the other binary is still denied.
  - After a data update, the item is denied to everyone, `msd` included. That is a denial of
    service, never a leak or a substituted value.
  - In response, items are sealed, and `list()` returns the sealed metadata.
- Any binary can delete **key** items, ours included (`ca_rejects_planted_keys`). It can also plant
  a non-extractable key under our label, made by a binary we trust, so we can sign with it.
  - Hence signing keys are pinned by public-key hash, in an `msd`-only generic item.
  - Other binaries are denied deleting generic items (`acl_other_binary_is_denied`, op `del`).
- An item planted with `security add-generic-password -A` is still **denied** to our binary: the
  partition list keeps us out. Reads refuse it, and `put` / `reset_*` replace it
  (`planted_items_are_replaced`).
- With `HOME` pointing elsewhere, the vault still uses the real login keychain (`home_env_is_ignored`).

## Gate

`npm run build` → `bash scripts/check.sh` exits 0. All 8 steps passed:

| Step | Result |
|---|---|
| 1 fmt | clean |
| 2 build | 0 warnings |
| 3 clippy `-D warnings` | 0 warnings |
| 4 tests | all pass; `ms-vault`: 18 passed, 3 ignored (child processes and `core_dump_scan`) |
| 5 cargo-deny | advisories, bans, licenses and sources ok (new: `security-framework` 3.7.0, `security-framework-sys` 2.17.0, `core-foundation` 0.10, all MIT/Apache-2.0) |
| 6 cargo-audit | 0 vulnerabilities |
| 7 supply chain | no patches or overrides |
| 8 ARI-42 scan | 0 findings |

Separately: `MORSEC_SIGN_IDENTITY="Developer ID Application: Akash Munshi (554MCRUAKK)" cargo test
-p ms-vault acl_developer_id` passes. After every run, `security dump-keychain | grep -c
cc.morsec.test` returns 0. Raw outputs are kept outside the repo in
`.loops/runs/vault-macos/interactive/proof/`.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 round trip | `round_trip`, `put_replaces_value_and_meta`, `missing_key`, `meta_name_must_match` |
| 2 ACL | `acl_other_binary_is_denied` (ad-hoc, other identifier: get, delete, put and CA sign are denied; a byte-identical copy reads); `acl_developer_id` (a Developer ID writer; a same-identifier, same-team upgrade reads; an ad-hoc binary is denied) |
| 3 no prompts | every call holds `quiet()`; denied reads return `-25293` errors, and no test raised a dialog |
| 4 reserved names, internal keys | `internal_keys` |
| 5 CA key | `ca_key`, `ca_rejects_planted_keys` |
| 6 memory | `Debug`, error and `list` canary checks in `round_trip` and `run_child` (asserts the child never prints the value). `core_dump_scan` **not run**: `/cores` is `root:wheel 0755` on this Mac. To run it: `sudo chmod 1777 /cores`, then `cargo test -p ms-vault core_dump_scan -- --ignored`. Expected residual: Security.framework's own `CFData` copies |
| 7 user presence | not applicable on this backend (S4); open item |
| 8 gate | above |
| 9 tampering | `acl_other_binary_is_denied` (direct updates), `pin_overwrite_fails_closed`, `planted_items_are_replaced`, `seal_failures_fail_closed`, `ca_rejects_planted_keys`, `home_env_is_ignored` |

## Review record

Fresh-context reviewers, read-only, three rounds.

| Round | Correctness | Security | Fixed in |
|---|---|---|---|
| 1 | 6 (2 medium, 4 low) | 9 (1 critical, 2 high, 2 medium, 4 low) | `f85a30c`: pin the login keychain; add-only writes; seal; planted-key checks; `reset_*`; list skips bad items; `unsafe fn constant`; unbuffered stdin; cleanup guards |
| 2 | 4 (1 high, 1 medium, 2 low) | 6 (2 high, 2 medium, 2 low) | next commit: pin signing keys by public-key hash; create them only at init; `list()` from sealed metadata; verify before parse; keep the real add error; home directory from `getpwuid_r` with no symlinks |
| 3 | 2 low | 3 low; security review states it has converged | next commit: `list()` errors on a missing seal key and skips only items that fail their own seal; the home directory is canonicalized before the symlink check; pins are domain-separated by label; a probe signature is verified against the pinned key; new `pin_overwrite_fails_closed` test |

Round 3 found no critical, high or medium issues; both reviews have converged. Note carried to L07: msd's resolver must refuse `ms://morsec/...` references from agents (`with_secret` serves the reserved names so L02/L03 can read the HMAC keys).

Accepted residuals, documented in the module docs, SPEC.md and ARI42 GW-1:
- Security.framework's `CFData` copies are not wiped.
- Denial of service by a same-user process: it can delete key items or overwrite item data.
- "Always Allow" granted by the user to another binary.
- Rollback or swap of the keychain file at the real path.
- No ACL audit yet (`ms doctor`, L07).
- Production user presence comes from the approval path (L11).
