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

## Gate

<!-- filled in at the end of the build -->

## Acceptance criteria (SPEC.md)

<!-- filled in at the end of the build -->
