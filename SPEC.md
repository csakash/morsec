# vault-foreign-items

Keys stored by another morsec build (for example a dev build, before installing the signed release)
must not wedge the vault. Today one such keychain item makes listing fail, so `ms doctor` says
"vault not reachable", `ms status` and `ms init --force` warn that the vault could not be listed, and
`ms add <same name>` fails on that listing before it can replace anything.

The keychain lets only the build that stored an item read or delete it (an existing test proves a
differently signed binary is denied `get`, `del` and `put`). So the signed msd cannot remove these
items itself; only the user can, with a macOS password prompt. morsec must say so precisely.

## Behaviour

1. **Listing skips them.** A key whose read is refused by the keychain's access control
   (`errSecAuthFailed`, `errSecUserCanceled`) is left out of the key list and reported separately
   as *unusable*. Every other listing error still fails closed (locked keychain, missing seal key).
   Items that fail their seal stay skipped as today.
2. **`ms status` / `ms init`** print one warning naming the unusable keys (at most five, then
   "and N more") and how to fix each: remove it with
   `security delete-generic-password -s cc.morsec.vault -a <name> ~/Library/Keychains/login.keychain-db`
   (macOS asks for the login password; the keychain is named so a decoy earlier in the search
   list can't catch it), then add it again with `ms add <name>`. Status also carries the names
   (`unusable`), so clients don't parse text.
3. **`ms doctor`** shows "vault reachable · N secrets" again, plus the same named warning as a
   problem to fix.
4. **`ms add <name>`** for an unusable key fails with that exact command for that name before it
   asks for the value, and msd refuses the store as well. `ms add` of any other name works while
   unusable keys exist.
5. **Reading an unusable key** (swap, run, scan) gives the same guidance for that name.
6. **`ms scan`** says which keys it did not search (it can't read them) and reports itself
   incomplete, instead of a clean report that never looked for them.
7. **Only the item's own read decides.** A key is unusable only when the keychain refuses that
   item's read. A failure loading morsec's seal key mid-scan is an error, never a reason to call a
   real key someone else's (which would tell the user to delete good keys). For morsec's own
   items the guidance is the removal command, then `ms init --force`.

## Not in scope

- Deleting other builds' items automatically: the keychain forbids it, by design.
- Any change to the ACL, the seal, or what a key is bound to.

## Tests

- Vault: an item written by another (ad-hoc signed) binary is listed as unusable, not as a key,
  and does not make the listing fail; a normal key next to it is still listed. Keychain test,
  not skipped.
- Daemon (memory vault with an unusable key): status keeps a key count and carries the named
  warning; `PutKey` for that name returns the removal command; `PutKey` for another name stores.
- Error text: the access-denied message names the removal command and `ms add <name>`; for a
  `morsec/` item it names the removal command and `ms init --force`.
- Leak scan: the report notes the unusable keys as not searched and is not complete.
