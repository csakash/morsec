# Evidence: `cli-scope`

Loop branch `feat/cli-scope`, 2026-11-14, macOS 26.2 (Darwin 25.2). Full logs are kept outside the
repo in `.loops/runs/cli-scope/interactive/proof/`.

## 1. CLI-only scope

`docs/PLAN.md` now says morsec ships as a CLI only: L11 approves in the terminal with Touch ID
(no `apps/MorsecApprove/`), L25 `menubar-app` is deferred, L28 is a CLI release (formula, docs,
signed release, no cask), and the first public CLI release follows v0.2 with a light hardening
pass pulled forward from L24.

## 2. Keychain tests raised a dialog: cause and fix

`acl_other_binary_is_denied` sometimes stopped on a SecurityAgent dialog. A securityd log stream
during the test (`log stream --predicate 'process == "securityd"'`) shows where it comes from:

```text
securityd [integrity] ACL partition mismatch: client cdhash:3da0a07a… ACL ( "cdhash:…" )
securityd [integrity] asking user about XARA partition for 'cdhash:3da0a07a…'
securityd [kcacl] displaying keychain prompt for …/T/.tmpkkAumU/other(77354)
securityd [kcacl] user approved 'always allow' for …/other(77354)        ← 4.6 s later, a click
```

A traced run matched the prompt to one step: the re-signed `other` copy running `update-attr`, a
`SecItemUpdate` of our item's attributes. That child already holds `quiet()`
(`SecKeychainSetUserInteractionAllowed(false)`) for the call, and the flag is per process
(checked with `SecKeychainGetUserInteractionAllowed` from two processes). So the flag stops ACL
prompts (reads, deletes, signing by the other binary all fail with `-25293` / `-25244`, no
dialog), but **not** the partition ("XARA") prompt that a modification by a differently signed
binary triggers. The old assertion accepted `UPDATED`, so the test passed only because someone
clicked Allow. A new audit session without UI (`SessionCreate`) would avoid it, but a non-root
process can't create one.

Fix (`crates/ms-vault/src/macos/tests.rs`):

- The untrusted child never updates attributes. The byte-identical trusted copy rewrites the
  comment instead, the worst case (as if the user had clicked Allow for an attacker); `list` must
  still report the sealed tier. A trusted-copy data overwrite is added, which the seal must refuse
  (`seal check failed`). The other binary's own data update raises no dialog (checked in the log
  with it restored) and stays, as do `pin_overwrite_fails_closed`'s.
- The ACL proof is unchanged: the other binary's `get`, `del`, `put` and `ca` are denied, the
  positive control (same signature) reads, and `get` by the other binary is denied after each
  tamper.
- Every child runs under a 60 s timeout. One that runs longer is killed, which withdraws its
  dialog, and the test fails naming the likely dialog. The gate can't hang on a human again.

After the fix (same log stream, filtered for `XARA`, `keychain prompt`, `user approved`):

| Run | Result | Prompts |
|---|---|---|
| the two tests, 5 times (both rounds) | 5 × ok, 1.3–1.6 s each (was 7 s with the dialog) | 0 |
| full `ms-vault` suite | 19 passed, 3 ignored | 0 |
| fresh build, 3 full suites in parallel | 3 × 19 passed | 0 |

The remaining securityd lines are silent `ACL partition mismatch` entries with no prompt.

Not claimed: what macOS does when a differently signed binary modifies our item without a human
present (it asks the user, so it can't run unattended); the seal is what protects against it, and
that is tested.

## 3. msd tunnel allowlist (L08 follow-up D2)

Not changed in this loop; written up as card L29 `egress-allowlist` in `docs/PLAN.md`. Reasons:
msd may only take an egress allowlist from MAC'd rules (Claude Code's `settings.json` and the
connector state are agent-writable), the rules have no such section yet (model, loosening
approval, project merge, IPC, CLI), and while `ms stop` already refuses new requests, allow-listed
tunnels that are already open last until idle, so `ms stop` has to close them.

## ARI-42

| Req | Change |
|---|---|
| GW-1 | ACL tests unchanged in what they prove; they can no longer hang on a keychain dialog |
| INJ-4 | gap recorded: the tunnel allowlist is empty, so unbound hosts are refused (fails closed); L29 |
| AUTH-3, INJ-3 | plan only: approvals in the terminal as inert text with Touch ID, refused from inside an agent session (L11) |
