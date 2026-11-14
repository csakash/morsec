# PROOF: `cli-scope`

morsec ships as a CLI only, the keychain ACL tests no longer stop on a dialog, and the empty msd
tunnel allowlist (L08 follow-up D2) is written up as card L29. Spec: `SPEC.md`. Evidence:
`docs/evidence/cli-scope.md`. Logs and gate output: `.loops/runs/cli-scope/interactive/proof/`
(not committed).

## Testing

**1. `docs/PLAN.md`, CLI only.**
- L25 `menubar-app` is deferred, with the reason.
- L11 `approvals-macos` approves from the CLI. The request is shown as inert text on `/dev/tty`, Touch ID goes through `LocalAuthentication` with the password as fallback, and a caller inside an agent session can't approve. The Touch ID sheet carries the key, the tier and a request code that the terminal repeats, because a same-uid agent can redraw the terminal (security review S1).
- L28 is a CLI release: Homebrew formula, docs, signed release, no cask.
- A note says the first public CLI release follows v0.2, after a light hardening pass pulled forward from L24 (threat model, plus fuzz targets for the dotenv parser, the proxy request head and the IPC framing).
- The mermaid graph has L25 dashed and off the L28 path, and adds L29.
- Promise coverage, §1, §3.1, §3.3, §3.6, §3.7, L10, L15, L17, L21, L24, the v0.2 and v1.0 gates, D4 and D6 are all updated to match.
- Both reviews checked the mermaid block, and it is valid. No mermaid renderer was run locally.

**2. Keychain dialogs: before and after**

*Before:* this is from a securityd log stream during `acl_other_binary_is_denied` (`keychain-before.log`, `keychain-before-run2.log`):
```text
asking user about XARA partition for 'cdhash:3da0a07a…'
displaying keychain prompt for …/T/.tmpkkAumU/other(77354)
user approved 'always allow' for …/other(77354)          ← a human click 4.6 s later
```
- A traced run showed which step causes it: the re-signed child calling `SecItemUpdate` on the item's attributes.
- Turning keychain interaction off, which every child call already does, does not suppress this partition prompt.
- The test only passed because someone clicked Allow.
- Each run took about 7 s while it waited on the dialog.

*Fix* (`crates/ms-vault/src/macos/tests.rs`):
- The attribute rewrite is now done by the trusted, byte-identical copy. That is the worst case, and the seal still has to hold.
- The other binary's own data update raises no dialog, so it stays. Its result is now checked without anything else interfering (S3).
- A trusted-copy data overwrite on a second item must fail with `seal check failed`.
- The other binary's `get`, `del`, `put`, `ca`, and its `get` after each tamper step are still asserted DENIED. These are what prove the ACL.
- Every child runs under a 60 s timeout. One that hangs is killed, which also withdraws its dialog, and the test fails with a message saying so.

*After:* the same log stream, filtered for `XARA`, `displaying keychain prompt` and `user approved`:

| Run (final code, 463351b) | Result | Prompts |
|---|---|---|
| the two tests, 5 times | 5 × ok, 1.5–2.1 s | 0 |
| fresh build, 3 full `ms-vault` suites in parallel | 3 × 19 passed, 3 ignored | 0 |

The earlier rounds got the same result (`keychain-after*.log`).

**3. Tunnel allowlist.** No code changed. Card L29 `egress-allowlist` in PLAN.md says why this is more than a small change:
- msd may take the list only from the MAC'd rules, because `settings.json` and the connector state are agent-writable.
- The rules need a new section, with loosening approval, the project merge, IPC and CLI support.
- `ms stop` refuses new requests but does not close a tunnel that is already open.
- Public-suffix wildcards must be rejected.

**Gate.** `npm run build` (`scripts/check.sh`, all 8 steps plus security-evals) on HEAD 0ccbdd7: `check.sh: all checks passed`, exit 0, 320 tests passed, 0 failed (`build-morsec.txt`; also green on 463351b, `build-morsec-463351b.txt`). No keychain dialog during either run.

**Reviews.**
- Fresh-context review: round 1 had R1 and R2 (important) and R3–R6 (nits). All were fixed in 4c9ad0b and 12e08c4. The re-review found no important finding open.
- Security review: S1 was important (terminal approval spoofing by a same-uid agent, a design hole in the L11 card). S2–S4 were nits. All were fixed in 463351b. The re-check found no important finding open; its nits (an argv digest in the Touch ID sheet with the residual recorded in AUTH-3, a pinned Public Suffix List for L29) are in 0ccbdd7.

**ARI-42.**
- `ari42_scan.py check`: 0 high, 0 medium, 5 low. The lows are pre-existing `bypassPermissions` strings in connector test goldens.
- The GW-1, AUTH-3, INJ-3 and INJ-4 rows are updated, with a change-log line. No status changed.

## Risk

- **Sensitive path:** `crates/ms-vault/**` (`crates/ms-vault/src/macos/tests.rs`, test code only). It needs a human reviewer. `gloop risk` does not know this loop ("No loop cli-scope"), so this was checked by hand against `loops.json` `sensitivePaths`.
- **Production code:** none changed.
- **What the test change gives up:** the test no longer shows what happens when another binary rewrites our item's attributes, because macOS asks the user, and that can't run unattended. The seal is what protects against it, and the seal is still tested by a worst-case trusted overwrite. This is recorded as `no_claim`.
- **Plan changes** affect loops that are running in parallel:
  - L11 must build terminal approvals rather than a Swift app.
  - L17 now depends on L29.
  - The v0.2 gate now includes L29.
- **Merge conflicts:** `ARI42.md` has small additive edits to four rows and the change log, so expect row-level conflicts with the parallel loops. `docs/PLAN.md` is edited only here.
- **Dialogs during this loop:** while I was diagnosing, two runs raised the dialog. Someone clicked Allow, and once "Always Allow". The grants were for throwaway test binaries and test items under `cc.morsec.test.*` services, which the tests deleted.

## How to revert

- `git revert` the loop's merge commit. Docs and test code only, so there is no data or state to migrate.
- To revert only the test change, revert ff8fb51, 4c9ad0b and 463351b in `crates/ms-vault/src/macos/tests.rs`. The dialog can come back after that.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
