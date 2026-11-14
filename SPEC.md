# SPEC: `cli-scope` (small loop, wave 3a, lands first)

Branch `feat/cli-scope`, port 4100. The user decided morsec ships as a **CLI only** for now, with
no app. This loop makes the plan say so, stops two keychain tests from raising dialogs that block
the gate, and settles the L08 follow-up D2 (the empty msd tunnel allowlist).

## 1. `docs/PLAN.md`: CLI-only scope

- **L25 `menubar-app`: out of scope (deferred).** Say why: the user chose CLI-only; every L25
  feature already has a CLI path (`ms status`, `ms log`, `ms log --export`, `ms stop`, `ms add`),
  and an app adds a signed Swift target, UI tests and a second approval surface to review. It can
  come back as its own loop later. Its card stays, marked deferred, so the history is readable.
- **L11 `approvals-macos`: approve from the CLI.** No `apps/MorsecApprove/` Swift app. The approval
  details (agent, project, session start, exact command, key and tier, effect preview, scope) are
  printed as inert text on the user's terminal (`/dev/tty`), control characters escaped, nothing
  truncated in a way that hides arguments. `ms` (or msd) confirms with Touch ID through
  `LocalAuthentication` (`LAContext`, biometrics, falling back to the login password). An agent
  can't approve its own request: the approving process must be outside every agent session (the
  same check as today's `at_terminal` path), and the token binds the request it approves.
- **L28 `release-1.0`: a CLI release.** Homebrew formula, docs and the signed release; no app cask.
- **First public CLI release after v0.2.** Add a note: the first public CLI release is cut after
  v0.2 (L11–L17), with a light hardening pass pulled forward from L24: the threat model and fuzz
  targets for the dotenv parser, the proxy request head and the IPC framing.
- Update everything that still promises an app so the plan is consistent: §1 at a glance, the
  mermaid graph (L25 shown deferred and off the L28 path), promise coverage (menu-bar row deferred,
  approval row via the CLI), §3.1 processes, §3.3, §3.6 tech choices, §3.7 layout, L10/L21
  mentions of the helper app, and decision D6.

## 2. Keychain tests never raise a dialog

`acl_other_binary_is_denied` and `ca_rejects_planted_keys` (`crates/ms-vault/src/macos/tests.rs`)
sometimes open a SecurityAgent dialog, which blocks `npm run build` until someone clicks it.

Root cause, from the securityd log (saved as proof): the re-signed "other binary" child already
runs every keychain call with interaction disabled (`quiet()`), and that does stop ACL prompts.
But when it calls `SecItemUpdate` on our item (`update-attr`), securityd checks the item's
partition list and **asks the user about the "XARA" partition anyway**, ignoring the flag. The
test passed only because someone clicked Allow.

Decision D1: the untrusted child never modifies items. The two tamper steps (`update-attr`,
`update-data`) are done by the byte-identical trusted copy instead: the worst case (as if the user
had clicked Allow for an attacker), and the seal must still catch it. Assertions get stricter
(exactly `UPDATED`, then the seal refuses the data). The other-binary checks that prove the ACL
(`get`, `del`, `put`, `ca`, and `get` after each tamper) stay exactly as they are.

Decision D2: every child runs under a timeout (60 s). A child that runs longer is killed (which
withdraws its dialog) and the test fails with a message naming the likely dialog, so the gate can
never hang on a human again.

Done when: the securityd log shows a prompt before the change and none after (the two tests 5×,
the full `ms-vault` suite, and three suites in parallel on a freshly built binary), the tests
still prove the ACL denies access, and the gate is green.

## 3. msd tunnel allowlist (L08 follow-up D2): a card, not code

Finding: filling `ProxyConfig.allow` is bigger than a small change, so per the brief it becomes a
card in PLAN.md. Reasons:

- The only place msd may take an egress allowlist from is MAC'd rules. Claude Code's
  `settings.json` and the connector state are agent-writable, so reading them would let an agent
  open egress to any host (INJ-4).
- Rules have no such section today. Adding one means a model and TOML change, loosening
  classification and approval (adding a host loosens), the tighten-only project merge, an IPC
  path to change it, `ms rules` CLI support, and connector parity.
- The proxy's allow-listed tunnel path does not consult the kill switch today (only bound keys go
  through policy), so a non-empty allowlist would survive `ms stop` (AUTH-4) until that is fixed
  in `ms-proxy`, and the proxy only rebuilds when bindings change.

The card (`L29 egress-allowlist`) specifies the design and its tests; L17 `doctor` depends on it.

## ARI-42

- GW-1: the ACL proof keeps running and can no longer hang on a dialog (evidence updated).
- INJ-4: the empty-allowlist gap and its card recorded.
- AUTH-3 / INJ-3: the approval plan moves to the terminal (inert text, Touch ID); statuses stay
  as they are until L11 builds it.

## Not in this loop

Any L11 code; the allowlist code (L29); changes to msd, ms-proxy or ms-rules.
