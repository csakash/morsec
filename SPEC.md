# SPEC: L11 `approvals-macos` (CLI only)

Status: committed on `feat/approvals-macos`. Scope changed by the user: **CLI only — no Swift
helper, no `apps/MorsecApprove/`.** The PLAN card (L11) is being rewritten by the parallel
`cli-scope` loop; this spec is the source of truth for this loop.

## Goal

Replace L07's `DenyApprover` with a real approver behind the frozen
`ms_approve::Approver` trait (PLAN §4), so that production-tier actions, loosening rules,
`ms start` and `ms scan` need a human's Touch ID (password fallback), bound to the exact request.
Remove the pre-L11 `--at-terminal` paths. ARI-42: AUTH-3, INJ-3, INJ-5.

## Decisions

**D1 — where the human sees and confirms (the main design call).**
The agent's own terminal is never trusted: the agent can type into it. Neither is a sheet that
pops up on its own (reflexive approval). So:

1. A request that needs approval becomes the single *pending approval* in msd and the requester
   blocks (up to the timeout).
2. The human reviews it with **`ms approve`**, run in their own terminal (outside every agent
   process tree). It shows every detail as inert text: agent, project (cwd), session start, the
   exact argv one argument per line, key and tier, effect preview if any, the scope choices, the
   request's fingerprint and how long is left. The human picks `o` (this exact command, once —
   the default), `s` (this exact command for this session) or `d` (deny).
3. On `o`/`s`, **msd itself** (a LaunchAgent in the user's GUI session) raises the system Touch ID
   sheet via LocalAuthentication. The sheet's reason text is built by msd from the real request
   (key, tier, agent, scope, the command, fingerprint), never by the client. Only a finger (or the
   login password typed into the system sheet) completes it.
4. msd mints the bound token and the requester continues.

`ms start`, a loosening `ms rules` and `ms scan` are already typed by the human at their own
terminal, so those commands run the same review inline (on `/dev/tty`, on a second connection)
for the request they themselves created. Without a terminal they print "approve it with
`ms approve` in another terminal".

msd never raises Touch ID unprompted; it does so only for an explicit `o`/`s` decision on the
current pending id.

**D2 — who may approve.** `ApprovalPending` and `ApprovalDecide` are refused to a caller inside
an agent process tree (L06 `Caller::Agent`) and to an unidentified caller. A detached same-user
process is "unattributed" and can send a decision, but it still has to get past the Touch ID sheet
msd draws, which names the real key and command. Residual, recorded in ARI42.md: a user who
touches an unexpected sheet without reading it; a same-user process writing into the
`ms approve` terminal's tty (the sheet text stays authoritative).

**D3 — one prompt at a time.** At most one pending approval. A second request while one is
pending is refused at once ("another approval is waiting"), never queued, so an agent can't
stack prompts. Session-scope grants that already cover a request don't prompt at all.

**D4 — timeout and failure.** Default 120 s. Nobody decides in time → `TimedOut` (rejected). A
Touch ID that fails, is cancelled, or completes after the deadline → denied; the sheet is
invalidated at the deadline; nothing is minted late. A failed/cancelled Touch ID denies the request
(no retry loop on the same pending id).

**D5 — the bound token.** `ApprovalToken` keeps its frozen shape (`id`, `mac`, `expires_unix_ms`).
`mac = HMAC-SHA256(k, "morsec-approval-v1" ‖ len-prefixed(id, scope, agent, session pid,
session start, key, argv_hash, cwd bytes, expiry))`. `k` is 32 random bytes made when msd starts
(tokens never outlive the daemon). The scope is encoded in the id (`once-<32 hex>` /
`sess-<32 hex>`) and covered by the MAC, so it can't be edited. Once tokens expire 60 s after
approval and are consumed by their first successful check. Session tokens last 8 h at most, and
`ms stop` revokes every grant.

**D6 — the executor API (for L15/L16).** `ms_approve::Approvals` (in msd: `Daemon::approve_exact`)
asks, then **verifies the token against the binding it is about to execute** and refuses on any
difference. `Approvals::verify(&token, &Binding)` is the check an executor runs right before
acting; `Binding = {session, key, argv_hash, cwd}`.

**D7 — inert rendering (INJ-3).** `ms_approve::render::inert` escapes, never strips: backslash,
C0/C1 controls and DEL (`\n`, `\t`, `\e`, `\x7f`, `\u{85}`…), bidi controls (U+200E/F, U+202A–E,
U+2066–9, U+061C), invisible/format characters (zero-width, U+2028/9, U+FEFF, tags…). Each argument
is shown on its own line, numbered and quoted, so spaces and empty arguments are visible.
`ms approve` never truncates. The Touch ID reason has a length cap; when it hits it, it says so
explicitly ("… N more characters not shown; full command in ms approve") next to the fingerprint,
so a cut can't silently hide arguments. Confusable characters (homoglyphs) are out of scope.

**D8 — `Scan` behind the approver (closes L09's INJ-5 residual).** `ms scan` from outside an agent
asks the approver (key `morsec/daemon`, argv `ms scan`) before reading any value.

**D9 — pre-L11 paths removed.** msd ignores `at_terminal` (kept in the wire format for
compatibility); every loosening and every resume goes through the approver. `ms init --resume`
becomes an alias of `ms start`; `ms rules --at-terminal` is hidden and ignored with a note. Hints
in `ms status` and `ms stop` say `ms start`.

**D10 — Touch ID behind a trait.** `ms_approve::Authenticator::authenticate(reason, deadline)`.
The macOS implementation (`crates/ms-approve/src/macos/`, objc2 LocalAuthentication bindings)
evaluates `.deviceOwnerAuthenticationWithBiometrics`, and on fallback / no biometry / lockout
evaluates `.deviceOwnerAuthentication` (login password in the system sheet). Off macOS it denies.
Tests use a fake. **There is no environment variable or flag that skips Touch ID in a release
build.** For the end-to-end tests only, a *debug* build of msd started with the ephemeral
`--vault memory` accepts `--test-touch-id allow|deny`, which replaces only the authenticator (the
pending slot, caller checks, rendering and token stay real). It is refused with the keychain vault
and refused at startup in release builds (`cfg!(debug_assertions)`).

## IPC v1 additions (backwards compatible)

- `ApprovalPending` → `Approval { pending: Option<PendingApproval> }`;
  `PendingApproval { id, request: ApprovalRequest, requested_unix_ms, expires_unix_ms }`.
- `ApprovalDecide { id, approve, scope? }` (`scope`: `once` | `session`) → `Ok` or an error.
- `ms status` asks `ApprovalPending` too and shows "1 approval waiting · run ms approve" (no new `Status` field, to keep other loops' code untouched).
- Responses to requests that wait for approval can take up to the timeout; the CLI waits longer
  than that.

## Out of scope

Swift UI, menu-bar notification of a pending approval (L25), run-mode execution (L12/L15/L16 call
`approve_exact`), Linux polkit (L21), homoglyph detection.

## Acceptance

1. Changing one argument (or cwd, key, session) after approval → the executor's verify refuses.
2. A timeout is rejected; nothing approved after the deadline.
3. ANSI, RTL-override, newline (and NUL, zero-width) payloads render inert in `ms approve` and in
   the Touch ID reason.
4. An agent-tree caller can't list or decide approvals (unit + real-binary e2e).
5. Once tokens are single-use; session tokens are reused only for the identical binding in the
   same session, and `ms stop` revokes them.
6. Only one pending approval; a second is refused at once.
7. `Scan`, `Start` and loosening go through the approver; `at_terminal` no longer bypasses it.
8. `npm run build` green; review + security review converged; PROOF.md written with the manual
   Touch ID check marked **needs a human**.
