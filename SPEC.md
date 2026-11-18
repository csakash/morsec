# SPEC: guided-setup-dashboard (design loop)

## Context

morsec needs five commands and some network vocabulary to protect one key. Non-technical users
who have just started vibe coding give up partway. This loop fixes the plan, not the code: it lands
the agreed design for a one-command `ms init` (machine mode and project mode), a local
dashboard in the landing-page style with the same powers as the CLI, and `ms dev`. It also adds
the four build loops that implement it.

## Decisions (user, 2026-11-18)

- D1: the dashboard can show and copy values, with Touch ID on every use; recorded as an accepted
  ARI-42 exception (GW-1, INJ-5).
- D2: project setup asks nothing; Undo from the dashboard.
- D3: add `ms dev` so the user's own `npm run dev` works after import.
- D4: one epic, four loops: L31 `guided-init`, L32 `dash-core`, L33 `dash-actions`, L34 `ms-dev`.

## Deliverables

| File | Change |
|---|---|
| `docs/design/guided-setup-dashboard.md` | New. The full design: modes, scan, import, data model, IPC, dashboard security, screens, CLI parity, Show/Copy, Undo, Replace, `ms dev`, threats, ARI-42 map, out of scope, loop order |
| `docs/PLAN.md` | Wave 7 with cards L31 to L34 (depends, owns, build, verify, ARI-42) |
| `ARI42.md` | D1 exception row; change-log line. No status changes (no code) |

## Acceptance criteria

1. The design names, for every new IPC request, whether it needs Touch ID and whether it is
   refused inside agent sessions.
2. Every threat in design §8 names a control and the test that proves it, and the loop that adds
   it.
3. Every CLI subcommand on `main` (`crates/ms-cli/src/main.rs`: init, add, import, connect,
   disconnect, run, rules, log, stop, start, approve, status, doctor, mcp, scan, stats) appears in
   the parity table in design §6.5, either with a dashboard screen or as an exemption with a reason.
4. Each card L31 to L34 lists `Depends on`, `Owns`, `Build`, `Verify` with named tests, and
   `ARI-42`.
5. `ARI42.md` holds the D1 exception with its controls, residual, who accepted it and a review
   date.
6. `npm run build` (`scripts/check.sh`) passes; the ARI-42 scanner reports no new finding.

## Out of scope

All product code. Each of L31 to L34 is its own loop with its own `SPEC.md` lifted from its card
and design section.

## Rollback

Docs only: revert the PR.
