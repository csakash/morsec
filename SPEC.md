# SPEC: fold L35 (dash-connect) into 0.2.0

v0.2.0 is not tagged yet. L35 (#37) landed after the bump (#36) with its CHANGELOG entries under
[Unreleased]. The user asked to ship it in 0.2.0.

- Move both L35 entries from [Unreleased] into [0.2.0], after the dashboard entry. Leave [Unreleased] empty.
- Remove the 0.2.0 sentence "Connecting an agent and setting up a project stay in Terminal",
  which L35 made untrue.
- Change the date to 2026-11-20, the publish day.
- README and docs/ONBOARDING.md already describe the L35 actions. No change there.
- Done when: release-check.sh (all steps) and `npm run build` pass. No code changes.
