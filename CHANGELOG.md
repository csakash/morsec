# Changelog

All notable changes to morsec. Each release gets a `## [X.Y.Z] - YYYY-MM-DD` section before it
is tagged; `scripts/release-check.sh` refuses a release whose version has no section with
entries. Move the entries from Unreleased into it when you bump the version.

## [Unreleased]

- First CLI release (L28): `ms` / `mors`, `msd`, `ms-shim`, installed with Homebrew from
  `csakash/tap`. Swap mode (proxy), run mode (`ms run`, shims), `ms mcp`, `ms doctor`, and
  connectors for Claude Code and Codex.
- `ms stop` now leaves a receipt for every run it kills.
