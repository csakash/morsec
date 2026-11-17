# Changelog

All notable changes to morsec. Each release gets a `## [X.Y.Z] - YYYY-MM-DD` section before it
is tagged; `scripts/release-check.sh` refuses a release whose version has no section with
entries. Move the entries from Unreleased into it when you bump the version.

## [Unreleased]

## [0.1.0] - 2026-11-17

First public release. Apple silicon macOS 13 or later only (`aarch64-apple-darwin`).

- `ms` / `mors`, `msd` and `ms-shim`, signed with Developer ID (team `554MCRUAKK`) and
  notarized. Swap mode (proxy), run mode (`ms run`, shims), `ms mcp`, `ms doctor`, and
  connectors for Claude Code and Codex.
- Three ways to install the same signed binaries: Homebrew (`brew install csakash/tap/morsec`),
  npm (`npm install -g morsec`, with the binaries in the `morsec-darwin-arm64` platform package
  and no install scripts), and a curl installer (`install.sh`, a release asset) that checks the
  checksums, the minisign signature when minisign is installed, the code signature, the team and
  notarization before it installs into `~/.local/bin`.
- `ms stop` now leaves a receipt for every run it kills.
- Upgrading needs no `ms init`: msd's LaunchAgent and the run shims point at Homebrew's stable
  `opt/morsec` path, or at the npm package's path, which `npm install -g` keeps. `ms doctor`
  flags a LaunchAgent whose install is gone (a removed Homebrew version, or an npm install under
  a Node version you switched away from), one that starts a different install's msd, and shims
  still pinned to a version.
