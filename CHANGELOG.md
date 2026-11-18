# Changelog

All notable changes to morsec. Each release gets a `## [X.Y.Z] - YYYY-MM-DD` section before it
is tagged; `scripts/release-check.sh` refuses a release whose version has no section with
entries. Move the entries from Unreleased into it when you bump the version.

## [Unreleased]

- `ms init` now sets up the project you run it in, in one command. In a project folder it finds
  the secrets in every `.env` file (as deep as the project goes, skipping `node_modules` and other
  dependency folders, never following symlinks), moves them into the vault, rewrites the files
  with `ms://` references, and asks you once (Touch ID) to let the keys it knows reach their
  services. Keys written straight into code are reported with file and line, never changed. A
  short summary says what is protected, what still needs you, and which files are in git
  history. Run in your home folder it only sets up this Mac. New flags: `--machine`,
  `--project [PATH]`, `--name`, `--no-connect`. It also connects Claude Code and Codex when it
  finds them.
- `ms projects [NAME]` lists the projects `ms init` set up, or shows one in full (no values).
- An existing `CLAUDE.md` or `AGENTS.md` gets a short note telling agents to keep `ms://`
  references as they are. morsec never creates those files.

- Keys stored by another morsec build (for example a dev build, before you installed the signed
  release) no longer break the vault. `ms doctor`, `ms status` and `ms init` list them by name
  with the command that removes each one (`security delete-generic-password -s cc.morsec.vault
  -a <name>`, which asks for your login password), and `ms add <name>` says the same instead of
  failing. The keychain lets only the build that stored a key read or delete it, so morsec can't
  remove them for you.

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
