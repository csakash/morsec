# Changelog

All notable changes to morsec. Each release gets a `## [X.Y.Z] - YYYY-MM-DD` section before it
is tagged; `scripts/release-check.sh` refuses a release whose version has no section with
entries. Move the entries from Unreleased into it when you bump the version.

## [Unreleased]

## [0.2.0] - 2026-11-20

- The dashboard (`ms dashboard`) now looks like morsec's site, with its fonts bundled in msd
  (nothing is fetched): one ruled sheet, a numbered rail of the five screens (with what's
  waiting, your projects and the open project's keys), breadcrumbs, rows that open what they
  name, and the site's light/dark switch, works in light and dark from phone width up, and can act, not only show.
  From Home you approve or deny the request an agent is waiting on, see each warning in plain
  words with its fix, and stop or start morsec. On a key's page you can show its value or copy
  it (Touch ID every time; a shown value hides after 15 seconds and the clipboard is cleared
  after 30, and clipboard managers are told to skip it), replace or delete it, give it a website
  or a command (adding one needs Touch ID, taking one away doesn't), and undo its import. A
  project can be undone as a whole. The leak scan runs from the Scan screen; Agents re-checks
  msd's view of your agents. Every action, done or refused, is in Activity.
- The dashboard connects and disconnects Claude Code and Codex, and sets up or re-scans a
  project folder, itself. Each shows exactly what will change first (the same redacted diff
  `ms connect` prints; the files, secrets and websites `ms init` would touch), then asks Touch ID
  once, and does precisely what was shown or nothing. A key's page can now add and remove git
  hosts, variables and SSH host keys.
- Security: the git-history check `ms init` runs (and now msd, for Add project) can no longer be
  made to run a program from a repository's own git config (a partial clone's lazy fetch).
- New commands with the same effect in Terminal: `ms set <key>` replaces a value, `ms rm <key>`
  deletes a key and its rule, `ms undo <project> [--key <key>]` writes the values back into the
  project's `.env` files. Each asks for Touch ID and refuses inside an agent session.
- `ms` and `msd` ship together: an older `ms approve` can't read a request from this msd that
  morsec made for its own actions (it is marked so it can be approved once only). Update both.
- `ms add` no longer replaces a key that exists (it never did from the CLI; a direct request to
  msd could, without asking). Replacing is `ms set`, with Touch ID.
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
- `ms dev -- <command>` runs your own app (for example `npm run dev`) so the `ms://` references
  `ms init` left in your `.env` work: requests to your keys' services go through morsec, which
  swaps the real key in, and database URLs are put in the command's environment. Only processes
  started by that `ms dev` can use its session; it ends when your command exits. Each run asks you
  once (Touch ID), showing the keys and variables it will use. Refused inside an agent session and for agent
  programs. Node 24 or later is needed for Node apps (older versions are warned about).
- Keys `ms init` set up for a project (`shop/stripe-secret-key`) are now swapped by the proxy;
  before, the proxy didn't know where their credential goes and skipped them.
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
