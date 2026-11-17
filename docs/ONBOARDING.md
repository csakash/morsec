# Getting started with morsec

morsec lets a coding agent (Claude Code, Codex) use your API keys, database passwords and tokens
without ever seeing them. The agent only ever holds references like `ms://stripe/test`. The
values stay in your macOS keychain, and `msd`, a daemon running as you, puts them in at the last
moment: in an outgoing HTTPS request (swap mode) or in a command it runs for the agent (run
mode). Every use is a receipt you can read with `ms log`.

`ms` and `mors` are the same command. This guide takes you from install to a protected agent
session; the target is under 5 minutes.

## 1. Install

You need an Apple silicon Mac with macOS 13 or later. Each of the three ways below installs `ms`,
`mors`, `msd` (the daemon) and `ms-shim` (run mode). They are the same files, signed with the
project's Developer ID (team `554MCRUAKK`) and notarized. Pick one.

**Homebrew**

```bash
brew install csakash/tap/morsec
```

**npm.** You need an arm64 Node.js 18 or later. The binaries come in the `morsec-darwin-arm64`
package. Neither package runs anything when it is installed.

```bash
npm install -g morsec
```

**curl.** This installs into `~/.local/bin`, or into `MORSEC_INSTALL_DIR`. It never uses sudo.
Before it installs anything, it checks:

- the release checksums;
- their minisign signature, when `minisign` is installed;
- each binary's code signature and team;
- notarization.

It only replaces files it installed itself.

```bash
curl -fsSL https://github.com/csakash/morsec/releases/latest/download/install.sh | sh
```

To read the installer before you run it, download `install.sh`, `SHA256SUMS` and
`SHA256SUMS.minisig` from the [latest release](https://github.com/csakash/morsec/releases/latest).
Check them as [packaging/VERIFY.md](../packaging/VERIFY.md) shows, then run
`sh install.sh` (add `--version 0.1.0` to pin a version). To build from source instead, use
`scripts/install-dev.sh` (see the README). The curl installer won't overwrite the links that
script makes.

There is no auto-update. To upgrade, use the same channel you installed with, then restart msd:

```bash
brew upgrade morsec                 # or: npm install -g morsec@latest, or run the curl installer again
launchctl kickstart -k gui/$(id -u)/cc.morsec.msd
```

msd's LaunchAgent points at a path that stays the same through an upgrade:

- Homebrew's `opt/morsec`;
- the npm package's own directory;
- `~/.local/bin` for the curl installer.

So the new version is picked up on its own, and the second line restarts the running msd on it.
The run shims follow upgrades in Homebrew and npm installs too. With the curl installer they are
hard links to the old file, so after a curl upgrade also run `ms run --link-shims` (the
installer reminds you).

If you installed with npm and then switch Node versions (nvm, fnm, volta), the global packages
change with the Node version. Install morsec under the new one, run `ms init` again, and
`ms connect` your agents again (their settings name the `ms` inside the old install). `ms doctor`
flags a LaunchAgent whose install is gone, or one that starts another install's msd.

To check a download yourself, see [packaging/VERIFY.md](../packaging/VERIFY.md).

## 2. Set up

```bash
ms init
```

It creates the vault in your login keychain and starts `msd` as a LaunchAgent. `ms status`
says whether morsec is on and how many secrets it protects.

## 3. Add your secrets

Type a value (hidden input):

```bash
ms add stripe/test --tier test
```

Or move a whole `.env` into the vault. It shows a review table first (the variables it takes as
secrets, with a tier and, for known providers, hosts), then stores those and rewrites them as
references. Check the table, and use `--include` for anything it missed, before you commit the
file; values already in git history stay readable there:

```bash
ms import .env
```

`ms add` keys are `production` tier unless you say otherwise; `ms import` proposes a tier per
variable. A production key asks you (Touch ID) before use, once or for the agent session as you
choose; `test` keys never prompt.

## 4. Say where each key may go

A key you added with `ms add` allows nothing until you give it a target. For an HTTP API (swap
mode, the default):

```bash
ms rules stripe/test --add-host api.stripe.com
```

For a command that needs the value (run mode, for `psql`, deploy scripts, `ssh`, `git`):

```bash
ms add db/staging --mode run --tier test
ms rules db/staging --add-root ~/code/shop --add-env PGPASSWORD --add-command '["psql", "**"]'
ms run --link-shims
```

In a command pattern `*` matches one argument and a trailing `**` any number. Every change that
loosens a rule asks for your approval in the terminal, confirmed with Touch
ID. Agents can't approve it: approvals are refused inside an agent session. Project files
(`.morsec.toml`) can only tighten your rules.

## 5. Connect your agent

```bash
ms connect claude-code --env STRIPE_API_KEY=ms://stripe/test
ms connect codex --env STRIPE_API_KEY=ms://stripe/test
```

Use `--dry-run` to see the changes first; `ms disconnect <agent>` undoes them. Start a new agent
session afterwards. The agent sees `STRIPE_API_KEY=ms://stripe/test`; when it calls
`api.stripe.com`, msd swaps the real key in on the way out. Sent anywhere else, the reference
stays a reference and the attempt is recorded as blocked.

For run mode, the Claude Code connector puts `~/.morsec/shims` first on the agent's `PATH`. When
the agent runs `PGPASSWORD=ms://db/staging psql …` inside your project root, the shim hands the
call to msd, which runs it with the value and sends back redacted output. With Codex, have it run
`ms run -- <command>` or give it the commands as MCP tools (`ms mcp`).

## 6. Check it

```bash
ms doctor
```

It checks the daemon, the vault, the run shims and every connected agent. `ms doctor --live`
also starts each agent headless and checks from inside its sandbox (it spends tokens).

## Day to day

| What | Command |
|---|---|
| Answer a production key's approval | `ms approve` (or `ms approve --watch` in a spare terminal) |
| See what was used, by whom, where | `ms log` (`--since 2h`, `--key`, `--result blocked`); `ms log --verify` checks the chain |
| Stop every agent's access now | `ms stop` (kills running commands too, and records it); `ms start` resumes, with Touch ID |
| Look for leaked values in transcripts | `ms scan` |
| Prompts per session, blocks, approvals | `ms stats` |
| Your run commands as MCP tools | `ms connect claude-code --with-mcp` |

## Upgrading from a dev install (before 1.0)

There were no public releases before 1.0. If you used `scripts/install-dev.sh`:

1. Stop the dev daemon (`launchctl bootout gui/$(id -u)/cc.morsec.msd` if `ms init` installed
   its LaunchAgent) and remove the links it made in `~/.local/bin` (`ms`, `mors`, `msd`).
2. Install a release (section 1). The curl installer refuses to replace the dev links in
   `~/.local/bin`, so remove them first, as step 1 says.
3. The keychain trusts the signed release `msd`, not a dev build, so don't carry a dev build's
   vault over: start over with `ms init --force` (old receipts are kept, renamed, for
   inspection) and add your keys again.
4. `ms run --link-shims` (it replaces the dev build's shims with links to the release),
   `ms connect` your agents again, and run `ms doctor`.
