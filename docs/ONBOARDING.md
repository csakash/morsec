# Getting started with morsec

morsec lets a coding agent (Claude Code, Codex) use your API keys, database passwords and tokens
without ever seeing them. The agent only ever holds references like `ms://stripe/test`. The
values stay in your macOS keychain, and `msd`, a daemon running as you, puts them in at the last
moment: in an outgoing HTTPS request (swap mode) or in a command it runs for the agent (run
mode). Every use is a receipt you can read with `ms log`.

`ms` and `mors` are the same command. This guide takes you from install to a protected agent
session; the target is under 5 minutes.

## 1. Install

Apple silicon, macOS 13 or later:

```bash
brew install csakash/tap/morsec
```

That installs `ms`, `mors`, `msd` (the daemon) and `ms-shim` (run mode), all signed with the
project's Developer ID and notarized. There is no auto-update; upgrade with `brew upgrade morsec`.
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

Or move a whole `.env` into the vault. It shows a review table first, then rewrites the file
with references, so it is safe to commit:

```bash
ms import .env
```

Keys are `production` tier unless you say otherwise; a production key asks you (Touch ID) before
each use. `test` keys never prompt.

## 4. Say where each key may go

A key allows nothing until you give it a target. For an HTTP API (swap mode, the default):

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
2. `brew install csakash/tap/morsec`.
3. The keychain trusts the signed release `msd`, not a dev build, so don't carry a dev build's
   vault over: start over with `ms init --force` (old receipts are kept, renamed, for
   inspection) and add your keys again.
4. `ms connect` your agents again and run `ms doctor`.
