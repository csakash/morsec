# morsec

Named after Morse code. CLI: `ms` or `mors` (same command, two names).

Coding agents use your API keys, database passwords and tokens without ever seeing them. Everything stays on your machine.

- Mockup, PRD and implementation plan: https://app.intraface.cc/b/warden-keys-mockup-gfnm5
- Plan in the repo: [docs/PLAN.md](docs/PLAN.md) · security record: [ARI42.md](ARI42.md)

## Install

Apple silicon, macOS 13 or later. Pick one; all three install the same Developer ID signed,
notarized binaries:

```bash
brew install csakash/tap/morsec                  # Homebrew
npm install -g morsec                            # npm (no install scripts)
curl -fsSL https://github.com/csakash/morsec/releases/latest/download/install.sh | sh   # into ~/.local/bin
```

The curl installer checks the checksums, the minisign signature (if minisign is installed), the
code signature, the team and notarization before installing anything, and never uses sudo. To
read it first: download `install.sh`, check it against the release's `SHA256SUMS`, then
`sh install.sh` ([packaging/VERIFY.md](packaging/VERIFY.md)). Then:

```bash
ms init
```

Run inside a project, `ms init` moves its `.env` secrets into the vault and leaves `ms://`
references. Run your app through morsec so they still work: `ms dev -- npm run dev`.

Then add a key, say where it may go, and connect your agent:

```bash
ms add stripe/test --tier test
ms rules stripe/test --add-host api.stripe.com
ms connect claude-code --env STRIPE_API_KEY=ms://stripe/test
ms doctor
```

The agent only ever sees `ms://stripe/test`; `msd` swaps the real key in on requests to
`api.stripe.com` and records every use (`ms log`). There is no auto-update: upgrade with
`brew upgrade morsec`, `npm install -g morsec@latest` or the curl installer again, then restart
msd with `launchctl kickstart -k gui/$(id -u)/cc.morsec.msd` (after a curl upgrade, also
`ms run --link-shims`). For commands that need a value (`psql`,
`ssh`, `git`, deploy scripts), use run mode; `ms stop` cuts every agent off at once.
`ms set` replaces a value, `ms rm` deletes a key and `ms undo <project>` writes a project's
values back into its `.env` files (each with Touch ID); `ms dashboard` does the same in your
browser. The whole
walk-through, including Codex and run mode, is [docs/ONBOARDING.md](docs/ONBOARDING.md).

## Status

Pre-1.0, CLI only (no app). Built: the keychain vault, swap proxy, run mode with Postgres and
SSH/git adapters, Touch ID approvals in the terminal, receipts, `ms import`, `ms mcp`,
`ms doctor`, `ms scan`, and connectors for Claude Code and Codex. The first signed release is
being prepared (`packaging/RELEASING.md`, `scripts/release-check.sh`); changes are in
[CHANGELOG.md](CHANGELOG.md). 1Password/Bitwarden import and the ARI-42 evidence export come
after it (v1.x).

## Develop

Requirements: Rust 1.93.1 (pinned in `rust-toolchain.toml`, installed by rustup automatically),
Python 3, and the two gate tools:

```bash
cargo install --locked cargo-deny cargo-audit
```

Run the gate. There is no hosted CI in v1; this script is the gate, and gloop's build gate runs it
through `npm run build`:

```bash
scripts/check.sh
```

Try it:

```bash
cargo run -q -p msd -- --foreground --socket /tmp/morsec-dev/msd.sock
```

```bash
MORSEC_SOCKET=/tmp/morsec-dev/msd.sock cargo run -q -p ms-cli -- status
```

Install dev builds of `ms`, `mors` and `msd` into `~/.local/bin` (links; refuses to overwrite
anything else). It also builds `ms-shim`, which `ms` finds beside its real path in
`target/release`:

```bash
scripts/install-dev.sh
```

Before a release, `scripts/release-check.sh` runs the release checklist (it signs and publishes
nothing; the human steps are in [packaging/RELEASING.md](packaging/RELEASING.md)).

## Layout

`crates/` holds one crate per component; see `docs/PLAN.md` §3.7 for which loop owns which crate.
