# morsec

Named after Morse code. CLI: `ms` or `mors` (same command, two names).

Coding agents use your API keys, database passwords and tokens without ever seeing them. Everything stays on your machine.

- Mockup, PRD and implementation plan: https://app.intraface.cc/b/warden-keys-mockup-gfnm5
- Plan in the repo: [docs/PLAN.md](docs/PLAN.md) · security record: [ARI42.md](ARI42.md)

## Status

Loop L00 `foundation`: the Rust workspace, frozen interfaces, the `ms`/`mors` skeleton and a dev
daemon. Only `ms status` and `ms --version` work; every other command says which loop builds it.

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

Install dev builds of `ms`, `mors` and `msd` into `~/.local/bin` (links, refuses to overwrite
anything else):

```bash
scripts/install-dev.sh
```

## Layout

`crates/` holds one crate per component; see `docs/PLAN.md` §3.7 for which loop owns which crate.
