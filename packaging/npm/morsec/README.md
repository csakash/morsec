# morsec

Coding agents (Claude Code, Codex) use your API keys, database passwords and tokens without
ever seeing them. The values stay in your macOS keychain; `msd`, a daemon running as you, puts
them in at the last moment and records every use.

```bash
npm install -g morsec
ms init
ms doctor
```

Apple silicon, macOS 13 or later. `ms` and `mors` are the same command. The binaries come from
the `morsec-darwin-arm64` package (an optional dependency, so don't install with
`--omit=optional`). They are the same Developer ID signed and notarized files as the GitHub
release and the Homebrew formula. Neither package runs anything at install time.

Upgrade with `npm install -g morsec@latest`, then restart msd:
`launchctl kickstart -k gui/$(id -u)/cc.morsec.msd`. If you switch Node versions (nvm, fnm,
volta), install morsec under the new one and run `ms init` again: msd's LaunchAgent points into
the npm install it was set up from. `ms doctor` tells you when that install is gone.

Getting started: https://github.com/csakash/morsec/blob/main/docs/ONBOARDING.md
