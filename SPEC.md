# SPEC: release-cli (L28, CLI-only release prep)

Loop `release-cli`, branch `feat/release-cli`. The first release is CLI-only (L25 menubar app
deferred). This loop prepares everything a signed Homebrew CLI release needs that does not
need a human. Developer ID signing, notarization, the tap repo, publishing and the clean-VM
install stay human steps (packaging/RELEASING.md).

## Goals

### G1. Ship `ms-shim` next to `ms` and `msd`
Run mode (L12) needs `ms-shim` beside the canonicalized `ms`: `ms run --link-shims` and
`ms doctor`'s "run shims" check look for it there. The release today ships only `ms` and `msd`.

- `packaging/macos/sign-targets` is the one list of what ships in `bin/`. It gains
  `ms-shim cc.morsec.ms-shim`. `ms` and `msd` identifiers stay frozen.
- `scripts/release.sh` builds, stages, hashes (BUILDINFO), SBOMs (root `ms-run`), signs,
  archives and repro-compares every binary sign-targets names, not a hard-coded `ms msd`.
- The Homebrew template installs `bin/ms-shim` with `bin.install` (in the Cellar, next to `ms`)
  and its `test do` checks `ms-shim` runs and refuses to run under its own name.
- `packaging/lib/formula.py` can list the binaries a template installs; a unit test pins that
  list to sign-targets.
- **Install test** (packaging tests): build a tarball from the built `ms`, `msd`, `ms-shim`
  with `archive.py`, install it into a temporary prefix the way the formula does (Cellar dir,
  then symlinks in `<prefix>/bin`, plus `mors`), start the installed `msd --vault memory` with a
  temp socket, state dir and `HOME`, add a test-tier run key allowing one program, and run the
  installed `ms doctor`. The "run shims" section must not say "ms-shim is not installed next to
  ms"; after `ms run --link-shims` it must pass ("1 shim linked"). A control run installs
  without `ms-shim` and must get the "not installed" failure, proving the check bites.
  Never touches the real `~/.claude`, `~/.codex`, `~/.ssh`, git credentials or keychain.

### G2. Receipt when `ms stop` kills a run (L12 review N3)
A run killed mid-flight by `ms stop` or a LOG-2 session stop writes one receipt per run-mode key
the run used: mode run, same target, argv hash, rule version and approval id as its start
receipt, result `Failed("killed: morsec was stopped (ms stop)")` or
`Failed("killed: this agent session was stopped (LOG-2)")`. Both `Run` (buffered) and
`RunStream`. Failed, not Blocked, so the kill does not count toward LOG-2 blocked-attempt
alerts. A receipt write failure is logged; the reply to the client stays the kill message.
Test: `stop_kills_a_running_command` also asserts the kill receipt.

### G3. `scripts/release-check.sh`
A local pre-release checklist. Runs, stopping at the first failure, never skipping a step:

1. **version**: workspace version is `X.Y.Z` and not `0.0.0`; every workspace member has that
   version; `Cargo.lock` agrees (`--locked`); if tag `v<version>` exists it must point at HEAD
   (otherwise that version was already released).
2. **changelog**: `CHANGELOG.md` has a `## [<version>]` section with at least one entry.
3. **build**: `cargo build --release --locked -p ms-cli -p msd -p ms-run`; the built `ms --version`
   prints `morsec <version>` (optionally followed by ` (<commit>)`).
4. **packaging tests**: `python3 -I -m unittest discover -s packaging/tests` (including the
   install test, which uses the debug build because it needs msd's debug-only Touch ID stand-in)
   and `shellcheck` on both scripts.
5. **formula matches build**: binaries the formula installs == sign-targets == built binaries
   present in `target/release`, each a thin arm64 Mach-O executable; the release binaries,
   installed from a tarball through the formula's install lines, pass its `test do` block.

It never signs, notarizes, tags, pushes, uploads or touches the tap repo, and reads no
credential variable. Version and changelog logic lives in `packaging/lib/releasecheck.py` with
unit tests. `CHANGELOG.md` is added with an `Unreleased` section.

### G4. Docs
- `packaging/RELEASING.md`: run `scripts/release-check.sh` before tagging; `ms-shim` listed in
  what is signed and uploaded; CHANGELOG step; human steps unchanged and still human.
- `packaging/VERIFY.md`: verify `ms-shim` as well.
- `docs/PLAN.md` L28 card: what this loop did and what is left for the human.

## Non-goals
- No signing, notarization, tag, push, release or tap repo. No credentials.
- No version bump (stays 0.0.0; release-check fails on it, by design).
- The Homebrew `msd_path()` Cellar follow-up from L10 notes, onboarding docs, timed install.

## Acceptance
- `npm run build` green (the gate runs the new packaging tests).
- Install test passes with `ms-shim`, fails the control without it.
- Kill receipt test passes for `ms stop`.
- `scripts/release-check.sh` on this branch fails at step 1 with "bump the version" (0.0.0),
  and its library tests cover passing and failing inputs for version, changelog and formula
  match.
- Code review and security review converge; PROOF.md has Testing, Risk, How to revert.
