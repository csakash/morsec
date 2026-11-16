# SPEC: launchagent-opt-path

## Problem

`ms init` writes msd's LaunchAgent (`~/Library/LaunchAgents/cc.morsec.msd.plist`) with msd's
canonical path. For a Homebrew install that is the versioned keg,
`<prefix>/Cellar/morsec/<version>/bin/msd`. `brew upgrade morsec` installs a new keg and deletes
the old one, so launchd can no longer start msd: after an upgrade (or a reboot after one) morsec
is down until the user re-runs `ms init`.

The run shims have the same flaw. `ms run --link-shims` hard-links (or copies)
`<keg>/bin/ms-shim` into `~/.morsec/shims`. After an upgrade those shims are the old `ms-shim`,
and they no longer match the new `ms-shim`, so `--link-shims` skips them as "not a morsec shim"
and `ms doctor` reports them as stale with no way to fix them short of deleting them by hand.

The docs and formula caveats work around this with
`brew upgrade morsec && ms init && ms run --link-shims`. This is the last code gap L28 flagged
before the first release.

## Goal

A Homebrew install keeps working across `brew upgrade morsec` with no extra command. Other
installs (a dev `cargo build`, a manual copy) keep exactly today's paths and behaviour.

## Behaviour

1. **Homebrew detection, derived, never by running `brew`.** Given an executable's canonical
   path `real`, it is a Homebrew keg binary when its last five components are
   `Cellar/morsec/<version>/bin/<name>` (`<version>` a single normal component, not `.` or
   `..`). Then `prefix` is the parent of `Cellar` and the stable path is
   `<prefix>/opt/morsec/bin/<name>`. The stable path is used **only if** it canonicalizes to
   exactly `real` (Homebrew's `opt/morsec` link points at this very keg). Any other case (not a
   keg, a custom `HOMEBREW_CELLAR` with no matching `opt`, an `opt` link pointing at another
   version, a missing `opt`) falls back to `real`: today's behaviour.
2. **`ms init`:** the LaunchAgent's program path (and the `msd --init` call) use the stable
   path from (1) when there is one. Defence in depth: `<prefix>/opt` must be a directory owned
   by the user or root and not group- or world-writable, and the `opt/morsec` link must be
   owned by the user or root; otherwise the canonical path is used (a shared prefix owned by
   another account, or Intel Homebrew with a group-writable `opt`, keeps today's behaviour and
   `ms doctor` says why). launchd follows the `opt` symlink on every start, so after
   `brew upgrade` it starts the new msd.
3. **`ms run --link-shims`:**
   - Homebrew install (stable path found): each shim is a **symlink** to
     `<prefix>/opt/morsec/bin/ms-shim`, so it follows upgrades.
   - Otherwise: a hard link of the canonical `ms-shim`, or a copy across file systems (today).
   - A file in `~/.morsec/shims` counts as a morsec shim (and may be replaced or removed) when
     it is: a hard link or byte-identical copy of the current `ms-shim` (today); a symlink whose
     target is the current `ms-shim` (either form); or a regular file or symlink target that
     carries the `ms-shim` marker string after an executable header (Mach-O, universal or ELF),
     read only from a regular file of at most 64 MiB (a planted link to a FIFO or device is
     never opened) (an older `ms-shim` build: this is how hard links left
     by an older version, or a dev build's copies, get migrated). Anything else is still left
     alone and reported as skipped.
   - An existing shim in the wrong form (a hard link where a symlink is wanted, or the reverse,
     or an old build) is replaced and reported as `updated`.
4. **`ms doctor`:**
   - New `launchagent` section, shown whether or not msd is running (a broken LaunchAgent is a
     common reason it isn't). It reads the plist's `ProgramArguments[0]`:
     - plist missing: info (msd may be started by hand with `ms init --no-launchd`).
     - the program does not exist: **fail**; when the path is in a `Cellar/morsec/<version>`
       keg it says that version is gone (removed by `brew upgrade`). Fix: `ms init`.
     - the program exists but is not named `msd`: **warn**.
     - the program exists in a versioned keg while `<prefix>/opt/morsec/bin/msd` exists:
       **warn**, saying which applies: `opt` is on the same version (the next `brew upgrade`
       breaks it), `opt` has moved on to a newer version (msd runs the old one until
       `brew cleanup` deletes it), or `opt` fails the ownership/mode check in (1) so `ms init`
       can't use it. Fix: `ms init` (except the last).
     - otherwise pass, naming the path.
     - plist unreadable or with no program in the form `ms init` writes (comments stripped;
       exactly one `ProgramArguments` key, then `<array>`, then a `<string>`, with only
       whitespace between): **fail**.
   - Run shims: a symlink to the current `ms-shim` counts as linked. In a Homebrew install a
     shim that is a hard link or copy (pinned to this version) is a **warning**: it goes stale
     on the next upgrade. Fix: `ms run --link-shims`.
5. **Docs:** remove the `ms init && ms run --link-shims` upgrade workaround from the formula
   caveats (`packaging/homebrew/morsec.rb.in`), `README.md`, `docs/ONBOARDING.md` and
   `packaging/RELEASING.md`. Upgrading is `brew upgrade morsec`. CHANGELOG gets a line.

## Keychain ACL / designated requirement (why this is safe)

The vault's keychain ACL trusts msd's designated requirement (identifier `cc.morsec.msd` and the
Developer ID team), not a path, and `ms` checks the socket server's signature against the same
requirement (T-03). launchd exec's the `opt` path; the kernel resolves the symlink, so the
process image is the very same signed file in the keg, and after an upgrade it is the new
signed msd with the same identifier and team. Nothing about the signature, the requirement, or
the identity checks changes. No ACL or requirement code is touched.

## Security notes

- The `opt` link and the keg are in the same user-writable Homebrew prefix, so pointing at
  `opt` gives a same-user attacker nothing new: they could already overwrite the keg binary or
  the plist itself. A substituted msd fails the keychain ACL and `ms`'s peer verification
  (T-03); a substituted `ms-shim` runs as the caller and holds no secrets.
- No `brew` subprocess, no `PATH` lookup, no environment variable decides the path.
- The plist template stays as it is: absolute program path, `--foreground`, no environment.

## Tests (no real `~/Library/LaunchAgents`, `~/.claude`, `~/.codex`, `~/.ssh`)

Every test builds a temporary fake Homebrew prefix (`<tmp>/Cellar/morsec/<ver>/bin/...` plus
`<tmp>/opt/morsec -> ../Cellar/morsec/<ver>`) and plist files in temp dirs:
- stable path derived for a keg binary; refused for a non-keg path, a wrong package name, an
  `opt` link to another version, a missing `opt`, a `..` version.
- `ms init`'s msd choice and the rendered plist use the `opt` path; a dev path is unchanged.
- shim sync makes symlinks in Homebrew mode, migrates old hard links/copies carrying the marker,
  never touches a user file; after a simulated upgrade (new keg, `opt` re-pointed, old keg
  deleted) the shims resolve to the new `ms-shim` with no re-link.
- doctor: plist into a deleted keg fails and names the version; a pinned existing keg warns;
  an `opt` path passes; missing plist is info; hard-linked shims in Homebrew mode warn.
- the keychain tests run unchanged in the gate (none skipped).

## Out of scope

Signing, notarization, the tap repository, clean-machine install (the user's next steps).
Making `ms doctor` repair anything.
