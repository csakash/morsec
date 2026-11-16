# launchagent-opt-path: msd's LaunchAgent and the run shims survive `brew upgrade`

Closes the last code gap L28 (PR #22) flagged before the first release. Spec: `SPEC.md` on the
branch (commit fcc7d06).

## What changed

- **`crates/ms-cli/src/brew.rs` (new):** derives Homebrew's stable path. It never runs `brew`
  and reads no environment variable.
  - A binary whose canonical path is `<prefix>/Cellar/morsec/<ver>/bin/<tool>` maps to
    `<prefix>/opt/morsec/bin/<tool>`. This is used only when that path canonicalizes to the very
    same file.
  - `<prefix>/opt` must be owned by the user or root and not group- or world-writable, and the
    `opt/morsec` link must be owned by the user or root.
  - In any other case it falls back to the canonical path, which is today's behaviour.
- **`ms init`:** the LaunchAgent (and the `msd --init` call) use the `opt` path in a Homebrew
  install. Dev and manual installs are unchanged.
- **`ms run --link-shims`:**
  - In a Homebrew install, shims are symlinks to `opt/morsec/bin/ms-shim`, so they follow
    upgrades. Elsewhere they are hard links or copies, as before.
  - Shims left by older builds are now recognised and replaced. A shim counts as an older build
    if it has an executable header and `ms_run::SHIM_MARKER`, read from a regular file of at
    most 64 MiB. Before this change, `--link-shims` skipped them as "not a morsec shim" after an
    upgrade.
  - User files are never touched.
- **`ms doctor`:**
  - A new `launchagent` section, shown even when msd is down.
    - **fail:** the program is in a Cellar version that no longer exists, the program doesn't
      exist at all, or there is no program in the form `ms init` writes.
    - **warn:** the program is pinned to a keg (opt on the same version, opt moved on, or opt
      unusable because of ownership or mode), or the program is not named `msd`.
    - **pass:** the `opt` path, or a dev path.
  - The run-shims check warns when a shim is pinned to a version.
- **`ms connect`:** when `ms` isn't found on a safe PATH entry, it now falls back to the `opt`
  path instead of the keg path.
- **Docs:** the `ms init && ms run --link-shims` workaround is removed from the formula caveats,
  `README.md`, `docs/ONBOARDING.md` and `packaging/RELEASING.md`. Upgrading is now
  `brew upgrade morsec`, then one `launchctl kickstart -k gui/$(id -u)/cc.morsec.msd` to
  restart the running msd. Homebrew can't restart it, because the formula whitelist forbids a
  `service` block. CHANGELOG has an entry. RELEASING step 8 now checks that the LaunchAgent names
  the `opt` path, and that `brew upgrade` alone works from the second release.
- **`packaging/lib/install_sim.py`:** creates `opt/morsec -> ../Cellar/morsec/<ver>`, as brew
  does.

## Testing

`npm run build` (`scripts/check.sh`, every step) is green on the head commit. Nothing was
skipped. The keychain suite ran (`ms-vault` `macos::tests`: 19 passed). Its 3 ignored tests are
the pre-existing by-design ones: two child helpers and `core_dump_scan`, which needs `/cores`.
No keychain dialog appeared.

Every new test uses a temporary fake Homebrew prefix (`Cellar/morsec/<ver>/bin` plus the
`opt/morsec` link). None touches the real `~/Library/LaunchAgents`, `~/.claude`, `~/.codex`,
`~/.ssh` or keychain. `test_install.py` asserts that the real HOME is unchanged.

| Claim | Test |
|---|---|
| Keg paths are recognised exactly; `..`, another formula and relative paths are refused | `brew::tests::keg_paths` |
| `opt` is used only when it resolves to this keg; another version, a missing `opt`, a group-writable `opt` and dev paths fall back | `brew::tests::stable_path_needs_opt_on_this_keg` |
| `ms init`'s plist names the `opt` path, never `/Cellar/`; dev paths are unchanged | `service::tests::launch_agent_uses_opt_path` |
| The plist program is read only from `ProgramArguments[0]` in `ms init`'s form; another key's array, duplicates and commented-out entries are refused | `service::tests::{plist_renders, plist_program_parsing}` |
| Homebrew shims are `opt` symlinks; old hard links are migrated; after upgrade plus cleanup they run the new `ms-shim` with no relink | `run::tests::sync_follows_brew_upgrade` |
| A dev build's old copies are migrated, a dangling `…/ms-shim` link is stale, and a user file or foreign link is never touched | `run::tests::{sync, sync_migrates_old_dev_shims}` |
| A planted link to a FIFO, `/dev/zero` or a file over 64 MiB is never read | `brew::tests::classify_never_reads_special_files` |
| Only executables carrying the marker count as old shims | `brew::tests::marker_needs_an_executable` |
| A real `ms-shim` reached via `shims/tool -> opt/… -> Cellar/…` passes through without looping, fails closed (69) with a ref and no msd, and still works after `opt` moves and the old keg is deleted | `ms-run` `tests/shim.rs::symlinked_through_opt_survives_upgrade` |
| Every `ms-shim` build carries the marker | `tests/shim.rs::binary_carries_the_marker` |
| Doctor's LaunchAgent verdicts: deleted keg (fail, names the version), pinned (warn), `opt` moved on (warn, names both versions), `opt` not owned (warn, says why), not msd (warn), `opt` or dev path (pass), no plist (info), no program (fail) | `doctor::tests::launch_agent_verdicts` |
| Doctor's shim verdicts, including a pinned Homebrew shim (warn) | `doctor::tests::{shim_check_verdicts, shim_check_brew}` |
| Release-shaped install (simulated brew prefix with real built binaries): `--link-shims` makes `opt` symlinks resolving to the Cellar `ms-shim`; doctor shows the `launchagent` section | `packaging/tests/test_install.py::test_installed_ms_finds_its_shim` |

**Reviews:**
- **Code review (fresh context):** 4 findings (1 important, 3 minor). All are fixed in 5dbe48e:
  - R1: doctor passed a LaunchAgent pinned to an old keg after `opt` moved on.
  - R2: unbounded read through a symlink.
  - R3: no program was a warning, which differed from SPEC.
  - R4: the ownership fallback was silent.
- **Security review (fresh context):** 2 findings (1 minor, 1 informational). Both are fixed in
  5dbe48e:
  - S1: DoS through a planted FIFO, `/dev/zero` or huge-file link.
  - S2: `plist_program` could be fooled, and the program wasn't checked to be msd.
  - Areas checked with no finding: who can repoint `opt`, the window between `ms init` and
    launchd's use, the keychain ACL/DR, T-03 peer verification, shim-migration abuse, terminal
    injection, fail-open paths and the docs.
- **ARI-42 scan:** 0 high, 0 medium. The 5 low findings are pre-existing `bypassPermissions`
  fixtures in `ms-connect` tests, untouched by this change.

**Not verified here (human steps):** a real `brew install` and `brew upgrade` of a signed build
on a clean Mac (RELEASING step 8 now covers it), and launchd itself loading the `opt`-path plist.
The `opt` path is a normal absolute path to launchd.

## Risk

**Sensitive paths (`gloop risk`) for a human reviewer:**
- `crates/ms-cli/src/{brew,connect,doctor,main,run,service}.rs`
- `crates/ms-run/src/{lib.rs,bin/ms-shim.rs}`
- `crates/ms-run/tests/shim.rs`
- `packaging/lib/install_sim.py`

**Keychain ACL / designated requirement:**
- Unchanged. Items trust msd's designated requirement (`cc.morsec.msd` plus the team), not a
  path.
- launchd execs the `opt` symlink, and the kernel resolves it to the same signed keg file.
- `ms`'s peer check (T-03) uses the socket peer's audit token, not a path.
- No ACL, requirement or peer-verify code changed.

**Who can repoint `opt/morsec`:**
- Only the user or root, because of the ownership and mode check. Otherwise the canonical path is
  used, as before.
- A same-user process (an agent) could already replace the keg binary or rewrite the plist, so it
  gains nothing new.
- A substituted msd fails the keychain ACL and `ms`'s identity check.
- A substituted `ms-shim` runs as its caller and holds no secret.

**After `brew upgrade`:**
- The old msd keeps running from a deleted file until it is restarted. It may then fail `ms`'s
  signature check; if so, it fails closed (`DaemonNotVerified`) and is not fail-open.
- This window existed before the change too. The docs and caveats tell users to restart msd with
  `launchctl kickstart -k`.

**Shim migration:**
- It now removes or replaces files in `~/.morsec/shims` that are executables carrying the
  `ms-shim` marker, as well as exact `ms-shim` copies.
- Anything else stays untouched and is reported as skipped. Symlinks are removed as links, never
  their targets.
- Residual (both reviewers rated it informational): the regular-file/size check and the read
  are two steps. A same-user process could swap a planted link's target to a FIFO in between
  and make `--link-shims` hang. That is DoS only, inside the user's own 0700 directory. The fix,
  if wanted, is to open once with `O_NONBLOCK` and check and read through that handle.

**Behaviour change for a shared or group-writable prefix:** for example Intel `/usr/local`
Homebrew with a group-writable `opt`, or a prefix owned by another admin account. These keep
the Cellar path, so `brew upgrade` still breaks msd there, and `ms doctor` now says so and why.

## How to revert

- Revert the two implementation commits on main (the merge commit with `git revert -m 1`, or
  221b072 and 5dbe48e). No data migration is involved.
- After the revert:
  - `ms init` writes the Cellar path again.
  - `opt` symlink shims keep working while `opt` exists. Running `ms run --link-shims` with the
    reverted `ms` reports them as "not a morsec shim", so delete `~/.morsec/shims/*` and re-run
    it to get hard links.
  - Restore the upgrade workaround in the caveats and docs.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
