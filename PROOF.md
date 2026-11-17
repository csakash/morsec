# distribution: morsec 0.1.0 on Homebrew, npm and curl

Spec: `SPEC.md` (loop `distribution`, base `9a20ad7`). Everything for the 0.1.0 release except
the human steps:

- **Version and team:** the version is bumped to 0.1.0, with a CHANGELOG entry, and the team ID
  `554MCRUAKK` is committed.
- **npm:** two packages, `morsec` and the `morsec-darwin-arm64` platform package, with no install
  scripts. Their binaries are copied from the signed tarball and checked against it by sha256.
- **curl installer:** checks minisign, sha256, the Developer ID team and notarization; never
  uses sudo; never overwrites files it doesn't own.
- **npm-aware shims and `ms doctor`.**
- **Docs:** `RELEASING.md` is rewritten for all three channels, with every human step marked.
- **Pre-public audit.**

Signing, notarization, the minisign key, tagging, pushing, the GitHub release, the tap,
`npm publish` and making the repo public were **not** done. They are the human steps in
`packaging/RELEASING.md`.

## Testing

Evidence is in `.loops/runs/distribution/interactive/proof/`, outside the repo.

- **Gate:** `npm run build` (`scripts/check.sh`) passes on `93930e4`: "check.sh: all checks
  passed". Output: `build-morsec.txt`. It now also
  requires node, npm and minisign; runs shellcheck on `packaging/install.sh` and `node --check` on
  the npm launcher; and runs the new packaging tests.
- **Release checklist:** `scripts/release-check.sh` passes all five steps at 0.1.0. Output:
  `release-check.txt`.
- **Release path, ad-hoc signed:** `MORSEC_SIGN_IDENTITY=- scripts/release.sh build` produced:
  - the tarball, SBOM and `BUILDINFO`;
  - `install.sh`;
  - `SHA256SUMS`, listing `install.sh`;
  - `npm-adhoc-NOT-FOR-PUBLISHING/morsec-0.1.0.tgz` and `…/morsec-darwin-arm64-0.1.0.tgz`
    (`release-build-adhoc.txt`). Only a Developer ID `release` writes `npm/`.

  The npm check printed the three binary hashes and "npm packages match the release tarball".
- **`packaging/tests/test_installer.py`** (23 tests). The real template is rendered against a
  `file://` fake release, with tiny ad-hoc signed programs and a throwaway minisign key. The real
  curl, shasum, tar, codesign and minisign run. Only `spctl`, `uname`, `sysctl` and `id` are
  stubbed, and only where a case needs it. Cases:
  - clean install from `latest`, then an idempotent re-run (same inodes, "already installed");
  - upgrade, a pinned `--version`, and `MORSEC_VERSION`;
  - foreign files refused with nothing changed: dev links, a user's own `ms`, and a file the
    installer wrote that was later edited;
  - `MORSEC_INSTALL_DIR`: relative paths and group-writable directories are refused;
  - tampered checksum;
  - tampered binary (codesign fails);
  - wrong team;
  - wrong identifier;
  - spctl rejection, and a source that isn't notarized;
  - a signature by another minisign key;
  - a signed comment that names another version;
  - running without minisign (says so and still checks codesign);
  - a mismatched or malformed version;
  - a tar entry that escapes `morsec-<v>/`;
  - Linux, and an Intel Mac; a Rosetta shell is accepted;
  - root, and sudo;
  - the real HOME is untouched;
  - the template refuses to run unrendered;
  - the BINS list matches `sign-targets`;
  - the production rendering pins team `554MCRUAKK` and the Developer ID requirement;
  - the CLI has no test switches.
- **Developer ID requirement against a real signed app** (`devid-requirement.txt`). The exact
  requirement the installer uses accepts a Developer ID app with that app's team (exit 0) and
  rejects the same app for team `554MCRUAKK` (exit 3).
- **`packaging/tests/test_npm.py`** (10 tests). Packs:
  - they match the tarball;
  - a tampered binary, a 0644 mode, an extra file and a `scripts` key (in the template or
    injected into the pack) are all refused;
  - the license is mapped.

  Real offline npm installs of the debug build's packs, with a temp cache, into a temp project
  and a global `--prefix`:
  - `ms` and `mors` work through the launcher, and exit code 2 passes through;
  - another platform, and x64 Node, get a clear refusal;
  - a missing platform package gets the message naming `morsec-darwin-arm64` and the fix;
  - a version mismatch is refused.

  Doctor from an npm install in the registry layout (nested), with a throwaway msd started from
  `node_modules`:
  - `ms run --link-shims` makes a symlink to the npm package's `ms-shim`, and doctor passes it;
  - a LaunchAgent (a file in the temp HOME; launchctl is never run) into `node_modules` passes;
  - a LaunchAgent from another Node install warns;
  - once that install is removed, doctor fails with "npm install that is gone … run: ms init".
- **Rust unit tests:**
  - `brew::tests::npm_paths`: the exact path shape, `..` refused, a group-writable package dir
    refused, and dev builds untouched;
  - `doctor::tests::launch_agent_npm_and_two_installs`;
  - the existing Homebrew tests still pass with `launch_agent_check(plist, None)`.
- **Homebrew:** `test_formula_targets_the_github_release` pins the 0.1.0 URL to
  `https://github.com/csakash/morsec/releases/download/v0.1.0/morsec-0.1.0-aarch64-apple-darwin.tar.gz`.
- **Pre-public audit** (`audit.md`, `gitleaks-full-history.txt`, `gitleaks-after-ignore.txt`).
  gitleaks 8.30.1 ran over all branches: 243 commits, 19 hits, every one a test canary or fixture.
  With `.gitleaksignore`, a rescan finds no leaks.
- **ARI-42:** the scan finds nothing in the new files. The GW-2 row and the change log are
  updated.

- **Code review (fresh context):** 0 important findings and 6 nits (R1–R6), all fixed in
  `3b5eb34`:
  - R1: the launcher forwards SIGTERM and SIGHUP to `ms`.
  - R2: the installer removes its temp files on an interrupt.
  - R3: the install directory is judged by its real path (`pwd -P`).
  - R4: the upgrade docs say what to do for curl shims and after an nvm switch.
  - R5: the wording is "Changed from X to Y".
  - R6: pnpm store paths are not treated as npm installs.
- **Security review (fresh context):** 0 important findings and 2 nits, both fixed in `06d97f3`:
  - S1: unsigned and ad-hoc builds write their npm packs to `npm-<signing>-NOT-FOR-PUBLISHING/`,
    so only a Developer ID `release` produces `npm/`.
  - S2: npm shim targets require every ancestor directory up to `/` to be safe.
- **Re-review round 1 (diff only, `3b5eb34` and `06d97f3`):** all fixes were confirmed. It found
  one **important** problem, fixed in `93930e4`. The new ancestor check, and the Homebrew `opt`
  check from #25, rejected Homebrew's own default prefix directories (`/opt/homebrew/opt` and
  `/opt/homebrew/lib` are `drwxrwxr-x <user>:admin` on this Mac). So `ms init` would pin the
  versioned Cellar path, and npm shims would fall back to hard links.

  Directories that only the `admin` group (gid 80) can write now count as safe. Members of admin
  can already sudo, so this exposes nothing new. `brew::tests::safe_dir_rules` covers it. Two
  installer nits were fixed in the same commit: PATH hints use the directory as given, and
  `set -f` stops globbing in cleanup.
- **Re-review round 2 (diff only, `93930e4`):** 0 important findings. Review and security review
  have converged. Four nits are left open and do not block:
  - `safe_owner_mode` could add a `cfg(target_os = "macos")` guard on the admin branch. morsec is
    macOS-only.
  - Three more `safe_dir_rules` cases.
  - Two glob/trailing-slash nits in install.sh, which only affect the "add to PATH" hint text.
- **Gate failures found and fixed:**
  - `crates/msd/tests/cli.rs` hard-coded `morsec 0.0.0`; it now uses `CARGO_PKG_VERSION`.
  - release-check.sh must not name signing tools (an existing test guards this), so its
    `need minisign` was dropped. The installer tests fail loudly without minisign.

Not tested here; these are human steps:

- real Developer ID signing and notarization, and a real `spctl` verdict on morsec;
- the npm registry and `npm publish`;
- GitHub's `latest/download` redirects;
- the clean-VM installs of the three channels (`RELEASING.md` step 8).

## Risk

`gloop risk` (`risk.txt`) lists these sensitive paths. **They need a human reviewer:**

- `Cargo.toml` and `Cargo.lock`: version only.
- `crates/ms-cli/src/{brew,doctor,run}.rs`: npm shim targets, and the doctor verdicts.
- `packaging/install.sh` and `packaging/lib/installer.py`: the installer, which runs on users'
  machines.
- `scripts/check.sh`, `scripts/release-check.sh` and `scripts/release.sh`.
- `crates/msd/tests/cli.rs`: the version test reads `CARGO_PKG_VERSION` instead of 0.0.0.

Specific risks:

- **Installer authenticity.**
  - The trust anchor is the code signature: `codesign -R` with Apple's Developer ID requirement
    pinned to team `554MCRUAKK`, plus the identifier, plus `spctl`'s notarization verdict.
  - minisign is checked only when it is installed. Without it, `SHA256SUMS` comes from the same
    server as the tarball, so the sha256 check protects integrity, not authenticity. The
    signature checks protect authenticity.
  - A downgrade to an older, validly signed release is possible if someone controls the
    download. They would need write access to the GitHub release, and `--version` pins
    explicitly.
- **npm:**
  - The launcher trusts whatever `morsec-darwin-arm64` Node resolves. That is the npm install
    itself, and it is not chosen by any environment variable.
  - Shims become symlinks into `node_modules` only when the package directories are owned by the
    user or root and are not group- or world-writable.
  - A Node version switch leaves the LaunchAgent pointing at a removed path. Doctor says so, and
    `ms init` fixes it. This is documented.
- **Trust rule widened (security-relevant, review it):** `brew::safe_dir` accepts a directory
  that is group-writable only by `admin` (gid 80). Before, Homebrew's default
  `/opt/homebrew/opt` was rejected, so `ms init` on a stock Apple silicon Homebrew wrote the
  versioned Cellar path (a gap left from #25). World-writable directories, other groups and other
  owners are still refused.
- **Doctor behaviour change:** a LaunchAgent that starts a different install's msd now **warns**
  (it used to pass). This can surface for developers running `target/debug/ms` alongside a
  Homebrew install. That is intended.
- **Gate:** it now requires node, npm and minisign. A machine without them fails the gate (no
  skips).
- **Licence:** the npm packages are `UNLICENSED`, following Cargo's `LicenseRef-Proprietary`. A
  licence decision is needed before going public (see the audit).
- **Accepted (pre-existing class, security review P1):** the installer checks only the install
  directory itself, not its parents. A `MORSEC_INSTALL_DIR` you choose under a directory other
  users can write is your own choice. The default `~/.local/bin` sits under your home.
- **Audit items that need a history rewrite** (only reported; nothing was rewritten): the
  personal email on 289 commits, and old `.pyc` files with a local path.

## How to revert

- Revert the merge commit: `git revert -m 1 <merge>`.
- The changes are self-contained:
  - new files: `packaging/install.sh`, `packaging/npm/`, `packaging/lib/{npm,installer}.py`,
    `packaging/tests/test_{npm,installer}.py`, `.gitleaksignore` and `packaging/macos/team-id`;
  - small edits elsewhere.
- Nothing was published, so there is nothing to unpublish. If 0.1.0 has been published by then,
  don't revert the version bump; ship 0.1.1 instead (never `npm unpublish`).
