# SPEC: distribution (v0.1.0 on Homebrew, npm and curl)

Loop `distribution`, branch `feat/distribution`, base `9a20ad7`.

## Goal

Everything for the first public release, morsec **0.1.0**, except the human steps. The release
targets **Apple silicon macOS only** (`aarch64-apple-darwin`). `csakash/morsec` becomes public and
hosts the GitHub releases. There are three ways to install:

1. the Homebrew tap `csakash/homebrew-tap`;
2. npm: `morsec` plus the platform package `morsec-darwin-arm64`;
3. a curl installer.

All three ship the same signed, notarized `ms`, `msd` and `ms-shim`. The repo is also audited
before it goes public.

Out of scope, and human-only: the Developer ID signature, notarization, the minisign key, tags,
pushes, the GitHub release, the tap repo, `npm publish`, and the repo's visibility. This loop
documents those steps but never does them.

## Decisions

- **D1 Version.** The workspace version goes to `0.1.0`, with `Cargo.lock` updated to match.
  CHANGELOG: `[Unreleased]` becomes `## [0.1.0] - 2026-11-17`. RELEASING says to fix the date if
  the release slips. `scripts/release-check.sh` passes every step on the branch. Tagging and the
  signed build stay human.
- **D2 Team ID.** Commit `packaging/macos/team-id` = `554MCRUAKK`.
- **D3 One build, three channels.** `release.sh build|release` produces the release tarball
  first. The npm packages and the curl installer are derived from what is in that tarball. The
  binaries are never rebuilt or re-signed per channel. `release.sh` checks the sha256 of each
  binary against the copy in the tarball.
- **D4 npm layout.**
  - Templates live in `packaging/npm/`.
  - `morsec-darwin-arm64` contains `bin/ms`, `bin/msd` and `bin/ms-shim` (mode 0755). Its
    package.json has `os: ["darwin"]`, `cpu: ["arm64"]`, no `bin`, no `scripts` and no
    dependencies.
  - `morsec` has:
    - `bin: {ms, mors}`, pointing at a small CommonJS wrapper with no dependencies;
    - `optionalDependencies: {"morsec-darwin-arm64": "<exact version>"}`;
    - no `scripts` at all, so no preinstall, install or postinstall.
  - The wrapper:
    - refuses any platform other than darwin/arm64 with a clear message, and names Rosetta when
      Node is x64 on an arm64 Mac;
    - resolves `morsec-darwin-arm64/package.json` from its own directory, and checks that the
      package's version equals its own;
    - spawns `bin/ms` with the TTY inherited and its argv unchanged;
    - while the child runs, it ignores SIGINT, SIGTERM and SIGHUP (the terminal sends them to
      the child too), then exits with the child's status or re-raises its signal;
    - when the platform package is missing (optional dependencies skipped, `--no-optional`, or
      Rosetta Node), it prints which package is missing and how to fix it.
  - The `license` field is mapped from Cargo's `license`: `LicenseRef-Proprietary` becomes
    `UNLICENSED`, and the audit flags it.
  - Staging is `release.sh` → `packaging/lib/npm.py`:
    - render both packages into `dist/<v>/npm/{morsec,morsec-darwin-arm64}/`;
    - copy the binaries out of the release tarball, never from the build directory;
    - run `npm pack --ignore-scripts` into `dist/<v>/npm/`;
    - re-open the packed `.tgz` files and check four things: the sha256 of every binary equals
      the tarball's, the mode is 0755, no `scripts` key exists, and the file list is exactly the
      expected one.
    - `npm` is required only for `build` and `release`, and is checked for up front.
- **D5 npm paths, LaunchAgent and shims.**
  - A global npm install puts the real binaries at
    `<npm prefix>/lib/node_modules/morsec/node_modules/morsec-darwin-arm64/bin/`, or at a
    hoisted sibling.
  - `npm install -g morsec@<new>` replaces the files *at the same path*, so that path is already
    as stable as Homebrew's `opt` path is across upgrades. **`ms init` keeps pointing the
    LaunchAgent at msd's real path inside node_modules.** It does not copy msd to a stable place
    (a copy would pin the old version) and it does not run Node (launchd must not depend on a
    Node version).
  - What does change the path is a different npm prefix: switching Node with nvm, fnm or volta,
    or `npm uninstall -g`. `ms doctor`'s `launchagent` section must then say that the LaunchAgent
    names an npm install that is gone, and tell the user to run `ms init` from the install they
    use now.
  - New in doctor: a warning when the LaunchAgent's msd is a different install from this `ms`'s
    sibling msd (two installs, e.g. npm and Homebrew).
  - Run shims in an npm install become **symlinks to the real node_modules `ms-shim` path**,
    the way Homebrew's become symlinks to `opt`. A hard link would pin the old inode after
    `npm install -g` replaces the file. This lives in `brew.rs` as `npm_path()`; the existing
    `stable_path` callers take `link_target()` = opt path, else npm path.
  - Neither path ever runs through the JS wrapper.
  - Upgrading still needs `launchctl kickstart -k gui/$(id -u)/cc.morsec.msd` (the old msd runs
    from the replaced file). This is documented for npm and curl, as it already is for brew.
- **D6 curl installer.** `packaging/install.sh` is a template. `release.sh` renders it into
  `dist/<v>/install.sh`, and lists it in `SHA256SUMS` so the minisign signature covers it.
  - Rendered from `packaging/macos/team-id` and `packaging/minisign.pub`. `release` refuses if
    either is missing. A `build` without the pub key renders an installer whose minisign check
    says the key is not set. The unrendered template refuses to run at all.
  - POSIX sh, shellcheck-clean.
  - Refuses: anything that is not Darwin with an arm64 CPU (an x86_64 shell under Rosetta on an
    arm64 Mac is accepted), running as root, and a sudo environment.
  - Source: `https://github.com/csakash/morsec/releases/latest/download/` or
    `…/download/v<version>/`, chosen with `--version X` or `MORSEC_VERSION`. curl runs with
    `--proto =https --proto-redir =https --tlsv1.2 -fsSL`.
  - Order of checks:
    1. download `SHA256SUMS` and `SHA256SUMS.minisig`;
    2. if `minisign` is on PATH, verify with the embedded key, or fail;
    3. take the version from the single tarball line in `SHA256SUMS`, which must match a
       requested version;
    4. download the tarball from the versioned URL (never `latest`, so the tarball can't change
       under the checksum);
    5. check its sha256;
    6. list its entries: every one under `morsec-<v>/`, with no `..` and no absolute path;
    7. extract it into a mktemp dir, and require regular files.
  - Then, per binary:
    1. `codesign --verify --strict`;
    2. the identifier is the one in `sign-targets`;
    3. `TeamIdentifier` is the embedded team;
    4. `spctl --assess --type install` reports `source=Notarized Developer ID`.
  - Installs to `${MORSEC_INSTALL_DIR:-$HOME/.local/bin}` with no sudo: `ms`, `msd`, `ms-shim`,
    plus `mors -> ms`.
  - Ownership: `<dir>/.morsec-install` records `sha256 name` for every file it wrote. An existing
    target is overwritten only when it is ours: its hash matches the manifest, it is
    byte-identical to the new file, or it is `mors` as a symlink to `ms`. Anything else (for
    example `install-dev.sh`'s links) is refused, and nothing is changed.
  - Each file goes to a temp name in the same directory, then `mv`. Re-running the same version
    is a no-op success.
  - Prints next steps: `ms init` and `ms doctor`, a PATH hint when the directory is not on PATH,
    and after an upgrade the kickstart line and `ms run --link-shims`.
  - Testing uses the same renderer with a `file://` base URL, `--proto =file`, a test team (`not
    set`, which is how ad-hoc signatures show) and a throwaway minisign key that the test
    generates in a temp dir. `spctl` and `uname` are stubbed on PATH. The shipped script has no
    test switches.
- **D7 Homebrew.** The formula URL stays
  `https://github.com/csakash/morsec/releases/download/v0.1.0/morsec-0.1.0-aarch64-apple-darwin.tar.gz`.
  A test pins `release.sh formula --version 0.1.0` to that URL.
- **D8 Pre-public audit.**
  - gitleaks runs over full history (`--log-opts=--all`). Every hit is reviewed, and the results
    go in PROOF.md.
  - Also reported: tracked agent config, personal emails and paths, historical `.pyc` files, old
    remote branches, the README link to a private board, and the missing LICENSE.
  - Safe fixes go on the branch: `.gitignore` gets `__pycache__/`, `*.pyc`, `.npmrc`, `*.tgz`,
    minisign secret keys, `.claude/settings.local.json`, `.env*` and `*.p12`/`*.p8`; nothing that
    doesn't belong is tracked today.
  - History is never rewritten; anything that needs a rewrite is only reported.
- **D9 Docs.**
  - RELEASING.md is rewritten in order: one-time setup (human); prepare (loop); build, sign and
    notarize; GitHub release; tap; npm publish with 2FA; a clean-VM install through each
    channel. Each step is marked **[human]** or **[script]**.
  - README, ONBOARDING and VERIFY get the curl one-liner, the "download and read first" variant,
    and npm.

## Acceptance

1. `npm run build` is green. That includes new packaging tests and the shellcheck of
   `packaging/install.sh` and the `packaging/npm` wrapper's lint (`node --check`).
2. `scripts/release-check.sh` passes all five steps at 0.1.0.
3. `MORSEC_SIGN_IDENTITY=- scripts/release.sh build --out <tmp>` produces the tarball, `npm/`
   with two `.tgz`, `install.sh`, and `SHA256SUMS` listing `install.sh`. The npm check passes and
   fails on a tampered binary.
4. Tests:
   - **npm:** `npm install --offline` of the two packed `.tgz` files into a temp project, plus a
     global `--prefix` install, both run `ms --version` and `mors --version` through the
     wrapper, and pass exit codes through.
   - **npm, wrong platform:** fails with the message, with the platform faked by a preload.
   - **npm, platform package absent:** fails with the message.
   - **npm, doctor and shims:** an install with `ms doctor`, `ms run --link-shims` and a
     symlinked shim, against a throwaway msd (debug build, as in `test_install`).
   - **curl:** clean install; idempotent re-run; upgrade over its own files; refusal of a foreign
     file; tampered checksum; tampered binary (codesign fails); wrong team; spctl rejection; bad
     minisign signature; wrong platform; root; a requested version that doesn't match.
   - **Rust:** unit tests for `npm_path`, `link_target` and the doctor launchagent npm and
     two-install cases.
   - **Homebrew:** a URL test.
5. No test touches the real `~/.claude`, `~/.codex`, `~/.ssh`, `~/Library/LaunchAgents`, the
   login keychain or the npm global prefix.
6. Code review and security review have converged, and PROOF.md has Testing, Risk and How to
   revert.
