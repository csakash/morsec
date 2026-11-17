# Releasing morsec

The release runs on your Mac with `scripts/release.sh` (no hosted CI, D7). One build makes
everything for all three channels (Homebrew, npm and the curl installer) from the same signed,
notarized binaries. The scripts never upload, tag, push or publish. Those steps are yours.

Every step below is marked:

- **[human]**: you do it, with your credentials. No script and no agent does it.
- **[loop]**: a gstack-loops PR, reviewed and merged as usual.
- **[script]**: run the command shown. It reads credentials only by reference (keychain profile,
  key path) and never prints or stores them.

Targets: Apple silicon macOS 13 or later (`aarch64-apple-darwin`) only. Downloads come from the
GitHub releases of `csakash/morsec`.

## One-time setup

1. **[human] Developer ID certificate** (D2).
   - Create a "Developer ID Application" certificate in Xcode → Settings → Accounts.
   - Check it's there: `security find-identity -v -p codesigning` lists
     `Developer ID Application: <Name> (554MCRUAKK)`.
   - The team is pinned in `packaging/macos/team-id` (`554MCRUAKK`, committed), and `release`
     refuses any other team. The keychain trusts `msd` by identifier `cc.morsec.msd` plus this
     team, so a different team would lock every user out of their stored keys after an upgrade.
     The team must never change.
2. **[human] Notary profile.**
   - Make an app-specific password at appleid.apple.com.
   - Store it in your keychain. You type it; nothing else sees it:
     `xcrun notarytool store-credentials morsec-notary --apple-id <you> --team-id 554MCRUAKK`
3. **[human] minisign key.**
   - Generate it, and pick a password:
     `minisign -G -p packaging/minisign.pub -s ~/.minisign/morsec.key`
   - Commit `packaging/minisign.pub` through a **[loop]**. `release.sh` embeds it in the curl
     installer, so the installer can't be rendered for a release without it.
   - Back up the secret key offline. Never commit it (`.gitignore` refuses `*.key`).
4. **[human] Public repository.**
   - Do the pre-public audit first (the `distribution` loop's PROOF.md lists what it found).
   - Then make `csakash/morsec` public. Homebrew, npm and the curl installer all download from
     its releases without a token.
5. **[human] Tap repository.**
   - Create the public repo `csakash/homebrew-tap`. `brew tap csakash/tap` clones it.
   - Copy `packaging/homebrew/README.md` into it.
6. **[human] npm account.**
   - Use an npmjs.com account with 2FA set to "authorization and writes".
   - `npm login` on your Mac. Your token stays in `~/.npmrc`, never in this repo
     (`.gitignore` refuses `.npmrc`).
   - The names `morsec` and `morsec-darwin-arm64` are free as of 2026-11-17. The first
     `npm publish` claims them.
7. **[human] Tools.** Install Node.js (it includes npm), `minisign` and `shellcheck`
   (`brew install node minisign shellcheck`), plus the Rust toolchain from `rust-toolchain.toml`.

## Each release, in order

### 1. Prepare [loop]

- Bump `version` in the root `Cargo.toml` (`[workspace.package]`) and update `Cargo.lock`.
- Move the `CHANGELOG.md` entries from `Unreleased` into a `## [<version>] - <date>` section.
  The date is the day you publish; fix it here if the release slips.
- Merge.

For 0.1.0 the `distribution` loop already did this.

### 2. Check [script]

On an up-to-date, clean `main`:

```bash
scripts/release-check.sh
```

It checks:

- The version: not 0.0.0, the same for every crate, `Cargo.lock` agrees, and no `v<version>` tag
  elsewhere.
- The CHANGELOG section.
- `cargo build --release --locked`.
- The packaging tests: the Homebrew install simulation, real npm installs of the packed
  packages, and the curl installer against a `file://` fake release, all from the debug build.
- shellcheck.
- That the formula installs exactly what `sign-targets` lists, and that those binaries pass the
  formula's `test do` block.

It signs, tags and publishes nothing. Fix anything it reports first.

### 3. Tag [human]

```bash
git tag -s v<version>    # or -a
```

### 4. Build, sign and notarize [script, with your credentials]

```bash
scripts/release.sh verify-repro     # two clean builds at different paths must match

MORSEC_SIGN_IDENTITY="Developer ID Application: <Name> (554MCRUAKK)" \
MORSEC_NOTARY_PROFILE=morsec-notary \
MORSEC_MINISIGN_KEY=~/.minisign/morsec.key \
scripts/release.sh release
```

It refuses to start without any of these:

- every variable above;
- a committed `packaging/minisign.pub`;
- `packaging/macos/team-id` matching the identity's team;
- a clean tree;
- the `v<version>` tag on `HEAD`.

It does the following, in order:

1. Builds `ms`, `msd` and `ms-shim`.
2. Signs every binary in `packaging/macos/sign-targets`: hardened runtime, secure timestamp, no
   entitlements. It checks that signing changed only the signature.
3. Notarizes, then checks each binary with `spctl`.
4. Writes the following to `dist/<version>/`:
   - `morsec-<version>-aarch64-apple-darwin.tar.gz`;
   - `morsec-<version>.cdx.json` (SBOM);
   - `BUILDINFO`;
   - `install.sh`: the curl installer, with the team ID and `packaging/minisign.pub` embedded;
   - `SHA256SUMS`, covering the four files above;
   - `SHA256SUMS.minisig`. minisign asks for your key's password.
5. Writes the Homebrew formula to `dist/<version>/homebrew-tap/Formula/morsec.rb` and
   `packaging/homebrew/Formula/morsec.rb`.
6. Writes the npm packages to `dist/<version>/npm/`:
   - `morsec-darwin-arm64-<version>.tgz` and `morsec-<version>.tgz`, made with
     `npm pack --ignore-scripts`;
   - `npm/SHA256SUMS`.

   Only a Developer ID `release` writes `npm/`. A `build` (unsigned or ad-hoc) writes its packs to `npm-none-NOT-FOR-PUBLISHING/` or `npm-adhoc-NOT-FOR-PUBLISHING/`, so they can't be published by mistake.

   The binaries in the platform package are copied out of the signed tarball. `release.sh`
   re-opens both packs and checks four things: every binary's sha256 equals the tarball's, the
   modes are 0755, the file lists are exact, and there is no `scripts` key, so nothing runs at
   install time.

### 5. GitHub release [human]

```bash
git push origin v<version>
```

Create the release `v<version>` on `csakash/morsec`. Mark it **Latest**, because the curl
installer's `latest/download/` URLs follow it. Upload these files from `dist/<version>/`:

- `morsec-<version>-aarch64-apple-darwin.tar.gz`
- `morsec-<version>.cdx.json`
- `BUILDINFO`
- `install.sh`
- `SHA256SUMS`
- `SHA256SUMS.minisig`

With the `gh` CLI, if you use it:
`gh release create v<version> --title v<version> --notes-file <notes> dist/<version>/{morsec-*.tar.gz,morsec-*.cdx.json,BUILDINFO,install.sh,SHA256SUMS,SHA256SUMS.minisig}`.

Check the downloads are public and unchanged, in an empty directory:

```bash
for f in SHA256SUMS morsec-<version>-aarch64-apple-darwin.tar.gz morsec-<version>.cdx.json BUILDINFO install.sh; do
  curl -fsSLO "https://github.com/csakash/morsec/releases/download/v<version>/$f"; done
shasum -a 256 -c SHA256SUMS
curl -fsSL https://github.com/csakash/morsec/releases/latest/download/SHA256SUMS | diff - SHA256SUMS
```

### 6. Homebrew tap [human]

1. Copy `dist/<version>/homebrew-tap/Formula/morsec.rb` into `csakash/homebrew-tap` as
   `Formula/morsec.rb`.
2. Commit and push.
3. Commit the same file to this repo (`packaging/homebrew/Formula/morsec.rb`) through a
   **[loop]**.

### 7. npm [human, with 2FA]

Publish the packed files from step 4 exactly as built. Don't run `npm publish` in a source
directory: that repacks. Publish the platform package first, so `morsec`'s optional dependency
resolves the moment `morsec` appears:

```bash
cd dist/<version>/npm
shasum -a 256 -c SHA256SUMS
npm publish ./morsec-darwin-arm64-<version>.tgz --access public    # asks for your 2FA code
npm publish ./morsec-<version>.tgz --access public                 # asks again
npm view morsec@<version> optionalDependencies
```

If the second publish fails, retry it. A platform package published without its `morsec` is
harmless; nothing depends on it. Never `npm unpublish` a release that people may have installed.
Publish a fixed patch version instead.

### 8. Clean-VM install, every channel [human]

Use a clean macOS VM (Apple silicon, no Rust, no Node unless the channel needs it, no morsec).
Take a snapshot first, and revert to it before each channel. Time each channel from install to
the first protected session; L28's target is under 5 minutes.

**Homebrew**

```bash
brew install csakash/tap/morsec && ms --version && mors --version && brew test morsec
ms init && ms doctor
```

`ms doctor`:

- The "run shims" section must not say ms-shim is missing.
- The "launchagent" section must name `$(brew --prefix)/opt/morsec/bin/msd`, not a
  `Cellar/morsec/<version>` path.

From the second release on, also check that `brew upgrade morsec` alone keeps msd starting
(`ms doctor` after `launchctl kickstart -k gui/$(id -u)/cc.morsec.msd`).

**npm** (arm64 Node.js from nodejs.org or `brew install node`)

```bash
npm install -g morsec && ms --version && mors --version
ms init && ms doctor
```

The "launchagent" section names
`<npm prefix>/lib/node_modules/morsec/node_modules/morsec-darwin-arm64/bin/msd`. Then:

- `ms run --link-shims`: the shims are symlinks to that package's `ms-shim`.
- From the second release on, `npm install -g morsec@latest` followed by the kickstart keeps
  msd starting.

**curl**

```bash
curl -fsSL https://github.com/csakash/morsec/releases/latest/download/install.sh | sh
~/.local/bin/ms --version
```

The installer must report "SHA256SUMS signature ok (minisign)" if minisign is installed, and
"code signatures ok (team 554MCRUAKK, notarized)". Then run `ms init && ms doctor`.

- Run the installer again: it must say "already installed".
- Install once without minisign, and once with it (`brew install minisign`).

**Finally**

Follow `packaging/VERIFY.md` once from the downloaded files.

## What stays human

`scripts/release-check.sh` and `scripts/release.sh` never do any of these. You do:

- the Developer ID certificate, the notary profile and the minisign key;
- committing `packaging/minisign.pub`;
- the tag, and `release.sh release` with your credentials;
- pushing the tag, the GitHub release and its uploads;
- the `csakash/homebrew-tap` repo and its formula;
- `npm login` and `npm publish`;
- making the repo public;
- the clean-VM installs.

## Never

- No auto-update. Users upgrade with `brew upgrade morsec`, `npm install -g morsec@latest` or
  by re-running the curl installer. The SBOM step fails the build if a self-update crate enters
  the dependency graph.
- No unsigned or ad-hoc release. `MORSEC_SIGN_IDENTITY=-` is for testing `build` only, and
  `release` refuses it.
- No install scripts in the npm packages. `npm.py` refuses a `scripts` key at staging and in
  the packed files.
- No binaries in npm or the installer other than the ones in the signed tarball. They are
  copied out of it, and checked against it by sha256.
- Don't change the `packaging/macos/sign-targets` identifiers or the Developer ID team. To add
  a binary, add a new line to `sign-targets` and the same name in three places: the formula's
  `bin.install` line, the `BINS` list in `packaging/install.sh`, and the `files` list of
  `packaging/npm/morsec-darwin-arm64/package.json`. The packaging tests refuse a mismatch.
