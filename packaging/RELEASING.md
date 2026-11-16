# Releasing morsec

The release runs on your Mac with `scripts/release.sh` (no hosted CI, D7). It builds, signs,
notarizes and checks everything locally. It never uploads, tags, pushes or publishes: those
steps are yours, below.

## One-time setup (human)

1. **Developer ID certificate** (D2). In Xcode → Settings → Accounts, create a
   "Developer ID Application" certificate. Check it's there:
   `security find-identity -v -p codesigning` shows
   `Developer ID Application: <Name> (<TEAMID>)`.
   The team must never change: the keychain trusts `msd` by identifier `cc.morsec.msd` plus this
   team, so a different team locks every user out of their stored keys after an upgrade.
   Commit the team ID (the 10 characters in parentheses) as `packaging/macos/team-id` through a
   loop. `release` refuses to sign with any other team.
2. **Notary profile.** Make an app-specific password at appleid.apple.com, then store it in your
   keychain (you type it; nothing else sees it):
   `xcrun notarytool store-credentials morsec-notary --apple-id <you> --team-id <TEAMID>`
3. **minisign key.** `minisign -G -p packaging/minisign.pub -s ~/.minisign/morsec.key`
   (pick a password). Commit `packaging/minisign.pub` through a loop. Back up the secret key
   offline. Never commit it.
4. **Tap repository.** Create the public GitHub repo `csakash/homebrew-tap` (that's what
   `brew tap csakash/tap` clones). Copy `packaging/homebrew/README.md` into it.
5. **Public downloads.** The formula downloads from
   `https://github.com/csakash/morsec/releases/download/v<version>/…`. Homebrew can't fetch from
   a private repo without a token, so either make `csakash/morsec` public or host the release
   files somewhere public and pass that URL to `scripts/release.sh formula --url`.

## Each release

1. Through a loop: bump `version` in the root `Cargo.toml` (workspace) and move the
   `CHANGELOG.md` entries from `Unreleased` into a `## [<version>] - <date>` section. Merge it.
2. On an up-to-date, clean `main`, run the checklist:

   ```bash
   scripts/release-check.sh
   ```

   It checks the version (not 0.0.0, the same for every crate, `Cargo.lock` agrees, no `v<version>`
   tag elsewhere), the CHANGELOG section, `cargo build --release --locked`, the packaging tests
   (including the install test: the formula's binaries installed into a temp prefix, `ms doctor`
   finding `ms-shim`), and that the formula installs exactly the binaries sign-targets lists and
   the build produced. It signs, tags and publishes nothing. Fix anything it reports first.
3. `git tag -s v<version>` (or `-a`).
4. Check reproducibility: `scripts/release.sh verify-repro`.
5. Build the release:

   ```bash
   MORSEC_SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" \
   MORSEC_NOTARY_PROFILE=morsec-notary \
   MORSEC_MINISIGN_KEY=~/.minisign/morsec.key \
   scripts/release.sh release
   ```

   It refuses to start without every one of these, a committed `packaging/minisign.pub` and
   `packaging/macos/team-id` matching the identity's team, a clean tree and the `v<version>` tag on `HEAD`. It signs every binary in
   `packaging/macos/sign-targets`, today `ms`, `msd` and `ms-shim` (hardened runtime,
   secure timestamp, no entitlements), checks that signing changed only the signature,
   notarizes, runs `spctl`, writes the SBOM, `BUILDINFO`, `SHA256SUMS` and
   `SHA256SUMS.minisig` to `dist/<version>/`, and renders the formula into
   `dist/<version>/homebrew-tap/` and `packaging/homebrew/Formula/morsec.rb`.
6. Push the tag and create the GitHub release `v<version>`. Upload from `dist/<version>/`:
   the `.tar.gz`, `morsec-<version>.cdx.json`, `BUILDINFO`, `SHA256SUMS`,
   `SHA256SUMS.minisig`.
7. Copy `dist/<version>/homebrew-tap/Formula/morsec.rb` into `csakash/homebrew-tap` and push.
   Commit the same file to this repo (`packaging/homebrew/Formula/morsec.rb`) through a loop.
8. On a clean macOS VM (Apple silicon, no Rust, no morsec):
   `brew install csakash/tap/morsec && ms --version && mors --version && brew test morsec`
   (`brew test` also checks `ms-shim`), then `ms init` and `ms doctor`: the "run shims" section
   must not say ms-shim is missing. Time it from `brew install` to the first protected session
   (L28's target is under 5 minutes). Then follow `packaging/VERIFY.md` once from the
   downloaded files.

## What stays human

`scripts/release-check.sh` and `scripts/release.sh` never do these; you do: the Developer ID
certificate and notary profile, `packaging/macos/team-id` and `packaging/minisign.pub`, the tag,
`release.sh release` with your credentials, pushing the tag, the GitHub release and its uploads,
the `csakash/homebrew-tap` repo and its formula, and the clean-VM install.

## Never

- No auto-update. Users upgrade with `brew upgrade morsec`. The SBOM step fails the build if a
  self-update crate enters the dependency graph.
- No unsigned or ad-hoc release: `MORSEC_SIGN_IDENTITY=-` is for testing `build` only and
  `release` refuses it.
- Don't change `packaging/macos/sign-targets` identifiers or the Developer ID team. Adding a
  binary means a new line there and the same name in the formula's `bin.install` line (the
  packaging tests and `release-check.sh` refuse a mismatch).
