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

1. Bump `version` in the root `Cargo.toml` (workspace) through a loop and merge it.
2. On an up-to-date, clean `main`: `git tag -s v<version>` (or `-a`).
3. Check reproducibility: `scripts/release.sh verify-repro`.
4. Build the release:

   ```bash
   MORSEC_SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" \
   MORSEC_NOTARY_PROFILE=morsec-notary \
   MORSEC_MINISIGN_KEY=~/.minisign/morsec.key \
   scripts/release.sh release
   ```

   It refuses to start without every one of these, a committed `packaging/minisign.pub`, a
   clean tree and the `v<version>` tag on `HEAD`. It signs `ms` and `msd` (hardened runtime,
   secure timestamp, no entitlements), checks that signing changed only the signature,
   notarizes, runs `spctl`, writes the SBOM, `BUILDINFO`, `SHA256SUMS` and
   `SHA256SUMS.minisig` to `dist/<version>/`, and renders the formula into
   `dist/<version>/homebrew-tap/` and `packaging/homebrew/Formula/morsec.rb`.
5. Push the tag and create the GitHub release `v<version>`. Upload from `dist/<version>/`:
   the `.tar.gz`, `morsec-<version>.cdx.json`, `BUILDINFO`, `SHA256SUMS`,
   `SHA256SUMS.minisig`.
6. Copy `dist/<version>/homebrew-tap/Formula/morsec.rb` into `csakash/homebrew-tap` and push.
   Commit the same file to this repo (`packaging/homebrew/Formula/morsec.rb`) through a loop.
7. On a clean macOS VM (Apple silicon, no Rust, no morsec):
   `brew install csakash/tap/morsec && ms --version && mors --version && brew test morsec`.
   Then follow `packaging/VERIFY.md` once from the downloaded files.

## Never

- No auto-update. Users upgrade with `brew upgrade morsec`. The SBOM step fails the build if a
  self-update crate enters the dependency graph.
- No unsigned or ad-hoc release: `MORSEC_SIGN_IDENTITY=-` is for testing `build` only and
  `release` refuses it.
- Don't change `packaging/macos/sign-targets` identifiers or the Developer ID team.
