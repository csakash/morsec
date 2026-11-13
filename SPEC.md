# SPEC: L10 `release-pipeline`

Card: `docs/PLAN.md` § "L10 `release-pipeline`". Depends on L07 (merged, 9d18109).
Owns `packaging/` and `scripts/release.sh`. Touches shared files only additively:
one step in `scripts/check.sh`, the GW-2 row and a changelog line in `ARI42.md`.

## Goal

A local release script (no hosted CI, D7) that turns a clean, tagged commit into a release a
user can install with `brew install csakash/tap/morsec` and check by hand. The release is
reproducible, signed, notarized, ships with a CycloneDX SBOM and minisign-signed checksums,
and contains no auto-update.

## Behaviour

### `scripts/release.sh`

Subcommands:

| Command | What it does |
|---|---|
| `build [--out DIR]` | Dev build. Clones the committed tree at `HEAD` into a fresh temp dir, builds `ms` and `msd` reproducibly, signs them if an identity is configured (see Signing), and writes the release files to `DIR` (default `dist/<version>/`). A dirty tree is allowed but warns, because only committed content is built. |
| `verify-repro` | Two clean builds of `HEAD`, each in its own temp clone at a **different path** with its own `CARGO_TARGET_DIR`. Fails unless `ms`, `msd`, the tarball and the SBOM hash the same in both. Prints both hash sets. |
| `release` | The real release. Fails closed unless **all** of these hold: clean tree; `HEAD` is tagged `v<version>`; version is not `0.0.0`; `MORSEC_SIGN_IDENTITY` names a `Developer ID Application` identity (`-`, ad-hoc, is refused); `MORSEC_NOTARY_PROFILE` is set; `MORSEC_MINISIGN_KEY` points at a secret key and `packaging/minisign.pub` exists. Then it builds, signs with hardened runtime and a secure timestamp, notarizes, verifies (`codesign --verify --strict`, `spctl`), writes signed checksums and renders the formula. It never uploads, tags, pushes or publishes. |
| `formula --version V --sha256 H [--url U]` | Renders `packaging/homebrew/Formula/morsec.rb` from the template (used by `release`, and by QA for a `file://` URL). |

The script never enters, prints or stores a credential. Identities, the notary keychain
profile and the minisign key path come from the environment. The notary password stays in the
user's keychain profile (`xcrun notarytool store-credentials`). The minisign password is read by
`minisign` itself from the terminal.

### Reproducible build

- Build from a fresh clone of the commit (only committed content; `build.rs` still sees git, so
  `ms --version` keeps the short SHA).
- `cargo build --release --locked -p ms-cli -p msd --target aarch64-apple-darwin`.
- `SOURCE_DATE_EPOCH` = commit time of `HEAD`.
- `RUSTFLAGS` adds `--remap-path-prefix` for the build dir → `/morsec` and `$CARGO_HOME` →
  `/cargo`, so no host path ends up in a binary.
- `MACOSX_DEPLOYMENT_TARGET=13.0` pinned. `CARGO_INCREMENTAL=0`.
- `ZERO_AR_DATE=1` for deterministic static archives.
- A `BUILDINFO` file records rustc version, Xcode/SDK version, target, commit, epoch and the
  hashes of the unsigned binaries, so a third party can rebuild and compare.
- Tarball built with Python `tarfile`: sorted entries, fixed mtime (`SOURCE_DATE_EPOCH`), uid/gid
  0, `root`/`wheel`, fixed modes, no xattrs; gzip with mtime 0 and no filename.

Reproducibility is claimed for the **unsigned** binaries and for the dev tarball and SBOM.
A Developer ID signature carries a secure timestamp, so signed bytes differ per signing run.
`packaging/VERIFY.md` explains how to check a signed release against a rebuild (compare the
`BUILDINFO` unsigned hashes, or remove the signature from both and compare).

### Signing (card: Developer ID, hardened runtime, notarization)

- `MORSEC_SIGN_IDENTITY` unset: no signing (no-op) in `build`. The binaries keep the
  linker's ad-hoc signature.
- `MORSEC_SIGN_IDENTITY=-`: ad-hoc signing with the release identifiers and hardened runtime.
  Used to test the signing path without the user's certificate. Refused by `release`.
- Otherwise: `codesign --force --options runtime --timestamp --identifier <id>
  --sign "$MORSEC_SIGN_IDENTITY"`, with an entitlements file from `packaging/macos/`.
- Signing identifiers are frozen: `cc.morsec.ms` and `cc.morsec.msd` (matching the LaunchAgent
  label `cc.morsec.msd`). The L01 keychain ACL trusts `msd`'s designated requirement
  (identifier + team), so changing the identifier or team would lock users out of their keys
  after an upgrade. A unit test pins them.
- Entitlements: none beyond hardened runtime (no JIT, no unsigned memory, no
  library-validation opt-out, no `get-task-allow`). A test checks the entitlements file stays
  empty.
- Notarization: `xcrun notarytool submit <zip> --keychain-profile "$MORSEC_NOTARY_PROFILE" --wait`
  on a zip of the two signed binaries. Bare Mach-O files can't be stapled; Gatekeeper checks the
  ticket online. Recorded.
- The helper app (`apps/MorsecApprove`, L11) doesn't exist yet. The script signs any `.app`
  under a build output list in `packaging/macos/sign-targets` when it exists; today the list
  holds `ms` and `msd`. L11 adds its app there.

### Homebrew tap

- `packaging/homebrew/` mirrors the layout of the tap repo `csakash/homebrew-tap` (which is what
  `brew tap csakash/tap` clones): `Formula/morsec.rb` plus a `README.md`.
- The formula installs the **prebuilt, signed** binaries (not a source build): a source build
  would be ad-hoc signed, and the L01 keychain ACL would refuse the user's keys after every
  upgrade. It installs `bin/ms`, `bin/msd` and the symlink `mors -> ms`, and puts the SBOM and
  `BUILDINFO` in `share/morsec/`.
- `depends_on arch: :arm64` and `depends_on :macos`.
- `test do` runs `ms --version` and `mors --version` and checks the version.
- No `service do` block: `ms init` owns the LaunchAgent (L07); two managers would fight.
- No auto-update: no updater code, no `livecheck`-driven self-update. A test fails if a known
  self-update crate (`self_update`, `self-replace`, `sparkle`-like bindings, `cargo-update`,
  `update-informer`, `tauri-plugin-updater`, `axoupdater`) enters the dependency graph of `ms` or
  `msd`.

### SBOM

CycloneDX 1.5 JSON (`morsec-<v>.cdx.json`) generated by `packaging/lib/sbom.py` from
`cargo metadata --locked --filter-platform aarch64-apple-darwin`: every package reachable from
`ms` and `msd` through normal and build dependencies (dev-only dependencies excluded), with
`purl` (`pkg:cargo/<name>@<version>`), the `Cargo.lock` SHA-256 checksum, licence expression and
the dependency graph. Deterministic: no random serial (UUID derived from the content hash),
timestamp = `SOURCE_DATE_EPOCH`, sorted components. No new tool needed.

### Checksums

`SHA256SUMS` over the tarball, SBOM and `BUILDINFO`; `SHA256SUMS.minisig` from
`minisign -S -s "$MORSEC_MINISIGN_KEY" -t "morsec <v> <commit>"`, then `minisign -V` against
`packaging/minisign.pub` before the script reports success. In `build`, minisign signing runs
only when `MORSEC_MINISIGN_KEY` is set.

### Gate

`scripts/check.sh` gets one additive step: `packaging tests` runs the Python unit tests in
`packaging/tests/` (SBOM, tarball determinism, formula rendering, release-mode refusals,
frozen identifiers and empty entitlements, no-auto-update) and `shellcheck` on
`scripts/release.sh`. It doesn't do a full release build (too slow for every gate run);
`release.sh verify-repro` is the release-time proof.

## Decisions (made in this loop; reopen if wrong)

1. **arm64 only for v0.1.** The toolchain file has no x86_64 target, and adding one changes the
   shared `rust-toolchain.toml`. The script takes the target from one variable, so an x86_64
   or universal build is a later, small change.
2. **Binary formula, not source.** The keychain ACL (L01) needs the Developer ID signature.
3. **Tap repo name `csakash/homebrew-tap`**, so the tap is `csakash/tap` (D5).
4. **SBOM and tarball made by in-repo Python** (`python3 -I`, standard library only), not
   `cargo-cyclonedx`/`syft`: no new tool in the supply chain, and the output is deterministic.
5. **Reproducibility is claimed on unsigned binaries.** Signed bytes include a timestamp.
6. **`release` fails closed** without Developer ID, notary profile and minisign key. There is no
   flag to skip a step.
7. **Version bump is not part of this loop.** The workspace is `0.0.0`; `release` refuses it.
   The user bumps the version and tags when cutting v0.1.
8. **Name check done:** `brew info`/`brew search` find no formula or cask named `ms`, `mors`,
   `msd` or `morsec`, and `brew which-formula` finds no formula that installs an `ms`, `mors`
   or `msd` command (control: `rg` → ripgrep resolves). Recorded in PROOF.md.

## Verify (from the card)

- Two clean builds give identical hashes (`release.sh verify-repro`).
- `codesign --verify --strict` passes on ad-hoc-signed binaries with the release identifiers and
  hardened runtime (`codesign -d --verbose` shows `flags=0x10002(adhoc,runtime)`). `spctl`
  will reject ad-hoc binaries; the real `spctl --assess` pass needs the Developer ID build
  (**not verifiable here**).
- Local tap install: `brew install` from a temporary local tap whose formula points at the dev
  tarball through a `file://` URL gives a working `ms --version` and `mors --version`, and `brew
  test` passes. Then uninstall and untap. A **clean macOS VM** install from the real tap is
  **not verifiable here** (needs the published release).
- minisign: sign and verify with a throwaway key generated in a scratch dir.

## Out of scope

- Creating the `csakash/homebrew-tap` repo, tagging, uploading, publishing (external steps for the
  user; listed in PROOF.md and `packaging/RELEASING.md`).
- Developer ID signing and notarization with real credentials.
- homebrew-core submission. x86_64/universal builds. Linux packaging (L21). The `apps/` helper
  (L11).

## ARI-42

GW-2 (agent stack as critical supply chain): reproducible builds, signed and notarized
binaries, CycloneDX SBOM, signed checksums, no auto-update, fail-closed release. Update the GW-2
row and add a changelog line. The scan must stay clean.
