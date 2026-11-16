# Verifying a morsec release

Anyone can check that a release is the one the maintainer signed and that its binaries are what
the source builds to.

## 1. Checksums and their signature

```bash
minisign -Vm SHA256SUMS -p minisign.pub      # minisign.pub from packaging/ at the release tag
shasum -a 256 -c SHA256SUMS
```

The trusted comment names the version, the full commit and the target.

## 2. Code signature

```bash
tar -xzf morsec-<version>-aarch64-apple-darwin.tar.gz
codesign --verify --strict --verbose=2 morsec-<version>/bin/ms morsec-<version>/bin/msd morsec-<version>/bin/ms-shim
codesign -d --verbose=2 morsec-<version>/bin/msd   # Identifier=cc.morsec.msd, flags include runtime,
                                                   # Authority=Developer ID Application: …, a Timestamp,
                                                   # TeamIdentifier = packaging/macos/team-id at the tag
codesign -d --entitlements - morsec-<version>/bin/msd   # empty: morsec has no entitlements
spctl --assess --type install --verbose=4 morsec-<version>/bin/msd   # accepted, source=Notarized Developer ID
codesign -d --verbose=2 morsec-<version>/bin/ms-shim   # Identifier=cc.morsec.ms-shim (ms: cc.morsec.ms)
```

## 3. Rebuild and compare

On an Apple silicon Mac with the toolchain from `rust-toolchain.toml` and the Xcode / SDK named
in `BUILDINFO`:

```bash
git clone https://github.com/csakash/morsec && cd morsec
git checkout <commit from BUILDINFO>
scripts/release.sh build --out /tmp/rebuild
diff <(grep -E '^(unsigned|code)_sha256' BUILDINFO) <(grep -E '^(unsigned|code)_sha256' /tmp/rebuild/BUILDINFO)
```

The two must match. Then tie the **signed** release binaries to your rebuild. A Developer ID
signature carries a timestamp, so signed bytes never match a rebuild; compare the code digest,
which covers every byte except the signature and the two size fields signing changes:

```bash
mkdir /tmp/rebuild/x && tar -xzf /tmp/rebuild/morsec-*.tar.gz -C /tmp/rebuild/x
python3 -I packaging/lib/machocmp.py --same morsec-<version>/bin/msd /tmp/rebuild/x/morsec-<version>/bin/msd
python3 -I packaging/lib/machocmp.py --same morsec-<version>/bin/ms  /tmp/rebuild/x/morsec-<version>/bin/ms
python3 -I packaging/lib/machocmp.py --same morsec-<version>/bin/ms-shim /tmp/rebuild/x/morsec-<version>/bin/ms-shim
```

Each prints the code digest, which is also `code_sha256.*` in `BUILDINFO`.

Don't use `codesign --remove-signature` for this: it leaves a different `__LINKEDIT` size behind.

What is and isn't reproducible:

- `ms`, `msd` and `ms-shim` before signing, the SBOM and `BUILDINFO`: byte-identical across clean builds,
  whatever the build directory, `CARGO_HOME` and `RUSTUP_HOME` paths, on the same toolchain and
  SDK (`scripts/release.sh verify-repro` proves it at release
  time).
- The tarball: identical when built from the same unsigned binaries with the same Python zlib.
  A released tarball holds the signed binaries, so it can't match a rebuild; check it with steps
  1 and 2 instead.
