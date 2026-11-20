# formula-0-2-0

Bring the in-repo Homebrew formula (`packaging/homebrew/Formula/morsec.rb`) up to the published 0.2.0 release.

`scripts/release.sh release` regenerated it for v0.2.0, and the same file is already live in `csakash/homebrew-tap` (commit 6573abc). The repo copy still points at 0.1.0.

## Acceptance
1. `url` points at `releases/download/v0.2.0/morsec-0.2.0-aarch64-apple-darwin.tar.gz`, `version` is `0.2.0`, and `sha256` equals the tarball's line in the signed `SHA256SUMS` of the v0.2.0 release.
2. The file is byte-identical to `Formula/morsec.rb` in the tap.
3. No other file changes. `npm run build` is clean.
