# morsec-darwin-arm64

The Apple silicon macOS binaries of [morsec](https://github.com/csakash/morsec): `ms`, `msd`
and `ms-shim`, signed with Developer ID and notarized. Install `morsec`, not this package: it
depends on this one and puts `ms` and `mors` on your PATH.

```bash
npm install -g morsec
```

To check these files against the GitHub release, see
https://github.com/csakash/morsec/blob/main/packaging/VERIFY.md
