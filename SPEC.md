# minisign-pub

Commit the release minisign public key at `packaging/minisign.pub` (key ID `848BC7976A5A2C53`),
so `scripts/release.sh release` can embed it in the curl installer and sign `SHA256SUMS`.
The secret key stays at `~/.minisign/morsec.key`, outside the repo. No code changes.
