# L30 `git-https-swap`: HTTPS git tokens through swap mode

Card: docs/PLAN.md "L30 `git-https-swap`". Follow-up from L16, which built a git credential helper
for HTTPS tokens and dropped it after review: a program git starts inside the run (receivepack,
`ext::` remotes, aliases, filters) could ask the helper for the raw token. Here git never holds the
token at all, so nothing git starts can read it.

## Problem

An agent needs `git push` / `git fetch` over HTTPS to a git host (for example `github.com`) with a
token. Today:

- A swap key goes to its hosts only in its catalog location. GitHub's is
  `Authorization: Bearer` on `api.github.com`. git's smart HTTP sends a token as the Basic-auth
  password on `github.com`, so a placeholder sent by git is never swapped. The proxy strips the
  credential and the push fails with 401.
- On macOS, git (Apple's and Homebrew's) trusts only `GIT_SSL_CAINFO`; it ignores the
  `SSL_CERT_FILE`, `CURL_CA_BUNDLE` and other CA variables the connectors set. So git through the
  proxy fails certificate checks. This was checked on this machine with git 2.49 and 2.50.

## Behaviour

### Rules (D1)

- New per-key field `git_hosts`, for swap keys only: exact DNS names, at most 16. Every git host is
  also in the key's `hosts`, so the host allowlist and `decide` don't change.
- `ms rules <key> --add-git-host H` adds H to `hosts` (if missing) and `git_hosts` in one change.
  That change is a loosening and needs an L11 approval, like every other loosening.
  `--remove-git-host H` removes it from `git_hosts` only (a tightening). `--remove-host H` also
  drops H from `git_hosts`. `ms rules <key>` shows a `git hosts` line.
- Adding a git host is a loosening even when the host is already in `hosts`, because it changes
  where on that host the key is used.
- A project `.morsec.toml` can't add git hosts: the file fails to parse, which disables every key.
  Narrowing `hosts` drops the git hosts that are no longer in it; a key the project disables loses
  them.
- Rules validation rejects git hosts on non-swap keys, wildcards and IPs, a git host missing from
  `hosts`, and more than 16.

### Swap bindings (D2)

- For a swap key with git hosts, msd builds a second proxy binding for those hosts on port 443:
  - provider name `<key with / as ->-git`;
  - location: Basic-auth **password**, any user name.
- The key's other hosts keep the catalog location as today. A key with only git hosts needs no
  catalog entry.
- On a git host, the proxy swaps `ms://<key>` (sent by git as `user:ms://<key>` in Basic auth) for
  the token. Every other L05 rule holds unchanged:
  - other credentials are stripped;
  - a placeholder for a key not bound to that host is refused, with a receipt;
  - upstream TLS is verified;
  - the SSRF guard applies;
  - redirects are not followed;
  - production keys need approval;
  - every swap is a receipt.
- A push larger than the proxy's body limit (16 MiB per request) fails with 413. That is a
  documented limit of this loop.

### git trusts the proxy (D3)

- The Claude Code and Codex connectors add `GIT_SSL_CAINFO` to the CA variables they point at
  their CA bundle (morsec CA plus the system roots). `disconnect` removes it like the others.

### Getting git to send the placeholder (D4)

- git asks credential helpers for a user name and password after a 401. The recommended setup
  scopes a helper to the git host and resets the list first. The reset stops a global helper,
  such as the macOS keychain, from sending (and, after a 401, erasing) the person's own
  credentials:

  ```
  git config credential.https://github.com.helper ''
  git config --add credential.https://github.com.helper \
    '!f() { echo username=x-access-token; echo password=ms://github/test; }; f'
  ```

  The helper prints only the placeholder. Nothing in git's process, environment, config or output
  ever holds the token; the swap happens in msd's proxy.
- `ms rules <key> --add-git-host` prints this recipe after the change.

### Test upstreams (D5, QA only)

- msd gets a hidden flag `--test-upstream HOST=127.0.0.1:PORT` (repeatable), with
  `--test-upstream-ca FILE`. It has effect only in a debug build with `--vault memory`, like
  `--test-touch-id`; otherwise msd refuses to start. With it, the proxy:
  - resolves HOST to that loopback address (the SSRF guard lets exactly those through);
  - verifies upstream TLS against FILE only.
- The ms-proxy hook behind it is compiled only in debug builds.

## Verify

1. Rules: `git_hosts` round-trips. Each invalid case in D1 is rejected. `--add-git-host`
   classifies as loosening, `--remove-git-host` as tightening. Projects can't add git hosts, and
   narrowing `hosts` drops them.
2. Bindings: a key with git hosts yields a Basic-password binding for exactly those hosts, and its
   catalog binding for the rest.
3. Proxy, with real git (ms-proxy integration test, local HTTPS git server via
   `git http-backend`, upstream CA trusted only by the proxy, git trusting only the morsec CA):
   - `git push` and `git fetch` with the D4 helper land, and the server sees the real token;
   - git's environment, config and output never contain it;
   - the same placeholder through a host the key isn't bound to is refused, with a receipt.
4. Connectors: `GIT_SSL_CAINFO` is set on connect and removed on disconnect (goldens updated).
5. Test-upstream flag: refused in release builds and without the memory vault.
6. QA with the real `ms` and `msd` (dev, memory vault, port 4500):
   - push and fetch to a local HTTPS git server;
   - receipts for every swap;
   - a production key needs `ms approve`;
   - the token string has 0 hits in files, logs and output.
7. `npm run build` green.

## Out of scope

- A credential helper that returns the token (L16 dropped it, see above), and `ms git-credential`.
- Bodies over the proxy's 16 MiB limit (large pushes); git over HTTP/2-only servers.
- GitHub App installation tokens (L19), SSH (L16).

## ARI-42

- GW-1: the token never leaves msd for the git process.
- AUTH-2: git hosts are explicit and loosening-approved.
- INJ-4: the SSRF guard is unchanged; the test hook is debug-only.
- LOG-1: a receipt for every swap.
