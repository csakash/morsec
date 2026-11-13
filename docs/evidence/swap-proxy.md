# Evidence: L05 `swap-proxy`

These commands were run on the loop branch `feat/swap-proxy` at `9be797a`, on 2026-11-13, on macOS (Darwin 25.2) with rustc 1.93.1 and go 1.24.2.
Full outputs are kept outside the repo, in `.loops/runs/swap-proxy/interactive/proof/`. That folder holds `build-morsec.txt`, `tests.txt`, `qa.md` and `qa-curl.txt`.

## Gate

`npm run build` runs `bash scripts/check.sh`. It exited 0 and passed all 8 steps:

| Step | Result |
|---|---|
| fmt, build, clippy `-D warnings` | clean |
| `cargo test --workspace --locked` | 81 passed, 0 failed, 1 ignored. The ignored test is the manual keychain test. |
| `cargo deny`, `cargo audit` | ok. 190 crates, 0 vulnerabilities. |
| Supply-chain check | ok. No patches; all 15 path packages are workspace members. |
| ARI-42 scan | 0 high, 0 medium, 0 low |

`ms-proxy` on its own has 36 tests passing and 1 ignored. All of them are unit tests or in-crate integration tests (`src/itests.rs`). The integration tests run a real proxy against a local TLS echo server that stands in for the provider, and use the L00 fakes for the vault, receipts and approvals.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 Swap upstream; agent `X-Api-Key` and `Cookie` stripped; one `Allowed` receipt | `swap_over_http1`. Unit test: `rewrite::header_swap_strips_others`. |
| 2 HTTP/2 in the tunnel | `swap_over_http2`. Concurrent h2 streams over an h1 upstream: `swap_with_http1_upstream`. |
| 3 Header, Basic and Query locations | `rewrite::basic_and_query` (Basic user and password; percent-encoded query placeholder), `swap_query_location` |
| 4 Mockup exfil to `paste.example.net` | `exfil_to_paste_site_blocked`. Plain HTTP gets 403 plus a `Blocked` receipt. CONNECT gets 403 plus a `BlockEvent`, and the host is never resolved. `oversized_plain_bodies` covers a ref in the prefix of a body over the limit. |
| 5 Foreign ref to a bound host | `foreign_ref_to_bound_host_blocked`, and `rewrite::foreign_refs_block`. The ref can be in the path, a header, the body, percent-encoded, a shaped placeholder or inside Basic credentials. |
| 6 INJ-4 targets unreachable | `ssrf_targets_unreachable` covers 11 CONNECT targets and 4 plain-HTTP targets. `ssrf::tests::blocked_ranges` has 40 rows; `public_ranges_pass`; `check_filters`. |
| 7 Redirects relayed, not followed | `redirects_not_followed`, and QA 9b |
| 8 Base-URL mode | `base_url_mode`, and QA 3 |
| 9 413 over the limit; responses stream | `body_limit_and_streaming`: the first chunk arrives while the upstream is paused. |
| 10 Policy Deny, NeedsApproval and approver | `policy_and_approvals` |
| 11 No session gives 403 | `no_session_refused` |
| 12 Name constraints; leaves only for bound hosts; Go accepts the chain | `ca::tests::*`. The CA permits exactly the bound DNS names and excludes all IP addresses. `go_client_accepts_chain` runs Go `crypto/x509` through the proxy. macOS keychain trust is checked by `keychain_trust_manual`, which is `#[ignore]` and needs a person. |
| 13 Fuzz | `fuzz_listener` runs 96 cases of mutated heads against the live listener. `rewrite::fuzz_rewriter` runs 512 cases. |
| 14 Canary never leaks | `assert_no_canary` checks receipts, block events and bodies. In QA, the canary appeared 0 times in the daemon log. |
| 15 Gate | above |
| 16 ARI42 rows and this file | INJ-2, INJ-4 and GW-1 updated |

Resource bounds added after review:
- The connection cap now holds for the full life of a tunnel: `tunnels_are_bounded_and_idle_closed`.
- Idle h1 and h2 tunnels are closed: `idle_h2_tunnel_closes` and `idle::tests::idle_watchdog`.
- Bodyless requests hold no body budget: `bodyless_requests_hold_no_budget`.

## QA (port 4500, `examples/swap_demo.rs`, real network)

The demo bound a fake canary key to httpbin.org. With curl, openssl and Python:
- The swap worked over h1, over h2, in base-URL mode, and on a 1 MiB POST.
- Exfil to a paste site, the metadata IP and example.com all got 403. Each was recorded.
- github.com, which is allowlisted, was tunnelled with its real Sectigo certificate.
- A client that doesn't trust the morsec CA refuses the connection.
- openssl shows the leaf `CN=httpbin.org` issued by `morsec local CA`, with critical Name Constraints.
- The demo refuses to start when `SSL_CERT_FILE` is set.

## Deviations from SPEC.md, with reasons

- **Upstream roots: `rustls-native-certs`, not the platform verifier.** `rustls-platform-verifier` depends on `webpki-root-certs` (CDLA-Permissive-2.0), which `deny.toml` rejects, and `deny.toml` is outside this loop. Roots come from the OS store. The proxy refuses to start if `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, because those would replace the OS store with files the agent can write (security review S2).
- **The `Policy` trait** is `decide(&SessionId, &Request) -> (Decision, u64)` plus `version()`, which is used for receipts of blocks that need no decision (review R5).
- **`SessionResolver::resolve`** takes `(peer, local, proxy_user)` and runs on the blocking pool. This matches L06's `PortResolver::resolve(peer, local)`.
- **Fuzzing** is property-based (proptest) rather than cargo-fuzz, because cargo-fuzz needs nightly.
- **Plain-HTTP requests to allowlisted hosts** get their bodies scanned too, not just their heads. This is stricter than the spec.
- **New limits** not named in the spec: `tunnel_idle_timeout` (300 s), `max_buffered_bytes` (64 MiB), and 32 h2 streams per tunnel.

## Review record

**Code review: 3 cycles, converged.**
- R1 was fixed in two steps: first the permit lifetime and idle timeout, then removing the h2 pings that kept idle tunnels alive.
- R2, R3, R4, R5 and R6 were fixed.
- R7 (nit) is open: concurrent undeclared-length uploads can stall each other until a 503. It fails closed.
- Platform-verifier nit: wontfix (licence, above).

**Security review: 3 cycles, converged with "no issues".**
- S1 is fixed, together with R1.
- S2 and S3 are fixed.
- N1 and N2 are fixed, together with R6 and R1.
- S4 is open for L11/L07: approval prompts a swap can trigger are not rate-limited. It is recorded in ARI42 GW-1.

## Open items for later loops

- **L07** runs `Proxy`:
  - plugs in `ms_rules`, the L02 receipt store, the L01 vault and L06 `PortResolver` plus `cross_check`;
  - stores the CA key with `Ca::store`;
  - re-issues the CA when hosts change;
  - starts `msd` without `SSL_CERT_*`.
- **L08** sets `HTTPS_PROXY` and the CA bundle variables for the agent, and the proxy username from `proxy_user_for`.
- **L09:** end-to-end canary through a real agent.
- **L11:** rate limiting and deduplication of approval prompts (S4).
- **Residual:** hyper, h2 and rustls copy header bytes into write buffers that are not zeroized.
