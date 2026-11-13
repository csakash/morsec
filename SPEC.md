# SPEC: L05 `swap-proxy`

Loop card: `docs/PLAN.md` §5 "L05 `swap-proxy`", mechanism: §3.2 "Swap". Owns `crates/ms-proxy/`
only. Requirements: ARI-42 INJ-4, GW-1, INJ-2.

## Problem

The agent holds `ms://stripe/test`, never the key. Something on the way out has to put the real
value into the request, only for the hosts that key belongs to, and refuse everything else. That
is the swap proxy. `msd` (L07) will run it; this loop builds it as a library with a test harness
and a demo binary.

## Scope

A library crate `ms-proxy` exposing `Proxy::bind(config, deps) -> Proxy` and `Proxy::serve()`,
plus everything below. No daemon wiring, no connector config, no CLI command (L07/L08).

### Inputs (all injected, so L07 plugs in the real ones)

| Dependency | Trait in `ms-proxy` | Real impl from | Fake used here |
|---|---|---|---|
| Vault | `ms_vault::Vault` (frozen) | L01 | `ms_vault::memory::MemoryVault` |
| Policy | `Policy::decide(&SessionId, &Request) -> (Decision, rule_version)` | L03 (`ms_rules::decide`) | allow-all / deny-all / scripted fakes |
| Receipts | `ms_receipts::ReceiptSink` (frozen) | L02 | `MemorySink` |
| Approvals | `ms_approve::Approver` (frozen), optional | L11 | `FakeApprover` |
| Session | `SessionResolver::resolve(peer_addr, proxy_user) -> Option<SessionId>` | L06 (port→pid) | fixed session |
| Bindings and catalog | `ProxyConfig.bindings: Vec<Binding>` | L04 catalog via L07 | literal config |
| Egress log | `EgressObserver::blocked(&BlockEvent)` for blocks that carry no key | L07 | recording fake |

No frozen interface in `docs/PLAN.md` §4 changes.

### Behaviour

1. **Listener.** Loopback only (`127.0.0.1` or `::1`; any other bind address is an error).
   HTTP/1.1 from the agent, with `CONNECT` and absolute-form `http://` requests. Inside a
   terminated TLS tunnel the agent may speak HTTP/1.1 or HTTP/2 (ALPN). Bounded: max concurrent
   connections, header read timeout, max header size.
2. **Session.** Every connection is mapped to a `SessionId` through `SessionResolver`. No session
   means `407`-free refusal: the connection gets `403` and nothing is forwarded (fail closed).
3. **Host classes.** For a `CONNECT host:port` or an absolute-form request:
   - **bound** (some `Binding` lists the host, exact match, case-insensitive, port matches):
     terminate TLS (MITM), see 4.
   - **allowlisted** (`ProxyConfig.allow` exact host or `*.suffix`), not bound: `CONNECT` is
     tunnelled byte-for-byte without inspection; plain `http://` is forwarded after the head
     check in 6.
   - anything else: `403`, plus a `BlockEvent` to the egress observer. Plain `http://` requests
     are also scanned (head plus up to the body limit) and every `ms://` ref found gets a
     `Blocked(HostNotAllowed)` receipt.
4. **Swap (bound hosts).** The proxy presents a leaf for the CONNECT host signed by the morsec CA
   (SNI, if sent, must equal the CONNECT host, else the handshake is aborted). For every request
   in the tunnel:
   - `Host` / `:authority` must equal the CONNECT host (`421` otherwise).
   - The request body is buffered up to `max_body` (`413` above it).
   - Head and body are scanned for `ms://` refs (and shaped placeholders). A ref to a key that is
     not bound to this host gives `403` and a `Blocked(HostNotAllowed)` receipt; nothing is sent
     upstream.
   - The placeholder for this host's key must sit in the binding's location (`Header { name,
     prefix }`, `Basic { user|password }`, or `Query { param }`). Policy is asked with
     `Request::Swap { key, host }`: `Allow` swaps, `Deny` gives `403` + receipt, `NeedsApproval`
     goes to the approver if one is configured (else `403`, fail closed).
   - Every other credential the agent supplied is removed: `Authorization`, `Proxy-Authorization`,
     `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `Cookie`, and the binding's own header if it held
     something other than the placeholder. `Proxy-*` and hop-by-hop headers are never forwarded.
   - The value is read inside `Vault::with_secret` and written into a zeroizing buffer; header
     values carrying it are marked sensitive (no HPACK indexing). The value never appears in
     logs, `Debug`, errors or receipts.
   - Upstream: a fresh TLS connection (rustls, platform verifier = system roots) to the IP the
     SSRF guard checked, ALPN h2 or http/1.1. A request with no placeholder for a bound host is
     forwarded with credentials stripped and no swap (and no receipt).
   - Each swap writes one `Allowed` (or `Approved`) receipt: session, key, `Mode::Swap`, target
     `host`, rule version.
5. **SSRF guard (INJ-4).** Every upstream (bound, tunnelled or plain) is resolved first, each
   address is classified, and the proxy connects only to an address that passed. Refused:
   unspecified, loopback, private (RFC 1918, `fc00::/7`), link-local (incl. `169.254.169.254`
   and `fe80::/10`), CGNAT `100.64/10`, multicast, broadcast, documentation and benchmarking
   ranges, `240/4`, and IPv4-mapped / NAT64 / 6to4 forms of any of these. IP-literal targets get
   the same check. If no address passes: `403`.
6. **Head check for plain `http://`.** Any `ms://` ref in the head of a plain-HTTP request is
   blocked (`403` + receipt): keys are never sent or swapped over cleartext. A bound host over
   plain HTTP is refused with a message to use https.
7. **Redirects** are relayed to the agent as is, never followed by the proxy.
8. **Base-URL mode** for pinned tools: an origin-form request `/p/<provider>/<rest>` to the
   listener is handled exactly as a request to the binding with that `provider` name, upstream
   `https://<host>/<rest>`.
9. **Streaming.** Response bodies stream (no buffering). Tunnels stream both ways.
10. **CA.** ECDSA P-256 CA with X.509 name constraints: permitted DNS subtrees are exactly the
    bound hosts. `Ca::generate(hosts)`, `Ca::cert_pem()`, and `Ca::store(vault, key)` /
    `Ca::load(vault, key)` keep the private key only in the vault (as PEM in a `SecretBytes`).
    Leaves are issued only for bound hosts, cached per host (bounded cache), short-lived.
11. **Errors** are plain-text `403/413/421/502` bodies that say what happened and the fix, e.g.
    `morsec: api.evil.example is not on the egress allowlist. Allow it with: ms rules`.

## Acceptance criteria

1. Integration test against a local TLS echo server: a request through the proxy with
   `Authorization: Bearer ms://stripe/test` arrives upstream with the vault value; an extra
   agent-supplied `X-Api-Key` and `Cookie` are gone; one `Allowed` receipt is recorded.
2. Same over HTTP/2 inside the tunnel.
3. Header, Basic and Query locations each swap correctly; the agent's own `Authorization` is
   replaced, not duplicated.
4. Mockup exfil case: `ms://stripe/test` sent to `paste.example.net` (plain `http://` and
   `CONNECT`) is refused with `403`; the plain form records a `Blocked` receipt for
   `stripe/test`; the `CONNECT` form records a `BlockEvent`; nothing reaches the network.
5. A foreign ref (`ms://aws/prod`) in a header or body of a request to a bound host gives `403`
   and a receipt, and nothing is sent upstream.
6. INJ-4: `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `[::1]`, `[::ffff:169.254.169.254]`, a
   name resolving to a private address, and a non-allowlisted domain are all unreachable; unit
   table over the address classifier covers every listed range.
7. A `302` from upstream reaches the agent unchanged and is not followed.
8. Base-URL mode `/p/stripe/v1/charges` swaps and forwards to the bound host.
9. Request body over `max_body` gives `413`; a large response body streams.
10. Policy `Deny` → `403` + `Blocked` receipt; `NeedsApproval` with no approver → `403`; with a
    `FakeApprover` that approves → swap + `Approved` receipt.
11. No session from the resolver → `403`, nothing forwarded.
12. The CA's name constraints are present; a leaf for an unbound host is never issued; Go's
    `crypto/x509` (strict name-constraint checking) accepts a proxy-issued chain when given the
    CA explicitly (test skipped if `go` is absent). System-trust (login keychain) is a manual,
    `#[ignore]` test: adding trust settings needs a person.
13. Fuzz: a property test throws arbitrary bytes and mutated request heads at the listener and at
    the head rewriter; no panic, and the canary value never appears in any response.
14. The canary value never appears in receipts, `BlockEvent`s, error bodies or `Debug` output.
15. `npm run build` (`scripts/check.sh`) passes: fmt, clippy `-D warnings`, tests, cargo-deny,
    cargo-audit, supply-chain check, ARI-42 scan. New deps only in `crates/ms-proxy/Cargo.toml`.
16. `ARI42.md` rows INJ-4, GW-1, INJ-2 updated with evidence; `docs/evidence/swap-proxy.md`
    written.

## Out of scope

Daemon wiring, port→PID mapping, persisting the CA at `ms init`, keychain trust and connector
env (`SSL_CERT_FILE` etc.), the real catalog, rules and receipts store, upstream connection
pooling across tunnels, shaped-placeholder generation (the config accepts the shaped string; L04
generates it).

## Known residual risk (to record, not fix here)

- hyper, h2 and rustls copy header bytes into their own write buffers, which are not zeroized.
  Our buffers are; theirs are freed normally.
- An allowlisted, unbound host is tunnelled uninspected, so a ref sent there is not seen. It is
  only a reference, so no value leaks.
