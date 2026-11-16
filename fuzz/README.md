# Fuzzing

L24 (`hardening`) owns this directory. The first part was done by the pre-release `hardening`
loop; L24 extends it (continuous runs, Miri and sanitizers).

There are two ways to fuzz the same three parsers, sharing one seed corpus.

| Parser | Stable proptest targets (run by the gate) | cargo-fuzz harness (nightly, here) | Seeds |
|---|---|---|---|
| dotenv (`ms-import`) | `crates/ms-import/src/dotenv.rs` `fuzz_dotenv_*` | `fuzz_targets/dotenv.rs` | `corpus/dotenv` |
| proxy request handling (`ms-proxy`) | `crates/ms-proxy/src/itests.rs` `fuzz_listener`, `fuzz_tunnel_bearer`, `fuzz_tunnel_basic`; `rewrite.rs` `fuzz_rewriter`, `fuzz_head_helpers*`; `server.rs` `fuzz_head_helpers_authority` | `fuzz_targets/proxy_head.rs` (via the `fuzzing` feature) | `corpus/proxy-heads`, `corpus/proxy-tunnel` |
| IPC framing and decoding (`ms-ipc`) | `crates/ms-ipc/tests/fuzz.rs` `fuzz_frame_*`, `fuzz_decode_*`, `fuzz_server_sequences` | `fuzz_targets/ipc_frame.rs`, `fuzz_targets/ipc_decode.rs` | `corpus/ipc-frames`, `corpus/ipc-messages` |

## Stable (what the gate runs)

The proptest targets mix grammar-aware generators with byte-mutated seeds from `corpus/`
(`crates/ms-fuzz`). They run in `cargo test` at small counts and again, deeper, in step 7c of
`scripts/check.sh` under a 90 s ceiling. A longer session is the same tests with more cases:

```bash
MORSEC_FUZZ_CASES=100000 cargo test -p ms-import -- fuzz_dotenv
```

A failure is shrunk and saved by proptest in the crate's `proptest-regressions/`; commit that file
with the fix so the case is replayed forever.

## Nightly, coverage-guided

Needs a nightly toolchain and `cargo install cargo-fuzz`. Pass a scratch directory first, so
libFuzzer writes what it finds there and the committed seeds stay as they are:

```bash
cd fuzz && cargo +nightly fuzz run dotenv runs/dotenv corpus/dotenv
```

`fuzz/Cargo.lock` is committed, so a nightly run builds the dependency versions reviewed here.
The gate's cargo-deny and cargo-audit do not cover this crate; run them in `fuzz/` before a long
session (`cargo deny check`, `cargo audit`).

Add a crash input that reproduces a bug to `corpus/<target>/` together with the fix and a
regression test in the crate.
