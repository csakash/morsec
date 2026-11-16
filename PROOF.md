# PROOF: hardening (early part of PLAN L24)

Threat model and fuzzing before the signed Homebrew release. Base `main` 2370043. Spec:
`SPEC.md` (D6 records the parent session's correction: L24 paths `docs/threat-model.md` and
`fuzz/`).

## What changed

- `docs/threat-model.md`: STRIDE threat model of morsec as on `main`. It covers the assets
  (vault values, keychain ACL, CA key, approvals, receipts, rules and kill switch), the actors
  (the agent, a compromised repo, other local users, the network) and the five trust boundaries
  (IPC socket, swap proxy, run mode, `ms mcp`, connector settings). It has 60 threats, each with
  a STRIDE class, the control, the test that proves it, a status (32 mitigated, 22 partial,
  6 open) and its ARI-42 ids, plus an open-threats list with owners.
  `scripts/threat_model_check.py` fails the gate if any of the 164 named tests goes missing.
- Fuzzing uses proptest on stable (SPEC D1). nightly and cargo-fuzz are not installed, the
  toolchain is pinned to 1.93, and the gate must run the targets on every pass. The new dev-only
  crate `crates/ms-fuzz` provides `MORSEC_FUZZ_CASES`, the seed loader and a byte mutator.
  Targets:
  - **dotenv:** `fuzz_dotenv_never_panics`, `_ascii`, `_rewrite_roundtrip`, `_corpus` and
    `_no_value_left`. The last one checks that every secret in a value position is either
    refused or imported, and that none survives the ref rewrite.
  - **proxy:**
    - `fuzz_listener`, extended with seeds, CONNECT authorities, absolute-form,
      Proxy-Authorization and chunked bodies.
    - `fuzz_tunnel_bearer` and `fuzz_tunnel_basic` send requests inside a terminated tunnel.
      Per request, they check that the value reaches the upstream only in the bound location,
      and only when that request carried the placeholder, and that the agent's own credential
      headers never do.
    - `fuzz_rewriter`, `fuzz_head_helpers`, `fuzz_head_helpers_basic` and
      `fuzz_head_helpers_authority`.
  - **IPC:**
    - `fuzz_frame_model`, `_secret_model` and `_roundtrip` check against a plain model of the
      framing, over arbitrary chunkings.
    - `fuzz_decode_request`, `_response` and `_roundtrip`.
    - `fuzz_server_sequences` runs against a live `Server`.
- `fuzz/` (owned by L24) holds the shared seed corpus `fuzz/corpus/<target>/` (67 seeds), with a
  README. It also holds the nightly cargo-fuzz harnesses (`dotenv`, moved from
  `crates/ms-import/fuzz`, plus `proxy_head`, `ipc_frame` and `ipc_decode`) and a committed
  lockfile. `proxy_head` reaches the rewriter through ms-proxy's off-by-default `fuzzing`
  feature, which no workspace member enables.
- `scripts/check.sh` step 7c runs the `fuzz_*` targets deeper: 2500 cases for the pure parsers
  and 200 for the live proxy and socket targets. It runs under a 90 s ceiling that kills the
  whole process group, and Ctrl-C does the same. The `gate_runs_fuzz_step` test keeps the step in
  the gate.
- **Finding fixed:** `split_authority` (ms-proxy) stripped IPv6 brackets before a trailing dot,
  so `[::1].` became `::1]`. It failed closed, since no binding, allowlist entry or resolver
  accepts that host, but the normalisation was wrong. The order is fixed, with regression test
  `split_authority_dot_after_brackets` and a committed proptest seed.
- `ARI42.md`: EVAL-1, INJ-1 and GW-1 updated (GW-1 now records the open gap T-03), with a
  change-log row. `docs/PLAN.md`: the L24 card says what this loop covered and what L24 still
  owns.

## Testing

- **Gate:** `npm run build` (`scripts/check.sh`) passed at 571cc85 (`check.sh: all checks
  passed`, exit 0; fuzz step 15 s) and again at the final head (see the final report).
  - Proof is in `.loops/runs/hardening/interactive/proof/build-morsec*.txt`.
  - Keychain tests ran: ms-vault had 19 passed. The only ignored tests are the pre-existing
    ACL/core-dump child processes (run by their parents) and the manual keychain-trust test.
- **Fuzz step cost:**
  - 15–20 s on an idle machine. It measured 88 s once, at 4000 and 300 cases, while a sibling
    session's release build loaded the machine (load average 28); the counts were then lowered to
    2500 and 200.
  - The ceiling was tested: an over-time step is killed with no leftover processes (exit 1), a
    failing first pass now fails the step (exit 1; the old version exited 0), and Ctrl-C exits 130
    with no leftovers.
- **Long local sessions** (`.loops/runs/hardening/interactive/proof/fuzz-long.txt`, script
  `fuzz-long.sh`). Each target ran at least 20× its gate count: 100,000 cases for the pure
  parsers (40× the gate) and 5,000 for the live targets (25×).

  | Target | Cases | Time | Result |
  |---|---|---|---|
  | `fuzz_dotenv_never_panics` | 100,000 | 16 s | pass |
  | `fuzz_dotenv_never_panics_ascii` | 100,000 | 15 s | pass |
  | `fuzz_dotenv_rewrite_roundtrip` | 100,000 | 44 s | pass |
  | `fuzz_dotenv_corpus` | 100,000 | 17 s | pass |
  | `fuzz_dotenv_no_value_left` | 100,000 | 93 s | pass |
  | `fuzz_frame_model` | 100,000 | 13 s | pass |
  | `fuzz_frame_secret_model` | 100,000 | 29 s | pass |
  | `fuzz_frame_roundtrip` | 100,000 | 87 s | pass |
  | `fuzz_decode_request` | 100,000 | 11 s | pass |
  | `fuzz_decode_response` | 100,000 | 10 s | pass |
  | `fuzz_decode_roundtrip` | 100,000 | 16 s, then 17 s | harness failure (the key-name generator ran out of proptest's reject budget); generator fixed, rerun passed |
  | `fuzz_server_sequences` | 5,000 | 1.5 s | pass |
  | `fuzz_rewriter` | 100,000 | 20 s | pass |
  | `fuzz_head_helpers` | 100,000 | 22 s | pass |
  | `fuzz_head_helpers_basic` | 100,000 | 15 s | pass |
  | `fuzz_head_helpers_authority` | 100,000 | 0.3 s, then 9 s | **finding**: `[@].` broke the bracket property, which exposed the `[::1].` → `::1]` normalisation bug; fixed, rerun passed |
  | `fuzz_listener` | 5,000 | 4 s | pass |
  | `fuzz_tunnel_bearer` | 5,000 | 24 s | pass |
  | `fuzz_tunnel_basic` | 5,000 | 23 s | pass |

  Earlier development runs also passed: the dotenv targets at 40,000 cases, IPC at 20,000 and
  the proxy at 3,000.
- **The properties catch what they claim to:**
  - Making the planner swap without a placeholder fails `fuzz_tunnel_bearer` ("value sent for
    request … that carried no placeholder").
  - Leaving the agent's `Authorization` header in place fails `fuzz_tunnel_basic` ("agent
    credential authorization reached upstream").
  - Both edits were reverted, and their regression files deleted.
- **Not run:** the nightly cargo-fuzz harnesses in `fuzz/`. No nightly toolchain or cargo-fuzz
  is installed. They type-check on stable (`cargo check --bins` and `clippy -D warnings` in
  `fuzz/`), and `head_entry_point_on_seeds` runs the `proxy_head` entry point on every seed in
  the normal suite. Coverage-guided runs are left to L24.
- **Reviews:**
  - **Fresh-context code review:** 3 cycles plus a diff-only pass on the fix, and it converged.
    - R1–R3 (important) were fixed: a failing first fuzz pass was masked by a passing second
      one; the agent's own Basic credential was not decoded before the check; and the
      placeholder check ran per exchange instead of per request.
    - R4, R5, R7, R8 and R9 were fixed.
    - R6 is wontfix: the threat-model name check is a plain grep, and there is no false pass
      today.
    - R10 is wontfix: the nightly-only `proxy_head` check partly restates the planner's filter,
      and the gated per-request tunnel check covers that case end to end.
  - **Fresh-context security review:** no important findings. S1 (the fuzz crate's lockfile
    was gitignored) was fixed by committing `fuzz/Cargo.lock`.
  - **Diff-only review of the `split_authority` fix:** no issues. Normalisation can only remove
    brackets and dots around a name, and SSRF handling of `[::1].` is now stricter (the host is
    parsed as an IP and refused as loopback).
- **Other checks:**
  - No test touches the real `~/.claude/settings.json`, `~/.codex`, `~/.ssh` or git credentials.
    The IPC server uses a temp socket under /tmp, and the proxy uses loopback fakes.
  - No Apple or Developer ID credentials were used.
  - The ARI-42 scan passes (`--fail-on high`); its only hits are pre-existing LOW ones in
    connector golden files.

## Risk

- **Sensitive paths (`gloop risk`, need a human reviewer):** `Cargo.toml` and `Cargo.lock` (new
  dev-only workspace member `ms-fuzz`, no new third-party crate), `scripts/check.sh` (new gate
  step), `crates/ms-proxy/src/server.rs` (`split_authority`, production code),
  `crates/ms-proxy/Cargo.toml` and `lib.rs` (`fuzzing` feature, off by default), the crates'
  `Cargo.toml` dev-dependencies, and the move of `crates/ms-import/fuzz` to `fuzz/`.
- **Production change:** only `split_authority`. It now normalises `[x].` like `[x]`. The
  diff-only review found no way to reach a host that wasn't reachable before.
- **Fuzzing depth:**
  - proptest has no coverage guidance, so the long runs are random and seeded, not
    "until no new coverage".
  - Continuous coverage-guided runs of `fuzz/` are still L24 work, along with fuzzing ms-rules,
    the ms-mcp schema validator and the run-mode adapters.
- **Gate timing:** the fuzz step uses a fresh random seed each run. On a heavily loaded machine
  it could approach the 90 s ceiling (88 s seen at higher counts). If it does, the gate fails
  loudly; it never passes silently.
- **Open threats** recorded in `docs/threat-model.md`, not fixed in this light pass:
  - **T-03 (most important):** `ms` authenticates msd by uid only, so a same-user process that
    takes over the socket path would receive values from `ms add` / `ms import`. This is
    unowned and needs a card; the fix is to verify the server peer's code signature before
    sending a value.
  - T-21 (receipt tail truncation, L23).
  - T-30 (an upstream can echo the value back).
  - T-34 (tunnels outlive `ms stop`; empty allowlist, L29).
  - T-52 (unwatched settings files).
  - T-56 (Codex direct egress).

## How to revert

- **Everything:** revert the PR's merge commit. The branch is self-contained: tests, docs,
  scripts, one dev-only crate, and one production function.
- **Only the gate step:** delete step 7c from `scripts/check.sh` and the `gate_runs_fuzz_step`
  entry in `tests/e2e/tests/canary.rs`.
- **Only the proxy fix:** revert 571cc85 (`split_authority` and its tests). The old behaviour
  failed closed.
- No data, state, keychain item or config format changes, so nothing needs migrating.
