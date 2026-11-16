# SPEC: hardening (threat model + fuzzing before the signed Homebrew release)

Loop slug `hardening`, branch `feat/hardening`, repo `morsec`. Base: `main` at 2370043 (waves 1–3,
L01–L17 and L30 merged). CLI-only product. Stops before shipping; the parent session ships.

## Goal

A light hardening pass before the signed Homebrew release (L28):

1. A written threat model of morsec as it stands on `main`, mapped to ARI-42.
2. Fuzzing of the three parsers that take attacker-shaped bytes: the dotenv parser (ms-import),
   the swap proxy's request handling (ms-proxy) and IPC framing and decoding (ms-ipc), wired into
   the local gate and run for a longer session once.
3. Every crash or important finding fixed in this loop with a regression test; `ARI42.md` updated.

## Decisions

- **D1. proptest, not cargo-fuzz.** The repo pins Rust 1.93 (`rust-toolchain.toml`), no nightly
  toolchain or `cargo-fuzz` is installed, and the gate (`scripts/check.sh`, no hosted CI) must run
  every target on every pass without a second toolchain. proptest is already a workspace
  dev-dependency, so cargo-deny sees no new crate. To get most of what cargo-fuzz's corpus gives,
  each target mixes (a) grammar-aware generators, (b) a committed seed corpus mutated byte-wise
  (flip, insert, delete, splice, truncate) and (c) raw bytes. Failures shrink and are persisted by
  proptest in `proptest-regressions/` files, which are committed as regression seeds.
  The nightly cargo-fuzz harnesses live in `fuzz/` (see D6): optional, not gated, reading the
  same corpus. What the gate gives up: coverage guidance; noted in Risk.
- **D2. A dev-only helper crate `crates/ms-fuzz`** (workspace member, `publish = false`, used only
  as a dev-dependency) holds the shared pieces: the case count, the corpus loader and the
  mutation strategy. It has no dependency outside the workspace's existing ones.
- **D3. One knob.** Every fuzz test is named `fuzz_*` and takes its case count from
  `MORSEC_FUZZ_CASES` (default: the small per-target count that `cargo test` already pays for).
  A long local session is the same tests with a large `MORSEC_FUZZ_CASES`.
- **D4. Gate step.** `scripts/check.sh` gets a `fuzz` step that runs only the `fuzz_*` tests of
  ms-import, ms-proxy and ms-ipc with a raised `MORSEC_FUZZ_CASES`, under a hard wall-clock
  ceiling of 90 s enforced by the script (a run that hits it fails the gate). Tuned so the step
  adds about a minute or less on the developer's machine.
- **D5. Threat model lives in `docs/threat-model.md`** (STRIDE, as the PLAN L24 card names it);
  `ARI42.md` links to it and its change log records this loop.
- **D6. Correction from the parent session (2026-11-16): this loop is the early part of PLAN L24
  `hardening`, so it uses that card's paths.** L24 owns `docs/threat-model.md` and `fuzz/`.
  `fuzz/` holds the shared seed corpus (`fuzz/corpus/<target>/`) and the nightly cargo-fuzz
  harnesses (`dotenv` moved from `crates/ms-import/fuzz`, plus `proxy_head`, `ipc_frame`,
  `ipc_decode`; the proxy one reaches the head rewriter through an off-by-default `fuzzing`
  feature of ms-proxy). The stable proptest targets stay in their crates, because they need
  crate-private items and must run in the gate. The PLAN L24 card notes which parts this loop
  covers.

## Scope

### S1. `docs/threat-model.md`

For morsec on `main` (2370043):

- **Assets:** vault values; the keychain items and their ACL (bound to the signed `msd`); the
  morsec CA private key (non-extractable) and leaves; approvals (pending requests, HMAC approval
  tokens, Touch ID); receipts (hash-chained, HMAC'd log) and the rules store / kill switch state.
- **Actors:** the agent itself (same Unix user, prompt-injected or misbehaving); a compromised
  project repo (`.env`, `.morsec.toml`, git config, transcripts); other local users; the network
  (upstream providers, DNS, redirects, MITM on the far side).
- **Trust boundaries:** the msd IPC socket; the swap proxy; ms-shim / run mode (including the
  postgres, ssh and git adapters); `ms mcp`; the connectors' settings files
  (`~/.claude/settings.json`, `~/.codex/config.toml`).
- **Threat table:** for each threat: actor, boundary, asset, the control that covers it, the test
  that proves it (file and test name, as on `main` or added here), status (`mitigated`,
  `partial`, `open`, `accepted`), and the ARI-42 ids from `ARI42.md`.
- An "open threats" section listing everything not fully mitigated, with the card or loop that
  owns it.

### S2. Fuzz targets (proptest, D1)

| Target | Entry point | Properties |
|---|---|---|
| `ms-import` `fuzz_dotenv_*` | `dotenv::parse`, `dotenv::rewrite` | never panics; spans in bounds on char boundaries; untouched rewrite is the identity; a full ref rewrite re-parses to the same keys with only refs as values; no original non-empty value survives anywhere in a full rewrite |
| `ms-proxy` `fuzz_listener` (extended) | the proxy's TCP listener (hyper + `front`/`connect`/`plain`/`base_url`) | arbitrary and mutated heads, CONNECT authorities, absolute-form, `Proxy-Authorization`, chunked and length bodies: never crashes, keeps answering, never puts a vault value in a response unless it is the legitimate echo of a base-URL swap, no vault value in receipts or block events |
| `ms-proxy` `fuzz_tunnel_*` (new) | requests inside a terminated CONNECT tunnel (`inspected` → `swap_and_send`) for a Bearer-header binding and a Basic binding | the value reaches the upstream only in the bound header (Bearer: `authorization: Bearer <v>`; Basic: base64 of the configured `user:password` shape) and only when the agent sent the placeholder; agent-supplied credentials for the bound host never reach upstream; chunked and malformed bodies never crash the proxy; no value in receipts or block events |
| `ms-proxy` `fuzz_head_helpers` (new) | `split_authority`, `proxy_user`, `pct_decode`, `rewrite::plan`/`apply` with Basic | never panic; `pct_decode` of an encoded string is the identity |
| `ms-ipc` `fuzz_frame_*` (new) | `frame::read_frame`, `read_secret_frame` over arbitrary byte streams in arbitrary chunk sizes | never panic; agree with a reference model of the framing (length, empty-frame and >1 MiB refusal, truncation); `write_frame`→`read_frame` round-trips |
| `ms-ipc` `fuzz_decode_*` (new) | `protocol::decode::<RequestBody>` / `<ResponseBody>` | never panic on arbitrary and mutated JSON; encode→decode is the identity for generated valid messages; wrong `v` yields `UnsupportedVersion` with the sender's id |
| `ms-ipc` `fuzz_server_*` (new) | a live `Server` on a temp socket with a recording handler | arbitrary frame sequences (including `PutKey` value frames and `RunStream` stdin frames) never crash the server; a fresh `Status` connection still answers afterwards |

Each target has a committed seed corpus under `fuzz/corpus/<target>/` (D6).

### S3. Findings

Any crash, hang, leak of a vault value, or other important finding from S1 or S2 is fixed in this
loop with a named regression test (`// protects=… fails_when=…` comment as elsewhere in the repo).
Threat-model items that are real but out of scope for a light pass are recorded as open in
`docs/threat-model.md` with an owner card, not fixed.

## Acceptance criteria

- **AC1** `docs/threat-model.md` exists (STRIDE-labelled) with the assets, actors, boundaries, threat table (control,
  test, status, ARI-42 ids) and open-threats section described in S1. Every test it names exists.
- **AC2** The fuzz targets in S2 exist, are named `fuzz_*`, honour `MORSEC_FUZZ_CASES`, and each
  reads a committed seed corpus.
- **AC3** `scripts/check.sh` has the fuzz step (D4); the step's extra time is measured and recorded
  in PROOF.md and is about a minute or less.
- **AC4** Each target was run locally for a longer session (at least 20× the gate's case count);
  cases run, duration and result per target are in PROOF.md.
- **AC5** Every crash or important finding has a fix and a regression test; each is listed in
  PROOF.md.
- **AC6** `ARI42.md` updated (EVAL-1 and the requirements the findings touch; change-log row).
- **AC7** `npm run build` is green; code review and security review converged.
- **AC8** (D6) `fuzz/` holds the seed corpus and the four cargo-fuzz harnesses, which type-check
  (`cargo check` in `fuzz/` on stable); the PLAN L24 card says what this loop covered.

## Constraints

- Tests never touch the real `~/.claude/settings.json`, `~/.codex`, `~/.ssh` or git credentials.
- Keychain tests are not skipped.
- No Apple or Developer ID credentials are entered.
- No frozen interface (`docs/PLAN.md` §4, IPC v1) changes shape. A fix that would need one is
  recorded as open instead.
- No new third-party dependency.

## Out of scope

- cargo-fuzz / nightly in the gate; OSS-Fuzz; hosted CI.
- Fuzzing ms-rules, ms-mcp JSON-Schema validation, ms-run adapters (noted as follow-ups in the
  threat model).
- External security review (EVAL-2, human).
