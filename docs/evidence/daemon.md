# Evidence: L07 `daemon`

Commands run on the loop branch `feat/daemon`, 2026-11-13, macOS (Darwin 25.2), rustc 1.93.1.
Full outputs are kept outside the repo in `.loops/runs/daemon/interactive/proof/`
(`build-morsec.txt`, `qa-run.txt`, `qa-run2.txt`, `qa.md`, `PROOF.md`). `ca-hosts.json`
mentioned in early commits no longer exists: the CA record lives in the vault.

## Decisions

- **D-A (user):** approvals before L11 are a deny stub (`msd::approve::DenyApprover`) plus a
  pre-L11 terminal path for loosening rules and resuming after `ms stop`: `--at-terminal`
  (`ms rules … --at-terminal`, `ms init --resume`) asks `yes` on `/dev/tty`, and msd accepts it
  only from a caller with no agent process above it. Production-tier keys can't be used until L11.
- **D-B:** msd MACs the rules with `morsec/rules-hmac` (the key L01 creates), not L03's default
  name `morsec/rules-mac`.
- **D-C:** the stop flag and the proxy CA key are keychain items written by msd only
  (`KeychainVault::put_internal`, two allowlisted names), so an agent can't delete or roll them
  back the way it could a file.
- **D-D:** the CA is issued lazily, for the exact hosts bound to swap keys; `ca.pem` and
  `ca-hosts.json` are written to the state directory. With nothing bound, a throwaway CA for
  `morsec.invalid` keeps the proxy listening (and refusing).
- **D-E:** IPC stays v1 and changes additively (see `docs/PLAN.md` §4).

Spec amendments made while building are listed in `SPEC.md` ("Amendments made during the
build"; `SPEC.md` itself goes into the PR body).

## Gate

See `PROOF.md` for the final run. `npm run build` → `scripts/check.sh`, all 8 steps.

## Acceptance criteria (SPEC.md)

| AC | Evidence |
|---|---|
| 1 gate | `build-morsec.txt` |
| 2 S3 bind | `ipc::{bind_refuses_symlinked_directory, bound_socket_is_private, bind_leaves_existing_directories_alone, bind_refuses_live_socket_and_regular_file}` |
| 3 S6 | `ipc::{held_connections_do_not_delay_stop, reserved_slots_refuse_other_requests, per_peer_cap, request_and_lifetime_caps}`; QA: 64 sockets held by one process, `ms stop` 0.01 s, `ms status` 0.00 s (`qa-run2.txt`) |
| 4 AUTH-4 | `daemon::tests::stop_is_immediate_and_survives_restart` (next decision `Deny(Stopped)`, still stopped after reopening over the same vault); `agent_e2e` (an agent runs `ms stop`, its next proxy request is refused, status says stopped, `ms start` from the agent refused) |
| 5 fail closed | `agent_e2e` (msd down: proxy port refuses, `ms status` exits 1 with the `ms start` hint); `daemon::tests::{tampered_and_rolled_back_rules_fail_closed, unreadable_stop_flag_means_stopped}`; `status_with_and_without_daemon` |
| 6 MCP-3 | `ipc::rejected_peer` (another uid), `session-identity` peer check, `agent_e2e` + `daemon::tests::{rules_changes, start_needs_approval_or_terminal}` (agent caller can't use the terminal path) |
| 7 add/import | `cli::add_and_import_store_through_msd` (both store, `ms rules` shows them verified by msd, no value in output or receipts); `daemon::tests::put_key_and_list` |
| 8 rules over IPC | `daemon::tests::rules_changes`; `agent_e2e` (terminal path from a detached process applies a loosening; from inside the fake agent it is refused) |
| 9 swap through the daemon | `agent_e2e` (placeholder to an unbound host: 403 and a `host_not_allowed` receipt; after `ms stop`: refused) ; `proxy::tests::bindings_from_rules` |
| 10 reviews, QA, proof, ARI-42 | below; `ARI42.md` AUTH-1, AUTH-3, AUTH-4, MCP-3, LOG-2 rows |

## Review record

| Id | Finding | Resolution |
|---|---|---|
| R1 (important) | a caller msd could no longer identify (connecting PID exited, child kept the fd) was treated as a non-agent: could replace keys and slip out of a LOG-2 stop | fixed 4625c1b: accept time carried in `PeerInfo`; unidentified callers get only status/stop (`unidentified_caller_is_refused`) |
| R2 (important) | `ms stop` and `ms start` not serialized: a racing start could undo a stop that reported success | fixed 4625c1b: one lock across flag and vault write (`stop_and_start_are_serialized`) |
| S1 (important) | `ms init --trust` trusted `ca.pem`, which an agent can replace with its own unconstrained CA | 4625c1b moved trust to `Status`, but round 1 showed the certificate still came from the file (`Ca::load` only byte-searches for the public key); fixed 5fc5b57: certificate and hosts live in the vault item `morsec/ca-cert`, `ca.pem` is export-only (`ca_comes_from_the_vault_not_the_file`) |
| S2 (important) | an agent could run `msd --init` directly, resetting keys and clearing `ms stop` | fixed 4625c1b: refuses inside an agent tree, asks on `/dev/tty`, real state dir only, never clears a stop (`agent_e2e`); archiving the old receipts key on `--force` deferred to L24 |
| S3 (important) | rules rollback by deleting the receipts (the floor lived only there) | fixed 4625c1b: floor also in the vault state item (`tampered_and_rolled_back_rules_fail_closed`) |
| R7 (important, round 1) | an unreadable state item persisted a `u64::MAX` floor, denying every key forever | fixed 5fc5b57 (`unreadable_state_never_persists_a_sentinel_floor`) |
| N7, N9, N10 (nits) | approval held the stop lock; `ca.pem` read unbounded; a resume approved before a newer stop | fixed 5fc5b57, 9142909, b193b26 |
| N8 (nit) | rules file deleted with keys present needs `ms init --force` | wontfix: that state is tampering; follow-up for a rules-only recovery |
| R-N1/S-N1..N4, R-N2..N6 (nits) | reserved-slot parking, spec drift, compat comment, wipe-before-bind, stale alerts, resume hint, drift reader, D-A wording | fixed 4625c1b, except stale skipped-binding alerts (kept; cleared on restart) |

Both reviews converged within the 2-round budget: code review (round 2: no important findings)
and security review (round 2: S1 resolved, no new issues).

## QA

The dev daemon (`msd --foreground --vault memory --port 4100`) was exercised with the real `ms`;
transcripts are in `qa-run.txt` and `qa-run2.txt`. One bug was found and fixed (f6218db): every
rules change rebuilt the proxy, briefly closing the port, so a request right after a change was
refused with a connection error. The proxy now rebinds only when its bindings change.

## Not proven here

- The keychain backend end to end (`ms init` → `msd --init` → LaunchAgent): it writes to the
  real login keychain and `~/Library/LaunchAgents`, so it was not run on this machine during the
  loop. The keychain primitives it uses are L01's (tested there); `put_internal` has its own
  keychain test. `ms init --trust` (macOS trust prompt) likewise.
- Touch ID (L11). Hardened-runtime signing with `crates/msd/msd.entitlements` (L10).
- Uninspected allowlisted tunnels opened before `ms stop` live until idle (no allowlist source
  exists yet; L08 adds one).
