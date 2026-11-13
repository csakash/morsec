# ARI-42 record: morsec

Security record for the AI and agent parts of this project, kept by the coding agent under the
ARI-42 skill and reviewed by people. Update it in the same change as the code.

- **Last reviewed:** 2026-11-13
- **Owner for AI security:** csakash (to confirm)
- **Score:** 1 of 27 in-scope requirements met with evidence · 0 Risk · 15 Gap · 11 Partial (L09: EVAL-1 Gap → Partial; other wave-1 loops' moves to be recomputed when they merge)

## What this project is, for scoping

morsec (CLI `ms` / `mors`) is a local secret broker for coding agents: it keeps API keys,
database passwords and tokens in the Keychain and lets Claude Code, Codex and others use them
without seeing them (swap via a local proxy, run commands on the agent's behalf, mint
short-lived credentials). Design: the PRD on the Intraface board
(https://app.intraface.cc/b/warden-keys-mockup-gfnm5).

**There is no product code yet.** Scope below comes from the PRD design plus what is in the repo
today (coding-agent config and skills). The product makes **no model calls**: it sits between
agents and secrets. So model-data requirements are N/A for morsec itself, while the
agent-facing surfaces it exposes (MCP server, approvals, command runner, proxy) are in scope.
Re-run scoping when the first code lands.

## AI-BOM (GOV-1)

Generated with `python3 .claude/skills/ari42/scripts/ari42_scan.py detect .`, then checked by hand.

| Component | Kind | Version / pin | Where | Data it can reach | Owner |
|---|---|---|---|---|---|
| ARI-42 skill | skill (vendored) | 1.0.1, csakash/ari42-skill@90a9b28 | `.claude/skills/ari42/`, `.agents/skills/ari42/` | repo contents | csakash |
| ARI-42 SessionStart hook | Claude Code hook | runs vendored `ari42_scan.py hook` | `.claude/settings.json` | repo contents (read-only scan) | csakash |
| gstack-loops conventions | rules file | csakash/gstack-loops (installed `gloop`, not vendored) | `CLAUDE.md`, `loops.json`, `REVIEW.md` | repo, worktrees | csakash |
| Claude Code, Codex | coding agents used on this repo | user-installed | developer machines | repo, developer environment | csakash |
| `ms mcp` (planned) | MCP server morsec exposes | — | PRD §8 | run capabilities (`db_query`, `deploy_staging`) | |

## Agent register (GOV-4)

morsec ships no agent of its own. The agents that act on this repo:

| Agent | Tools (read / write / consequential) | Autonomy | Approval required for | Accountable owner |
|---|---|---|---|---|
| Claude Code (incl. `/gloop-*` loops) | read/write repo; shell; git push; `gh` PRs | act with approval (per-session permission mode) | push, PR creation, merges | csakash |
| Codex | read/write repo; shell | act with approval | push, PR creation | csakash |

## Trust boundaries (INJ-1, INJ-2)

| Agent | Untrusted inputs (who can write them) | Private data | Exfiltration paths | Control that breaks the trifecta |
|---|---|---|---|---|
| Any agent calling morsec (product, planned) | everything the agent says: commands, hosts, arguments (an injected agent can write any of it) | secret values in the vault | agent network egress; command output; approval prompt text | values never enter the agent (refs only); per-key host binding; broker-run commands with redacted output; approvals rendered by morsec from real args (PRD §9) |
| Coding agents on this repo | issues, PR comments, fetched web pages, board content | developer's local env and credentials | network, git push | session permission modes; CODEOWNERS on agent config (Partial) |

## Data flow (DATA-1)

N/A: morsec sends no data to any model. Receipts stay local; export is user-initiated (PRD §14.4).

## Status of the 42

Status: **Met** (enforced + passing check) · **Partial** · **Gap** · **Risk** · **N/A** (reason) ·
**Human** (owned by a person) · **Exception** (accepted risk).

| ID | Requirement | Status | Evidence / reason |
|---|---|---|---|
| GOV-1 | Maintain an AI bill of materials | Partial | AI-BOM above; not yet generated in CI or checked on change |
| GOV-2 | AI policy and risk assessment | Human | Needs a person to write and sign |
| GOV-3 | Notify customers of AI changes | Human | B2B buyers (PRD §3); needs a change-notice process |
| GOV-4 | Define agent autonomy and owner | Partial | Register above covers coding agents; product's per-key tiers (PRD §5) to be added when built |
| DATA-1 | Map data reaching models | N/A | Product makes no model calls (PRD §6) |
| DATA-2 | Minimise data sent to models | N/A | No model calls |
| DATA-3 | No provider training; bounded retention | N/A | No model provider |
| DATA-4 | Control inference location | N/A | No inference |
| DATA-5 | Isolate and purge agent memory | N/A | No memory, vector store or cache in the design |
| AUTH-1 | Per-agent identity | Partial | L06 `ms-session`: session = outermost agent process `{agent, pid, start time}` derived from the kernel (Unix peer PID; loopback source port → PID for the proxy) plus proxy-username cross-check; tests: `crates/ms-session/tests/live.rs` (nested fake-agent trees, PID reuse, port→PID), unit tests in `walk.rs`/`port.rs`/`peer.rs`/`proxy.rs`. L07 wires it into msd: the socket peer check is `SessionPeerCheck`, every request is attributed to its session, and the proxy maps each connection to a session (refused when none); test `crates/msd/tests/agent_e2e.rs` (a fake `claude` tree). Still to do: per-session grants/minted creds (L11, L18+). Residual: same-user process can detach (Unattributed, never more rights) or exec a binary named like an agent; see `docs/evidence/session-identity.md` |
| AUTH-2 | Never exceed the user's permissions | Partial | L03 policy side: each key is deny-by-default and narrowed to its own mode, hosts, argv patterns and mint scopes. The project `.morsec.toml` can only tighten (property test `project_never_widens`). The rules file is MAC'd with a vault key and fails closed when tampered (`store::tests::tampering_fails_closed`). Still open: daemon wiring (L07), read-only roles in the pg adapter (L15) |
| AUTH-3 | Approval for consequential actions | Partial | L03 policy side: a production key always yields `NeedsApproval` (proptest `production_always_needs_approval`). `decide_run` binds the `ApprovalRequest` to the canonical `argv_hash` of the real argv, and a changed argument changes the hash (`decide_run_binds_approval_to_argv`). Loosening the rules needs an approval (`save_requires_approval_to_loosen`). L07: rule changes go through msd (`RulesProposeLoosen` carries the proposed rule); tightening is saved, loosening and `ms start` need an approval. Until L11 the approver is a deny stub (production keys can't be used), and loosening/resuming use a pre-L11 terminal path that msd accepts only from a caller outside every agent session after a `/dev/tty` confirmation (L07 SPEC D-A; tests `daemon::tests::{rules_changes, start_needs_approval_or_terminal}`, `agent_e2e`). Residual: the `/dev/tty` confirmation is in `ms`; msd checks only that the caller is outside every agent tree, so any fully detached same-user process passes that path (no pty needed). `msd --init` refuses inside an agent tree and asks on `/dev/tty` too. L11 replaces both with Touch ID |
| AUTH-4 | Kill switch and hard limits | Partial | L07: `ms stop` sets the stop flag in memory (the next request is refused), saves it in msd's keychain item (with the rules rollback floor) so killing msd doesn't undo it, and `msd --init` never clears it, and needs no approval; resuming needs an approval (pre-L11 terminal path). The socket keeps reserved slots for `Status`/`Stop`, a per-process cap and per-connection lifetime/request caps, so held connections can't starve the kill switch (S6). Tests: `daemon::tests::stop_is_immediate_and_survives_restart`, `agent_e2e` (stop run by an agent, next proxy request refused, proxy port closed with msd down), `ipc::held_connections_do_not_delay_stop`. Still to do: revoking minted credentials (L18–L20); per-session usage caps. Residual: an uninspected allowlisted tunnel opened before `ms stop` lives until it goes idle; enough same-user processes can also fill the reserved slots |
| INJ-1 | Inventory untrusted inputs | Partial | Trust-boundary table above; refine per command when built |
| INJ-2 | Break the lethal trifecta | Partial | Swap path (L05): the agent holds only `ms://` refs; the value is added by `ms-proxy` after the agent's request leaves it, only for bound hosts. Canary tests: `ms-proxy` itests `exfil_to_paste_site_blocked`, `foreign_ref_to_bound_host_blocked`, `fuzz_listener` (canary never in any response, receipt, block event or error). Met once L07 runs the proxy and L09 runs the end-to-end canary |
| INJ-3 | Contain injection in code | Gap | Approval UI and `ms log` must show agent-supplied strings as inert text (no control chars, no truncation hiding args) |
| INJ-4 | Deny-by-default egress | Partial | `ms-proxy` (L05): bound hosts get the key, allowlisted hosts are tunnelled, all else `403`; SSRF guard resolves first, refuses loopback/private/link-local/metadata/CGNAT/multicast/reserved and mapped/NAT64/6to4 forms, and connects only to the checked IP. Tests: `ssrf::tests::*`, itests `ssrf_targets_unreachable`, `exfil_to_paste_site_blocked`. Enforced end to end when L07 runs it and L08 points agents at it |
| INJ-5 | No secrets in prompts | Partial | Core promise: only `ms://` refs reach agents; test via transcript canary scan (PRD §12). L01: the vault never returns a value outside `with_secret`, and no value appears in `Debug`, errors or `list` (canary tests in `ms-vault`). Core promise: only `ms://` refs reach agents. L04: `ms import` leaves a `.env` holding only refs (canary absent from every file in the dir, `ms-import` `envfile::tests::import_leaves_only_refs`); its review table and errors never print a value beyond a public catalog prefix (`ms-cli` `import_add::dry_run_masks_and_changes_nothing`, `stub_daemon_fails_closed_and_is_terminal_safe`); `ms add` has no value flag and reads hidden input (`hidden_input` pty tests). L09: `ms scan` searches Claude Code and Codex transcripts for every vault value (raw, JSON-escaped, URL, hex, base64/base64url at any offset); matching runs inside msd over directories msd picks, output is file:line, key and encoding only, refused inside an agent session (`tests/e2e` `ms_scan_catches_a_leaky_transcript`, `msd` `scan::tests::report_has_location_not_value`, `daemon::tests::scan_refused_inside_agent`, `ms-scan` `every_encoding_is_found`, `base64_at_any_offset`); fake-agent canary suite in the gate (`canary_never_reaches_the_agent`). Residual (L09 security review S1, until L11): msd refuses `Scan` only to callers inside an agent tree, so a fully detached same-user process (an agent can start one) gets the report; with a file of guesses in a transcript directory that makes it a guessing oracle for low-entropy values of 8+ bytes (passwords, PINs), same class as the AUTH-3 terminal-path residual. Mitigations now: refused while stopped; every scan writes one receipt per key it read (`ms log` shows `ms scan: agent transcripts, N findings`; also withheld if a receipt fails or `ms stop` lands during the scan; stopped refusal in `daemon::tests::scan_refused_inside_agent`, receipts per key and per scan in e2e `ms_scan_catches_a_leaky_transcript`; the withhold paths (a receipt write fails, or `ms stop` lands mid-scan) have no test). L11 should put `Scan` behind the approver. Still open: one real-agent run (`tests/e2e/real-agent.sh`, manual/nightly, spends tokens; agents get an empty environment plus an allowlist) to confirm real Claude Code / Codex transcripts scan clean |
| OUT-1 | Validate model output before sinks | Gap | Run mode executes agent-supplied commands: argv only, never a shell string; per-key command allowlist |
| OUT-2 | Disclose AI; guard user-facing output | N/A | No model output shown to end users |
| OUT-3 | People in decisions about people | N/A | No decisions about people |
| OUT-4 | Sandbox agent-generated code | Gap | Run mode runs agent-requested commands outside the agent sandbox with a secret: limit to allowlisted binaries, scrubbed env, least-privilege creds |
| MCP-1 | Allowlist and pin servers and skills | Partial | ARI-42 skill vendored at a pinned commit; no written allowlist; gloop skills are user-global, unpinned |
| MCP-2 | Detect tool-description changes | Partial | Skills are vendored, so changes show in diffs; no check for `ms mcp` tool manifests yet |
| MCP-3 | Authenticate exposed MCP/agent APIs | Partial | L07: the broker socket is a 0600 Unix socket in a 0700 directory checked through an `O_NOFOLLOW` descriptor (S3), every peer is checked by uid and resolved to a session (`SessionPeerCheck`); the proxy listens on loopback only and refuses connections that don't map to an agent session. Tests: `ipc::{bind_refuses_symlinked_directory, bound_socket_is_private, rejected_peer}`, `agent_e2e`. Still to do: `ms mcp` (L14) |
| MCP-4 | Sandbox MCP servers | Gap | `ms mcp` and other local MCP servers launched via `ms run` with explicit minimal env |
| GW-1 | Protect provider keys | Partial | L01: values live in the login keychain, ACL-bound to the signed `msd` (another binary of the user is denied read, delete, replace and CA signing), pinned to the login keychain, sealed against overwrite, read with dialogs off (`ms-vault` `macos::tests::acl_*`, `planted_*`, `seal_*`; `docs/evidence/vault-macos.md`). Signing keys pinned by public-key hash; keychain path from the user database, not `$HOME`. Residual: a same-user process can make items unusable (DoS) or roll back or swap the keychain file, a user can click "Always Allow" on a dialog another binary raises, and production user presence is not enforced by the Keychain (L11 approval instead) until the data-protection keychain is available (needs a provisioning profile, D2). L09: canary keys end to end with a fake agent: after `ms import`, its process tree runs `env` (plain, after sourcing `.env`, nested), `cat .env`, `curl` (direct and via the proxy) and `psql`, and no canary in any encoding reaches its output, env, files, curl's target, psql, msd's log or the receipts (`tests/e2e` `canary_never_reaches_the_agent`, in the gate's security-evals step). Real `claude -p` / `codex exec` runs are manual/nightly (`tests/e2e/real-agent.sh`), not yet run. `ms-proxy` (L05) swaps the value in only at the configured location for bound hosts over verified TLS, strips agent credentials, never follows redirects; CA is name-constrained to bound hosts (Go `crypto/x509` accepts it: itest `go_client_accepts_chain`). Tests: itests `swap_over_http1/2`, `swap_with_http1_upstream`, `redirects_not_followed`, `tunnel_host_must_match`. Residual: hyper/rustls write buffers are not zeroized. Open for L11/L07: no rate limit on approval prompts a swap can trigger (L05 security review S4) Core product function (keys never reach agent commands); test with canary key per agent. L04: provider catalog binds each known key to its hosts and credential location; unknown keys get no hosts (unusable until `ms rules`, fails closed); an existing key is never overwritten by import or add; values held in `SecretBytes`/zeroizing buffers (`catalog::tests`, `plan::tests::naming_and_dedupe`). Still to come: Keychain storage (L01), per-agent canary tests (L09) |
| GW-2 | Agent stack as critical supply chain | Partial | `Cargo.lock` committed; `--locked` builds; `cargo deny` (advisories, licences, crates.io-only sources) and `cargo audit` in `scripts/check.sh` (L00). Signed releases and reproducible builds still to come (L10) |
| GW-3 | Pin models; evaluate before switching | N/A | No model in the product |
| LOG-1 | Log every agent run | Partial | L02: `ms-receipts` store writes one hash-chained, HMAC'd JSONL record per use with every PLAN §3.4 field; agent-supplied strings redacted before write (patterns + exact values, canary test); tamper table and byte-flip property test fail `verify` (`docs/evidence/receipts.md`). Wiring every daemon path to the store is L07. Residual: tail truncation or rollback of the files is not detected (anchor the head in the vault in L07; L23 closes it); `morsec/*` key names must be reserved by L03/L04 so the receipts key can never be requested; `hmac` pad state is not zeroized (accepted) |
| LOG-2 | Detect abnormal agent behaviour | Partial | L02: N blocked/denied attempts by one session within M minutes (default 5 in 10 min) write a MAC'd `alert` record and call the daemon's handler with `stop_session` when configured (test `alert_detector`). L07 wires it: msd stops the alerting session (its swaps and socket requests are refused) while others carry on (test `daemon::tests::log2_alert_stops_the_session`). Residual: the stop lasts until msd restarts |
| LOG-3 | Plan for AI incidents | Human | Needs an incident plan (leaked key, broker compromise) |
| LOG-4 | Customer access to agent records | Partial | L02: `ms log --export json|csv` with time/agent/key/result/pid filters, formula- and terminal-safe, `--out` creates 0600 and never overwrites. `ms log --verify` in the CLI checks the chain only: the HMAC key is daemon-only and IPC v1 has no verify message (L07). ARI-42 bundle is L27 |
| EVAL-1 | Gate releases on security evals | Partial | The local gate exists and gloop's build gate requires it (`scripts/check.sh` via `package.json`, L00). L09: its `security-evals` step runs the canary suite (`tests/e2e`: data leakage through env, files, network, psql, receipts and transcripts; a planted leak must be caught); the step and its place in the gate are themselves tested (`gate_requires_security_evals`); tool-misuse evals for rules and the kill switch run in `msd` `agent_e2e`. Still open: release gating proper (L10 release pipeline) and injection/tool-misuse evals for `ms mcp` (L14). morsec makes no model calls, so jailbreak evals of a model are N/A |
| EVAL-2 | Independent adversarial testing | Human | PRD v0.3 exit test: one external security review |
| EVAL-3 | Version prompts and config as code | N/A | No prompts; agent connector config is code-generated and versioned once built |
| SDLC-1 | Approve coding assistants | Human | Confirm Claude Code and Codex are the approved assistants |
| SDLC-2 | Sandbox coding agents | Partial | Agents run with per-session permission prompts; no sandbox enforced for this repo |
| SDLC-3 | Review AI-written code | Partial | gstack-loops: fresh-context and security review per loop, `REVIEW.md`, PR per feature; no branch protection yet |
| SDLC-4 | Protect agent configuration | Partial | `.github/CODEOWNERS` covers agent config; needs branch protection requiring code-owner review to enforce. L03: the agent (same Unix user) can't loosen morsec's own policy. `rules.toml` is MAC'd (any edit, foreign MAC or rollback fails closed), and the agent-writable `.morsec.toml` only tightens |
| SDLC-5 | Isolate CI agents | N/A | No CI workflows in the repo |
| SDLC-6 | Block hallucinated packages | Met | One manifest (Cargo workspace) with a committed `Cargo.lock`; `cargo deny check sources` allows crates.io only (no unknown registries or git), passing in `scripts/check.sh` (L00, `docs/evidence/foundation.md`). Age check for new crates is a reviewer step in `REVIEW.md` |

In scope: 27 (17 Gap, 9 Partial, 1 Met). Human: 5. N/A: 10.

## Exceptions

| ID | What is not met | Why accepted | Accepted by | Review by |
|---|---|---|---|---|

## Needs a human

- [ ] GOV-2 write and sign the AI risk assessment for morsec
- [ ] GOV-3 decide how customers are told about changes to agent handling
- [ ] LOG-3 incident plan: leaked secret, compromised broker, bad release
- [ ] EVAL-2 book the external security review (PRD v0.3 exit test)
- [ ] SDLC-1 confirm Claude Code and Codex as approved assistants
- [ ] SDLC-4 turn on branch protection for `main` requiring code-owner review
- [ ] INJ-5/AUTH-3 accept, or ask L11 to close, the pre-L11 `ms scan` oracle residual (a detached process can scan; receipts record each scan)

## Change log

| Date | Change | Requirements touched | Status after |
|---|---|---|---|
| 2026-11-13 | Installed ARI-42 1.0.1 (Claude Code, Codex, SessionStart hook); first scoping from the PRD; added CODEOWNERS | all (initial scoping) | 0 of 27 met; 8 Partial; 19 Gap |
| 2026-11-13 | L00 foundation: Rust workspace with lockfile, cargo-deny/cargo-audit local gate (no hosted CI, D7), deny-by-default policy stub, `SecretBytes` that can't be serialized or printed | GW-2, SDLC-6, EVAL-1 | 1 of 27 met; 9 Partial; 17 Gap |
| 2026-11-13 | L01 vault-macos: login-keychain vault bound to the signed `msd`, pinned, sealed; non-extractable CA and seal keys; reserved internal HMAC keys | GW-1, INJ-5 | 1 of 27 met; 10 Partial; 16 Gap |
| 2026-11-13 | L03 rules-policy: rules model, MAC'd rules store, tighten-only project merge, `decide`/`decide_run`, `ms rules` (read and preview only) | AUTH-2, AUTH-3, SDLC-4 | 1 of 27 met; 10 Partial; 16 Gap AUTH-2, AUTH-3 Gap → Partial; SDLC-4 Partial (strengthened) |
| 2026-11-13 | L02 receipts: hash-chained, HMAC'd receipt store with redaction before write, LOG-2 alert detector, `ms log` (filter, `--verify` chain check, `--export json|csv`), `ms stats` | LOG-1, LOG-2, LOG-4 | LOG-1, LOG-2, LOG-4 Gap → Partial |
| 2026-11-13 | L07 daemon: msd assembles vault, rules, receipts, swap proxy and socket; kill switch saved in the vault; S3/S6 socket hardening; rules changes and key storage over IPC; pre-L11 deny-stub approver with a terminal path | AUTH-1, AUTH-3, AUTH-4, MCP-3, LOG-2 | AUTH-4, MCP-3 Gap → Partial; AUTH-1, AUTH-3, LOG-2 Partial (strengthened) |
| 2026-11-13 | L04 import-env: `ms import` (masked review, atomic ref-only rewrite, fails closed, git-history warning), `ms add` (hidden input, no value flag), provider catalog | INJ-5, GW-1 | INJ-5 Partial, GW-1 Partial (score line to be recomputed when wave 1 merges) |
| 2026-11-14 | L09 e2e-canary: `ms scan` (matching inside msd, file:line/key/encoding only, refused inside agents), fake-agent canary suite as the gate's `security-evals` step, opt-in real-agent job | EVAL-1, GW-1, INJ-5 | EVAL-1 Gap → Partial; GW-1, INJ-5 Partial (strengthened) |
