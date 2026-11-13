# ARI-42 record: morsec

Security record for the AI and agent parts of this project, kept by the coding agent under the
ARI-42 skill and reviewed by people. Update it in the same change as the code.

- **Last reviewed:** 2026-11-13
- **Owner for AI security:** csakash (to confirm)
- **Score:** 1 of 27 in-scope requirements met with evidence · 0 Risk · 16 Gap · 10 Partial

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
| AUTH-1 | Per-agent identity | Gap | PRD: each session gets its own grant and minted creds; not built |
| AUTH-2 | Never exceed the user's permissions | Gap | Run/mint modes must narrow each key; read-only roles for staging DB; not built |
| AUTH-3 | Approval for consequential actions | Gap | Touch ID prompt rendered by broker from real argv, bound to it; test: changed arg voids approval |
| AUTH-4 | Kill switch and hard limits | Gap | `ms stop`, per-session caps; not built |
| INJ-1 | Inventory untrusted inputs | Partial | Trust-boundary table above; refine per command when built |
| INJ-2 | Break the lethal trifecta | Gap | Design breaks it (agent never holds values); needs a canary test |
| INJ-3 | Contain injection in code | Gap | Approval UI and `ms log` must show agent-supplied strings as inert text (no control chars, no truncation hiding args) |
| INJ-4 | Deny-by-default egress | Gap | Per-key host binding; block private, link-local and metadata ranges; not built |
| INJ-5 | No secrets in prompts | Gap | Core promise: only `ms://` refs reach agents; test via transcript canary scan (PRD §12). L01: the vault never returns a value outside `with_secret`, and no value appears in `Debug`, errors or `list` (canary tests in `ms-vault`). |
| OUT-1 | Validate model output before sinks | Gap | Run mode executes agent-supplied commands: argv only, never a shell string; per-key command allowlist |
| OUT-2 | Disclose AI; guard user-facing output | N/A | No model output shown to end users |
| OUT-3 | People in decisions about people | N/A | No decisions about people |
| OUT-4 | Sandbox agent-generated code | Gap | Run mode runs agent-requested commands outside the agent sandbox with a secret: limit to allowlisted binaries, scrubbed env, least-privilege creds |
| MCP-1 | Allowlist and pin servers and skills | Partial | ARI-42 skill vendored at a pinned commit; no written allowlist; gloop skills are user-global, unpinned |
| MCP-2 | Detect tool-description changes | Partial | Skills are vendored, so changes show in diffs; no check for `ms mcp` tool manifests yet |
| MCP-3 | Authenticate exposed MCP/agent APIs | Gap | `ms mcp`, proxy and broker socket: loopback/Unix socket only, per-session auth; not built |
| MCP-4 | Sandbox MCP servers | Gap | `ms mcp` and other local MCP servers launched via `ms run` with explicit minimal env |
| GW-1 | Protect provider keys | Partial | L01: values live in the login keychain, ACL-bound to the signed `msd` (another binary of the user is denied read, delete, replace and CA signing), pinned to the login keychain, sealed against overwrite, read with dialogs off (`ms-vault` `macos::tests::acl_*`, `planted_*`, `seal_*`; `docs/evidence/vault-macos.md`). Signing keys pinned by public-key hash; keychain path from the user database, not `$HOME`. Residual: a same-user process can make items unusable (DoS) or roll back or swap the keychain file, a user can click "Always Allow" on a dialog another binary raises, and production user presence is not enforced by the Keychain (L11 approval instead) until the data-protection keychain is available (needs a provisioning profile, D2). Still open: canary key per agent end to end (L09). |
| GW-2 | Agent stack as critical supply chain | Partial | `Cargo.lock` committed; `--locked` builds; `cargo deny` (advisories, licences, crates.io-only sources) and `cargo audit` in `scripts/check.sh` (L00). Signed releases and reproducible builds still to come (L10) |
| GW-3 | Pin models; evaluate before switching | N/A | No model in the product |
| LOG-1 | Log every agent run | Gap | Hash-chained receipts (PRD §6); not built |
| LOG-2 | Detect abnormal agent behaviour | Gap | Flag blocked-host attempts and denied approvals in receipts; not built |
| LOG-3 | Plan for AI incidents | Human | Needs an incident plan (leaked key, broker compromise) |
| LOG-4 | Customer access to agent records | Gap | `ms log --export` / `--ari42`; not built |
| EVAL-1 | Gate releases on security evals | Gap | The local gate exists and gloop's build gate requires it (`scripts/check.sh` via `package.json`, L00); the security evals themselves (canary leak tests) come in L09 |
| EVAL-2 | Independent adversarial testing | Human | PRD v0.3 exit test: one external security review |
| EVAL-3 | Version prompts and config as code | N/A | No prompts; agent connector config is code-generated and versioned once built |
| SDLC-1 | Approve coding assistants | Human | Confirm Claude Code and Codex are the approved assistants |
| SDLC-2 | Sandbox coding agents | Partial | Agents run with per-session permission prompts; no sandbox enforced for this repo |
| SDLC-3 | Review AI-written code | Partial | gstack-loops: fresh-context and security review per loop, `REVIEW.md`, PR per feature; no branch protection yet |
| SDLC-4 | Protect agent configuration | Partial | `.github/CODEOWNERS` covers agent config; needs branch protection requiring code-owner review to enforce |
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

## Change log

| Date | Change | Requirements touched | Status after |
|---|---|---|---|
| 2026-11-13 | Installed ARI-42 1.0.1 (Claude Code, Codex, SessionStart hook); first scoping from the PRD; added CODEOWNERS | all (initial scoping) | 0 of 27 met; 8 Partial; 19 Gap |
| 2026-11-13 | L00 foundation: Rust workspace with lockfile, cargo-deny/cargo-audit local gate (no hosted CI, D7), deny-by-default policy stub, `SecretBytes` that can't be serialized or printed | GW-2, SDLC-6, EVAL-1 | 1 of 27 met; 9 Partial; 17 Gap |
| 2026-11-13 | L01 vault-macos: login-keychain vault bound to the signed `msd`, pinned, sealed; non-extractable CA and seal keys; reserved internal HMAC keys | GW-1, INJ-5 | 1 of 27 met; 10 Partial; 16 Gap |
