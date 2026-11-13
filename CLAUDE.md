## gstack-loops (loop-engineering)

This workspace uses [gstack-loops](https://github.com/csakash/gstack-loops) on top of
[gstack](https://github.com/garrytan/gstack). Repos: morsec.

**Every feature is a loop. Never edit `main` or the root checkouts directly** — parallel
sessions share these repos; an isolated worktree per loop is what stops them clobbering each
other. Start each feature with `gloop new <slug>`, then work inside `worktrees/<slug>/`.

The loop: `/gloop-spec` (commit `SPEC.md`) → `/gloop-build` (build → fresh-context review
and security review → `/qa`, with proof) → `/gloop-ship` (raise the PR). There's a
`/gloop-*` shortcut for every step, or just `/gloop <what you want>` to drive it
conversationally. For headless runs use `gloop run <slug> --mode <interactive|bypass|autonomous>`.

- Use `/browse` for all web browsing/QA — never `mcp__claude-in-chrome__*`.
- Definition of Done: behavior matches `SPEC.md`; `PROOF.md` (Testing / Risk / How to revert)
  is the PR body; `npm run build` clean per repo; review and security review converged, every
  important finding fixed or closed with a reason; each repo's `REVIEW.md` followed; sensitive
  paths flagged for a human reviewer (`gloop risk`); no `.env` committed; cross-repo PRs
  cross-linked.
- Landing several PRs at once: see [docs/PARALLEL_SHIPPING.md](docs/PARALLEL_SHIPPING.md)
  (shared-DB isolation via `hooks.preLoop`, merge order, rebase-before-ship).
- After a loop's PR merges: `gloop reap` (records the merge, re-checks recent merges for
  reverts). `gloop stats` shows how loops are doing.

<!-- ari42:start -->
## ARI-42 agent security (required)

The `ari42` skill is the primary guideline for all development and agent work in this project.
Use it by default; do not wait to be asked.

Before any task that touches AI or agent code (LLM calls, prompts, tools or function calling, MCP
servers or clients, A2A, agent SDKs and frameworks, RAG, memory or vector stores, code execution
or sandboxes, model providers or gateways, skills or plugins, chat UIs that render model output,
agent config such as AGENTS.md, CLAUDE.md, .mcp.json or hooks, or AI steps in CI):

1. Load the `ari42` skill (`.claude/skills/ari42/SKILL.md`) and follow its workflow.
2. Read `ARI42.md` at the project root for the in-scope requirements. If it is missing, create it
   (skill step 1) before the first change.
3. Plan the change against the requirements it touches, build the controls in by default, and
   prove each one with a test.
4. Run `python3 .claude/skills/ari42/scripts/ari42_scan.py check .` and fix or justify every finding.
5. Update `ARI42.md` and tell the user the status of each requirement the change touched.

Never weaken an in-scope requirement silently. If a request would break one, explain the risk,
offer the secure alternative, and record any accepted exception in `ARI42.md`.
<!-- ari42:end -->
