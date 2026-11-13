# REVIEW.md

What gstack-loops' reviewer should care about in this repo. It reads this file on every review,
headless or in `/gloop-build`. Keep it short. When the same finding keeps coming back, add a line
here (or a lint rule) rather than paying for another review cycle.

## What failure looks like here
- A secret value must never reach an agent: not its environment, files, process arguments, stdout/stderr or logs. Only `ms://` references.
- Fail closed: if traffic or a command can't go through the broker, it errors loudly; it never falls back to sending the raw secret.
- A key goes only to its own hosts and commands; agent-supplied auth headers are stripped and redirects never carry credentials.
- Production-tier approvals are bound to the exact command and arguments shown in the prompt.
- `ms` and `mors` must behave identically (same binary, two names).

## Do not nitpick
- Formatting and naming the linter or formatter already enforces.
- Style preferences with no effect on behavior.

## Ignore
<!-- Paths the reviewer should skip. -->
- Generated files, lockfiles, vendored code, `worktrees/`.

## How to report
- Every finding names a file and a line. Never guess a filename.
- Start with a summary that gives the count, or says exactly "no issues".
