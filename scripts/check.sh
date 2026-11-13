#!/usr/bin/env bash
# The local check gate for morsec. There is no hosted CI in v1 (decision D7 in docs/PLAN.md);
# this script is the gate. gloop's build gate runs it through `npm run build` (package.json).
#
# Stops at the first failure. Never skips a step: a missing tool is a failure.
set -euo pipefail

cd "$(dirname "$0")/.."

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "check.sh: $1 is not installed, so the gate cannot run. Install it with: $2" >&2
    exit 1
  fi
}

# Check every tool before running anything, so a missing tool fails fast.
need cargo "https://rustup.rs"
need cargo-deny "cargo install --locked cargo-deny"
need cargo-audit "cargo install --locked cargo-audit"
need python3 "your OS package manager"
need shellcheck "brew install shellcheck"

step() { printf '\n== %s\n' "$*"; }

step "1/8 cargo fmt --check"
cargo fmt --all --check

step "2/8 cargo build (all bins; integration tests run the built ms and msd)"
cargo build --workspace --all-targets --locked

step "3/8 cargo clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "4/8 cargo test"
cargo test --workspace --locked

step "5/8 cargo deny"
cargo deny --locked check

step "6/8 cargo audit"
cargo audit --deny warnings

step "7/8 no patches or overrides; path packages are workspace members"
# cargo-deny's [sources] does not police path dependencies or patches; this does.
cargo metadata --format-version 1 --locked | python3 -I scripts/supply_chain_check.py

step "7b release tooling: packaging tests and shellcheck (L10)"
python3 -I -m unittest discover -s packaging/tests
shellcheck scripts/release.sh

step "8/8 ARI-42 scan"
python3 .claude/skills/ari42/scripts/ari42_scan.py check . --fail-on high

printf '\ncheck.sh: all checks passed\n'
