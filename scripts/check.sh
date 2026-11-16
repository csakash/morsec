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
need perl "your OS package manager (macOS ships it)"

step() { printf '\n== %s\n' "$*"; }

step "1/8 cargo fmt --check"
cargo fmt --all --check

step "2/8 cargo build (all bins; integration tests run the built ms and msd)"
cargo build --workspace --all-targets --locked

step "3/8 cargo clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "4/8 cargo test"
# The canary suite runs in its own step below, so a failure there is named as a security eval.
cargo test --workspace --locked --exclude ms-e2e

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

step "7c fuzz: fuzz_* property targets with more cases, 90 s ceiling (hardening loop)"
# proptest on stable (SPEC D1-D4, docs/threat-model.md): the dotenv parser, the proxy's request
# handling and IPC framing/decoding/server. Step 4 ran them at their small default counts; this
# runs them deeper. Pure parsers get many cases; the targets that drive a live proxy or socket
# per case get fewer. The whole step runs under one hard ceiling: past it, every process of the
# step is killed and the gate fails (macOS has no timeout(1)).
# A longer local session: MORSEC_FUZZ_CASES=100000 cargo test -p <crate> -- fuzz_<name>
with_ceiling() {
  perl -e '
    my $t = shift;
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) { setpgrp(0, 0); exec(@ARGV) or die "exec: $!"; }
    $SIG{ALRM} = sub { kill("KILL", -$pid); print STDERR "check.sh: fuzz step passed its ${t}s ceiling\n"; exit 1; };
    alarm($t);
    waitpid($pid, 0);
    my $s = $?;
    exit(($s & 127) ? 1 : ($s >> 8));
  ' "$@"
}
fuzz_step() {
  MORSEC_FUZZ_CASES="${MORSEC_FUZZ_CASES:-2500}" cargo test --locked -q \
    -p ms-fuzz -p ms-import -p ms-ipc -p ms-proxy -- \
    fuzz_dotenv fuzz_frame fuzz_decode fuzz_head fuzz_rewriter
  MORSEC_FUZZ_CASES="${MORSEC_FUZZ_LIVE_CASES:-200}" cargo test --locked -q \
    -p ms-ipc -p ms-proxy -- fuzz_listener fuzz_tunnel fuzz_server
}
fuzz_start=$SECONDS
export -f fuzz_step
with_ceiling 90 bash -c fuzz_step
echo "fuzz step: $((SECONDS - fuzz_start)) s"
python3 -I scripts/threat_model_check.py

step "8/8 ARI-42 scan"
python3 .claude/skills/ari42/scripts/ari42_scan.py check . --fail-on high

step "security-evals (EVAL-1): canary suite, a fake agent against a throwaway msd (L09)"
# tests/e2e: no canary may reach an agent's output, env, files or receipts, and ms scan must
# catch a planted leak. Memory vault only; never the login keychain. The real-agent job
# (tests/e2e/real-agent.sh) is manual or nightly and is not run here.
cargo test --locked -p ms-e2e
# msd's own fake-agent test (rules loosening refused, exfiltration blocked, kill switch). It also
# runs in step 4; it is repeated here so this step holds every security eval.
cargo test --locked -p msd --test agent_e2e

printf '\ncheck.sh: all checks passed\n'
