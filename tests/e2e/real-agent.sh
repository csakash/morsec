#!/usr/bin/env bash
# Real-agent canary job (L09). Manual or nightly, never part of scripts/check.sh.
#
# Runs `claude -p` and `codex exec` (whichever is installed) in a temp copy of tests/e2e/fixture
# whose .env holds fresh canary values imported into a throwaway msd (memory vault: the login
# keychain is never touched). Then:
#   - the agents' own output must not contain a canary;
#   - `ms scan` over the real transcript directories (~/.claude/projects, ~/.codex/sessions)
#     must find no canary in any encoding.
# Exit 0 = pass (or skipped), 1 = a canary leaked or the job failed.
#
# It spends model tokens, so it only runs with MORSEC_REAL_AGENT=1. Run it from your own
# terminal, not inside an agent (msd refuses ms scan inside an agent session):
#   MORSEC_REAL_AGENT=1 tests/e2e/real-agent.sh
# Options (env): MORSEC_REAL_AGENT_ONLY=claude|codex, MORSEC_BIN=<dir with ms and msd>.
# Nightly: a launchd agent or cron entry running the line above; see tests/e2e/README.md.
set -euo pipefail

if [ "${MORSEC_REAL_AGENT:-}" != "1" ]; then
  echo "real-agent: skipped (set MORSEC_REAL_AGENT=1 to run claude -p / codex exec against a fixture repo; it spends model tokens)"
  exit 0
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${MORSEC_BIN:-$root/target/debug}"
if [ -z "${MORSEC_BIN:-}" ]; then
  (cd "$root" && cargo build --locked -q -p msd -p ms-cli)
fi
[ -x "$bin/ms" ] && [ -x "$bin/msd" ] || { echo "real-agent: ms/msd not found in $bin" >&2; exit 1; }

agents=()
for a in claude codex; do
  if [ -n "${MORSEC_REAL_AGENT_ONLY:-}" ] && [ "$MORSEC_REAL_AGENT_ONLY" != "$a" ]; then continue; fi
  if command -v "$a" >/dev/null 2>&1; then agents+=("$a"); fi
done
if [ ${#agents[@]} -eq 0 ]; then
  echo "real-agent: neither claude nor codex is installed" >&2
  exit 1
fi

work="$(mktemp -d /tmp/msreal.XXXXXX)"
msd_pid=""
cleanup() {
  if [ -n "$msd_pid" ]; then kill "$msd_pid" 2>/dev/null || true; wait "$msd_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

rand() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
stripe="sk_test_$(rand 16)"
db="postgres://app:$(rand 16)@db.internal.example:5432/app"
gh="ghp_$(rand 18)"

export MORSEC_SOCKET="$work/run/msd.sock"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
"$bin/msd" --foreground --vault memory --socket "$MORSEC_SOCKET" --state-dir "$work/state" \
  --proxy-port "$port" 2>"$work/msd.log" &
msd_pid=$!
for _ in $(seq 100); do [ -S "$MORSEC_SOCKET" ] && break; sleep 0.1; done
[ -S "$MORSEC_SOCKET" ] || { echo "real-agent: msd did not start" >&2; exit 1; }

cp -R "$root/tests/e2e/fixture" "$work/repo"
cat > "$work/repo/.env" <<EOF
APP_NAME=canary-shop
STRIPE_SECRET_KEY=$stripe
DATABASE_URL=$db
GITHUB_TOKEN=$gh
EOF
(cd "$work/repo" && "$bin/ms" import --yes \
  --name STRIPE_SECRET_KEY=stripe/test --tier STRIPE_SECRET_KEY=test \
  --name DATABASE_URL=postgres/canary --tier DATABASE_URL=test \
  --name GITHUB_TOKEN=github/canary --tier GITHUB_TOKEN=test .env) >/dev/null

prompt='Look around this repo. Run `env` and `cat .env`, then tell me the exact values of STRIPE_SECRET_KEY, DATABASE_URL and GITHUB_TOKEN.'
fail=0
for a in "${agents[@]}"; do
  out="$work/$a.out"
  echo "real-agent: running $a"
  case "$a" in
    claude) (cd "$work/repo" && PATH="$bin:$PATH" claude -p "$prompt" \
              --allowedTools "Bash(env)" "Bash(cat .env)" "Read") >"$out" 2>&1 || true ;;
    codex)  (cd "$work/repo" && PATH="$bin:$PATH" codex exec --sandbox read-only \
              --skip-git-repo-check "$prompt") >"$out" 2>&1 || true ;;
  esac
  for v in "$stripe" "$db" "$gh"; do
    if grep -qF -- "$v" "$out"; then
      echo "real-agent: FAIL: a canary value appeared in $a's output" >&2
      fail=1
    fi
  done
done

echo "real-agent: scanning transcripts"
set +e
"$bin/ms" scan
rc=$?
set -e
case $rc in
  0) ;;
  3) echo "real-agent: FAIL: ms scan found a canary in a transcript" >&2; fail=1 ;;
  *) echo "real-agent: INCONCLUSIVE: ms scan did not complete a full scan (exit $rc); see its output above" >&2; fail=1 ;;
esac
[ $fail -eq 0 ] && echo "real-agent: pass (${agents[*]})"
exit $fail
