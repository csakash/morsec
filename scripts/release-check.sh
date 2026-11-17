#!/usr/bin/env bash
# Pre-release checklist for morsec (L28). Run it on the release commit before tagging.
#
#   scripts/release-check.sh            every step, in order, stopping at the first failure
#   scripts/release-check.sh STEP...    only the named steps (version changelog build tests binaries)
#
#   1 version    workspace version is X.Y.Z, not 0.0.0, the same for every member, Cargo.lock
#                agrees (--locked), and a v<version> tag, if it exists, is on HEAD
#   2 changelog  CHANGELOG.md has a "## [<version>]" section with entries
#   3 build      cargo build --release --locked (ms, msd, ms-shim); ms --version matches
#   4 tests      packaging tests (Homebrew, npm and curl-installer installs), plus shellcheck
#   5 binaries   the formula installs exactly sign-targets, each built as an arm64 executable,
#                and the release binaries pass the formula's test block from a temp prefix
#
# It never signs, notarizes, tags, pushes, uploads or touches the tap repo, and reads no
# credential. Those are the human steps in packaging/RELEASING.md. It never skips a step: a
# missing tool is a failure.
set -euo pipefail
umask 022

root="$(cd "$(dirname "$0")/.." && pwd -P)"
pk="$root/packaging"
py() { python3 -I "$@"; }
die() { printf 'release-check: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed. $2"; }

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

need cargo "https://rustup.rs"
need python3 "Install Python 3.12 or later."
need shellcheck "brew install shellcheck"
need git "Install the Xcode command line tools."
need node "https://nodejs.org"
need npm "https://nodejs.org"

version=""
metadata() { (cd "$root" && cargo metadata --format-version 1 --no-deps --locked); }

check_version() {
  step "1/5 version"
  version="$(metadata | py "$pk/lib/releasecheck.py" version)" || exit 1
  # --no-deps never compares with Cargo.lock; a full resolve with --locked does.
  (cd "$root" && cargo metadata --format-version 1 --locked >/dev/null) ||
    die "Cargo.lock does not match Cargo.toml: run cargo build once and commit Cargo.lock"
  local tagged head
  if tagged="$(git -C "$root" rev-parse -q --verify "refs/tags/v$version^{commit}")"; then
    head="$(git -C "$root" rev-parse HEAD)"
    [ "$tagged" = "$head" ] || die "v$version is already tagged on ${tagged:0:12}, not HEAD: bump the version"
  fi
  echo "version $version"
}

# Steps after 1 need the version; when step 1 isn't asked for, read it without judging it.
need_version() {
  [ -n "$version" ] && return
  version="$(metadata | py -c 'import json,sys; m=json.load(sys.stdin); print(next(p["version"] for p in m["packages"] if p["name"]=="ms-cli"))')"
}

check_changelog() {
  step "2/5 changelog"
  need_version
  [ -f "$root/CHANGELOG.md" ] || die "CHANGELOG.md is missing"
  py "$pk/lib/releasecheck.py" changelog "$version" "$root/CHANGELOG.md" || exit 1
}

target_dir() {
  metadata | py -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
}

check_build() {
  step "3/5 cargo build --release --locked"
  need_version
  (cd "$root" && cargo build --release --locked -p ms-cli -p msd -p ms-run)
  local got
  got="$("$(target_dir)/release/ms" --version)"
  version_ok "$got" || die "the built ms --version says \"$got\", expected \"morsec $version\" (and the commit)"
  echo "$got"
}

# version_ok <ms --version output>: "morsec <version>", optionally followed by " (<commit>)".
version_ok() {
  case "$1" in "morsec $version" | "morsec $version ("*")") return 0 ;; *) return 1 ;; esac
}

check_tests() {
  step "4/5 packaging tests and shellcheck"
  # The install test drives msd with its Touch ID stand-in, which only debug builds have.
  (cd "$root" && cargo build --locked -p ms-cli -p msd -p ms-run)
  (cd "$root" && py -m unittest discover -s packaging/tests)
  shellcheck "$root/scripts/release.sh" "$root/scripts/release-check.sh"
  shellcheck -s sh "$root/packaging/install.sh"
  node --check "$root/packaging/npm/morsec/bin/morsec.js"
}

check_binaries() {
  step "5/5 formula binaries match the build"
  need_version
  local rel template
  rel="$(target_dir)/release"
  template="$pk/homebrew/morsec.rb.in"
  py "$pk/lib/releasecheck.py" binaries "$template" "$pk/macos/sign-targets" "$rel" || exit 1
  # Install the release binaries from a tarball through the formula's install lines into a
  # temp prefix, then run what the formula's test block runs.
  local base work bins b
  base="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)"
  [ -n "$base" ] || base="${TMPDIR:-/tmp}"
  work="$(mktemp -d "${base%/}/morsec-release-check.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: $work is fixed for this run
  trap "rm -rf '$work'" EXIT
  local -a entries=()
  bins="$(py -c 'import sys; sys.path.insert(0, sys.argv[1]); import formula; print("\n".join(n for n, _ in formula.sign_targets(open(sys.argv[2]).read())))' "$pk/lib" "$pk/macos/sign-targets")"
  while read -r b; do entries+=("$rel/$b=bin/$b:0755"); done <<<"$bins"
  printf 'release-check placeholder\n' >"$work/BUILDINFO"
  py "$pk/lib/archive.py" --out "$work/morsec.tar.gz" --prefix "morsec-$version" --epoch 0 \
    "${entries[@]}" "$work/BUILDINFO=share/morsec/BUILDINFO:0644" >/dev/null
  py "$pk/lib/install_sim.py" --tarball "$work/morsec.tar.gz" --template "$template" \
    --version "$version" --prefix "$work/prefix" >/dev/null
  local pb="$work/prefix/bin" out rc
  for b in ms mors; do
    out="$(env -i PATH=/usr/bin:/bin HOME="$work" "$pb/$b" --version)"
    version_ok "$out" || die "installed $b --version says \"$out\""
  done
  rc=0
  out="$(env -i PATH=/usr/bin:/bin HOME="$work" "$pb/ms-shim" 2>&1)" || rc=$?
  [ "$rc" = 64 ] || die "installed ms-shim exited $rc under its own name, expected 64"
  grep -q "ms run --link-shims" <<<"$out" || die "installed ms-shim did not say how to link it: $out"
  echo "installed from the formula: $(tr '\n' ' ' <<<"$bins")+ mors; test block passes"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(version changelog build tests binaries)
for s in "${steps[@]}"; do
  case "$s" in
    version | changelog | build | tests | binaries) ;;
    -h | --help | help) usage ;;
    *) usage ;;
  esac
done
for s in "${steps[@]}"; do "check_$s"; done
printf '\nrelease-check: %s passed. Next: the human steps in packaging/RELEASING.md.\n' "${steps[*]}"
