#!/usr/bin/env bash
# The morsec release, run locally (no hosted CI in v1, decision D7 in docs/PLAN.md). L10.
#
#   scripts/release.sh build [--out DIR]     reproducible build of HEAD; signs only if asked
#   scripts/release.sh verify-repro          two clean builds at different paths, same hashes
#   scripts/release.sh release [--out DIR]   the real release; fails closed without credentials
#   scripts/release.sh formula --version V --sha256 H [--url U] [--out FILE]
#
# It never uploads, tags, pushes or publishes anything, and never asks for, prints or stores a
# credential. Credentials come from the environment, by reference only:
#   MORSEC_SIGN_IDENTITY   codesign identity. Unset: no signing (build only). "-": ad-hoc, to
#                          test the signing path (build only). release needs
#                          "Developer ID Application: Name (TEAMID)".
#   MORSEC_NOTARY_PROFILE  keychain profile made with `xcrun notarytool store-credentials`.
#   MORSEC_MINISIGN_KEY    path to the minisign secret key; minisign asks for its password.
#   MORSEC_MINISIGN_PUB    build only: public key to verify against (release always uses
#                          packaging/minisign.pub).
# See packaging/RELEASING.md for the whole procedure and packaging/VERIFY.md for checking one.
set -euo pipefail
umask 022

root="$(cd "$(dirname "$0")/.." && pwd -P)"
pk="$root/packaging"
TARGET="aarch64-apple-darwin"
DEPLOYMENT_TARGET="13.0"
URL_BASE="https://github.com/csakash/morsec/releases/download"

die() { printf 'release.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '== %s\n' "$*"; }
py() { python3 -I "$@"; }

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not installed. $2"
}

check_host() {
  [ "$(uname -s)" = Darwin ] || die "releases are built on macOS"
  [ "$(uname -m)" = arm64 ] || die "releases are built on Apple silicon (target $TARGET)"
  need git "Install the Xcode command line tools."
  need cargo "https://rustup.rs"
  need python3 "Install Python 3.11 or later."
  need codesign "Install the Xcode command line tools."
  need shasum "It ships with macOS."
}

# Version of the ms-cli package in the workspace at $1.
workspace_version() {
  cargo metadata --format-version 1 --no-deps --locked --manifest-path "$1/Cargo.toml" |
    py -c 'import json,sys; m=json.load(sys.stdin); print(next(p["version"] for p in m["packages"] if p["name"]=="ms-cli"))'
}

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

dev_id_re='^Developer ID Application: .+ \(([A-Z0-9]{10})\)$'

# Everything `release` needs, checked before anything is built. Fails closed: no skip flags.
release_preflight() {
  local id="${MORSEC_SIGN_IDENTITY:-}"
  [ -n "$id" ] || die "release needs MORSEC_SIGN_IDENTITY set to your \"Developer ID Application: Name (TEAMID)\" identity"
  [[ "$id" =~ $dev_id_re ]] || die "release signs with a Developer ID Application identity only (got \"$id\"); ad-hoc and development identities are for build"
  [ -n "${MORSEC_NOTARY_PROFILE:-}" ] || die "release needs MORSEC_NOTARY_PROFILE (a profile from: xcrun notarytool store-credentials)"
  [[ "$MORSEC_NOTARY_PROFILE" =~ ^[A-Za-z0-9._-]+$ ]] || die "MORSEC_NOTARY_PROFILE must be a profile name"
  [ -n "${MORSEC_MINISIGN_KEY:-}" ] || die "release needs MORSEC_MINISIGN_KEY (path to the minisign secret key)"
  [ -f "$MORSEC_MINISIGN_KEY" ] || die "MORSEC_MINISIGN_KEY is not a file: $MORSEC_MINISIGN_KEY"
  need minisign "brew install minisign"
  need xcrun "Install Xcode."
  need spctl "It ships with macOS."
  local v
  v="$(workspace_version "$root")"
  [ "$v" != "0.0.0" ] || die "the workspace version is 0.0.0; bump it in Cargo.toml and tag v<version> first"
  [ -f "$pk/minisign.pub" ] || die "packaging/minisign.pub is missing; commit the release public key first"
  [ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree is not clean"
  git -C "$root" tag --points-at HEAD | grep -qx "v$v" || die "HEAD is not tagged v$v"
}

# sign <file> <identifier> <identity>
sign() {
  local f="$1" ident="$2" id="$3" ts="--timestamp"
  [ "$id" = "-" ] && ts="--timestamp=none"
  codesign --force --options runtime "$ts" --identifier "$ident" \
    --entitlements "$pk/macos/entitlements.plist" --sign "$id" "$f"
  codesign --verify --strict --verbose=2 "$f"
  local info
  info="$(codesign -d --verbose=2 "$f" 2>&1)"
  grep -qx "Identifier=$ident" <<<"$info" || die "$f: signed identifier is not $ident"
  grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' <<<"$info" || die "$f: no hardened runtime"
  if [ "$id" != "-" ]; then
    [[ "$id" =~ $dev_id_re ]] || die "unexpected identity $id"
    local team="${BASH_REMATCH[1]}"
    grep -qx "Authority=Developer ID Application: .*" <<<"$info" || die "$f: not signed by a Developer ID Application certificate"
    grep -qx "TeamIdentifier=$team" <<<"$info" || die "$f: team is not $team"
    grep -q '^Timestamp=' <<<"$info" || die "$f: no secure timestamp"
  fi
  # No entitlements at all: hardened runtime with no exceptions.
  if codesign -d --entitlements - --xml "$f" 2>/dev/null | grep -q '<key>'; then
    die "$f: has entitlements; morsec ships with none"
  fi
}

notarize() { # notarize <dir with bin/> <work>
  local zip="$2/notarize.zip" out="$2/notary.json"
  ditto -c -k --keepParent "$1/bin" "$zip"
  say "notarizing (this waits for Apple)"
  xcrun notarytool submit "$zip" --keychain-profile "$MORSEC_NOTARY_PROFILE" --wait \
    --output-format json >"$out" || die "notarytool failed; see $out"
  local status
  status="$(py -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$out")"
  [ "$status" = "Accepted" ] || die "notarization status is \"$status\"; run: xcrun notarytool log <id> --keychain-profile $MORSEC_NOTARY_PROFILE (id in $out)"
  local f
  for f in "$1"/bin/*; do
    spctl --assess --type execute --verbose=4 "$f" || die "$f: spctl rejects it"
  done
}

# build_release <work dir> <out dir> <identity or empty> <mode: build|release>
build_release() {
  local work="$1" out="$2" id="$3" mode="$4"
  local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  case "$work$cargo_home" in *[[:space:]]*) die "the build and cargo paths must not contain spaces" ;; esac

  local commit
  commit="$(git -C "$root" rev-parse HEAD)"
  if [ -n "$(git -C "$root" status --porcelain)" ]; then
    [ "$mode" = build ] || die "the working tree is not clean"
    printf 'release.sh: warning: uncommitted changes are NOT in this build (it builds %s)\n' "${commit:0:12}" >&2
  fi

  say "cloning ${commit:0:12} into $work/src"
  git clone -q --no-hardlinks --no-checkout "$root" "$work/src"
  git -C "$work/src" checkout -q --detach "$commit"
  local src="$work/src" epoch version
  epoch="$(git -C "$src" log -1 --format=%ct)"
  version="$(workspace_version "$src")"

  say "building morsec $version for $TARGET (SOURCE_DATE_EPOCH=$epoch)"
  local sep=$'\x1f'
  (
    cd "$src"
    unset RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER
    export SOURCE_DATE_EPOCH="$epoch" CARGO_INCREMENTAL=0 ZERO_AR_DATE=1
    export MACOSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET" CARGO_TARGET_DIR="$work/target"
    # No host path in the binaries: rustc paths, C paths (ring), and the linker's object paths
    # (which feed the Mach-O UUID).
    export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$src=/morsec${sep}--remap-path-prefix=$cargo_home=/cargo${sep}-Clink-arg=-Wl,-oso_prefix,$work/"
    export CFLAGS="-ffile-prefix-map=$src=/morsec -ffile-prefix-map=$cargo_home=/cargo"
    cargo build --release --locked -p ms-cli -p msd --target "$TARGET"
  )

  local rel="$work/target/$TARGET/release" stage="$work/stage" unsigned="$work/unsigned"
  mkdir -p "$stage/bin" "$stage/share/morsec" "$unsigned"
  local b
  for b in ms msd; do
    cp "$rel/$b" "$unsigned/$b"
    cp "$rel/$b" "$stage/bin/$b"
  done

  say "SBOM (CycloneDX 1.5) and auto-update check"
  (cd "$src" && cargo metadata --format-version 1 --locked --filter-platform "$TARGET") |
    py "$pk/lib/sbom.py" --lock "$src/Cargo.lock" --version "$version" --commit "$commit" \
      --epoch "$epoch" --root ms-cli --root msd --out "$stage/share/morsec/morsec.cdx.json"

  local signing=none
  if [ -n "$id" ]; then
    signing=adhoc
    [ "$id" = "-" ] || signing=developer-id
    say "signing ($signing, hardened runtime)"
    local name ident
    while read -r name ident; do
      case "$name" in '' | '#'*) continue ;; esac
      [ -f "$stage/bin/$name" ] || die "sign-targets names $name, which the build did not produce"
      sign "$stage/bin/$name" "$ident" "$id"
      # Signing may change only the signature, never the code.
      py "$pk/lib/machocmp.py" --same "$stage/bin/$name" "$unsigned/$name" >/dev/null
    done <"$pk/macos/sign-targets"
  fi

  {
    echo "morsec_version=$version"
    echo "commit=$commit"
    echo "target=$TARGET"
    echo "source_date_epoch=$epoch"
    echo "macosx_deployment_target=$DEPLOYMENT_TARGET"
    echo "rustc=$(cd "$src" && rustc --version)"
    echo "cargo=$(cd "$src" && cargo --version)"
    echo "sdk=macosx $(xcrun --show-sdk-version 2>/dev/null || echo unknown)"
    echo "clang=$(clang --version 2>/dev/null | head -1)"
    for b in ms msd; do
      echo "unsigned_sha256.$b=$(sha256 "$unsigned/$b")"
      echo "code_sha256.$b=$(py "$pk/lib/machocmp.py" "$unsigned/$b" | cut -d' ' -f1)"
    done
  } >"$stage/share/morsec/BUILDINFO"

  if [ "$mode" = release ]; then notarize "$stage" "$work"; fi

  local tarball="morsec-$version-$TARGET.tar.gz"
  mkdir -p "$out"
  py "$pk/lib/archive.py" --out "$out/$tarball" --prefix "morsec-$version" --epoch "$epoch" \
    "$stage/bin/ms=bin/ms:0755" "$stage/bin/msd=bin/msd:0755" \
    "$stage/share/morsec/BUILDINFO=share/morsec/BUILDINFO:0644" \
    "$stage/share/morsec/morsec.cdx.json=share/morsec/morsec.cdx.json:0644"
  cp "$stage/share/morsec/BUILDINFO" "$out/BUILDINFO"
  cp "$stage/share/morsec/morsec.cdx.json" "$out/morsec-$version.cdx.json"
  (cd "$out" && shasum -a 256 "$tarball" "morsec-$version.cdx.json" BUILDINFO >SHA256SUMS)

  local key="${MORSEC_MINISIGN_KEY:-}" pub="${MORSEC_MINISIGN_PUB:-$pk/minisign.pub}"
  if [ "$mode" = release ]; then pub="$pk/minisign.pub"; fi
  if [ -n "$key" ]; then
    need minisign "brew install minisign"
    say "signing SHA256SUMS with minisign"
    minisign -S -s "$key" -m "$out/SHA256SUMS" -x "$out/SHA256SUMS.minisig" \
      -t "morsec $version $commit $TARGET"
    if [ -f "$pub" ]; then
      minisign -V -q -p "$pub" -m "$out/SHA256SUMS" -x "$out/SHA256SUMS.minisig" ||
        die "SHA256SUMS.minisig does not verify against $pub"
    else
      [ "$mode" = build ] || die "no public key to verify the checksums against"
      printf 'release.sh: warning: no public key at %s, so the signature was not verified\n' "$pub" >&2
    fi
  fi

  local sha
  sha="$(sha256 "$out/$tarball")"
  mkdir -p "$out/homebrew-tap/Formula"
  cp "$pk/homebrew/README.md" "$out/homebrew-tap/README.md"
  py "$pk/lib/formula.py" --template "$pk/homebrew/morsec.rb.in" --version "$version" \
    --sha256 "$sha" --url "$URL_BASE/v$version/$tarball" --out "$out/homebrew-tap/Formula/morsec.rb"
  if [ "$mode" = release ]; then
    cp "$out/homebrew-tap/Formula/morsec.rb" "$pk/homebrew/Formula/morsec.rb"
  fi

  say "done: $out"
  (cd "$out" && cat SHA256SUMS)
}

new_out() { # new_out <dir>: refuses to reuse a non-empty directory
  if [ -d "$1" ] && [ -n "$(ls -A "$1")" ]; then
    die "$1 already exists and is not empty; remove it or pass --out"
  fi
  mkdir -p "$1"
  (cd "$1" && pwd -P)
}

# A fresh temp dir by its real path: the path remaps must match the paths cargo and the linker
# see, and $TMPDIR may end in "/" and sits behind the /var -> /private/var symlink.
new_work() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/$1.XXXXXX")"
  (cd "$d" && pwd -P)
}

work=""
cleanup() {
  if [ -n "$work" ]; then rm -rf "$work"; fi
}

cmd_build() { # cmd_build <mode> [--out DIR]
  local mode="$1" out=""
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  check_host
  local id="${MORSEC_SIGN_IDENTITY:-}"
  if [ "$mode" = release ]; then release_preflight; fi
  [ -n "$out" ] || out="$root/dist/$(workspace_version "$root")"
  out="$(new_out "$out")"
  work="$(new_work morsec-release)"
  trap cleanup EXIT
  build_release "$work" "$out" "$id" "$mode"
}

cmd_verify_repro() {
  [ $# -eq 0 ] || usage
  check_host
  work="$(new_work morsec-repro)"
  trap cleanup EXIT
  # Different path lengths on purpose, so a leaked path would show.
  local a="$work/a" b="$work/build-two-at-a-longer-path"
  mkdir -p "$a" "$b"
  ( MORSEC_MINISIGN_KEY="" build_release "$a" "$a/out" "" build )
  ( MORSEC_MINISIGN_KEY="" build_release "$b" "$b/out" "" build )
  say "build 1"; cat "$a/out/SHA256SUMS"; grep -E '^(unsigned|code)_sha256' "$a/out/BUILDINFO"
  say "build 2"; cat "$b/out/SHA256SUMS"; grep -E '^(unsigned|code)_sha256' "$b/out/BUILDINFO"
  if cmp -s "$a/out/SHA256SUMS" "$b/out/SHA256SUMS" && cmp -s "$a/out/BUILDINFO" "$b/out/BUILDINFO" &&
    cmp -s "$a/unsigned/ms" "$b/unsigned/ms" && cmp -s "$a/unsigned/msd" "$b/unsigned/msd"; then
    say "reproducible: both builds are identical"
  else
    diff "$a/out/BUILDINFO" "$b/out/BUILDINFO" >&2 || true
    die "NOT reproducible: the two builds differ"
  fi
}

cmd_formula() {
  local version="" sha="" url="" out="$pk/homebrew/Formula/morsec.rb"
  while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
      --version) version="$2" ;;
      --sha256) sha="$2" ;;
      --url) url="$2" ;;
      --out) out="$2" ;;
      *) usage ;;
    esac
    shift 2
  done
  [ -n "$version" ] && [ -n "$sha" ] || usage
  [ -n "$url" ] || url="$URL_BASE/v$version/morsec-$version-$TARGET.tar.gz"
  py "$pk/lib/formula.py" --template "$pk/homebrew/morsec.rb.in" --version "$version" \
    --sha256 "$sha" --url "$url" --out "$out"
  echo "$out"
}

[ $# -ge 1 ] || usage
sub="$1"
shift
case "$sub" in
  build) cmd_build build "$@" ;;
  release) cmd_build release "$@" ;;
  verify-repro) cmd_verify_repro "$@" ;;
  formula) cmd_formula "$@" ;;
  -h | --help | help) usage ;;
  *) usage ;;
esac
