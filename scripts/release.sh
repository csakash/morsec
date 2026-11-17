#!/usr/bin/env bash
# The morsec release, run locally (no hosted CI in v1, decision D7 in docs/PLAN.md). L10.
#
#   scripts/release.sh build [--out DIR]     reproducible build of HEAD; signs only if asked
#   scripts/release.sh verify-repro          two clean builds at different paths, same hashes
#   scripts/release.sh release [--out DIR]   the real release; fails closed without credentials
#   scripts/release.sh formula --version V --sha256 H [--url U] [--out FILE]
#   scripts/release.sh check-build-root DIR  checks DIR is safe to build under (see new_work)
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
# Packaging inputs for the build being made (scripts, sign-targets, entitlements, template).
# build_release points it at the clone, so a dirty working tree never changes a build.
bpk="$pk"
TARGET="aarch64-apple-darwin"
DEPLOYMENT_TARGET="13.0"
URL_BASE="https://github.com/csakash/morsec/releases/download"

die() { printf 'release.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '== %s\n' "$*"; }
py() { python3 -I "$@"; }

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
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
  need npm "Install Node.js (it brings npm); the npm packages are staged with npm pack."
}

# Version of the ms-cli package in the workspace at $1.
workspace_version() { workspace_field "$1" version; }

# workspace_field <workspace> <field>: a field of the ms-cli package (version, license).
workspace_field() {
  cargo metadata --format-version 1 --no-deps --locked --manifest-path "$1/Cargo.toml" |
    py -c 'import json,sys; m=json.load(sys.stdin); print(next(p[sys.argv[1]] for p in m["packages"] if p["name"]=="ms-cli"))' "$2"
}

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# shipped_bins <packaging dir>: the bin/ tools a release ships, one per line, in the order of
# <packaging dir>/macos/sign-targets. That file is the one list: everything shipped is signed.
shipped_bins() {
  local name ident rest n=0
  while read -r name ident rest; do
    case "$name" in '' | '#'*) continue ;; esac
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ && -n "$ident" && -z "$rest" ]] ||
      die "malformed line in $1/macos/sign-targets: $name $ident $rest"
    printf '%s\n' "$name"
    n=$((n + 1))
  done <"$1/macos/sign-targets"
  [ "$n" -gt 0 ] || die "$1/macos/sign-targets lists no binaries"
}

dev_id_re='^Developer ID Application: .+ \(([A-Z0-9]{10})\)$'

# The Developer ID team every release is signed by. The keychain trusts msd by identifier plus
# team (L01), so a release from another team would lock users out of their keys.
pinned_team() {
  local t
  [ -f "$pk/macos/team-id" ] || return 1
  t="$(tr -d '[:space:]' <"$pk/macos/team-id")"
  [[ "$t" =~ ^[A-Z0-9]{10}$ ]] || return 1
  printf '%s\n' "$t"
}

# Everything `release` needs, checked before anything is built. Fails closed: no skip flags.
release_preflight() {
  local id="${MORSEC_SIGN_IDENTITY:-}"
  [ -n "$id" ] || die "release needs MORSEC_SIGN_IDENTITY set to your \"Developer ID Application: Name (TEAMID)\" identity"
  [[ "$id" =~ $dev_id_re ]] || die "release signs with a Developer ID Application identity only (got \"$id\"); ad-hoc and development identities are for build"
  [ -n "${MORSEC_NOTARY_PROFILE:-}" ] || die "release needs MORSEC_NOTARY_PROFILE (a profile from: xcrun notarytool store-credentials)"
  [[ "$MORSEC_NOTARY_PROFILE" =~ ^[A-Za-z0-9._-]+$ ]] || die "MORSEC_NOTARY_PROFILE must be a profile name"
  [ -n "${MORSEC_MINISIGN_KEY:-}" ] || die "release needs MORSEC_MINISIGN_KEY (path to the minisign secret key)"
  [ -f "$MORSEC_MINISIGN_KEY" ] || die "MORSEC_MINISIGN_KEY is not a file: $MORSEC_MINISIGN_KEY"
  local v
  v="$(workspace_version "$root")"
  [ "$v" != "0.0.0" ] || die "the workspace version is 0.0.0; bump it in Cargo.toml and tag v<version> first"
  [ -f "$pk/minisign.pub" ] || die "packaging/minisign.pub is missing; commit the release public key first"
  local pinned
  pinned="$(pinned_team)" || die "packaging/macos/team-id is missing or malformed; commit your 10-character Developer ID team ID first"
  [[ "$id" =~ $dev_id_re ]]
  [ "${BASH_REMATCH[1]}" = "$pinned" ] || die "MORSEC_SIGN_IDENTITY is team ${BASH_REMATCH[1]}, but releases are pinned to team $pinned (packaging/macos/team-id); the keychain trusts msd only from that team"
  [ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree is not clean"
  git -C "$root" tag --points-at HEAD | grep -qx "v$v" || die "HEAD is not tagged v$v"
  need minisign "brew install minisign"
  need xcrun "Install Xcode."
  need spctl "It ships with macOS."
}

# sign <file> <identifier> <identity>
sign() {
  local f="$1" ident="$2" id="$3" ts="--timestamp"
  [ "$id" = "-" ] && ts="--timestamp=none"
  codesign --force --options runtime "$ts" --identifier "$ident" \
    --entitlements "$bpk/macos/entitlements.plist" --sign "$id" "$f"
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
    local pinned
    if pinned="$(pinned_team)"; then
      [ "$team" = "$pinned" ] || die "$f: team $team is not the pinned release team $pinned"
    fi
    grep -q '^Timestamp=' <<<"$info" || die "$f: no secure timestamp"
  fi
  # No entitlements at all: hardened runtime with no exceptions. Fails closed if codesign fails.
  local ents
  ents="$(codesign -d --entitlements - --xml "$f" 2>/dev/null)" || die "$f: cannot read its entitlements"
  case "$ents" in *'<key>'*) die "$f: has entitlements; morsec ships with none" ;; esac
}

notarize() { # notarize <dir with bin/> <work> <out dir>: the notarytool record stays in <out dir>
  local zip="$2/notarize.zip" out="$3/notary.json"
  ditto -c -k --keepParent "$1/bin" "$zip"
  say "notarizing (this waits for Apple)"
  xcrun notarytool submit "$zip" --keychain-profile "$MORSEC_NOTARY_PROFILE" --wait \
    --output-format json >"$out" || die "notarytool failed; see $out"
  local status
  status="$(py -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$out")"
  [ "$status" = "Accepted" ] || die "notarization status is \"$status\"; run: xcrun notarytool log <id> --keychain-profile $MORSEC_NOTARY_PROFILE (id in $out)"
  local f
  for f in "$1"/bin/*; do
    # `--type execute` is for app bundles and rejects a bare tool; `install` assesses its signature
    # and notarization ("source=Notarized Developer ID").
    local verdict
    verdict="$(spctl --assess --type install --verbose=4 "$f" 2>&1)" || die "$f: spctl rejects it: $verdict"
    grep -q 'source=Notarized Developer ID' <<<"$verdict" || die "$f: spctl does not report it as notarized: $verdict"
  done
}

# build_release <work dir> <out dir> <identity or empty> <mode: build|release>
build_release() {
  local work="$1" out="$2" id="$3" mode="$4"
  local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  case "$work$cargo_home" in *[[:space:]]*) die "the build and cargo paths must not contain spaces" ;; esac

  local commit
  # verify-repro pins one commit for both builds, so a commit made meanwhile can't split them.
  commit="${pinned_commit:-$(git -C "$root" rev-parse HEAD)}"
  if [ -n "$(git -C "$root" status --porcelain)" ]; then
    [ "$mode" = build ] || die "the working tree is not clean"
    printf 'release.sh: warning: uncommitted changes are NOT in this build (it builds %s)\n' "${commit:0:12}" >&2
  fi

  say "cloning ${commit:0:12} into $work/src"
  git clone -q --no-hardlinks --no-checkout "$root" "$work/src"
  git -C "$work/src" checkout -q --detach "$commit"
  local src="$work/src" epoch version
  bpk="$src/packaging"
  epoch="$(git -C "$src" log -1 --format=%ct)"
  version="$(workspace_version "$src")"

  say "building morsec $version for $TARGET (SOURCE_DATE_EPOCH=$epoch)"
  mkdir -p "$work/tmp"
  local sep=$'\x1f' devdir
  devdir="$(xcode-select -p)" || die "no Xcode developer directory selected (xcode-select -p)"
  # The build sees only this environment (env -i): no inherited RUSTFLAGS, wrappers, RUSTC,
  # linker, CC or CFLAGS overrides, and no RUSTUP_TOOLCHAIN (rust-toolchain.toml decides).
  local -a benv=(
    env -i "PATH=$PATH" "HOME=$HOME" "TMPDIR=$work/tmp" "CARGO_HOME=$cargo_home"
    "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}" "DEVELOPER_DIR=$devdir"
    "SOURCE_DATE_EPOCH=$epoch" CARGO_INCREMENTAL=0 ZERO_AR_DATE=1
    "MACOSX_DEPLOYMENT_TARGET=$DEPLOYMENT_TARGET" "CARGO_TARGET_DIR=$work/target"
    # No host path in the binaries: rustc paths, C paths (ring), and the linker's debug-map
    # object paths, which feed the Mach-O UUID even though `strip` removes them afterwards.
    # -oso_prefix covers objects in the build dir; -S drops the debug map entirely, which also
    # covers std's objects under RUSTUP_HOME.
    "CARGO_ENCODED_RUSTFLAGS=--remap-path-prefix=$src=/morsec${sep}--remap-path-prefix=$cargo_home=/cargo${sep}-Clink-arg=-Wl,-oso_prefix,$work/${sep}-Clink-arg=-Wl,-S"
    "CFLAGS=-ffile-prefix-map=$src=/morsec -ffile-prefix-map=$cargo_home=/cargo"
  )
  # ms-cli: ms; msd: msd; ms-run: ms-shim (run mode, L12).
  (cd "$src" && "${benv[@]}" cargo build --release --locked -p ms-cli -p msd -p ms-run --target "$TARGET")

  local rel="$work/target/$TARGET/release" stage="$work/stage" unsigned="$work/unsigned"
  mkdir -p "$stage/bin" "$stage/share/morsec" "$unsigned"
  local b bins_list
  local -a bins=()
  bins_list="$(shipped_bins "$bpk")" || exit 1
  while read -r b; do bins+=("$b"); done <<<"$bins_list"
  for b in "${bins[@]}"; do
    [ -f "$rel/$b" ] || die "sign-targets names $b, which the build did not produce"
    cp "$rel/$b" "$unsigned/$b"
    cp "$rel/$b" "$stage/bin/$b"
  done

  say "SBOM (CycloneDX 1.5) and auto-update check"
  (cd "$src" && "${benv[@]}" cargo metadata --format-version 1 --locked --filter-platform "$TARGET") |
    py "$bpk/lib/sbom.py" --lock "$src/Cargo.lock" --version "$version" --commit "$commit" \
      --epoch "$epoch" --root ms-cli --root msd --root ms-run --out "$stage/share/morsec/morsec.cdx.json"

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
      py "$bpk/lib/machocmp.py" --same "$stage/bin/$name" "$unsigned/$name" >/dev/null
    done <"$bpk/macos/sign-targets"
  fi

  local rustc_v cargo_v sdk_v clang_v
  rustc_v="$(cd "$src" && "${benv[@]}" rustc --version)"
  cargo_v="$(cd "$src" && "${benv[@]}" cargo --version)"
  sdk_v="$("${benv[@]}" xcrun --show-sdk-version)"
  clang_v="$("${benv[@]}" clang --version | head -1)"
  local -a hashes=()
  local u c
  for b in "${bins[@]}"; do
    u="$(sha256 "$unsigned/$b")"
    c="$(py "$bpk/lib/machocmp.py" "$unsigned/$b")"
    c="${c%% *}"
    [[ "$u" =~ ^[0-9a-f]{64}$ && "$c" =~ ^[0-9a-f]{64}$ ]] || die "could not hash $b"
    hashes+=("unsigned_sha256.$b=$u" "code_sha256.$b=$c")
  done
  {
    echo "morsec_version=$version"
    echo "commit=$commit"
    echo "target=$TARGET"
    echo "source_date_epoch=$epoch"
    echo "macosx_deployment_target=$DEPLOYMENT_TARGET"
    echo "rustc=$rustc_v"
    echo "cargo=$cargo_v"
    echo "sdk=macosx $sdk_v"
    echo "clang=$clang_v"
    printf '%s\n' "${hashes[@]}"
  } >"$stage/share/morsec/BUILDINFO"

  if [ "$mode" = release ]; then notarize "$stage" "$work" "$out"; fi

  local tarball="morsec-$version-$TARGET.tar.gz"
  mkdir -p "$out"
  local -a entries=()
  for b in "${bins[@]}"; do entries+=("$stage/bin/$b=bin/$b:0755"); done
  py "$bpk/lib/archive.py" --out "$out/$tarball" --prefix "morsec-$version" --epoch "$epoch" \
    "${entries[@]}" \
    "$stage/share/morsec/BUILDINFO=share/morsec/BUILDINFO:0644" \
    "$stage/share/morsec/morsec.cdx.json=share/morsec/morsec.cdx.json:0644"
  cp "$stage/share/morsec/BUILDINFO" "$out/BUILDINFO"
  cp "$stage/share/morsec/morsec.cdx.json" "$out/morsec-$version.cdx.json"

  # The curl installer, with the team and the minisign key embedded. It is listed in
  # SHA256SUMS, so the minisign signature covers it too.
  local -a pubarg=()
  if [ -f "$bpk/minisign.pub" ]; then
    pubarg=(--pubkey-file "$bpk/minisign.pub")
  else
    [ "$mode" = build ] || die "packaging/minisign.pub is missing"
    printf 'release.sh: warning: no packaging/minisign.pub, so install.sh has no key to check SHA256SUMS.minisig with\n' >&2
  fi
  py "$bpk/lib/installer.py" --template "$bpk/install.sh" --team-file "$bpk/macos/team-id" \
    ${pubarg[@]+"${pubarg[@]}"} --out "$out/install.sh" >/dev/null
  (cd "$out" && shasum -a 256 "$tarball" "morsec-$version.cdx.json" BUILDINFO install.sh >SHA256SUMS)

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
  cp "$bpk/homebrew/README.md" "$out/homebrew-tap/README.md"
  py "$bpk/lib/formula.py" --template "$bpk/homebrew/morsec.rb.in" --version "$version" \
    --sha256 "$sha" --url "$URL_BASE/v$version/$tarball" --out "$out/homebrew-tap/Formula/morsec.rb"
  if [ "$mode" = release ]; then
    mkdir -p "$pk/homebrew/Formula"
    cp "$out/homebrew-tap/Formula/morsec.rb" "$pk/homebrew/Formula/morsec.rb"
  fi

  stage_npm "$out" "$tarball" "$version" "$(workspace_field "$src" license)"

  say "done: $out"
  (cd "$out" && cat SHA256SUMS)
}

# stage_npm <out> <tarball> <version> <cargo license>: the npm packages, from the binaries in the
# release tarball (signed in a release), packed with npm pack and checked against the tarball.
# Publishing them is a human step (packaging/RELEASING.md).
stage_npm() {
  local out="$1" tarball="$2" version="$3" license="$4" n="$1/npm"
  say "npm packages (morsec, morsec-darwin-arm64)"
  mkdir -p "$n"
  py "$bpk/lib/npm.py" stage --tarball "$out/$tarball" --version "$version" --license "$license" \
    --templates "$bpk/npm" --sign-targets "$bpk/macos/sign-targets" --out "$n" >/dev/null
  # --ignore-scripts: nothing in either package may run, at pack time or install time.
  (cd "$n" && npm pack --ignore-scripts --silent --pack-destination . ./morsec-darwin-arm64 ./morsec >/dev/null)
  py "$bpk/lib/npm.py" verify --tarball "$out/$tarball" --version "$version" \
    --sign-targets "$bpk/macos/sign-targets" --dir "$n"
  (cd "$n" && shasum -a 256 "morsec-darwin-arm64-$version.tgz" "morsec-$version.tgz" >SHA256SUMS)
}

new_out() { # new_out <dir>: refuses to reuse a non-empty directory
  if [ -d "$1" ] && [ -n "$(ls -A "$1")" ]; then
    die "$1 already exists and is not empty; remove it or pass --out"
  fi
  mkdir -p "$1"
  (cd "$1" && pwd -P)
}

# check_build_root <dir>: cargo reads .cargo/config.toml from every parent of the build, so a
# build under a directory another user can write (/tmp) would run their linker or rustc wrapper
# and the result would then be signed. Every directory from <dir> up to / must be owned by root
# or by us, not writable by group or others, and hold no .cargo.
check_build_root() {
  local p me owner mode
  p="$(cd "$1" && pwd -P)" || die "no such directory: $1"
  me="$(id -un)"
  while :; do
    owner="$(stat -f '%Su' "$p")"
    mode="$(stat -f '%Lp' "$p")"
    [ "$owner" = root ] || [ "$owner" = "$me" ] || die "unsafe build location: $p is owned by $owner"
    (( (8#$mode & 8#022) == 0 )) || die "unsafe build location: $p is writable by group or others (mode $mode)"
    [ ! -e "$p/.cargo" ] || die "unsafe build location: $p/.cargo would configure the build"
    [ "$p" = / ] && break
    p="$(dirname "$p")"
  done
}

# A fresh build dir in the per-user temp dir (not $TMPDIR, which may be unset or point at /tmp),
# by its real path: the path remaps must match the paths cargo and the linker see.
new_work() {
  local base d
  base="$(getconf DARWIN_USER_TEMP_DIR)" || die "no per-user temp dir (getconf DARWIN_USER_TEMP_DIR)"
  check_build_root "$base"
  d="$(mktemp -d "$base/$1.XXXXXX")"
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

pinned_commit=""
cmd_verify_repro() {
  [ $# -eq 0 ] || usage
  check_host
  pinned_commit="$(git -C "$root" rev-parse HEAD)"
  work="$(new_work morsec-repro)"
  trap cleanup EXIT
  # Build 2 differs from build 1 in every host path a binary could pick up: the build dir (a
  # different length on purpose), CARGO_HOME (registry sources) and RUSTUP_HOME (std's objects).
  # The homes are APFS clones (cp -c), so they cost no space.
  local a="$work/a" b="$work/build-two-at-a-longer-path"
  mkdir -p "$a" "$b"
  local ch="${CARGO_HOME:-$HOME/.cargo}" rh="${RUSTUP_HOME:-$HOME/.rustup}" channel
  channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
  [ -d "$rh/toolchains/$channel-$TARGET" ] || die "toolchain $channel-$TARGET is not installed in $rh"
  mkdir -p "$b/other-homes/rustup/toolchains" "$b/other-homes/cargo-home"
  cp -c "$rh/settings.toml" "$b/other-homes/rustup/"
  cp -cR "$rh/toolchains/$channel-$TARGET" "$b/other-homes/rustup/toolchains/" ||
    die "cloning the toolchain failed (needs APFS)"
  cp -cR "$ch/registry" "$b/other-homes/cargo-home/" || die "cloning the cargo registry failed (needs APFS)"
  if [ -f "$ch/config.toml" ]; then cp -c "$ch/config.toml" "$b/other-homes/cargo-home/"; fi
  ( MORSEC_MINISIGN_KEY="" build_release "$a" "$a/out" "" build )
  ( export CARGO_HOME="$b/other-homes/cargo-home" RUSTUP_HOME="$b/other-homes/rustup"
    MORSEC_MINISIGN_KEY="" build_release "$b" "$b/out" "" build )
  say "build 1"; cat "$a/out/SHA256SUMS"; grep -E '^(unsigned|code)_sha256' "$a/out/BUILDINFO"
  say "build 2"; cat "$b/out/SHA256SUMS"; grep -E '^(unsigned|code)_sha256' "$b/out/BUILDINFO"
  local same=1 bin bins_list
  bins_list="$(shipped_bins "$a/src/packaging")" || exit 1
  cmp -s "$a/out/SHA256SUMS" "$b/out/SHA256SUMS" || same=0
  cmp -s "$a/out/BUILDINFO" "$b/out/BUILDINFO" || same=0
  while read -r bin; do cmp -s "$a/unsigned/$bin" "$b/unsigned/$bin" || same=0; done <<<"$bins_list"
  if [ "$same" = 1 ]; then
    say "reproducible: both builds are identical"
  else
    diff "$a/out/BUILDINFO" "$b/out/BUILDINFO" >&2 || true
    trap - EXIT # keep both builds for diffing (no credentials are in them)
    die "NOT reproducible: the two builds differ; both builds are kept in $work"
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
  check-build-root) [ $# -eq 1 ] || usage; check_build_root "$1"; echo "ok: $1" ;;
  formula) cmd_formula "$@" ;;
  -h | --help | help) usage ;;
  *) usage ;;
esac
