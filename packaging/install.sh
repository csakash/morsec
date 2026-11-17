#!/bin/sh
# Installs morsec (ms, mors, msd, ms-shim) for the current user on Apple silicon macOS.
#
#   curl -fsSL https://github.com/csakash/morsec/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/csakash/morsec/releases/latest/download/install.sh | sh -s -- --version 0.1.0
#
# Or download it, read it, then run it: sh install.sh [--version X.Y.Z]
#
# What it does, and refuses:
#   - Darwin on Apple silicon only; never as root, never with sudo.
#   - Downloads SHA256SUMS (and SHA256SUMS.minisig) from the GitHub release, the latest or the
#     one you name (--version, or MORSEC_VERSION), then the tarball SHA256SUMS names.
#   - Checks the minisign signature of SHA256SUMS with the key below when minisign is installed,
#     the tarball's sha256, and every binary's code signature: valid, Developer ID, the team
#     below, the expected identifier, and notarized (Gatekeeper's install assessment).
#   - Installs into ${MORSEC_INSTALL_DIR:-~/.local/bin}. It replaces only files it installed
#     itself (recorded in .morsec-install there) and refuses to touch anything else.
#   - Running it again is safe: same version, nothing changes; a newer one replaces its own files.
#
# This file is a template: scripts/release.sh fills in the values below from
# packaging/macos/team-id and packaging/minisign.pub. The template itself refuses to run.
set -eu
umask 022

MORSEC_TEAM_ID='@TEAM_ID@'
MORSEC_MINISIGN_PUBKEY='@MINISIGN_PUBKEY@'
MORSEC_RELEASES='@BASE_URL@'
MORSEC_CURL_PROTO='@CURL_PROTO@'
MORSEC_SIGNER='@SIGNER_REQUIREMENT@'

TARGET=aarch64-apple-darwin
# <name>:<code signing identifier>, as in packaging/macos/sign-targets (a test checks they agree).
BINS='ms:cc.morsec.ms msd:cc.morsec.msd ms-shim:cc.morsec.ms-shim'
MANIFEST_NAME=.morsec-install

die() {
  printf 'morsec install: %s\n' "$*" >&2
  exit 1
}
say() { printf '%s\n' "$*"; }

case "$MORSEC_TEAM_ID$MORSEC_RELEASES$MORSEC_CURL_PROTO$MORSEC_SIGNER" in
  *@*) die "this is the unrendered template (packaging/install.sh); use the install.sh from a GitHub release" ;;
esac

usage() {
  say "usage: install.sh [--version X.Y.Z]"
  say "  MORSEC_VERSION      the version to install (default: the latest release)"
  say "  MORSEC_INSTALL_DIR  where to install (default: ~/.local/bin)"
  exit 2
}

version="${MORSEC_VERSION:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || usage
      version="$2"
      shift 2
      ;;
    --version=*)
      version="${1#--version=}"
      shift
      ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done
version="${version#v}"
if [ -n "$version" ]; then
  printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$' ||
    die "\"$version\" is not a version like 0.1.0"
fi

# --- where we are ---------------------------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
[ "$os" = Darwin ] || die "morsec runs on Apple silicon macOS only (this is $os $arch)"
if [ "$arch" != arm64 ]; then
  # A shell running under Rosetta reports x86_64 on an Apple silicon Mac: the binaries still
  # run natively there.
  translated="$(sysctl -in sysctl.proc_translated 2>/dev/null || true)"
  [ "$arch" = x86_64 ] && [ "$translated" = 1 ] ||
    die "morsec runs on Apple silicon Macs only (this Mac is $arch)"
fi
macos="$(sw_vers -productVersion 2>/dev/null || echo 0)"
[ "${macos%%.*}" -ge 13 ] 2>/dev/null || die "morsec needs macOS 13 or later (this is $macos)"
[ "$(id -u)" != 0 ] || die "don't run this as root or with sudo: morsec installs for your own user"
[ -z "${SUDO_USER:-}" ] || die "don't run this with sudo: morsec installs for your own user"

for t in curl shasum tar codesign spctl mktemp stat; do
  command -v "$t" >/dev/null 2>&1 || die "$t is not installed (it ships with macOS)"
done

if [ -n "${MORSEC_INSTALL_DIR:-}" ]; then
  dir="$MORSEC_INSTALL_DIR"
else
  [ -n "${HOME:-}" ] || die "HOME is not set; set MORSEC_INSTALL_DIR"
  dir="$HOME/.local/bin"
fi
case "$dir" in
  /*) ;;
  *) die "MORSEC_INSTALL_DIR must be an absolute path (got $dir)" ;;
esac

tmp="$(mktemp -d "${TMPDIR:-/tmp}/morsec-install.XXXXXX")"
# Temp files written next to the targets, removed if the install is interrupted.
partial=""
cleanup() {
  rm -rf "$tmp"
  set -f # the names are split on spaces only, never globbed
  for p in $partial; do rm -f "$p"; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

fetch() { # fetch <url> <file>
  curl --proto "$MORSEC_CURL_PROTO" --proto-redir "$MORSEC_CURL_PROTO" --tlsv1.2 -fsSL \
    --retry 2 -o "$2" "$1" || die "download failed: $1"
}
sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# --- what to install ------------------------------------------------------------------------
if [ -n "$version" ]; then
  from="$MORSEC_RELEASES/download/v$version"
else
  from="$MORSEC_RELEASES/latest/download"
fi
say "morsec: reading the release checksums from $from"
fetch "$from/SHA256SUMS" "$tmp/SHA256SUMS"

line="$(grep -E "^[0-9a-f]{64}  morsec-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?-$TARGET\.tar\.gz\$" "$tmp/SHA256SUMS" || true)"
[ -n "$line" ] && [ "$(printf '%s\n' "$line" | wc -l | tr -d ' ')" = 1 ] ||
  die "SHA256SUMS does not name exactly one morsec tarball for $TARGET"
sum="${line%%  *}"
tarball="${line#*  }"
ver="${tarball#morsec-}"
ver="${ver%-"$TARGET".tar.gz}"
[ -z "$version" ] || [ "$ver" = "$version" ] || die "asked for $version, but the release's SHA256SUMS is for $ver"

if command -v minisign >/dev/null 2>&1; then
  if [ -z "$MORSEC_MINISIGN_PUBKEY" ]; then
    say "morsec: warning: this installer has no minisign key (not a release build); not checking SHA256SUMS.minisig"
  else
    fetch "$from/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig"
    out="$(minisign -V -P "$MORSEC_MINISIGN_PUBKEY" -m "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" 2>&1)" ||
      die "SHA256SUMS does not match its minisign signature: $out"
    # The trusted comment is signed too: "morsec <version> <commit> <target>".
    printf '%s\n' "$out" | grep -Eq "^Trusted comment: morsec $ver [0-9a-f]{40} $TARGET\$" ||
      die "the signed comment does not name morsec $ver for $TARGET: $out"
    say "morsec: SHA256SUMS signature ok (minisign)"
  fi
else
  say "morsec: minisign is not installed, so the checksums' signature is not checked (brew install minisign to check it too); the code signature and notarization still are"
fi

say "morsec: downloading morsec $ver"
fetch "$MORSEC_RELEASES/download/v$ver/$tarball" "$tmp/$tarball"
[ "$(sha256 "$tmp/$tarball")" = "$sum" ] || die "$tarball does not match its sha256 in SHA256SUMS"

tar -tzf "$tmp/$tarball" >"$tmp/list" || die "$tarball is not a readable tar.gz"
while IFS= read -r entry; do
  case "$entry" in
    "morsec-$ver/"* | "morsec-$ver") ;;
    *) die "$tarball has an entry outside morsec-$ver/: $entry" ;;
  esac
  case "/$entry/" in
    */../* | */./*) die "$tarball has an unsafe entry: $entry" ;;
  esac
done <"$tmp/list"
mkdir "$tmp/x"
tar -xzf "$tmp/$tarball" -C "$tmp/x" || die "could not unpack $tarball"
src="$tmp/x/morsec-$ver/bin"

for pair in $BINS; do
  b="${pair%%:*}"
  id="${pair#*:}"
  f="$src/$b"
  [ -f "$f" ] && [ ! -L "$f" ] || die "$tarball has no regular file bin/$b"
  codesign --verify --strict -R "=$MORSEC_SIGNER and identifier \"$id\"" "$f" 2>"$tmp/cs" ||
    die "bin/$b: the code signature is invalid or not morsec's ($(tr '\n' ' ' <"$tmp/cs"))"
  info="$(codesign -d --verbose=2 "$f" 2>&1)" || die "bin/$b: can't read its code signature"
  printf '%s\n' "$info" | grep -qx "Identifier=$id" || die "bin/$b: signed as another program (expected $id)"
  printf '%s\n' "$info" | grep -qx "TeamIdentifier=$MORSEC_TEAM_ID" ||
    die "bin/$b: not signed by morsec's team $MORSEC_TEAM_ID"
  verdict="$(spctl --assess --type install --verbose=4 "$f" 2>&1)" ||
    die "bin/$b: Gatekeeper rejects it: $verdict"
  printf '%s\n' "$verdict" | grep -q 'source=Notarized Developer ID' ||
    die "bin/$b: not notarized: $verdict"
done
say "morsec: code signatures ok (team $MORSEC_TEAM_ID, notarized)"

# --- install --------------------------------------------------------------------------------
mkdir -p "$dir"
# As given, without trailing slashes, for the PATH hints below (PATH entries rarely have them).
dir_given="$dir"
while [ "${dir_given%/}" != "$dir_given" ] && [ "$dir_given" != / ]; do dir_given="${dir_given%/}"; done
# Check and use the real directory: ~/.local/bin is often a symlink (dotfile managers).
dir="$(cd "$dir" && pwd -P)" || die "can't use $dir"
case "$dir" in
  *[[:space:]]*) die "the install directory must not contain spaces ($dir)" ;;
esac
me="$(id -u)"
[ "$(stat -f %u "$dir")" = "$me" ] || die "$dir is not owned by you"
mode="$(stat -f %Lp "$dir")"
[ $((0$mode & 022)) = 0 ] || die "$dir is writable by other users (mode $mode); fix it with chmod go-w"
manifest="$dir/$MANIFEST_NAME"
if [ -e "$manifest" ] || [ -L "$manifest" ]; then
  [ -f "$manifest" ] && [ ! -L "$manifest" ] || die "$manifest is not a regular file"
  grep -Evq '^(version [0-9A-Za-z.-]+|[0-9a-f]{64}  [A-Za-z0-9._-]+)$' "$manifest" &&
    die "$manifest is not one morsec wrote; remove it if you know why it's there"
fi
recorded() { [ -f "$manifest" ] && grep -qx "$1  $2" "$manifest"; }
previous="$(sed -n 's/^version //p' "$manifest" 2>/dev/null || true)"

# Every target must be absent or ours before anything is written.
foreign=""
changes=0
for pair in $BINS; do
  b="${pair%%:*}"
  t="$dir/$b"
  new="$(sha256 "$src/$b")"
  if [ ! -e "$t" ] && [ ! -L "$t" ]; then
    changes=1
  elif [ -f "$t" ] && [ ! -L "$t" ]; then
    cur="$(sha256 "$t")"
    if [ "$cur" = "$new" ]; then
      :
    elif recorded "$cur" "$b"; then
      changes=1
    else
      foreign="$foreign $t"
    fi
  else
    foreign="$foreign $t"
  fi
done
t="$dir/mors"
if [ -L "$t" ] && [ "$(readlink "$t")" = ms ]; then
  :
elif [ ! -e "$t" ] && [ ! -L "$t" ]; then
  changes=1
else
  foreign="$foreign $t"
fi
[ -z "$foreign" ] || die "these exist and were not installed by this script, so nothing was changed:$foreign
Remove them (a dev install: scripts/install-dev.sh made links there), or install elsewhere with MORSEC_INSTALL_DIR."

if [ "$changes" = 0 ] && [ "$previous" = "$ver" ]; then
  say "morsec $ver is already installed in $dir"
else
  for pair in $BINS; do
    b="${pair%%:*}"
    partial="$partial $dir/.$b.morsec-new.$$"
    cp "$src/$b" "$dir/.$b.morsec-new.$$"
    chmod 755 "$dir/.$b.morsec-new.$$"
    mv -f "$dir/.$b.morsec-new.$$" "$dir/$b"
  done
  if [ ! -L "$dir/mors" ]; then
    partial="$partial $dir/.mors.morsec-new.$$"
    ln -s ms "$dir/.mors.morsec-new.$$"
    mv -f "$dir/.mors.morsec-new.$$" "$dir/mors"
  fi
  partial="$partial $manifest.new.$$"
  {
    echo "version $ver"
    for pair in $BINS; do
      b="${pair%%:*}"
      echo "$(sha256 "$dir/$b")  $b"
    done
  } >"$manifest.new.$$"
  mv -f "$manifest.new.$$" "$manifest"
  say "morsec $ver installed in $dir: ms, mors, msd, ms-shim"
fi

# --- next steps -----------------------------------------------------------------------------
case ":${PATH:-}:" in
  *":$dir_given:"* | *":$dir:"*) ;;
  *)
    say ""
    say "$dir_given is not on your PATH. Add it, for zsh:"
    say "  echo 'export PATH=\"$dir_given:\$PATH\"' >> ~/.zshrc && exec zsh"
    ;;
esac
other="$(command -v ms 2>/dev/null || true)"
if [ -n "$other" ] && [ "$other" != "$dir/ms" ] && [ "$other" != "$dir_given/ms" ]; then
  say ""
  say "note: \`ms\` on your PATH is $other, not this install. Remove the other one or put $dir first."
fi
say ""
if [ -n "$previous" ] && [ "$previous" != "$ver" ]; then
  say "Changed from morsec $previous to $ver. Restart msd on this version and refresh the run shims:"
  say "  launchctl kickstart -k gui/\$(id -u)/cc.morsec.msd"
  say "  ms run --link-shims"
  say "  ms doctor"
else
  say "Next:"
  say "  ms init      # creates the vault in your keychain and starts msd"
  say "  ms doctor    # checks the setup"
  say "Getting started: https://github.com/csakash/morsec/blob/main/docs/ONBOARDING.md"
fi
