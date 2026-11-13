#!/usr/bin/env bash
# Builds release binaries and links `ms`, `mors` and `msd` into ~/.local/bin for local use.
# Refuses to overwrite a file there that is not a link into this checkout.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd -P)"
bin_dir="${MORSEC_BIN_DIR:-$HOME/.local/bin}"

cargo build --release --locked -p ms-cli -p msd
mkdir -p "$bin_dir"

link() { # link <target> <name>
  local dest="$bin_dir/$2"
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    local current
    current="$(readlink "$dest" 2>/dev/null || true)"
    case "$current" in
      "$root"/target/release/*) ;;
      *)
        echo "install-dev.sh: $dest exists and is not a morsec dev link; leaving it alone." >&2
        exit 1
        ;;
    esac
  fi
  ln -sfn "$1" "$dest"
  echo "linked $dest -> $1"
}

link "$root/target/release/ms" ms
link "$root/target/release/ms" mors
link "$root/target/release/msd" msd
