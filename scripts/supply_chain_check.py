"""Supply-chain policy that cargo-deny does not cover. Run by scripts/check.sh step 7.

1. No `[patch]` or `[replace]` in any manifest, and no `paths` overrides in .cargo/config(.toml).
   Manifests are parsed as TOML, so `[ patch.x ]`, `["patch".x]` and dotted keys such as
   `patch.crates-io.tokio = {...}` are all caught (a regex misses those).
2. Every package without a registry source (a path package) is a workspace member. A path
   dependency, even one inside the repo, would build code that cargo-deny and cargo-audit skip.

Usage: cargo metadata --format-version 1 --locked | python3 -I scripts/supply_chain_check.py
"""

import glob
import json
import sys
import tomllib

FORBIDDEN_MANIFEST_KEYS = ("patch", "replace")


def main() -> int:
    problems = []

    manifests = ["Cargo.toml", *sorted(glob.glob("crates/*/Cargo.toml"))]
    for path in manifests:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
        for key in FORBIDDEN_MANIFEST_KEYS:
            if key in doc:
                problems.append(f"{path}: [{key}] is not allowed (it bypasses cargo-deny)")

    for path in (".cargo/config", ".cargo/config.toml"):
        try:
            with open(path, "rb") as f:
                doc = tomllib.load(f)
        except FileNotFoundError:
            continue
        for key in (*FORBIDDEN_MANIFEST_KEYS, "paths"):
            if key in doc:
                problems.append(f"{path}: '{key}' is not allowed (it overrides dependencies)")

    meta = json.load(sys.stdin)
    members = set(meta["workspace_members"])
    for pkg in meta["packages"]:
        if pkg["source"] is None and pkg["id"] not in members:
            problems.append(
                f"path dependency {pkg['name']} {pkg['version']} ({pkg['manifest_path']}) is not a "
                "workspace member; cargo-deny and cargo-audit would not check it"
            )

    if problems:
        for p in problems:
            print(f"check.sh: {p}", file=sys.stderr)
        return 1
    print(f"supply chain: no patches or overrides; all {len(members)} path packages are workspace members")
    return 0


if __name__ == "__main__":
    sys.exit(main())
