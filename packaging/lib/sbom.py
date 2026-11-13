"""CycloneDX 1.5 SBOM for the morsec release, from `cargo metadata` and `Cargo.lock` (L10).

Standard library only, so the release adds no tool to the supply chain. The output is
deterministic: sorted, no random serial number, timestamp from SOURCE_DATE_EPOCH.

Usage (run with `python3 -I`):
    cargo metadata --format-version 1 --locked --filter-platform aarch64-apple-darwin \
      | python3 -I sbom.py --lock Cargo.lock --version 0.1.0 --commit <sha> --epoch <s> \
          --root ms-cli --root msd [--out FILE]

It also refuses a dependency graph that contains a self-update crate (morsec has no
auto-update; ARI-42 GW-2). Exit 1 with a message on any problem.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import tomllib
import uuid

# Crates that update a binary in place, or check for updates and nag. None may ship in morsec.
UPDATER_CRATES = frozenset(
    {
        "self_update",
        "self-update",
        "self-replace",
        "self_replace",
        "axoupdater",
        "update-informer",
        "update_informer",
        "tauri-plugin-updater",
        "cargo-update",
        "sparkle",
        "sparkle-rs",
        "check-latest",
        "updater",
        "velopack",
    }
)

# Edges that ship in the binary or run to build it. Dev-only edges don't.
SHIPPED_KINDS = frozenset({None, "normal", "build"})

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


class SbomError(Exception):
    pass


def _lock_checksums(lock_text: str) -> dict[tuple[str, str, str], str]:
    lock = tomllib.loads(lock_text)
    out: dict[tuple[str, str, str], str] = {}
    for pkg in lock.get("package", []):
        if "checksum" in pkg:
            out[(pkg["name"], pkg["version"], pkg.get("source", ""))] = pkg["checksum"]
    return out


def reachable(metadata: dict, roots: list[str]) -> list[dict]:
    """Packages reachable from the root packages through shipped (normal/build) edges."""
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    by_name = {}
    for p in metadata["packages"]:
        if p["id"] in metadata.get("workspace_members", []):
            by_name[p["name"]] = p["id"]
    todo = []
    for r in roots:
        if r not in by_name:
            raise SbomError(f"root package {r!r} is not a workspace member")
        todo.append(by_name[r])
    seen: set[str] = set()
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [])}
            if kinds & SHIPPED_KINDS:
                todo.append(dep["pkg"])
    return [packages[i] for i in seen]


def _ref(pkg: dict) -> str:
    return f"{pkg['name']}@{pkg['version']}"


def deny_updaters(pkgs: list[dict]) -> None:
    bad = sorted({p["name"] for p in pkgs if p["name"].lower() in UPDATER_CRATES})
    if bad:
        raise SbomError(
            "morsec has no auto-update, but the release would ship: " + ", ".join(bad)
        )


def build_sbom(
    metadata: dict,
    lock_text: str,
    roots: list[str],
    version: str,
    commit: str,
    epoch: int,
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        raise SbomError(f"commit {commit!r} is not a git SHA")
    pkgs = reachable(metadata, roots)
    deny_updaters(pkgs)
    checksums = _lock_checksums(lock_text)
    members = set(metadata.get("workspace_members", []))
    in_set = {p["id"] for p in pkgs}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}

    components = []
    for p in sorted(pkgs, key=lambda p: (p["name"], p["version"], p.get("source") or "")):
        c: dict = {
            "type": "library",
            "bom-ref": _ref(p),
            "name": p["name"],
            "version": p["version"],
            "scope": "required",
        }
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"]}]
        source = p.get("source")
        if p["id"] in members:
            c["properties"] = [{"name": "morsec:workspace-member", "value": "true"}]
        elif source == CRATES_IO:
            c["purl"] = f"pkg:cargo/{p['name']}@{p['version']}"
            sha = checksums.get((p["name"], p["version"], source))
            if not sha:
                raise SbomError(f"{_ref(p)} has no checksum in Cargo.lock")
            c["hashes"] = [{"alg": "SHA-256", "content": sha}]
        else:
            # check.sh's cargo deny allows crates.io only; anything else is a supply-chain change.
            raise SbomError(f"{_ref(p)} comes from {source!r}, not crates.io")
        components.append(c)

    ref_of = {p["id"]: _ref(p) for p in pkgs}
    dependencies = []
    for p in sorted(pkgs, key=_ref):
        deps = set()
        for d in nodes[p["id"]]["deps"]:
            kinds = {k.get("kind") for k in d.get("dep_kinds", [])}
            if kinds & SHIPPED_KINDS and d["pkg"] in in_set:
                deps.add(ref_of[d["pkg"]])
        dependencies.append({"ref": _ref(p), "dependsOn": sorted(deps)})
    root_refs = sorted(_ref(p) for p in pkgs if p["name"] in roots and p["id"] in members)
    dependencies.insert(0, {"ref": f"morsec@{version}", "dependsOn": root_refs})

    stamp = datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": stamp,
            "tools": {
                "components": [
                    {"type": "application", "name": "morsec packaging/lib/sbom.py", "version": "1"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"morsec@{version}",
                "name": "morsec",
                "version": version,
                "properties": [{"name": "morsec:git-commit", "value": commit}],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }
    body = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "morsec-sbom:" + body))
    return bom


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--epoch", required=True, type=int)
    ap.add_argument("--root", action="append", required=True)
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    try:
        metadata = json.load(sys.stdin)
        with open(a.lock, encoding="utf-8") as f:
            lock_text = f.read()
        bom = build_sbom(metadata, lock_text, a.root, a.version, a.commit, a.epoch)
    except (SbomError, ValueError, KeyError, OSError) as e:
        print(f"sbom.py: {e}", file=sys.stderr)
        return 1
    text = json.dumps(bom, indent=2, sort_keys=True) + "\n"
    if a.out:
        with open(a.out, "x", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
