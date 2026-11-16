"""Checks behind scripts/release-check.sh (L28). Pure functions plus a small CLI.

  python3 -I releasecheck.py version            < cargo metadata JSON (--no-deps --locked)
  python3 -I releasecheck.py changelog VERSION CHANGELOG.md
  python3 -I releasecheck.py binaries FORMULA_TEMPLATE SIGN_TARGETS BUILT_DIR

Each prints what it found and exits 0, or prints why not and exits 1. None of them signs,
tags, pushes or reads a credential.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys

# Run as a script under `python3 -I`, which leaves this directory off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import formula  # noqa: E402

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?")
# The CLI package: `ms --version` prints its version.
CLI_PACKAGE = "ms-cli"
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 2


class CheckError(Exception):
    pass


def check_version(metadata: dict) -> str:
    """The workspace version, after checking it is releasable and every member has it."""
    members = set(metadata.get("workspace_members", []))
    pkgs = [p for p in metadata.get("packages", []) if p.get("id") in members]
    if not pkgs:
        raise CheckError("cargo metadata lists no workspace members")
    cli = [p for p in pkgs if p.get("name") == CLI_PACKAGE]
    if len(cli) != 1:
        raise CheckError(f"no {CLI_PACKAGE} package in the workspace")
    version = cli[0]["version"]
    if not SEMVER.fullmatch(version):
        raise CheckError(f"version {version!r} is not MAJOR.MINOR.PATCH[-pre]")
    if version == "0.0.0":
        raise CheckError("the workspace version is 0.0.0: bump [workspace.package] version in Cargo.toml first")
    odd = sorted(f"{p['name']} {p['version']}" for p in pkgs if p["version"] != version)
    if odd:
        raise CheckError(f"these workspace packages are not at {version}: {', '.join(odd)}")
    return version


def check_changelog(version: str, text: str) -> int:
    """Number of entries under `## [version]`. Refuses a missing or empty section."""
    heading = re.compile(r"^## \[(.+?)\](.*)$")
    lines = text.splitlines()
    found = [i for i, l in enumerate(lines) if (m := heading.match(l)) and m.group(1) == version]
    if not found:
        raise CheckError(f"CHANGELOG.md has no '## [{version}]' section")
    if len(found) > 1:
        raise CheckError(f"CHANGELOG.md has '## [{version}]' more than once")
    entries = 0
    for line in lines[found[0] + 1:]:
        if line.startswith("## "):
            break
        if re.match(r"^\s*[-*] \S", line):
            entries += 1
    if entries == 0:
        raise CheckError(f"CHANGELOG.md's '## [{version}]' section has no entries")
    return entries


def is_arm64_executable(path: str) -> bool:
    """A thin 64-bit arm64 Mach-O executable (what release.sh signs and machocmp reads)."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    if len(head) < 16:
        return False
    magic, cpu, _sub, ftype = struct.unpack("<IiII", head)
    return magic == MH_MAGIC_64 and cpu == CPU_TYPE_ARM64 and ftype == MH_EXECUTE


def check_binaries(template: str, sign_targets: str, built_dir: str) -> list[str]:
    """The formula installs exactly the sign-targets list, in the same order, and each is built
    in `built_dir` as an arm64 executable."""
    installs = formula.installed_bins(template)
    signed = [n for n, _ in formula.sign_targets(sign_targets)]
    if installs != signed:
        raise CheckError(f"the formula installs {installs} but sign-targets (what release.sh builds and signs) lists {signed}")
    missing = [b for b in installs if not os.path.isfile(os.path.join(built_dir, b))]
    if missing:
        raise CheckError(f"not built in {built_dir}: {', '.join(missing)}")
    wrong = [b for b in installs if not is_arm64_executable(os.path.join(built_dir, b))]
    if wrong:
        raise CheckError(f"not thin arm64 Mach-O executables: {', '.join(wrong)}")
    return installs


def _read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["version"] and len(argv) == 1:
            print(check_version(json.load(sys.stdin)))
        elif argv[:1] == ["changelog"] and len(argv) == 3:
            n = check_changelog(argv[1], _read(argv[2]))
            print(f"{n} entr{'y' if n == 1 else 'ies'} for {argv[1]}")
        elif argv[:1] == ["binaries"] and len(argv) == 4:
            print(" ".join(check_binaries(_read(argv[1]), _read(argv[2]), argv[3])))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (CheckError, formula.FormulaError, OSError, ValueError, KeyError) as e:
        print(f"release-check: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
