"""Renders the Homebrew formula from packaging/homebrew/morsec.rb.in (L10).

Every value lands inside a Ruby double-quoted string, where `#{...}` would run code when brew
loads the formula. So each value is checked against a strict pattern before substitution, and
`#`, quotes, backslashes and `$` are refused outright.

Usage: python3 -I formula.py --template T --version V --sha256 H --url U --out FILE
"""

from __future__ import annotations

import argparse
import re
import sys

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?")
SHA256 = re.compile(r"[0-9a-f]{64}")
# https:// for a real release; file:/// only for a local test tap. No '#', quotes, '\' or '$'.
URL = re.compile(r"(https://[A-Za-z0-9.-]+|file://)/[A-Za-z0-9._~/%+-]+\.tar\.gz")
PLACEHOLDERS = ("@URL@", "@VERSION@", "@SHA256@")


class FormulaError(Exception):
    pass


def render(template: str, version: str, sha256: str, url: str) -> str:
    if not VERSION.fullmatch(version):
        raise FormulaError(f"version {version!r} is not MAJOR.MINOR.PATCH[-pre]")
    if not SHA256.fullmatch(sha256):
        raise FormulaError("sha256 must be 64 lowercase hex characters")
    if not URL.fullmatch(url) or ".." in url:
        raise FormulaError(f"url {url!r} is not an https:// (or file:// test) .tar.gz URL")
    for p in PLACEHOLDERS:
        if template.count(p) != 1:
            raise FormulaError(f"template must hold {p} exactly once")
    out = template.replace("@URL@", url).replace("@VERSION@", version).replace("@SHA256@", sha256)
    m = re.search(r"@[A-Z0-9_]+@", out)
    if m:
        raise FormulaError(f"unrendered placeholder {m.group(0)}")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Render the morsec Homebrew formula")
    ap.add_argument("--template", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.template, encoding="utf-8") as f:
            text = render(f.read(), a.version, a.sha256, a.url)
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    except (FormulaError, OSError) as e:
        print(f"formula.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
