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


# A file name: no leading dot (so never "." or ".."), no slash.
NAME = r"[A-Za-z0-9_-][A-Za-z0-9._-]*"
BIN_INSTALL = re.compile(r'^\s*bin\.install\s+(.+?)\s*$', re.M)
BIN_ARG = re.compile(rf'"bin/({NAME})"')
SYMLINK = re.compile(rf'bin\.install_symlink\s+"({NAME})"\s*=>\s*"({NAME})"')

# The whole formula, line by line: what may appear in the class body and in each block. Anything
# else, another method (post_install, service), a `system` call or a write, is refused, so
# nothing is installed, written or run that the bin.install check doesn't see.
CLASS_STMT = re.compile(
    r'(desc|homepage|url|version|sha256) "[^"#\\$`]*"'
    r'|depends_on (arch|macos): :[a-z0-9_]+( # [^#`]*)?'
    r'|def install|def caveats|test do|end')
INSTALL_STMT = re.compile(
    rf'bin\.install "bin/{NAME}"(, "bin/{NAME}")*'
    rf'|bin\.install_symlink "{NAME}" => "{NAME}"'
    rf'|\(share/"morsec"\)\.install "share/morsec/{NAME}"(, "share/morsec/{NAME}")*')
TEST_STMT = re.compile(r'assert_match "[^"#`$\\]*", shell_output\("#\{bin\}/' + NAME + r'[^"`$\\]*"(, [0-9]+)?\)'
                       r'|assert_match "morsec #\{version\}", shell_output\("#\{bin\}/' + NAME + r' --version"\)')
CAVEATS_STMT = re.compile(r'<<~EOS|EOS|[^#`$\\]*')


def check_structure(template: str) -> None:
    """Refuses a formula that does anything but the known statements (see CLASS_STMT)."""
    lines = template.splitlines()
    i = 0
    while i < len(lines) and (not lines[i].strip() or lines[i].startswith("#")):
        i += 1
    if i >= len(lines) or lines[i] != "class Morsec < Formula":
        raise FormulaError("the formula must start with `class Morsec < Formula`")
    if [l for l in lines[i + 1:] if l.strip()][-1:] != ["end"]:
        raise FormulaError("the formula must end with the class's `end`")
    block = None
    seen = []
    for raw in lines[i + 1:-1] if lines[-1] == "end" else lines[i + 1:]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "end" and raw == "end":
            break
        if block is None:
            if not raw.startswith("  ") or raw.startswith("   ") or not CLASS_STMT.fullmatch(line):
                raise FormulaError(f"unexpected statement in the formula: {line!r}")
            if line in ("def install", "def caveats", "test do"):
                if line in seen:
                    raise FormulaError(f"{line!r} appears twice")
                seen.append(line)
                block = line
            elif line == "end":
                raise FormulaError("unbalanced `end` in the formula")
            continue
        if raw == "  end":
            block = None
            continue
        ok = {"def install": INSTALL_STMT, "test do": TEST_STMT, "def caveats": CAVEATS_STMT}[block]
        if not ok.fullmatch(line):
            raise FormulaError(f"unexpected statement in {block}: {line!r}")
    if block is not None:
        raise FormulaError(f"{block!r} is not closed")
    if "def install" not in seen:
        raise FormulaError("the formula has no `def install … end` block")


def installed_bins(template: str) -> list[str]:
    """The bin/ tools the formula installs: the names in its single `bin.install "bin/…", …`
    line, in order. The whole formula must pass check_structure, and anything it can't read
    exactly is refused, so a check built on it fails closed."""
    check_structure(template)
    lines = BIN_INSTALL.findall(template)
    if len(lines) != 1:
        raise FormulaError(f"the formula must have exactly one bin.install line, found {len(lines)}")
    args = [a.strip() for a in lines[0].split(",")]
    names = []
    for a in args:
        m = BIN_ARG.fullmatch(a)
        if not m:
            raise FormulaError(f"bin.install argument {a!r} is not a \"bin/<name>\" string")
        names.append(m.group(1))
    if len(set(names)) != len(names):
        raise FormulaError("bin.install names a binary twice")
    for target, link in SYMLINK.findall(template):
        if target not in names or link in names:
            raise FormulaError(f"install_symlink {link} => {target} must point at an installed tool and not replace one")
    return names


def sign_targets(text: str) -> list[tuple[str, str]]:
    """Rows of packaging/macos/sign-targets: (bin name, signing identifier)."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise FormulaError(f"sign-targets line {line!r} is not '<name> <identifier>'")
        rows.append((parts[0], parts[1]))
    return rows


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
