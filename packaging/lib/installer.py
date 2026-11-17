"""Renders the curl installer, packaging/install.sh, for a release (loop distribution).

The template carries five placeholders. A release fills them from the repository only:
  @TEAM_ID@             packaging/macos/team-id (10 characters)
  @MINISIGN_PUBKEY@     the key line of packaging/minisign.pub (empty if there is no key yet:
                        a `build` only; `release` refuses that)
  @BASE_URL@            https://github.com/csakash/morsec/releases
  @CURL_PROTO@          =https
  @SIGNER_REQUIREMENT@  a Developer ID Application certificate of that team

The CLI has no way to change the last three: the tests call `render()` directly to point a copy
at a file:// fake release with ad-hoc signed binaries. Every value lands inside a single-quoted
sh string, so a single quote, a newline or a backslash is refused outright.

Usage: python3 -I installer.py --template T --team-file F [--pubkey-file P] --out FILE
"""

from __future__ import annotations

import argparse
import os
import re
import sys

BASE_URL = "https://github.com/csakash/morsec/releases"
CURL_PROTO = "=https"
TEAM = re.compile(r"[A-Z0-9]{10}")
# minisign public keys: base64 of 42 bytes ("Ed" + 8-byte key id + 32-byte key) = 56 characters.
PUBKEY = re.compile(r"RW[A-Za-z0-9+/]{54}")
PLACEHOLDERS = ("@TEAM_ID@", "@MINISIGN_PUBKEY@", "@BASE_URL@", "@CURL_PROTO@", "@SIGNER_REQUIREMENT@")


class InstallerError(Exception):
    pass


def developer_id_requirement(team: str) -> str:
    """Apple's Developer ID Application requirement, pinned to `team`."""
    if not TEAM.fullmatch(team):
        raise InstallerError(f"team ID {team!r} is not 10 characters A-Z/0-9")
    return ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            f'and certificate leaf[subject.OU] = "{team}"')


def read_pubkey(path: str) -> str:
    """The key line of a minisign .pub file (the line after the untrusted comment)."""
    with open(path, encoding="utf-8") as f:
        lines = [l.strip() for l in f.read().splitlines() if l.strip()]
    keys = [l for l in lines if not l.startswith("untrusted comment:")]
    if len(keys) != 1 or not PUBKEY.fullmatch(keys[0]):
        raise InstallerError(f"{path} is not a minisign public key")
    return keys[0]


def read_team(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        team = f.read().strip()
    if not TEAM.fullmatch(team):
        raise InstallerError(f"{path} does not hold a 10-character team ID")
    return team


def render(template: str, team: str, pubkey: str, base_url: str = BASE_URL,
           proto: str = CURL_PROTO, signer: str | None = None) -> str:
    if signer is None:
        signer = developer_id_requirement(team)
    values = {"@TEAM_ID@": team, "@MINISIGN_PUBKEY@": pubkey, "@BASE_URL@": base_url,
              "@CURL_PROTO@": proto, "@SIGNER_REQUIREMENT@": signer}
    for k, v in values.items():
        if any(c in v for c in "'\\\n\r@`$"):
            raise InstallerError(f"refusing {k} value {v!r}")
    if pubkey and not PUBKEY.fullmatch(pubkey):
        raise InstallerError("the minisign public key is malformed")
    out = template
    for k in PLACEHOLDERS:
        n = out.count(f"'{k}'")
        if n != 1:
            raise InstallerError(f"the template must have exactly one '{k}' (found {n})")
        out = out.replace(f"'{k}'", f"'{values[k]}'")
    if re.search(r"@[A-Z_]+@", out):
        raise InstallerError("a placeholder is left after rendering")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="installer.py")
    ap.add_argument("--template", required=True)
    ap.add_argument("--team-file", required=True)
    ap.add_argument("--pubkey-file", help="packaging/minisign.pub; omit only when there is none yet")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.template, encoding="utf-8") as f:
            template = f.read()
        pub = read_pubkey(a.pubkey_file) if a.pubkey_file else ""
        text = render(template, read_team(a.team_file), pub)
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(a.out, 0o755)
    except (InstallerError, OSError) as e:
        print(f"installer.py: {e}", file=sys.stderr)
        return 1
    print(a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
