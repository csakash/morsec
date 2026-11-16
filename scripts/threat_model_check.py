"""Every test docs/THREAT_MODEL.md names must exist. Run by scripts/check.sh (hardening loop).

A name is written `path::test_name` in backticks; `*` in a name matches any suffix (for a family
such as `fuzz_frame_*`). The test is found when `path` holds `fn <name>`.

Usage: python3 -I scripts/threat_model_check.py
"""

import os
import re
import sys

DOC = "docs/THREAT_MODEL.md"
REF = re.compile(r"`((?:crates|tests)/[^`:]+)::([A-Za-z0-9_*]+)`")


def main() -> int:
    with open(DOC, encoding="utf-8") as f:
        refs = sorted(set(REF.findall(f.read())))
    if not refs:
        print(f"{DOC}: names no tests", file=sys.stderr)
        return 1
    missing = []
    for path, name in refs:
        if not os.path.isfile(path):
            missing.append(f"{path}::{name} (no such file)")
            continue
        pat = re.compile(r"\bfn " + re.escape(name).replace(r"\*", r"[A-Za-z0-9_]*") + r"\b")
        with open(path, encoding="utf-8") as f:
            if not pat.search(f.read()):
                missing.append(f"{path}::{name}")
    for m in missing:
        print(f"{DOC}: test not found: {m}", file=sys.stderr)
    if missing:
        return 1
    print(f"{DOC}: all {len(refs)} named tests exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
