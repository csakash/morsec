"""Installs a release tarball into a prefix the way the Homebrew formula does (L28).

Used by the packaging tests and scripts/release-check.sh to prove that what the formula installs
works as installed: ms, msd and ms-shim land together in <prefix>/Cellar/morsec/<version>/bin
(so `ms` finds `ms-shim` next to its real path), `mors` is a symlink to `ms` there, and every
tool is linked into <prefix>/bin the way `brew link` does. It reads the formula template's
`bin.install` and `bin.install_symlink` lines, so a template that drops a binary installs
without it. It never runs brew and never writes outside <prefix>.

Usage: python3 -I install_sim.py --tarball T --template F --version V --prefix DIR
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile

# Run as a script under `python3 -I`, which leaves this directory off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import formula  # noqa: E402

SHARE = ("BUILDINFO", "morsec.cdx.json")


class InstallError(Exception):
    pass


def install(tarball: str, template: str, version: str, prefix: str) -> str:
    """Installs into `prefix`; returns the Cellar bin directory."""
    if not formula.VERSION.fullmatch(version):
        raise InstallError(f"version {version!r} is not MAJOR.MINOR.PATCH[-pre]")
    bins = formula.installed_bins(template)
    links = formula.SYMLINK.findall(template)
    keg = os.path.join(prefix, "Cellar", "morsec", version)
    if os.path.exists(keg):
        raise InstallError(f"{keg} already exists")
    cellar_bin = os.path.join(keg, "bin")
    os.makedirs(cellar_bin)
    with tempfile.TemporaryDirectory() as unpack:
        with tarfile.open(tarball, "r:gz") as t:
            # The data filter refuses absolute paths, links out of the tree and device files.
            t.extractall(unpack, filter="data")
        top = os.path.join(unpack, f"morsec-{version}")
        if not os.path.isdir(top):
            raise InstallError(f"the tarball has no morsec-{version}/ directory")
        for b in bins:
            src = os.path.join(top, "bin", b)
            if not os.path.isfile(src) or os.path.islink(src):
                raise InstallError(f"the formula installs bin/{b}, which the tarball does not hold")
            shutil.copy2(src, os.path.join(cellar_bin, b))
            os.chmod(os.path.join(cellar_bin, b), 0o755)
        share = os.path.join(keg, "share", "morsec")
        os.makedirs(share)
        for name in SHARE:
            src = os.path.join(top, "share", "morsec", name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(share, name))
    for target, name in links:
        if target not in bins:
            raise InstallError(f"install_symlink {name} => {target}, which is not installed")
        os.symlink(target, os.path.join(cellar_bin, name))
    # `brew link`: <prefix>/bin/<tool> -> ../Cellar/morsec/<version>/bin/<tool>.
    linked = os.path.join(prefix, "bin")
    os.makedirs(linked, exist_ok=True)
    for name in sorted(os.listdir(cellar_bin)):
        os.symlink(os.path.relpath(os.path.join(cellar_bin, name), linked), os.path.join(linked, name))
    return cellar_bin


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Install a morsec tarball the way the formula does")
    ap.add_argument("--tarball", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--prefix", required=True)
    a = ap.parse_args(argv)
    try:
        with open(a.template, encoding="utf-8") as f:
            print(install(a.tarball, f.read(), a.version, a.prefix))
    except (InstallError, formula.FormulaError, OSError, tarfile.TarError) as e:
        print(f"install_sim.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
