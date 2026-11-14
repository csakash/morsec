"""Deterministic .tar.gz for the morsec release (L10).

Same inputs give the same bytes: entries sorted, directories listed explicitly, mtime from
SOURCE_DATE_EPOCH, owner root:wheel (0:0), fixed modes, ustar format (no pax headers, no
extended attributes), gzip with no filename and mtime 0.

Usage: python3 -I archive.py --out OUT.tar.gz --prefix morsec-0.1.0 --epoch N \
           SRC=DEST[:MODE] ...
DEST is relative to the prefix; MODE is octal (default 0644). SRC must be a regular file.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import posixpath
import re
import stat
import sys
import tarfile

SAFE_PATH = re.compile(r"[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*")


class ArchiveError(Exception):
    pass


def _check_rel(path: str) -> str:
    if not SAFE_PATH.fullmatch(path) or any(p in (".", "..") for p in path.split("/")):
        raise ArchiveError(f"unsafe archive path {path!r}")
    return path


def parse_entry(spec: str) -> tuple[str, str, int]:
    if "=" not in spec:
        raise ArchiveError(f"entry {spec!r} is not SRC=DEST[:MODE]")
    src, dest = spec.rsplit("=", 1)
    mode = 0o644
    if ":" in dest:
        dest, m = dest.rsplit(":", 1)
        if not re.fullmatch(r"0?[0-7]{3}", m):
            raise ArchiveError(f"bad mode {m!r}")
        mode = int(m, 8)
    return src, _check_rel(dest), mode


def build(out: str, prefix: str, epoch: int, entries: list[tuple[str, str, int]]) -> None:
    _check_rel(prefix)
    if "/" in prefix:
        raise ArchiveError("prefix must be one path component")
    files: dict[str, tuple[str, int]] = {}
    for src, dest, mode in entries:
        st = os.lstat(src)
        if not stat.S_ISREG(st.st_mode):
            raise ArchiveError(f"{src} is not a regular file")
        name = f"{prefix}/{dest}"
        if name in files:
            raise ArchiveError(f"{dest} listed twice")
        files[name] = (src, mode)
    dirs = {prefix}
    for name in files:
        d = posixpath.dirname(name)
        while d and d not in dirs:
            dirs.add(d)
            d = posixpath.dirname(d)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(dirs | set(files)):
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname, info.gname = "root", "wheel"
            if name in dirs:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            else:
                src, mode = files[name]
                with open(src, "rb") as f:
                    data = f.read()
                info.size = len(data)
                info.mode = mode
                tar.addfile(info, io.BytesIO(data))
    # "x": never overwrite an existing file.
    with open(out, "xb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
            gz.write(raw.getvalue())


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Deterministic release tarball")
    ap.add_argument("--out", required=True)
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--epoch", required=True, type=int)
    ap.add_argument("entries", nargs="+")
    a = ap.parse_args(argv)
    try:
        build(a.out, a.prefix, a.epoch, [parse_entry(e) for e in a.entries])
    except (ArchiveError, OSError) as e:
        print(f"archive.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
