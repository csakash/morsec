"""Code digest of a thin 64-bit Mach-O that ignores its code signature (L10).

A Developer ID signature carries a secure timestamp, so a signed release binary never equals a
rebuild byte for byte. Removing the signature doesn't help either: `codesign` leaves the larger
`__LINKEDIT` vmsize behind. This digest covers every byte of the file up to the signature,
with only the fields the signature changes set to zero:

- `LC_CODE_SIGNATURE` datasize
- the `__LINKEDIT` segment's vmsize and filesize

So a signed binary and the unsigned binary it was made from have the same code digest, and any
change to code, data, load commands or entitlements-free content changes it.
The signature blob itself (identifier, flags, entitlements) is checked with `codesign`, not here.

Usage: python3 -I machocmp.py FILE [FILE ...]   prints "<digest>  <file>" per file
       python3 -I machocmp.py --same A B         exit 0 when the code digests match
"""

from __future__ import annotations

import hashlib
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
HEADER_SIZE = 32


class MachOError(Exception):
    pass


def normalized(data: bytes) -> bytes:
    if len(data) < HEADER_SIZE:
        raise MachOError("too short to be a Mach-O file")
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        raise MachOError("not a thin little-endian 64-bit Mach-O file (fat binaries unsupported)")
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    if HEADER_SIZE + sizeofcmds > len(data):
        raise MachOError("load commands run past the end of the file")
    buf = bytearray(data)
    end = len(buf)
    off = HEADER_SIZE
    limit = HEADER_SIZE + sizeofcmds
    seen_sig = False
    sig_end = 0
    for _ in range(ncmds):
        if off + 8 > limit:
            raise MachOError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize < 8 or off + cmdsize > limit:
            raise MachOError("bad load command size")
        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise MachOError("short LC_SEGMENT_64")
            name = bytes(buf[off + 8 : off + 24]).rstrip(b"\0")
            if name == b"__LINKEDIT":
                struct.pack_into("<Q", buf, off + 32, 0)  # vmsize
                struct.pack_into("<Q", buf, off + 48, 0)  # filesize
        elif cmd == LC_CODE_SIGNATURE:
            if seen_sig:
                raise MachOError("two LC_CODE_SIGNATURE commands")
            seen_sig = True
            dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
            if dataoff + datasize > len(buf) or dataoff < limit:
                raise MachOError("code signature outside the file")
            struct.pack_into("<I", buf, off + 12, 0)  # datasize
            end = dataoff
            sig_end = dataoff + datasize
        off += cmdsize
    # The signature must be the last thing in the file: bytes after it would escape the digest.
    if seen_sig and sig_end != len(buf):
        raise MachOError("bytes after the code signature")
    return bytes(buf[:end])


def code_digest(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(normalized(data)).hexdigest()


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["--same"]:
            if len(argv) != 3:
                print("usage: machocmp.py --same A B", file=sys.stderr)
                return 2
            a, b = code_digest(argv[1]), code_digest(argv[2])
            if a != b:
                print(f"machocmp.py: code differs\n  {a}  {argv[1]}\n  {b}  {argv[2]}", file=sys.stderr)
                return 1
            print(f"{a}  same code")
            return 0
        if not argv:
            print(__doc__, file=sys.stderr)
            return 2
        for p in argv:
            print(f"{code_digest(p)}  {p}")
        return 0
    except (MachOError, OSError) as e:
        print(f"machocmp.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
