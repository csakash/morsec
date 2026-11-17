"""Stages and checks morsec's npm packages from the release tarball (loop distribution).

Two packages, from the templates in packaging/npm/:

  morsec-darwin-arm64  the signed bin/ tools of the release tarball (sign-targets order), with
                       os ["darwin"] and cpu ["arm64"]; no bin, no scripts, no dependencies
  morsec               the `ms` / `mors` launcher (bin/morsec.js), with the platform package as
                       an exact-version optional dependency; no scripts

The binaries are copied out of the release tarball, never rebuilt or re-signed, and `verify`
re-opens the packed .tgz files and checks every binary's sha256 against the tarball's. Neither
package may carry a `scripts` key: npm would run preinstall/install/postinstall on every user's
machine.

  python3 -I npm.py stage  --tarball T --version V --license L --templates DIR --sign-targets F --out DIR
  python3 -I npm.py verify --tarball T --version V --sign-targets F --dir DIR

`stage` writes DIR/morsec-darwin-arm64/ and DIR/morsec/ (each must not exist yet). `verify`
reads DIR/morsec-darwin-arm64-V.tgz and DIR/morsec-V.tgz (from `npm pack`). Both exit 0 or
print why not and exit 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import formula  # noqa: E402

PLATFORM = "morsec-darwin-arm64"
MAIN = "morsec"
WRAPPER = "bin/morsec.js"
TARGET = "aarch64-apple-darwin"
# Cargo's license -> npm's. npm spells "all rights reserved" as UNLICENSED.
LICENSES = {"LicenseRef-Proprietary": "UNLICENSED"}
SPDX = re.compile(r"[A-Za-z0-9.+-]+( (OR|AND) [A-Za-z0-9.+-]+)*")
FORBIDDEN_KEYS = ("scripts", "dependencies", "peerDependencies", "bundleDependencies",
                  "bundledDependencies", "gypfile", "binding")


class NpmError(Exception):
    pass


def npm_license(cargo_license: str) -> str:
    lic = LICENSES.get(cargo_license, cargo_license)
    if not SPDX.fullmatch(lic) or lic.startswith("LicenseRef-"):
        raise NpmError(f"no npm license for Cargo license {cargo_license!r}")
    return lic


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tarball_bins(tarball: str, version: str, names: list[str]) -> dict[str, bytes]:
    """The bin/ tools of the release tarball, by name. Each must be a regular file."""
    prefix = f"morsec-{version}/bin/"
    out: dict[str, bytes] = {}
    with tarfile.open(tarball, "r:gz") as tf:
        for m in tf.getmembers():
            if m.name.startswith(prefix) and m.name[len(prefix):] in names:
                if not m.isreg():
                    raise NpmError(f"{m.name} in {tarball} is not a regular file")
                f = tf.extractfile(m)
                assert f is not None
                out[m.name[len(prefix):]] = f.read()
    missing = [n for n in names if n not in out]
    if missing:
        raise NpmError(f"{tarball} has no {', '.join(prefix + n for n in missing)}")
    return out


def render_manifest(template_path: str, version: str, license_: str) -> dict:
    with open(template_path, encoding="utf-8") as f:
        text = f.read()
    for k, v in (("@VERSION@", version), ("@LICENSE@", license_)):
        if '"' in v or "\\" in v:
            raise NpmError(f"refusing a quote or backslash in {k}")
        text = text.replace(k, v)
    if re.search(r"@[A-Z_]+@", text):
        raise NpmError(f"{template_path} has an unrendered placeholder")
    return json.loads(text)


def check_manifest(m: dict, name: str, version: str) -> None:
    if m.get("name") != name or m.get("version") != version:
        raise NpmError(f"package.json says {m.get('name')}@{m.get('version')}, expected {name}@{version}")
    bad = [k for k in FORBIDDEN_KEYS if k in m]
    if bad:
        raise NpmError(f"{name}: package.json must not have {', '.join(bad)} (npm would run or fetch them on install)")
    if name == PLATFORM:
        if m.get("os") != ["darwin"] or m.get("cpu") != ["arm64"]:
            raise NpmError(f"{name}: os must be [\"darwin\"] and cpu [\"arm64\"]")
        if "bin" in m or "optionalDependencies" in m:
            raise NpmError(f"{name}: must have no bin and no dependencies")
    else:
        if m.get("optionalDependencies") != {PLATFORM: version}:
            raise NpmError(f"{name}: optionalDependencies must be exactly {{{PLATFORM!r}: {version!r}}}")
        if m.get("bin") != {"ms": WRAPPER, "mors": WRAPPER}:
            raise NpmError(f"{name}: bin must map ms and mors to {WRAPPER}")


def expected_files(name: str, bins: list[str]) -> set[str]:
    if name == PLATFORM:
        return {"package.json", "README.md"} | {f"bin/{b}" for b in bins}
    return {"package.json", "README.md", WRAPPER}


def _new_dir(p: str) -> None:
    if os.path.lexists(p):
        raise NpmError(f"{p} already exists")
    os.makedirs(p)


def stage(tarball: str, version: str, license_: str, templates: str, sign_targets: str, out: str) -> list[str]:
    if not formula.VERSION.fullmatch(version):
        raise NpmError(f"version {version!r} is not MAJOR.MINOR.PATCH[-pre]")
    with open(sign_targets, encoding="utf-8") as f:
        bins = [n for n, _ in formula.sign_targets(f.read())]
    data = tarball_bins(tarball, version, bins)
    made = []
    for name in (PLATFORM, MAIN):
        src = os.path.join(templates, name)
        dst = os.path.join(out, name)
        _new_dir(dst)
        m = render_manifest(os.path.join(src, "package.json"), version, license_)
        check_manifest(m, name, version)
        if sorted(m.get("files", [])) != sorted(expected_files(name, bins) - {"package.json"}):
            raise NpmError(f"{name}: package.json files must list exactly {sorted(expected_files(name, bins) - {'package.json'})}")
        with open(os.path.join(dst, "package.json"), "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)
            f.write("\n")
        shutil.copyfile(os.path.join(src, "README.md"), os.path.join(dst, "README.md"))
        os.chmod(os.path.join(dst, "README.md"), 0o644)
        os.makedirs(os.path.join(dst, "bin"))
        if name == PLATFORM:
            for b in bins:
                p = os.path.join(dst, "bin", b)
                with open(p, "wb") as f:
                    f.write(data[b])
                os.chmod(p, 0o755)
        else:
            p = os.path.join(dst, WRAPPER)
            shutil.copyfile(os.path.join(src, WRAPPER), p)
            os.chmod(p, 0o755)
        made.append(dst)
    return made


def read_pack(tgz: str) -> dict[str, tuple[int, bytes]]:
    """The files of an `npm pack` tarball (under package/): path -> (mode, bytes)."""
    out: dict[str, tuple[int, bytes]] = {}
    with tarfile.open(tgz, "r:gz") as tf:
        for m in tf.getmembers():
            if m.isdir():
                continue
            if not m.isreg():
                raise NpmError(f"{tgz}: {m.name} is not a regular file")
            if not m.name.startswith("package/") or ".." in m.name.split("/"):
                raise NpmError(f"{tgz}: unexpected path {m.name}")
            rel = m.name[len("package/"):]
            if rel in out:
                raise NpmError(f"{tgz}: {rel} appears twice")
            f = tf.extractfile(m)
            assert f is not None
            out[rel] = (stat.S_IMODE(m.mode), f.read())
    return out


def verify(tarball: str, version: str, sign_targets: str, d: str) -> list[str]:
    with open(sign_targets, encoding="utf-8") as f:
        bins = [n for n, _ in formula.sign_targets(f.read())]
    want = tarball_bins(tarball, version, bins)
    report = []
    for name in (PLATFORM, MAIN):
        tgz = os.path.join(d, f"{name}-{version}.tgz")
        files = read_pack(tgz)
        exp = expected_files(name, bins)
        if set(files) != exp:
            raise NpmError(f"{tgz} holds {sorted(files)}, expected exactly {sorted(exp)}")
        check_manifest(json.loads(files["package.json"][1]), name, version)
        if name == PLATFORM:
            for b in bins:
                mode, body = files[f"bin/{b}"]
                if mode & 0o111 != 0o111:
                    raise NpmError(f"{tgz}: bin/{b} is mode {mode:o}, not executable")
                got, exp_sha = sha256_bytes(body), sha256_bytes(want[b])
                if got != exp_sha:
                    raise NpmError(f"{tgz}: bin/{b} sha256 {got} differs from the release tarball's {exp_sha}")
                report.append(f"{exp_sha}  {name}/bin/{b}")
        else:
            mode, _ = files[WRAPPER]
            if mode & 0o111 != 0o111:
                raise NpmError(f"{tgz}: {WRAPPER} is mode {mode:o}, not executable")
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="npm.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stage")
    v = sub.add_parser("verify")
    for p in (s, v):
        p.add_argument("--tarball", required=True)
        p.add_argument("--version", required=True)
        p.add_argument("--sign-targets", required=True)
    s.add_argument("--license", required=True, help="Cargo's license field")
    s.add_argument("--templates", required=True)
    s.add_argument("--out", required=True)
    v.add_argument("--dir", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "stage":
            for p in stage(a.tarball, a.version, npm_license(a.license), a.templates, a.sign_targets, a.out):
                print(p)
        else:
            for line in verify(a.tarball, a.version, a.sign_targets, a.dir):
                print(line)
            print(f"npm packages match the release tarball ({a.version})")
    except (NpmError, formula.FormulaError, OSError, ValueError, tarfile.TarError) as e:
        print(f"npm.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
