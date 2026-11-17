"""Install test for the release payload (L28): the formula installs ms-shim next to ms.

Builds a tarball with archive.py from the built ms, msd and ms-shim (the list in
packaging/macos/sign-targets), installs it into a temporary prefix the way the formula does
(packaging/lib/install_sim.py), starts the installed msd with a memory vault and a temp socket,
state directory and HOME, adds a test-tier run key that allows one program, and runs the
installed `ms doctor`. A second install from a template without ms-shim is the control: doctor
must say ms-shim is missing there.

It needs the debug build (`cargo build --workspace`, step 2 of scripts/check.sh): the Touch ID
stand-in (`msd --test-touch-id allow`) exists only in debug builds, and the rules change below
needs an approval. Nothing here uses the real HOME, ~/.claude, ~/.codex, ~/.ssh, git
credentials or the login keychain; the test checks those are untouched.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import signal
import time
import tomllib
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(PKG)
sys.path.insert(0, os.path.join(PKG, "lib"))

import archive  # noqa: E402
import formula  # noqa: E402
import install_sim  # noqa: E402

IS_MAC_ARM = sys.platform == "darwin" and platform.machine() == "arm64"
BUILT = os.path.join(ROOT, "target", "debug")
with open(os.path.join(ROOT, "Cargo.toml"), "rb") as _f:
    # The workspace version the built binaries carry (every crate inherits it).
    VERSION = tomllib.load(_f)["workspace"]["package"]["version"]
REAL_HOME = os.path.expanduser("~")
# What the test must never touch (mtime, or absence, before and after).
# (Not ~/.claude itself: a running Claude Code writes under it all the time.)
REAL_PATHS = [".claude/settings.json", ".codex/config.toml", ".ssh", ".gitconfig", ".git-credentials",
              ".morsec/shims"]


def _read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def _snapshot() -> dict[str, float | None]:
    out = {}
    for r in REAL_PATHS:
        try:
            out[r] = os.stat(os.path.join(REAL_HOME, r)).st_mtime
        except FileNotFoundError:
            out[r] = None
    return out


def section(doctor_out: str, name: str) -> str:
    """The lines of one `ms doctor` section."""
    lines = doctor_out.splitlines()
    try:
        start = lines.index(name)
    except ValueError:
        raise AssertionError(f"no {name!r} section in:\n{doctor_out}") from None
    body = []
    for line in lines[start + 1:]:
        if not line.strip():
            break
        body.append(line)
    return "\n".join(body)


class LiveMsd:
    """A throwaway msd (memory vault, temp socket, state dir and HOME) started from an installed
    msd (cls.msd_path), and outside() to run the installed ms as a user's own terminal would."""

    # Directories put on PATH after the install's bin/ (npm's launcher needs node), with a
    # trailing ':'.
    extra_path = ""

    @classmethod
    def init_dirs(cls, prefix: str):
        # /tmp keeps the socket path short; mkdtemp makes it 0700.
        cls.dir = os.path.realpath(tempfile.mkdtemp(prefix=prefix, dir="/tmp"))
        cls.home = os.path.join(cls.dir, "home")
        for d in (cls.home, os.path.join(cls.dir, "tmp")):
            os.makedirs(d)
        cls.sock = os.path.join(cls.dir, "s.sock")
        cls.runs = 0
        cls.msd = None
        # Process groups of the detached shells, killed in tearDownClass whatever happened.
        cls.groups = []

    @classmethod
    def add_run_key(cls, prefix: str):
        """A test-tier run key that allows psql, so doctor and --link-shims want one shim."""
        code, out = cls.outside(
            "printf 'not-a-real-value' | ms add run/inst --stdin --mode run --tier test >/dev/null && "
            "(sleep 1; printf 'o\\n'; sleep 3) | script -q /dev/null ms rules run/inst --add-command '[\"psql\"]' >/dev/null",
            prefix)
        if code != 0:
            raise AssertionError(f"setting up the run key failed:\n{out}")

    @classmethod
    def tearDownClass(cls):
        for g, rc in cls.groups:
            # A finished command (rc written) left nothing behind, and its group id may already
            # belong to someone else: only kill a group whose command never finished.
            if os.path.exists(rc):
                continue
            try:
                os.killpg(g, signal.SIGKILL)
            except OSError:
                pass
        if cls.msd is not None:
            cls.msd.terminate()
            try:
                cls.msd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.msd.kill()
                cls.msd.wait()
            cls.msd = None
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def env(cls) -> dict[str, str]:
        # The binaries under test are cargo builds with no Developer ID, so ms only talks to msd
        # with the explicit dev opt-out (T-03, ms-ipc peer_verify). A signed release ignores it.
        return {"PATH": "/usr/bin:/bin", "HOME": cls.home, "TMPDIR": os.path.join(cls.dir, "tmp"), "LANG": "C",
                "MORSEC_DEV_UNVERIFIED_DAEMON": "1"}

    @classmethod
    def start_msd(cls):
        log = open(os.path.join(cls.dir, "msd.log"), "wb")
        cls.msd = subprocess.Popen(
            [cls.msd_path, "--foreground", "--vault", "memory", "--socket", cls.sock,
             "--state-dir", os.path.join(cls.dir, "state"), "--proxy-port", "0", "--test-touch-id", "allow"],
            env=cls.env(), stdout=subprocess.DEVNULL, stderr=log, stdin=subprocess.DEVNULL)
        log.close()
        deadline = time.monotonic() + 15
        while not os.path.exists(cls.sock):
            if cls.msd.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("msd did not start:\n" + _read(os.path.join(cls.dir, "msd.log")))
            time.sleep(0.05)

    @classmethod
    def outside(cls, command: str, prefix: str) -> tuple[int, str]:
        """Runs `command` with `<prefix>/bin` first on PATH, detached from this process tree (as
        the user's own terminal would be: a rules change from inside an agent session is
        refused). Returns (exit code, stdout + stderr)."""
        cls.runs += 1
        n = cls.runs
        script = os.path.join(cls.dir, f"outside{n}.sh")
        out = os.path.join(cls.dir, f"outside{n}.out")
        rc = os.path.join(cls.dir, f"outside{n}.rc")
        env = cls.env()
        with open(script, "w", encoding="utf-8") as f:
            f.write(
                f"export PATH='{prefix}/bin:{cls.extra_path}{env['PATH']}' HOME='{cls.home}' MORSEC_SOCKET='{cls.sock}' "
                f"TMPDIR='{env['TMPDIR']}' LANG=C MORSEC_DEV_UNVERIFIED_DAEMON=1\nunset CLAUDE_CONFIG_DIR CODEX_HOME\ncd '{cls.home}'\n{command}\n")
        # Its own session and process group (setsid), so teardown can kill whatever is left.
        p = subprocess.Popen(
            ["/bin/sh", "-c",
             f"(sleep 0.3; /bin/sh '{script}' > '{out}' 2>&1; echo $? > '{rc}.tmp'; mv '{rc}.tmp' '{rc}') "
             "</dev/null >/dev/null 2>&1 &"],
            env={"PATH": "/usr/bin:/bin"}, start_new_session=True)
        cls.groups.append((p.pid, rc))
        if p.wait() != 0:
            raise AssertionError("could not start a detached shell")
        deadline = time.monotonic() + 120
        while not os.path.exists(rc):
            if time.monotonic() > deadline:
                raise AssertionError(f"detached command never finished: {command}")
            time.sleep(0.05)
        return int(_read(rc).strip() or -1), _read(out)


@unittest.skipUnless(IS_MAC_ARM, "the release is macOS arm64 only")
class InstalledShimTests(LiveMsd, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = _snapshot()
        cls.bins = [n for n, _ in formula.sign_targets(_read(os.path.join(PKG, "macos", "sign-targets")))]
        for b in cls.bins:
            p = os.path.join(BUILT, b)
            if not os.path.isfile(p):
                raise AssertionError(f"{p} is not built; run cargo build --workspace first (scripts/check.sh does)")
        cls.init_dirs("msinst")
        try:
            tar = cls.tarball()
            template = _read(os.path.join(PKG, "homebrew", "morsec.rb.in"))
            cls.prefix = os.path.join(cls.dir, "brew")
            cls.cellar = install_sim.install(tar, template, VERSION, cls.prefix)
            # The control: the same tarball through a formula that does not install ms-shim.
            old = template.replace('bin.install "bin/ms", "bin/msd", "bin/ms-shim"', 'bin.install "bin/ms", "bin/msd"')
            assert old != template, "the template's bin.install line changed; update this test"
            cls.control = os.path.join(cls.dir, "brew-old")
            install_sim.install(tar, old, VERSION, cls.control)
            cls.msd_path = os.path.join(cls.prefix, "bin", "msd")
            cls.start_msd()
            cls.add_run_key(cls.prefix)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tarball(cls) -> str:
        stage = os.path.join(cls.dir, "stage")
        os.makedirs(stage)
        entries = [(os.path.join(BUILT, b), f"bin/{b}", 0o755) for b in cls.bins]
        for name in install_sim.SHARE:
            p = os.path.join(stage, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write("placeholder for the install test\n")
            entries.append((p, f"share/morsec/{name}", 0o644))
        out = os.path.join(cls.dir, f"morsec-{VERSION}-aarch64-apple-darwin.tar.gz")
        archive.build(out, f"morsec-{VERSION}", 1_700_000_000, entries)
        return out

    def tearDown(self):
        self.assertEqual(_snapshot(), self.real, "the install test touched the real HOME")

    # protects=L28: the formula installs ms-shim next to ms, so run mode works from a Homebrew
    # install (ms resolves its Cellar path and finds ms-shim there), and the shims link to the
    # opt path so they survive brew upgrade; fails_when=the formula or the release drops ms-shim,
    # or a shim names the versioned keg; no_claim=a real brew install or a signed build (human step)
    def test_installed_ms_finds_its_shim(self):
        cellar = os.path.join(self.prefix, "Cellar", "morsec", VERSION, "bin")
        self.assertEqual(sorted(os.listdir(cellar)), sorted(self.bins + ["mors"]))
        self.assertTrue(os.path.islink(os.path.join(self.prefix, "bin", "ms")))
        code, out = self.outside("ms doctor", self.prefix)
        shims = section(out, "run shims")
        self.assertNotIn("not installed next to ms", shims, out)
        self.assertIn("shims missing or stale: psql", shims, out)
        code, out = self.outside("ms run --link-shims && ms doctor", self.prefix)
        self.assertIn("linked psql", out)
        self.assertIn("✓ 1 shim linked in", section(out, "run shims"), out)
        # The shim is a symlink to the stable opt path (it follows brew upgrade), and it is the
        # Cellar's ms-shim, not something else named psql.
        psql = os.path.join(self.home, ".morsec", "shims", "psql")
        self.assertTrue(os.path.islink(psql))
        opt_shim = os.path.join(os.path.realpath(self.prefix), "opt", "morsec", "bin", "ms-shim")
        self.assertEqual(os.readlink(psql), opt_shim)
        self.assertEqual(os.path.realpath(psql), os.path.realpath(os.path.join(cellar, "ms-shim")))
        # No LaunchAgent in this HOME (ms init is not run here): doctor says so, as info.
        self.assertIn("no LaunchAgent at", section(out, "launchagent"), out)

    # protects=the shim check bites: without ms-shim in the formula, doctor and --link-shims say
    # it is missing; fails_when=a release without ms-shim passes doctor; no_claim=-
    def test_control_without_shim_is_reported(self):
        self.assertFalse(os.path.exists(os.path.join(self.control, "bin", "ms-shim")))
        code, out = self.outside("ms doctor", self.control)
        self.assertNotEqual(code, 0, out)
        self.assertIn("ms-shim is not installed next to ms", section(out, "run shims"), out)
        code, out = self.outside("ms run --link-shims", self.control)
        self.assertNotEqual(code, 0, out)
        self.assertIn("ms-shim is not installed next to ms", out)

    # protects=the formula's `test do` holds for the installed tools: ms and mors print the
    # version, ms-shim under its own name refuses (64) and says how to link it; fails_when=one
    # of them is missing or misbehaves; no_claim=-
    def test_formula_test_block(self):
        b = os.path.join(self.prefix, "bin")
        for tool in ("ms", "mors"):
            r = subprocess.run([os.path.join(b, tool), "--version"], env=self.env(), capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"morsec {VERSION}", r.stdout)
        r = subprocess.run([os.path.join(b, "ms-shim")], env=self.env(), capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)
        self.assertIn("ms run --link-shims", r.stderr)


class InstallSimTests(unittest.TestCase):
    """install_sim refuses what it can't install exactly (no binary, no runtime needed)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.template = _read(os.path.join(PKG, "homebrew", "morsec.rb.in"))
        self.files = {}
        for name in ("ms", "msd", "ms-shim", "BUILDINFO"):
            p = os.path.join(self.tmp, name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n")
            self.files[name] = p

    def tar(self, bins):
        out = os.path.join(self.tmp, f"t{len(os.listdir(self.tmp))}.tar.gz")
        entries = [(self.files[b], f"bin/{b}", 0o755) for b in bins]
        entries.append((self.files["BUILDINFO"], "share/morsec/BUILDINFO", 0o644))
        archive.build(out, "morsec-1.2.3", 1_700_000_000, entries)
        return out

    def test_installs_what_the_formula_names(self):
        prefix = os.path.join(self.tmp, "p")
        cellar = install_sim.install(self.tar(["ms", "msd", "ms-shim"]), self.template, "1.2.3", prefix)
        self.assertEqual(sorted(os.listdir(cellar)), ["mors", "ms", "ms-shim", "msd"])
        self.assertEqual(os.readlink(os.path.join(cellar, "mors")), "ms")
        self.assertEqual(os.path.realpath(os.path.join(prefix, "bin", "ms-shim")),
                         os.path.realpath(os.path.join(cellar, "ms-shim")))

    def test_refuses_a_tarball_without_a_formula_binary(self):
        with self.assertRaisesRegex(install_sim.InstallError, "bin/ms-shim"):
            install_sim.install(self.tar(["ms", "msd"]), self.template, "1.2.3", os.path.join(self.tmp, "p"))

    def test_refuses_bad_version_and_reinstall(self):
        with self.assertRaises(install_sim.InstallError):
            install_sim.install(self.tar(["ms", "msd", "ms-shim"]), self.template, "1.2", os.path.join(self.tmp, "p"))
        prefix = os.path.join(self.tmp, "q")
        install_sim.install(self.tar(["ms", "msd", "ms-shim"]), self.template, "1.2.3", prefix)
        with self.assertRaisesRegex(install_sim.InstallError, "already exists"):
            install_sim.install(self.tar(["ms", "msd", "ms-shim"]), self.template, "1.2.3", prefix)


if __name__ == "__main__":
    unittest.main()
