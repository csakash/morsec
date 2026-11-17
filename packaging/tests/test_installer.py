"""Tests for the curl installer, packaging/install.sh (loop distribution).

The installer under test is the real template, rendered by installer.render() with test values:
a file:// fake release in a temp dir instead of GitHub, `--proto =file`, a throwaway minisign
key made here, and, since the binaries are tiny ad-hoc signed programs (no Developer ID here),
the team "not set" (how codesign shows an ad-hoc signature) and the signer requirement `always`.
`spctl` (Gatekeeper's notarization verdict), `uname` and `id` are stubbed on PATH where a case
needs it. Everything else (curl, shasum, tar, codesign, minisign) is the real tool.

Nothing here touches the real HOME: HOME and MORSEC_INSTALL_DIR point into the temp dir.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(PKG)
sys.path.insert(0, os.path.join(PKG, "lib"))

import archive  # noqa: E402
import formula  # noqa: E402
import installer  # noqa: E402

IS_MAC_ARM = sys.platform == "darwin" and platform.machine() == "arm64"
TEMPLATE = os.path.join(PKG, "install.sh")
TARGET = "aarch64-apple-darwin"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
REAL_HOME = os.path.expanduser("~")


def _read(p: str) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def sha256(p: str) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def which(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        raise AssertionError(f"{tool} is not installed; the installer tests need it (never skipped)")
    return p


class TemplateTests(unittest.TestCase):
    """The template and its rendering, no binaries needed."""

    def test_bins_match_sign_targets(self):
        # protects=the installer checks exactly the shipped binaries with their frozen
        # identifiers; fails_when=sign-targets gains a binary the installer doesn't install
        targets = formula.sign_targets(_read(os.path.join(PKG, "macos", "sign-targets")))
        line = next(l for l in _read(TEMPLATE).splitlines() if l.startswith("BINS="))
        pairs = [tuple(p.split(":")) for p in line.split("=", 1)[1].strip("'").split()]
        self.assertEqual(pairs, [tuple(t) for t in targets])

    def test_release_rendering_pins_team_and_developer_id(self):
        team = installer.read_team(os.path.join(PKG, "macos", "team-id"))
        self.assertEqual(team, "554MCRUAKK")
        out = installer.render(_read(TEMPLATE), team, "RW" + "A" * 54)
        self.assertIn("MORSEC_TEAM_ID='554MCRUAKK'", out)
        self.assertIn("MORSEC_RELEASES='https://github.com/csakash/morsec/releases'", out)
        self.assertIn("MORSEC_CURL_PROTO='=https'", out)
        self.assertIn('certificate leaf[subject.OU] = "554MCRUAKK"', out)
        self.assertIn("certificate 1[field.1.2.840.113635.100.6.2.6] exists", out)
        self.assertNotRegex(out, r"@[A-Z_]+@")

    def test_render_refuses_bad_values(self):
        t = _read(TEMPLATE)
        for bad in ("abc", "554MCRUAK'", "554mcruakk"):
            with self.assertRaises(installer.InstallerError):
                installer.render(t, bad, "")
        with self.assertRaises(installer.InstallerError):
            installer.render(t, "554MCRUAKK", "RW'x")
        with self.assertRaises(installer.InstallerError):
            installer.render(t, "554MCRUAKK", "", base_url="https://x/$(id)")
        with self.assertRaises(installer.InstallerError):
            installer.render(t.replace("'@CURL_PROTO@'", "x"), "554MCRUAKK", "")

    def test_cli_has_no_test_switches(self):
        # protects=a release can only render the production installer; fails_when=the CLI grows
        # a way to change the source, the protocol or the signer
        r = run([sys.executable, "-I", os.path.join(PKG, "lib", "installer.py"), "--help"])
        for flag in ("--base-url", "--proto", "--signer"):
            self.assertNotIn(flag, r.stdout)

    def test_unrendered_template_refuses(self):
        r = run(["/bin/sh", TEMPLATE], env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("unrendered template", r.stderr)

    def test_shellcheck(self):
        r = run([which("shellcheck"), "-s", "sh", TEMPLATE])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_developer_id_requirement_parses(self):
        # protects=the production requirement is valid requirement-language text (a syntax
        # error would make codesign fail every install); fails_when=codesign reports a syntax
        # error rather than "failed to satisfy"
        if not IS_MAC_ARM:
            self.skipTest("codesign is macOS only")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        t = os.path.join(d, "t")
        shutil.copy("/usr/bin/true", t)
        req = installer.developer_id_requirement("554MCRUAKK")
        r = run(["codesign", "--verify", "-R", f'={req} and identifier "cc.morsec.ms"', t])
        self.assertNotIn("syntax", r.stderr.lower(), r.stderr)
        self.assertNotEqual(r.returncode, 0)


@unittest.skipUnless(IS_MAC_ARM, "the installer is for Apple silicon macOS")
class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.realpath(tempfile.mkdtemp(prefix="msinstaller"))
        cls.minisign = which("minisign")
        cls.cc = which("cc")
        try:
            cls.key_pub, cls.key_sec = cls.keypair("release")
            cls.bins = [n for n, _ in formula.sign_targets(_read(os.path.join(PKG, "macos", "sign-targets")))]
            cls.idents = dict(formula.sign_targets(_read(os.path.join(PKG, "macos", "sign-targets"))))
            cls.builds = {}
        except BaseException:
            shutil.rmtree(cls.dir, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def keypair(cls, name):
        """A throwaway, passwordless minisign key pair for this test only."""
        d = os.path.join(cls.dir, f"key-{name}")
        os.makedirs(d)
        pub, sec = os.path.join(d, "k.pub"), os.path.join(d, "k.key")
        r = run([cls.minisign, "-G", "-W", "-p", pub, "-s", sec])
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        return installer.read_pubkey(pub), sec

    def setUp(self):
        self.case = tempfile.mkdtemp(dir=self.dir)
        self.home = os.path.join(self.case, "home")
        os.makedirs(self.home)
        self.stubs = os.path.join(self.case, "stubs")
        os.makedirs(self.stubs)
        self.stub("spctl", 'echo "$5: accepted"; echo "source=Notarized Developer ID"')
        self.releases = os.path.join(self.case, "releases")

    def stub(self, name, body):
        p = os.path.join(self.stubs, name)
        with open(p, "w") as f:
            f.write(f"#!/bin/sh\n{body}\n")
        os.chmod(p, 0o755)

    # --- a fake release ------------------------------------------------------------------
    def program(self, version, tag=""):
        """Tiny ad-hoc signed executables with the release identifiers (cached per version)."""
        key = (version, tag)
        if key not in self.builds:
            d = os.path.join(self.dir, f"bins-{version}{tag}")
            os.makedirs(d)
            for b in self.bins:
                src = os.path.join(d, f"{b}.c")
                with open(src, "w") as f:
                    f.write(f'#include <stdio.h>\nint main(void){{puts("{b} {version}{tag}");return 0;}}\n')
                out = os.path.join(d, b)
                r = run([self.cc, "-o", out, src])
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run(["codesign", "-f", "-s", "-", "--identifier", self.idents[b], out])
                self.assertEqual(r.returncode, 0, r.stderr)
            self.builds[key] = d
        return self.builds[key]

    def publish(self, version, *, bins_dir=None, sign_with=None, comment_version=None, latest=True,
                tamper_sum=False, extra_entries=()):
        """Writes releases/download/v<version>/ (and latest/download/ when `latest`)."""
        bins_dir = bins_dir or self.program(version)
        d = os.path.join(self.releases, "download", f"v{version}")
        os.makedirs(d)
        tarball = f"morsec-{version}-{TARGET}.tar.gz"
        entries = [(os.path.join(bins_dir, b), f"bin/{b}", 0o755) for b in self.bins]
        entries += list(extra_entries)
        archive.build(os.path.join(d, tarball), f"morsec-{version}", 1_700_000_000, entries)
        s = sha256(os.path.join(d, tarball))
        if tamper_sum:
            s = ("0" if s[0] != "0" else "1") + s[1:]
        with open(os.path.join(d, "SHA256SUMS"), "w") as f:
            f.write(f"{s}  {tarball}\n{'a' * 64}  BUILDINFO\n")
        sec = sign_with or self.key_sec
        r = run([self.minisign, "-S", "-s", sec, "-m", os.path.join(d, "SHA256SUMS"), "-x",
                 os.path.join(d, "SHA256SUMS.minisig"), "-t",
                 f"morsec {comment_version or version} {COMMIT} {TARGET}"], input="")
        self.assertEqual(r.returncode, 0, r.stderr)
        if latest:
            ld = os.path.join(self.releases, "latest", "download")
            shutil.rmtree(ld, ignore_errors=True)
            os.makedirs(ld)
            for n in ("SHA256SUMS", "SHA256SUMS.minisig", tarball):
                shutil.copy(os.path.join(d, n), ld)
        return d

    def installer(self, team="not set", pubkey=None):
        p = os.path.join(self.case, "install.sh")
        with open(p, "w") as f:
            f.write(installer.render(_read(TEMPLATE), team, self.key_pub if pubkey is None else pubkey,
                                     base_url="file://" + self.releases, proto="=file", signer="always"))
        return p

    def install(self, *args, env=None, minisign=True, script=None):
        path = [self.stubs, "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        if minisign:
            path.insert(1, os.path.dirname(self.minisign))
        e = {"PATH": ":".join(path), "HOME": self.home, "TMPDIR": self.case, "LANG": "C"}
        e.update(env or {})
        r = run(["/bin/sh", script or self.installer(), *args], env=e)
        return r.returncode, r.stdout + r.stderr

    @property
    def bindir(self):
        return os.path.join(self.home, ".local", "bin")

    def assertInstalled(self, version):
        for b in self.bins:
            r = run([os.path.join(self.bindir, b)])
            self.assertEqual(r.stdout.strip(), f"{b} {version}")
        self.assertEqual(os.readlink(os.path.join(self.bindir, "mors")), "ms")
        manifest = _read(os.path.join(self.bindir, ".morsec-install"))
        self.assertIn(f"version {version}\n", manifest)

    def assertNothingInstalled(self):
        self.assertFalse(os.path.exists(os.path.join(self.bindir, "ms")), "something was installed")

    # --- the cases -------------------------------------------------------------------------
    # protects=a clean install from `latest` puts ms, msd, ms-shim and mors in ~/.local/bin after
    # every check passes, and prints the next steps; fails_when=it skips a check or installs
    # elsewhere; no_claim=a real Developer ID or notarization (stubbed spctl; human clean-VM step)
    def test_clean_install_latest_then_idempotent(self):
        self.publish("0.1.0")
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertInstalled("0.1.0")
        self.assertIn("signature ok (minisign)", out)
        self.assertIn("code signatures ok", out)
        self.assertIn("ms init", out)
        self.assertIn("ms doctor", out)
        self.assertIn("is not on your PATH", out)
        before = {b: os.stat(os.path.join(self.bindir, b)).st_ino for b in self.bins}
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertIn("already installed", out)
        self.assertEqual(before, {b: os.stat(os.path.join(self.bindir, b)).st_ino for b in self.bins})
        self.assertFalse(os.path.exists(os.path.join(self.case, "home", ".local", "bin", "ms.morsec-new")))
        self.assertEqual([n for n in os.listdir(self.case) if n.startswith("morsec-install.")], [],
                         "the temp dir was not cleaned up")

    # protects=a newer release replaces the installer's own files (new inodes, so a running msd
    # is unaffected) and says how to restart msd and refresh shims; a pinned --version installs
    # that one; fails_when=an upgrade refuses its own files or skips the restart note
    def test_upgrade_and_pinned_version(self):
        self.publish("0.1.0")
        self.publish("0.2.0")
        code, out = self.install("--version", "0.1.0")
        self.assertEqual(code, 0, out)
        self.assertInstalled("0.1.0")
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertInstalled("0.2.0")
        self.assertIn("Upgraded from 0.1.0", out)
        self.assertIn("launchctl kickstart -k", out)
        self.assertIn("ms run --link-shims", out)
        code, out = self.install(env={"MORSEC_VERSION": "v0.1.0"})
        self.assertEqual(code, 0, out)
        self.assertInstalled("0.1.0")

    # protects=files the installer did not write are never overwritten (a dev install's links,
    # a user's own ms), and nothing at all is changed then; fails_when=any foreign file is
    # replaced or a partial install happens
    def test_refuses_foreign_files(self):
        self.publish("0.1.0")
        os.makedirs(self.bindir)
        os.symlink("/somewhere/target/release/msd", os.path.join(self.bindir, "msd"))
        with open(os.path.join(self.bindir, "ms"), "w") as f:
            f.write("mine\n")
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("were not installed by this script", out)
        self.assertEqual(_read(os.path.join(self.bindir, "ms")), "mine\n")
        self.assertEqual(os.readlink(os.path.join(self.bindir, "msd")), "/somewhere/target/release/msd")
        self.assertFalse(os.path.exists(os.path.join(self.bindir, "ms-shim")))
        self.assertFalse(os.path.exists(os.path.join(self.bindir, ".morsec-install")))
        # A file the installer wrote and the user then edited is not its own any more.
        shutil.rmtree(self.bindir)
        self.assertEqual(self.install()[0], 0)
        with open(os.path.join(self.bindir, "msd"), "ab") as f:
            f.write(b"edited")
        self.publish("0.2.0")
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn(os.path.join(self.bindir, "msd"), out)

    # protects=MORSEC_INSTALL_DIR is honoured, must be absolute, and must not be writable by
    # others; fails_when=it installs into a relative or group-writable dir
    def test_install_dir(self):
        self.publish("0.1.0")
        other = os.path.join(self.case, "opt-bin")
        code, out = self.install(env={"MORSEC_INSTALL_DIR": other})
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.isfile(os.path.join(other, "msd")))
        self.assertNothingInstalled()
        code, out = self.install(env={"MORSEC_INSTALL_DIR": "rel/bin"})
        self.assertEqual(code, 1)
        self.assertIn("absolute path", out)
        shared = os.path.join(self.case, "shared")
        os.makedirs(shared)
        os.chmod(shared, 0o777)
        code, out = self.install(env={"MORSEC_INSTALL_DIR": shared})
        self.assertEqual(code, 1, out)
        self.assertIn("writable by other users", out)
        self.assertEqual(os.listdir(shared), [])

    # protects=a tarball that doesn't match SHA256SUMS is refused before anything is unpacked
    # or installed; fails_when=a tampered download installs
    def test_tampered_checksum(self):
        self.publish("0.1.0", tamper_sum=True)
        # Re-sign the tampered SHA256SUMS, so only the sha256 check can catch it.
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("does not match its sha256", out)
        self.assertNothingInstalled()

    # protects=a binary whose code signature is broken (bytes changed after signing) is refused;
    # fails_when=codesign --verify --strict is not run or its failure ignored
    def test_tampered_binary(self):
        good = self.program("0.1.0")
        bad = os.path.join(self.case, "bad")
        shutil.copytree(good, bad)
        with open(os.path.join(bad, "msd"), "r+b") as f:
            f.seek(0x4000)
            b = f.read(1)
            f.seek(0x4000)
            f.write(bytes([b[0] ^ 0xFF]))
        self.publish("0.1.0", bins_dir=bad)
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("bin/msd: the code signature is invalid", out)
        self.assertNothingInstalled()

    # protects=the team pin: binaries not signed by the embedded team are refused;
    # fails_when=any validly signed binary is accepted
    def test_wrong_team(self):
        self.publish("0.1.0")
        code, out = self.install(script=self.installer(team="554MCRUAKK"))
        self.assertEqual(code, 1, out)
        self.assertIn("not signed by morsec's team 554MCRUAKK", out)
        self.assertNothingInstalled()

    # protects=a binary signed under another identifier (another program of the same team) is
    # refused; fails_when=the identifier is not checked
    def test_wrong_identifier(self):
        swapped = os.path.join(self.case, "swapped")
        shutil.copytree(self.program("0.1.0"), swapped)
        shutil.copy(os.path.join(swapped, "ms"), os.path.join(swapped, "msd"))  # cc.morsec.ms as msd
        self.publish("0.1.0", bins_dir=swapped)
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("bin/msd", out)
        self.assertNothingInstalled()

    # protects=Gatekeeper's verdict is required: a rejection or a non-notarized source fails;
    # fails_when=spctl's answer is ignored
    def test_not_notarized(self):
        self.publish("0.1.0")
        self.stub("spctl", 'echo "$5: rejected"; echo "source=Unnotarized Developer ID"; exit 3')
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("Gatekeeper rejects it", out)
        self.stub("spctl", 'echo "$5: accepted"; echo "source=Developer ID"')
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("not notarized", out)
        self.assertNothingInstalled()

    # protects=with minisign installed, SHA256SUMS must carry a valid signature by the embedded
    # key, and its signed comment must name the version; fails_when=another key's signature or
    # a replayed signature of another version passes
    def test_minisign(self):
        _, other_sec = self.keypair("attacker")
        self.publish("0.1.0", sign_with=other_sec)
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("does not match its minisign signature", out)
        self.assertNothingInstalled()
        # Without minisign the signature is not checked, and it says so; the code signature still is.
        code, out = self.install(minisign=False)
        self.assertEqual(code, 0, out)
        self.assertIn("minisign is not installed", out)

    def test_minisign_comment_names_the_version(self):
        self.publish("0.1.0", comment_version="0.0.9")
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("signed comment does not name morsec 0.1.0", out)

    # protects=a requested version must be the one SHA256SUMS names; fails_when=--version is
    # silently ignored
    def test_version_mismatch_and_bad_version(self):
        d = self.publish("0.1.0")
        os.rename(d, os.path.join(self.releases, "download", "v0.3.0"))
        code, out = self.install("--version", "0.3.0")
        self.assertEqual(code, 1, out)
        self.assertIn("asked for 0.3.0", out)
        code, out = self.install("--version", "0.1;rm")
        self.assertEqual(code, 1, out)
        self.assertIn("is not a version", out)
        code, out = self.install("--version", "9.9.9")
        self.assertEqual(code, 1, out)
        self.assertIn("download failed", out)

    # protects=an archive entry outside morsec-<v>/ is refused before extraction;
    # fails_when=a crafted tarball can write outside the temp dir
    def test_unsafe_tar_entries(self):
        evil = os.path.join(self.case, "evil")
        with open(evil, "w") as f:
            f.write("x")
        # archive.py refuses unsafe paths itself, so craft the tar by hand.
        import tarfile
        self.publish("0.1.0")
        d = os.path.join(self.releases, "download", "v0.1.0")
        tb = os.path.join(d, f"morsec-0.1.0-{TARGET}.tar.gz")
        with tarfile.open(tb, "w:gz") as tf:
            for b in self.bins:
                tf.add(os.path.join(self.program("0.1.0"), b), f"morsec-0.1.0/bin/{b}")
            tf.add(evil, "morsec-0.1.0/../escape")
        s = sha256(tb)
        with open(os.path.join(d, "SHA256SUMS"), "w") as f:
            f.write(f"{s}  morsec-0.1.0-{TARGET}.tar.gz\n")
        run([self.minisign, "-S", "-s", self.key_sec, "-m", os.path.join(d, "SHA256SUMS"), "-x",
             os.path.join(d, "SHA256SUMS.minisig"), "-t", f"morsec 0.1.0 {COMMIT} {TARGET}"], input="")
        code, out = self.install("--version", "0.1.0")
        self.assertEqual(code, 1, out)
        self.assertIn("unsafe entry", out)
        self.assertFalse(os.path.exists(os.path.join(self.case, "escape")))
        self.assertNothingInstalled()

    # protects=wrong platforms are refused before anything is downloaded: another OS, an Intel
    # Mac; a Rosetta shell on Apple silicon is accepted; fails_when=it installs arm64 binaries
    # on Linux or an Intel Mac
    def test_wrong_platform(self):
        self.publish("0.1.0")
        self.stub("uname", '[ "$1" = -s ] && echo Linux || echo x86_64')
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("Apple silicon macOS only", out)
        self.assertNotIn("reading the release", out)
        self.stub("uname", '[ "$1" = -s ] && echo Darwin || echo x86_64')
        self.stub("sysctl", "echo 0")
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("Apple silicon Macs only (this Mac is x86_64)", out)
        self.assertNothingInstalled()
        self.stub("sysctl", "echo 1")  # an x86_64 shell under Rosetta on an Apple silicon Mac
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertInstalled("0.1.0")

    # protects=never as root or under sudo; fails_when=it installs for root
    def test_refuses_root_and_sudo(self):
        self.publish("0.1.0")
        code, out = self.install(env={"SUDO_USER": "someone"})
        self.assertEqual(code, 1, out)
        self.assertIn("with sudo", out)
        self.stub("id", '[ "$1" = -u ] && echo 0 || /usr/bin/id "$@"')
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("as root", out)
        self.assertNothingInstalled()

    # protects=the real HOME is never touched by these tests; fails_when=an install escapes the
    # temp HOME
    def test_real_home_untouched(self):
        self.publish("0.1.0")
        before = os.path.exists(os.path.join(REAL_HOME, ".local", "bin", ".morsec-install"))
        self.assertEqual(self.install()[0], 0)
        self.assertEqual(before, os.path.exists(os.path.join(REAL_HOME, ".local", "bin", ".morsec-install")))


if __name__ == "__main__":
    unittest.main()
