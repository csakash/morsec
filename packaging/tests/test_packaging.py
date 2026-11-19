"""Tests for the L10 release tooling. Run: python3 -I -m unittest discover -s packaging/tests -v

They run in the check gate (scripts/check.sh). The full reproducible build is too slow for every
gate run; `scripts/release.sh verify-repro` is the release-time proof of that.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(PKG)
sys.path.insert(0, os.path.join(PKG, "lib"))

import archive  # noqa: E402
import formula  # noqa: E402
import machocmp  # noqa: E402
import sbom  # noqa: E402

RELEASE = os.path.join(ROOT, "scripts", "release.sh")
IS_MAC_ARM = sys.platform == "darwin" and platform.machine() == "arm64"
CRATES = sbom.CRATES_IO


def _pkg(name, version="1.0.0", source=CRATES, license="MIT"):
    pid = f"{source or 'path+file:///w/' + name}#{name}@{version}"
    return {"id": pid, "name": name, "version": version, "source": source, "license": license}


def _dep(pkg, *kinds):
    return {"name": pkg["name"], "pkg": pkg["id"], "dep_kinds": [{"kind": k, "target": None} for k in kinds]}


def _metadata(edges, packages, members):
    nodes = [{"id": p["id"], "deps": edges.get(p["name"], [])} for p in packages]
    return {
        "packages": packages,
        "workspace_members": [p["id"] for p in members],
        "resolve": {"nodes": nodes},
    }


def _lock(*pkgs):
    out = []
    for p in pkgs:
        if p["source"]:
            out.append(
                f'[[package]]\nname = "{p["name"]}"\nversion = "{p["version"]}"\n'
                f'source = "{p["source"]}"\nchecksum = "{"ab" * 32}"\n'
            )
    return "\n".join(out)


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.app = _pkg("app", "0.1.0", source=None, license="LicenseRef-Proprietary")
        self.lib = _pkg("lib")
        self.devonly = _pkg("devonly")
        self.buildonly = _pkg("buildonly")
        self.pkgs = [self.app, self.lib, self.devonly, self.buildonly]
        self.edges = {
            "app": [_dep(self.lib, None), _dep(self.devonly, "dev")],
            "lib": [_dep(self.buildonly, "build")],
        }

    def bom(self, edges=None, pkgs=None, lock=None):
        pkgs = pkgs or self.pkgs
        md = _metadata(edges or self.edges, pkgs, [self.app])
        return sbom.build_sbom(md, lock if lock is not None else _lock(*pkgs), ["app"], "0.1.0", "abcdef1", 1_700_000_000)

    def test_shipped_edges_only(self):
        names = {c["name"] for c in self.bom()["components"]}
        self.assertEqual(names, {"app", "lib", "buildonly"})

    def test_component_fields(self):
        comps = {c["name"]: c for c in self.bom()["components"]}
        self.assertEqual(comps["lib"]["purl"], "pkg:cargo/lib@1.0.0")
        self.assertEqual(comps["lib"]["hashes"], [{"alg": "SHA-256", "content": "ab" * 32}])
        self.assertNotIn("purl", comps["app"])
        self.assertEqual(comps["app"]["licenses"], [{"expression": "LicenseRef-Proprietary"}])
        self.assertEqual(comps["app"]["type"], "application")
        self.assertEqual(comps["lib"]["type"], "library")

    def test_legacy_cargo_licenses_become_spdx(self):
        self.assertEqual(sbom.spdx_expression("MIT/Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(sbom.spdx_expression("Apache-2.0 / MIT"), "Apache-2.0 OR MIT")
        self.assertEqual(sbom.spdx_expression("MIT OR Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(sbom.spdx_expression("Apache-2.0 WITH LLVM-exception"), "Apache-2.0 WITH LLVM-exception")

    def test_deterministic(self):
        a, b = self.bom(), self.bom()
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertRegex(a["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        self.assertEqual(a["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
        self.assertEqual(a["specVersion"], "1.5")
        self.assertEqual(a["dependencies"][0], {"ref": "morsec@0.1.0", "dependsOn": ["app@0.1.0"]})

    def test_serial_changes_with_content(self):
        other = dict(self.edges)
        other["lib"] = []
        self.assertNotEqual(self.bom()["serialNumber"], self.bom(edges=other)["serialNumber"])

    def test_refuses_updater_crate(self):
        upd = _pkg("self_update")
        edges = dict(self.edges)
        edges["lib"] = [_dep(upd, None)]
        with self.assertRaisesRegex(sbom.SbomError, "no auto-update.*self_update"):
            self.bom(edges=edges, pkgs=self.pkgs + [upd])

    def test_dev_only_updater_is_not_shipped(self):
        upd = _pkg("axoupdater")
        edges = dict(self.edges)
        edges["app"] = edges["app"] + [_dep(upd, "dev")]
        self.bom(edges=edges, pkgs=self.pkgs + [upd])

    def test_refuses_non_crates_io_source(self):
        git = _pkg("gitdep", source="git+https://example.com/x#deadbeef")
        edges = dict(self.edges)
        edges["lib"] = [_dep(git, None)]
        with self.assertRaisesRegex(sbom.SbomError, "not crates.io"):
            self.bom(edges=edges, pkgs=self.pkgs + [git])

    def test_refuses_missing_checksum(self):
        with self.assertRaisesRegex(sbom.SbomError, "no checksum"):
            self.bom(lock="")

    def test_refuses_bad_commit(self):
        md = _metadata(self.edges, self.pkgs, [self.app])
        with self.assertRaises(sbom.SbomError):
            sbom.build_sbom(md, _lock(*self.pkgs), ["app"], "0.1.0", "HEAD; rm", 0)

    @unittest.skipUnless(shutil.which("cargo"), "needs cargo")
    def test_real_workspace(self):
        md = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", "aarch64-apple-darwin"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout
        with open(os.path.join(ROOT, "Cargo.lock"), encoding="utf-8") as f:
            lock = f.read()
        bom = sbom.build_sbom(json.loads(md), lock, ["ms-cli", "msd"], "0.0.0", "abcdef1", 0)
        names = {c["name"] for c in bom["components"]}
        self.assertTrue({"ms-cli", "msd", "ms-vault"} <= names)
        # Dev-only crates never reach the shipped SBOM.
        self.assertFalse({"proptest", "assert_cmd", "predicates"} & names)
        self.assertFalse({n.lower() for n in names} & sbom.UPDATER_CRATES)

    def test_sbom_lists_fonts(self):
        # L33 SPEC D-1: the fonts msd embeds are file components with OFL-1.1 and the SHA-256
        # that SOURCES.txt (and ms-dash's fonts_are_pinned) pin.
        files = sbom.font_components(ROOT)
        md = _metadata(self.edges, self.pkgs, [self.app])
        bom = sbom.build_sbom(md, _lock(*self.pkgs), ["app"], "0.1.0", "abcdef1", 0, files)
        fonts = [c for c in bom["components"] if c["type"] == "file"]
        self.assertEqual(len(fonts), 5)
        with open(os.path.join(ROOT, sbom.FONTS_DIR, "SOURCES.txt"), encoding="utf-8") as f:
            sources = f.read()
        families = set()
        for c in fonts:
            self.assertEqual(c["licenses"], [{"license": {"id": "OFL-1.1"}}])
            sha = c["hashes"][0]["content"]
            self.assertIn(f"{sha}  {c['name']}", sources)
            families |= {p["value"] for p in c["properties"] if p["name"] == "morsec:font-family"}
        self.assertEqual(families, {"Archivo", "Instrument Serif", "IBM Plex Mono"})
        with self.assertRaises(sbom.SbomError):
            sbom.font_components(os.path.join(ROOT, "no-such-dir"))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = os.path.join(self.tmp, "ms")
        with open(self.bin, "wb") as f:
            f.write(b"\x7fbinary")
        self.doc = os.path.join(self.tmp, "BUILDINFO")
        with open(self.doc, "w") as f:
            f.write("x=1\n")

    def make(self, name, entries=None):
        out = os.path.join(self.tmp, name)
        archive.build(out, "morsec-0.1.0", 1_700_000_000, entries or [
            (self.doc, "share/morsec/BUILDINFO", 0o644), (self.bin, "bin/ms", 0o755)])
        with open(out, "rb") as f:
            return f.read()

    def test_same_bytes_whatever_the_file_times_and_order(self):
        a = self.make("a.tar.gz")
        os.utime(self.bin, (time.time() - 99999, time.time() - 99999))
        os.chmod(self.bin, 0o700)
        b = self.make("b.tar.gz", [(self.bin, "bin/ms", 0o755), (self.doc, "share/morsec/BUILDINFO", 0o644)])
        self.assertEqual(a, b)

    def test_entries(self):
        data = self.make("a.tar.gz")
        self.assertEqual(data[4:8], b"\0\0\0\0")  # gzip mtime 0
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as t:
            members = t.getmembers()
            self.assertEqual([m.name for m in members], [
                "morsec-0.1.0", "morsec-0.1.0/bin", "morsec-0.1.0/bin/ms", "morsec-0.1.0/share",
                "morsec-0.1.0/share/morsec", "morsec-0.1.0/share/morsec/BUILDINFO"])
            for m in members:
                self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, "root", "wheel", 1_700_000_000))
                self.assertFalse(m.pax_headers)
            self.assertEqual(t.getmember("morsec-0.1.0/bin/ms").mode, 0o755)

    def test_refuses_unsafe_paths_and_links(self):
        for dest in ("../x", "/abs", "a/../b", "a b", "a/./b"):
            with self.assertRaises(archive.ArchiveError, msg=dest):
                archive.parse_entry(f"{self.bin}={dest}")
        link = os.path.join(self.tmp, "link")
        os.symlink(self.bin, link)
        with self.assertRaisesRegex(archive.ArchiveError, "regular file"):
            self.make("l.tar.gz", [(link, "bin/ms", 0o755)])

    def test_refuses_duplicates_and_overwrite(self):
        with self.assertRaisesRegex(archive.ArchiveError, "twice"):
            self.make("d.tar.gz", [(self.bin, "bin/ms", 0o755), (self.doc, "bin/ms", 0o644)])
        self.make("once.tar.gz")
        with self.assertRaises(FileExistsError):
            self.make("once.tar.gz")


class FormulaTests(unittest.TestCase):
    URL = "https://github.com/csakash/morsec/releases/download/v0.1.0/morsec-0.1.0-aarch64-apple-darwin.tar.gz"

    def setUp(self):
        with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as f:
            self.template = f.read()

    def test_renders(self):
        out = formula.render(self.template, "0.1.0", "a" * 64, self.URL)
        self.assertIn(f'url "{self.URL}"', out)
        self.assertIn('sha256 "' + "a" * 64 + '"', out)
        self.assertIn('bin.install_symlink "ms" => "mors"', out)
        self.assertIn('bin.install "bin/ms", "bin/msd", "bin/ms-shim"', out)
        self.assertIn('shell_output("#{bin}/ms-shim 2>&1", 64)', out)
        self.assertIn("depends_on arch: :arm64", out)
        self.assertIn("depends_on macos: :ventura", out)
        self.assertIn('shell_output("#{bin}/mors --version")', out)
        # ms init owns the LaunchAgent (L07); no brew service, no updater.
        self.assertNotIn("service do", out)
        self.assertNotRegex(out, r"@[A-Z0-9_]+@")

    def test_refuses_ruby_injection_and_bad_values(self):
        bad_urls = [
            'https://x.example/a".tar.gz',
            "https://x.example/#{system('id')}.tar.gz",
            "https://x.example/$(id).tar.gz",
            "https://x.example/a\\b.tar.gz",
            "http://x.example/a.tar.gz",
            "https://x.example/../a.tar.gz",
            "file:///tmp/a.zip",
        ]
        for u in bad_urls:
            with self.assertRaises(formula.FormulaError, msg=u):
                formula.render(self.template, "0.1.0", "a" * 64, u)
        for v in ("0.1", '0.1.0"', "0.1.0#{x}", "v0.1.0"):
            with self.assertRaises(formula.FormulaError, msg=v):
                formula.render(self.template, v, "a" * 64, self.URL)
        for s in ("A" * 64, "a" * 63, "g" * 64):
            with self.assertRaises(formula.FormulaError):
                formula.render(self.template, "0.1.0", s, self.URL)
        formula.render(self.template, "0.1.0", "a" * 64, "file:///private/tmp/x/morsec-0.1.0.tar.gz")

    def test_refuses_broken_template(self):
        with self.assertRaises(formula.FormulaError):
            formula.render(self.template.replace("@SHA256@", ""), "0.1.0", "a" * 64, self.URL)
        with self.assertRaises(formula.FormulaError):
            formula.render(self.template + "\n# @OTHER@\n", "0.1.0", "a" * 64, self.URL)


class InstalledBinsTests(unittest.TestCase):
    BINS = '    bin.install "bin/ms", "bin/msd", "bin/ms-shim"\n'

    def setUp(self):
        with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as f:
            self.t = f.read()
        self.assertIn(self.BINS, self.t)

    def test_reads_the_bin_install_line(self):
        t = self.t.replace(self.BINS, '    bin.install "bin/ms", "bin/b-c"\n')
        self.assertEqual(formula.installed_bins(t), ["ms", "b-c"])

    def test_refuses_what_it_cannot_read_exactly(self):
        for line in ('    bin.install "bin/ms"\n    bin.install "bin/msd"\n', '    bin.install "bin/ms", libexec/"x"\n',
                     '    bin.install "bin/ms", "bin/ms"\n', '    bin.install "bin/#{x}"\n', '    bin.install Dir["bin/*"]\n',
                     '    bin.install "bin/.."\n', ""):
            with self.assertRaises(formula.FormulaError, msg=line):
                formula.installed_bins(self.t.replace(self.BINS, line))
        with self.assertRaises(formula.FormulaError):
            formula.installed_bins("")

    # protects=the whole formula is whitelisted, not just def install: post_install, service,
    # system calls, writes, a renamed or commented def line all fail (re-review finding);
    # fails_when=one of them passes; no_claim=Ruby semantics beyond these line forms
    def test_refuses_anything_outside_the_known_statements(self):
        t = self.t
        cases = [
            t.replace("  test do", '  def post_install\n    system "curl", "x"\n  end\n\n  test do'),
            t.replace("  test do", '  service do\n    run bin/"msd"\n  end\n\n  test do'),
            t.replace("  def install", "  def install # bins"),
            t.replace("  def install", "  def install()"),
            t.replace(self.BINS, self.BINS + '    system "curl", "x"\n'),
            t.replace(self.BINS, self.BINS + '    (bin/"x").write "echo"\n'),
            t.replace(self.BINS, self.BINS + '    libexec.install "bin/x"\n'),
            t.replace('bin.install_symlink "ms" => "mors"', 'bin.install_symlink "ms" => ".."'),
            t.replace('bin.install_symlink "ms" => "mors"', 'bin.install_symlink "ms" => "msd"'),
            t.replace('bin.install_symlink "ms" => "mors"', 'bin.install_symlink "x" => "mors"'),
            t.replace("  test do", "  test do\n    system bin/\"ms\", \"init\""),
            t.replace("  def caveats", "  def install\n  end\n\n  def caveats"),
            t.replace('desc "', 'desc "#{`id`}'),
            t + "system 'x'\n",
        ]
        for i, bad in enumerate(cases):
            self.assertNotEqual(bad, t, i)
            with self.assertRaises(formula.FormulaError, msg=str(i)):
                formula.installed_bins(bad)

    # protects=the formula can't install or write anything the bin.install check doesn't see
    # (security review observation); fails_when=libexec.install or a write in def install passes;
    # no_claim=-
    def test_install_block_holds_only_known_statements(self):
        with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as f:
            t = f.read()
        self.assertEqual(formula.installed_bins(t), ["ms", "msd", "ms-shim"])
        anchor = '    bin.install_symlink "ms" => "mors"\n'
        self.assertIn(anchor, t)
        for extra in ('    libexec.install "bin/x"\n', '    (bin/"x").write "echo"\n', '    system "curl", "x"\n',
                      '    bin.install_symlink "ms" => "../x"\n'):
            with self.assertRaises(formula.FormulaError, msg=extra):
                formula.installed_bins(t.replace(anchor, anchor + extra))

    def test_sign_targets_rows(self):
        self.assertEqual(formula.sign_targets("# c\n\nms cc.x\n"), [("ms", "cc.x")])
        with self.assertRaises(formula.FormulaError):
            formula.sign_targets("ms\n")


class FrozenConfigTests(unittest.TestCase):
    def test_signing_identifiers_are_frozen(self):
        with open(os.path.join(PKG, "macos", "sign-targets"), encoding="utf-8") as f:
            rows = [l.split() for l in f if l.strip() and not l.startswith("#")]
        self.assertEqual(rows, [["ms", "cc.morsec.ms"], ["msd", "cc.morsec.msd"],
                                ["ms-shim", "cc.morsec.ms-shim"]])

    # protects=L28: what the formula installs is exactly what release.sh builds and signs
    # (sign-targets), so ms-shim can't be dropped from one and not the other; fails_when=the two
    # lists differ; no_claim=the built binaries themselves (scripts/release-check.sh)
    def test_formula_installs_exactly_the_signed_binaries(self):
        with open(os.path.join(PKG, "macos", "sign-targets"), encoding="utf-8") as f:
            signed = [n for n, _ in formula.sign_targets(f.read())]
        with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as f:
            self.assertEqual(formula.installed_bins(f.read()), signed)
        self.assertIn("ms-shim", signed)

    # protects=release.sh ships what sign-targets lists, not a hard-coded pair; fails_when=a
    # loop over a fixed `ms msd` list comes back; no_claim=-
    def test_release_script_has_no_fixed_binary_list(self):
        with open(RELEASE, encoding="utf-8") as f:
            text = f.read()
        self.assertNotRegex(text, r"for b in ms msd")
        self.assertIn("-p ms-run", text)
        self.assertIn("--root ms-run", text)

    def test_msd_identifier_matches_launch_agent_label(self):
        with open(os.path.join(ROOT, "crates", "ms-cli", "src", "service.rs"), encoding="utf-8") as f:
            self.assertRegex(f.read(), r'pub const LABEL: &str = "cc\.morsec\.msd";')

    def test_no_entitlements(self):
        with open(os.path.join(PKG, "macos", "entitlements.plist"), "rb") as f:
            self.assertEqual(plistlib.load(f), {})


@unittest.skipUnless(IS_MAC_ARM and shutil.which("codesign") and shutil.which("cc"), "needs macOS arm64")
class MachoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.orig = os.path.join(self.tmp, "orig")
        # A thin arm64 binary with the linker's ad-hoc signature, like cargo's output.
        subprocess.run(["cc", "-x", "c", "-", "-o", self.orig], input=b"int main(void){return 0;}\n",
                       check=True, capture_output=True)

    def copy(self, name):
        p = os.path.join(self.tmp, name)
        shutil.copy(self.orig, p)
        return p

    def test_signature_does_not_change_code_digest(self):
        signed = self.copy("signed")
        subprocess.run(["codesign", "--force", "--options", "runtime", "--identifier", "cc.morsec.test",
                        "-s", "-", signed], check=True, capture_output=True)
        with open(self.orig, "rb") as a, open(signed, "rb") as b:
            self.assertNotEqual(a.read(), b.read())
        self.assertEqual(machocmp.code_digest(self.orig), machocmp.code_digest(signed))

    def text_offset(self, path):
        out = subprocess.run(["otool", "-l", path], check=True, capture_output=True, text=True).stdout
        m = re.search(r"sectname __text\n\s+segname __TEXT\n(?:.*\n){2}\s+offset (\d+)", out)
        self.assertIsNotNone(m, out)
        return int(m.group(1))

    def test_code_change_changes_digest(self):
        tampered = self.copy("tampered")
        with open(tampered, "r+b") as f:
            f.seek(self.text_offset(tampered))  # first instruction of __text
            byte = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([byte[0] ^ 0xFF]))
        self.assertNotEqual(machocmp.code_digest(self.orig), machocmp.code_digest(tampered))

    def test_refuses_bytes_after_signature_and_fat(self):
        padded = self.copy("padded")
        with open(padded, "ab") as f:
            f.write(b"extra")
        with self.assertRaisesRegex(machocmp.MachOError, "after the code signature"):
            machocmp.code_digest(padded)
        with self.assertRaisesRegex(machocmp.MachOError, "fat"):
            machocmp.code_digest("/usr/bin/true")


@unittest.skipUnless(IS_MAC_ARM and shutil.which("cargo"), "needs macOS arm64 and cargo")
class ReleaseScriptTests(unittest.TestCase):
    """`release` fails closed before building anything when a credential or precondition is missing."""

    def run_release(self, **env):
        base = {k: v for k, v in os.environ.items() if not k.startswith("MORSEC_")}
        base.update(env)
        return subprocess.run(["bash", RELEASE, "release", "--out", os.path.join(self.tmp, "out")],
                              env=base, capture_output=True, text=True, timeout=120)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.key = os.path.join(self.tmp, "k.key")
        with open(self.key, "w") as f:
            f.write("not a real key\n")

    def assertRefused(self, r, pattern):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertRegex(r.stderr, pattern)
        self.assertNotIn("cloning", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out")))

    def test_needs_identity(self):
        self.assertRefused(self.run_release(), "MORSEC_SIGN_IDENTITY")

    def test_refuses_adhoc_and_development_identities(self):
        for ident in ("-", "Apple Development: A B (ABCDE12345)", "Developer ID Application: A B",
                      "Developer ID Installer: A B (ABCDE12345)"):
            self.assertRefused(self.run_release(MORSEC_SIGN_IDENTITY=ident), "Developer ID Application identity only")

    def test_needs_notary_profile_and_key(self):
        ident = "Developer ID Application: A B (ABCDE12345)"
        self.assertRefused(self.run_release(MORSEC_SIGN_IDENTITY=ident), "MORSEC_NOTARY_PROFILE")
        self.assertRefused(self.run_release(MORSEC_SIGN_IDENTITY=ident, MORSEC_NOTARY_PROFILE="a b"), "profile name")
        self.assertRefused(self.run_release(MORSEC_SIGN_IDENTITY=ident, MORSEC_NOTARY_PROFILE="morsec"),
                           "MORSEC_MINISIGN_KEY")
        self.assertRefused(self.run_release(MORSEC_SIGN_IDENTITY=ident, MORSEC_NOTARY_PROFILE="morsec",
                                            MORSEC_MINISIGN_KEY=os.path.join(self.tmp, "missing")), "not a file")

    def test_later_preconditions_still_refuse(self):
        # With every credential named, it still stops at the repository checks (0.0.0 today; a
        # missing minisign.pub, a dirty tree or a missing tag later) before building.
        r = self.run_release(MORSEC_SIGN_IDENTITY="Developer ID Application: A B (ABCDE12345)",
                             MORSEC_NOTARY_PROFILE="morsec", MORSEC_MINISIGN_KEY=self.key)
        self.assertRefused(r, "0.0.0|minisign.pub|team-id|pinned to team|not clean|not tagged")

    def test_build_root_must_not_be_shared(self):
        # cargo reads .cargo/config.toml from every parent of the build dir.
        r = subprocess.run(["bash", RELEASE, "check-build-root", "/private/tmp"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("writable by group or others", r.stderr)
        r = subprocess.run(["bash", RELEASE, "check-build-root", self.tmp], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        os.mkdir(os.path.join(self.tmp, ".cargo"))
        child = os.path.join(self.tmp, "child")
        os.mkdir(child)
        r = subprocess.run(["bash", RELEASE, "check-build-root", child], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn(".cargo would configure the build", r.stderr)

    def test_formula_subcommand_refuses_bad_url(self):
        r = subprocess.run(["bash", RELEASE, "formula", "--version", "0.1.0", "--sha256", "a" * 64,
                            "--url", "https://x.example/#{x}.tar.gz", "--out", os.path.join(self.tmp, "f.rb")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "f.rb")))

    # protects=distribution: the 0.1.0 formula downloads the release tarball from the public
    # GitHub release of csakash/morsec; fails_when=the default URL points anywhere else
    def test_formula_targets_the_github_release(self):
        out = os.path.join(self.tmp, "f.rb")
        r = subprocess.run(["bash", RELEASE, "formula", "--version", "0.1.0", "--sha256", "a" * 64, "--out", out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as f:
            text = f.read()
        self.assertIn('  url "https://github.com/csakash/morsec/releases/download/v0.1.0/'
                      'morsec-0.1.0-aarch64-apple-darwin.tar.gz"\n', text)
        self.assertIn('  version "0.1.0"\n', text)

    def test_unknown_subcommand(self):
        r = subprocess.run(["bash", RELEASE, "publish"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


class NoSecretsInPackagingTests(unittest.TestCase):
    def test_no_key_material_committed(self):
        for dirpath, _, files in os.walk(PKG):
            for name in files:
                if name.endswith(".pyc"):
                    continue
                with open(os.path.join(dirpath, name), "rb") as f:
                    data = f.read()
                # Split so this file doesn't match itself.
                self.assertNotIn(b"minisign encrypted " + b"secret key", data, name)
                self.assertFalse(re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY", data), name)


if __name__ == "__main__":
    unittest.main()
