"""Tests for packaging/lib/releasecheck.py and scripts/release-check.sh (L28)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
ROOT = os.path.dirname(PKG)
sys.path.insert(0, os.path.join(PKG, "lib"))

import releasecheck  # noqa: E402

CHECK = os.path.join(ROOT, "scripts", "release-check.sh")
with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as _f:
    TEMPLATE = _f.read()
TARGETS = "# c\nms cc.morsec.ms\nmsd cc.morsec.msd\nms-shim cc.morsec.ms-shim\n"


def meta(versions: dict[str, str]) -> dict:
    pkgs = [{"id": f"path+file:///w/{n}#{v}", "name": n, "version": v} for n, v in versions.items()]
    return {"packages": pkgs + [{"id": "registry#x@9.9.9", "name": "x", "version": "9.9.9"}],
            "workspace_members": [p["id"] for p in pkgs]}


class VersionTests(unittest.TestCase):
    def test_accepts_one_released_version(self):
        self.assertEqual(releasecheck.check_version(meta({"ms-cli": "1.0.0", "msd": "1.0.0"})), "1.0.0")
        self.assertEqual(releasecheck.check_version(meta({"ms-cli": "1.0.0-rc.1"})), "1.0.0-rc.1")

    # protects=a release is never cut at 0.0.0 or with members at different versions;
    # fails_when=either passes; no_claim=-
    def test_refuses_unbumped_mixed_or_odd_versions(self):
        for m, pat in ((meta({"ms-cli": "0.0.0"}), "0.0.0"),
                       (meta({"ms-cli": "1.0.0", "msd": "0.9.0"}), "msd 0.9.0"),
                       (meta({"ms-cli": "1.0"}), "MAJOR"),
                       (meta({"ms-cli": "01.0.0"}), "MAJOR"),
                       (meta({"msd": "1.0.0"}), "ms-cli"),
                       ({"packages": [], "workspace_members": []}, "no workspace")):
            with self.assertRaisesRegex(releasecheck.CheckError, pat):
                releasecheck.check_version(m)


class ChangelogTests(unittest.TestCase):
    def test_counts_entries_of_the_version(self):
        t = "# C\n\n## [Unreleased]\n- later\n\n## [1.0.0] - 2026-12-01\n- one\n* two\n  - nested\n## [0.9.0]\n- old\n"
        self.assertEqual(releasecheck.check_changelog("1.0.0", t), 3)

    def test_refuses_missing_empty_or_duplicate_sections(self):
        for t in ("## [Unreleased]\n- x\n", "## [1.0.0]\n\n## [0.9.0]\n- x\n", "## [1.0.0]\n- a\n## [1.0.0]\n- b\n",
                  "## [1.0.0]\ntext only\n", "## 1.0.0\n- x\n"):
            with self.assertRaises(releasecheck.CheckError, msg=t):
                releasecheck.check_changelog("1.0.0", t)

    def test_repo_changelog_has_unreleased_and_no_0_0_0(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("## [Unreleased]", text)
        with self.assertRaises(releasecheck.CheckError):
            releasecheck.check_changelog("0.0.0", text)


class BinariesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def put(self, name, head=b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00"):
        with open(os.path.join(self.tmp, name), "wb") as f:
            f.write(head + b"\0" * 64)

    def test_matching_build_passes(self):
        for b in ("ms", "msd", "ms-shim"):
            self.put(b)
        self.assertEqual(releasecheck.check_binaries(TEMPLATE, TARGETS, self.tmp), ["ms", "msd", "ms-shim"])

    # protects=L28: the formula, the signing list and the build agree, so a release can't ship
    # without ms-shim or ship an unsigned tool; fails_when=a mismatch, a missing binary or a
    # non-arm64 file passes; no_claim=the code signature (release.sh)
    def test_refuses_mismatch_missing_or_wrong_arch(self):
        for b in ("ms", "msd", "ms-shim"):
            self.put(b)
        with self.assertRaisesRegex(releasecheck.CheckError, "sign-targets"):
            releasecheck.check_binaries(TEMPLATE.replace(', "bin/ms-shim"', ""), TARGETS, self.tmp)
        with self.assertRaisesRegex(releasecheck.CheckError, "sign-targets"):
            releasecheck.check_binaries(TEMPLATE, "ms a\nmsd b\n", self.tmp)
        os.remove(os.path.join(self.tmp, "ms-shim"))
        with self.assertRaisesRegex(releasecheck.CheckError, "not built.*ms-shim"):
            releasecheck.check_binaries(TEMPLATE, TARGETS, self.tmp)
        self.put("ms-shim", head=b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00")  # x86_64
        with self.assertRaisesRegex(releasecheck.CheckError, "arm64"):
            releasecheck.check_binaries(TEMPLATE, TARGETS, self.tmp)
        self.put("ms-shim", head=b"#!/bin/sh\n" + b"\0" * 6)
        with self.assertRaisesRegex(releasecheck.CheckError, "arm64"):
            releasecheck.check_binaries(TEMPLATE, TARGETS, self.tmp)

    def test_repo_formula_matches_sign_targets(self):
        with open(os.path.join(PKG, "homebrew", "morsec.rb.in"), encoding="utf-8") as f:
            template = f.read()
        with open(os.path.join(PKG, "macos", "sign-targets"), encoding="utf-8") as f:
            targets = f.read()
        for b in ("ms", "msd", "ms-shim"):
            self.put(b)
        self.assertEqual(releasecheck.check_binaries(template, targets, self.tmp), ["ms", "msd", "ms-shim"])


class ScriptTests(unittest.TestCase):
    """release-check.sh against a throwaway workspace (never this repo: a bumped repo would run
    the whole checklist, and these tests are part of it). The script finds its root from its
    own path, so a copy in the fixture checks the fixture."""

    def fixture(self, version: str, lock_version: str | None = None) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, "scripts"))
        shutil.copy(CHECK, os.path.join(d, "scripts", "release-check.sh"))
        shutil.copytree(os.path.join(PKG, "lib"), os.path.join(d, "packaging", "lib"))
        for crate in ("ms-cli", "msd"):
            os.makedirs(os.path.join(d, "crates", crate, "src"))
            with open(os.path.join(d, "crates", crate, "Cargo.toml"), "w") as f:
                f.write(f'[package]\nname = "{crate}"\nversion.workspace = true\nedition = "2021"\n')
            with open(os.path.join(d, "crates", crate, "src", "main.rs"), "w") as f:
                f.write("fn main() {}\n")
        with open(os.path.join(d, "Cargo.toml"), "w") as f:
            f.write(f'[workspace]\nmembers = ["crates/ms-cli", "crates/msd"]\nresolver = "2"\n'
                    f'[workspace.package]\nversion = "{version}"\n')
        lv = lock_version or version
        with open(os.path.join(d, "Cargo.lock"), "w") as f:
            f.write(f'version = 4\n\n[[package]]\nname = "ms-cli"\nversion = "{lv}"\n\n'
                    f'[[package]]\nname = "msd"\nversion = "{lv}"\n')
        subprocess.run(["git", "init", "-q", d], check=True)
        return d

    def run_check(self, d: str, *steps: str) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_TARGET", "MORSEC_"))}
        return subprocess.run(["bash", os.path.join(d, "scripts", "release-check.sh"), *steps],
                              capture_output=True, text=True, timeout=120, env=env)

    # protects=release-check stops at step 1 while the version is 0.0.0 and never reaches the
    # build; fails_when=it builds or passes unbumped; no_claim=-
    def test_stops_at_an_unbumped_version(self):
        r = self.run_check(self.fixture("0.0.0"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("0.0.0", r.stderr)
        self.assertNotIn("2/5", r.stdout)

    def test_version_step_passes_a_bumped_workspace(self):
        r = self.run_check(self.fixture("1.2.3"), "version")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("version 1.2.3", r.stdout)

    # protects=a stale Cargo.lock fails step 1 on its own (not only at the build); fails_when=a
    # lock at another version passes; no_claim=-
    def test_version_step_refuses_a_stale_lock(self):
        r = self.run_check(self.fixture("1.2.3", lock_version="1.2.2"), "version")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Cargo.lock", r.stderr)

    def test_changelog_step_on_the_fixture(self):
        d = self.fixture("1.2.3")
        r = self.run_check(d, "changelog")
        self.assertEqual(r.returncode, 1)
        self.assertIn("CHANGELOG.md is missing", r.stderr)
        with open(os.path.join(d, "CHANGELOG.md"), "w") as f:
            f.write("## [1.2.3] - 2026-12-01\n- first\n")
        r = self.run_check(d, "changelog")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unknown_step_is_usage(self):
        r = subprocess.run(["bash", CHECK, "publish"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    # protects=release-check never signs, notarizes, tags, pushes or uploads, and reads no
    # credential variable; fails_when=one of those commands or MORSEC_* credentials appear;
    # no_claim=what a human runs afterwards
    def test_has_no_release_side_effects(self):
        with open(CHECK, encoding="utf-8") as f:
            code = "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))
        for bad in ("codesign", "notarytool", "minisign", "git tag", "git push", "gh ", "curl", "MORSEC_SIGN",
                    "MORSEC_NOTARY", "MORSEC_MINISIGN", "release.sh release", "brew tap", "brew install morsec", "brew upgrade"):
            self.assertNotIn(bad, code)


if __name__ == "__main__":
    unittest.main()
