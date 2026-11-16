# PROOF: release-cli (L28, CLI-only release prep)

Branch `feat/release-cli`. Spec: `SPEC.md`. This loop prepares the first signed Homebrew CLI
release. It does not sign, notarize, tag, push, publish or create the tap repo; those stay human
steps in `packaging/RELEASING.md`.

## What changed

- **`ms-shim` ships with `ms` and `msd`.** `packaging/macos/sign-targets` is now the one list of
  shipped binaries. `scripts/release.sh` builds, hashes (BUILDINFO), SBOMs (root `ms-run`),
  signs, archives and repro-compares every name on it, with no hard-coded `ms msd`. It gains
  `ms-shim cc.morsec.ms-shim`; `cc.morsec.ms` and `cc.morsec.msd` are unchanged. The Homebrew
  template installs `bin/ms-shim` next to `ms`, and its `test do` block checks it.
- **Formula checks fail closed.** `packaging/lib/formula.py` whitelists the whole formula: the
  class statements, `def install`, `def caveats` and `test do`. It refuses `post_install`,
  `service`, `system`, writes, `.`/`..` names and symlinks that replace a tool. The formula must
  install exactly the sign-targets list.
- **Install test** (`packaging/tests/test_install.py`, runs in the gate):
  - Builds a tarball from the built `ms`, `msd` and `ms-shim`.
  - Installs it into a temp prefix the way the formula does (`packaging/lib/install_sim.py`:
    Cellar keg, `brew link`-style symlinks, `mors`).
  - Starts the installed `msd --vault memory` with a temp HOME, socket and state, and a
    debug-only Touch ID stand-in.
  - Adds a test-tier run key and runs the installed `ms doctor`. The run-shims section does not
    say ms-shim is missing; after `ms run --link-shims` it passes ("✓ 1 shim linked"), and the
    shim is a hard link of the Cellar `ms-shim`.
  - Control: the same tarball through a formula without `ms-shim`. Doctor and `--link-shims`
    both report "ms-shim is not installed next to ms".
- **Kill receipts** (`crates/msd/src/daemon/run.rs`, L12 review N3). A run killed by `ms stop`
  or a LOG-2 session stop writes one `Failed("killed: …")` receipt per run-mode key. The receipt
  carries the start receipt's target, argv hash, rule version and approval id. This covers both
  buffered `Run` and `RunStream`. It is `Failed`, not `Blocked`, so LOG-2 alert counting is
  unchanged.
- **`scripts/release-check.sh`** runs five steps:
  1. version: X.Y.Z, not 0.0.0, and every crate the same. `Cargo.lock` is checked with a
     resolving `--locked`. No `v<version>` tag may sit anywhere but HEAD.
  2. CHANGELOG section.
  3. `cargo build --release --locked`, and `ms --version` matches.
  4. Packaging tests and shellcheck.
  5. The formula matches sign-targets and the release build, each an arm64 executable. The
     release binaries, installed through the formula's lines, pass its `test do` block.

  Logic is in `packaging/lib/releasecheck.py`. The script never signs, tags or publishes.
- **Docs:**
  - `CHANGELOG.md` (new) and `docs/ONBOARDING.md` (new): install to a protected session, run
    mode, day to day, upgrade, and migration from dev installs.
  - README rewritten. RELEASING runs release-check before the tag, adds a "What stays human"
    section and puts `ms-shim` in the steps. VERIFY covers `ms-shim`.
  - Formula caveats: upgrade with `brew upgrade morsec && ms init && ms run --link-shims`.
  - PLAN: the L28 card is updated, and L26/L27 move to a new wave 6 (v1.x), so L28 depends on
    L24 only.
  - ARI42.md: GW-2 and LOG-1 rows, plus a change-log line.
- **Small fixes:**
  - `scripts/install-dev.sh` also builds `ms-shim`.
  - `ms add --help` no longer promises 1Password/Bitwarden, which is L26, v1.x.
  - `scripts/check.sh` 7b also shellchecks `release-check.sh` (a one-line change).

## Testing

| Check | Result |
|---|---|
| `npm run build` (scripts/check.sh) on a3bdd6f (and on fc4f353) | **all checks passed**: fmt, build, clippy `-D warnings`, 494 cargo tests (0 failed), deny, audit, supply chain, 59 packaging tests + shellcheck, ARI-42 scan, security evals (canary, doctor e2e, agent_e2e) |
| Kill receipts | `stop_kills_a_running_command` (buffered) and `stop_kill_is_recorded_when_streaming` (streamed): exactly one `{"failed":"killed: morsec was stopped (ms stop)"}` receipt, with the same argv hash as the start receipt, and no value in receipts |
| Install test | `test_installed_ms_finds_its_shim`, `test_control_without_shim_is_reported`, `test_formula_test_block` pass. The real `~/.claude/settings.json`, `~/.codex/config.toml`, `~/.ssh`, `~/.gitconfig`, `~/.git-credentials` and `~/.morsec/shims` are unchanged, checked by the test. No processes or temp dirs are left behind |
| `scripts/release-check.sh` on this branch | Fails at step 1, as specified: "the workspace version is 0.0.0: bump [workspace.package] version in Cargo.toml first" |
| `scripts/release-check.sh build tests binaries` | passed: `morsec 0.0.0 (bed8c5c)`, 54 packaging tests at that point, `ms msd ms-shim`, "installed from the formula: ms msd ms-shim + mors; test block passes" |
| Script tests on a throwaway workspace | Unbumped stops at step 1; 1.2.3 passes the version step; a stale `Cargo.lock` fails step 1; the changelog step fails when the file is missing and passes with an entry |
| `scripts/release.sh build` (unsigned, from a clean clone of c201467) | Tarball holds `bin/ms`, `bin/ms-shim`, `bin/msd`. BUILDINFO has `unsigned_sha256.ms-shim` and `code_sha256.ms-shim`. The SBOM includes `ms-run`. The rendered formula installs all three |
| `MORSEC_SIGN_IDENTITY=- scripts/release.sh build` (ad-hoc) | `ms-shim` signed `Identifier=cc.morsec.ms-shim`, flags `adhoc,runtime`, machocmp `--same` passed. BUILDINFO is byte-identical to the unsigned build's |
| `scripts/release.sh verify-repro` on a3bdd6f | **reproducible: both builds are identical**, including `ms-shim` (`unsigned_sha256.ms-shim=bc7ca1b2…`). A first run was split by a commit made between its two builds (only `ms`, which embeds the commit, differed); `verify-repro` now pins one commit for both builds |

Not tested (human steps): a Developer ID signature, notarization, `spctl`, a real `brew install`
from the tap, `brew test`, `brew upgrade`, and the clean-VM install and its timing.

## Risk

- **Sensitive paths for a human reviewer** (loops.json `review.sensitivePaths`):
  `crates/msd/src/daemon/run.rs`, `crates/ms-cli/src/main.rs` (help text only),
  `scripts/release.sh`, `scripts/release-check.sh`, `scripts/check.sh` (one line),
  `scripts/install-dev.sh`, `packaging/lib/install_sim.py`.
- **Signing surface grows by one binary.** `ms-shim` gets a new identifier,
  `cc.morsec.ms-shim`, with hardened runtime and no entitlements. The frozen identifiers are
  unchanged and pinned by tests. Nothing in the keychain ACL trusts `ms-shim`.
- **msd change is small and fail-closed.** The child is killed before the kill receipt is
  written. A receipt write failure is logged and the client still gets `Denied`. A client that
  hangs up mid-run (no stop) still has only its start receipt.
- **Known gap, still open:** `ms init` writes the LaunchAgent with the canonicalized (Cellar,
  versioned) msd path, and run shims are copies of the old `ms-shim`. After `brew upgrade` the
  user must re-run `ms init && ms run --link-shims`; the caveats, README and ONBOARDING say so.
  The real fix is to use `$(brew --prefix)/opt/morsec/bin/…` under a Cellar (L10 follow-up). It
  is recorded in the PLAN L28 card as "fix before the first release".
- **Process note:** during exploration, one manual trial ran a dev `msd` without the Touch ID
  stand-in, so `ms rules` asked for real Touch ID. Nothing was approved. msd was killed (the
  sheet went with it) and every test since uses `--test-touch-id allow`.

## Reviews

| Round | Result |
|---|---|
| Code review (fresh context) | 2 important, 2 minor. All fixed: the install test reads the workspace version; script tests are hermetic (no release-check recursion after a bump); step 1 really checks the lock; detached shells are reaped; doc wording fixed |
| Security review (fresh context) | No security issues. One minor finding, the same recursion as above, is fixed. Acted on its observation that only `def install` was whitelisted |
| Re-review of the fixes | 2 important, 4 minor. All fixed in fc4f353: whole-formula whitelist; the brew upgrade path documented and in the caveats; dot and shadowing names refused; safer teardown; ONBOARDING accuracy (import tiers and hosts, session approvals, commit advice, not yet released); stale `ms add` help |

## ARI-42

- **GW-2:** Partial (strengthened). `ms-shim` is signed, hashed, SBOM'd and archived like
  `ms`/`msd`; the formula is whitelisted and tied to sign-targets; release-check runs before
  tagging.
- **LOG-1:** Partial (strengthened). Runs killed by a stop are recorded.
- Scan: no high findings. Low SDLC-2 hits are pre-existing ms-connect test fixtures.

## How to revert

`git revert` the loop's merge commit on main (or its commits on this branch: bed8c5c spec,
94fd7a3, the check.sh commit, c201467, fc4f353, a3bdd6f, and this PROOF update). Nothing outside the repo changes: no release,
tag, tap or user data was created. After a revert, the release again ships only `ms` and `msd`
(run mode needs a manual `ms-shim`), and `ms stop` kills runs without a kill receipt.
