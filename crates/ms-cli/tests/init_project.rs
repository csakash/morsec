//! `ms init` end to end (L31 guided-init, SPEC criteria 1 to 4 and 8): the built `ms` and a dev
//! `msd` (memory vault, `--test-touch-id allow` standing in for the Touch ID sheet only), a temp
//! HOME and a fixture project under /tmp.
//!
//! These tests may run inside an agent session (the gate is often run by one), and msd refuses
//! `ProjectSave` there. So every `ms init` runs detached from this test's process tree (reparented
//! to PID 1), as the user's own terminal would. Approvals are answered the way a person does: in
//! `ms init`'s inline review on a pseudo-terminal (`script`), typing `o` (or `d`).

// `--test-touch-id` exists only in debug builds of msd.
#![cfg(debug_assertions)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Keys written into code: must never be stored, rewritten or printed.
const CODE_CANARY: &str = concat!("sk_live_", "CODECANARY0a1b2c3d4e5f6g7h8i9j");
/// Values in files morsec must never read: behind a symlink and in node_modules.
const LINK_CANARY: &str = "sk_test_51LINKCANARYlinkcanary0000000";
const NM_CANARY: &str = "sk_test_51NODEMODULESCANARY000000000";
/// The real values.
const T_ROOT: &str = "sk_test_51ROOTvalueROOTvalueROOTvalue";
const T_PROD: &str = "sk_test_51PRODvaluePRODvaluePRODvalue";
// A fake OpenAI-shaped value, split so secret scanners don't take the source for a key.
const OAI: &str = concat!("sk-", "proj-", "OAIvalueOAIvalueOAIvalueOAIvalue0123");
const SESSION: &str = "f3a9c2e7b1d84f6a9c0e2b4d6f8a1c3e";

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

fn msd() -> PathBuf {
    let p = ms().with_file_name("msd");
    assert!(
        p.exists(),
        "{} not built; run cargo build --workspace first",
        p.display()
    );
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

static RUNS: AtomicU32 = AtomicU32::new(0);

struct Fx {
    dir: tempfile::TempDir,
    _d: Daemon,
}

impl Fx {
    fn new() -> Self {
        // /tmp keeps the socket path short; canonical so paths match msd's (/tmp is a link).
        let dir = tempfile::Builder::new()
            .prefix("msinit")
            .tempdir_in("/tmp")
            .unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        for d in ["home", "tmp", "outside"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join("run"))
            .unwrap();
        let socket = base.join("run/msd.sock");
        let child = Command::new(msd())
            .args(["--foreground", "--vault", "memory", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(base.join("state"))
            .args(["--proxy-port", &free_port().to_string()])
            .args(["--test-touch-id", "allow"])
            // Nothing from the developer's environment (SSL_CERT_FILE makes msd refuse to start).
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", base.join("home"))
            .env("TMPDIR", base.join("tmp"))
            .env("MORSEC_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let d = Daemon(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "msd never came up");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { dir, _d: d }
    }

    fn base(&self) -> PathBuf {
        std::fs::canonicalize(self.dir.path()).unwrap()
    }
    fn home(&self) -> PathBuf {
        self.base().join("home")
    }
    fn socket(&self) -> PathBuf {
        self.base().join("run/msd.sock")
    }
    fn audit(&self) -> PathBuf {
        self.base().join("walk-audit.txt")
    }

    fn env_line(&self) -> String {
        format!(
            "export PATH='/usr/bin:/bin' HOME='{}' MORSEC_SOCKET='{}' TMPDIR='{}/tmp' LANG=C MORSEC_DEV_UNVERIFIED_DAEMON=1 MORSEC_TEST_WALK_AUDIT='{}'",
            self.home().display(),
            self.socket().display(),
            self.base().display(),
            self.audit().display()
        )
    }

    /// Runs `command` in `cwd`, detached from this test's process tree (the user's own
    /// terminal). Returns (exit code, output).
    fn outside(&self, cwd: &Path, command: &str) -> (i32, String) {
        let n = RUNS.fetch_add(1, Ordering::Relaxed);
        let d = self.base();
        let script = d.join(format!("outside{n}.sh"));
        let out = d.join(format!("outside{n}.out"));
        let rc = d.join(format!("outside{n}.rc"));
        std::fs::write(
            &script,
            format!("{}\ncd '{}'\n{command}\n", self.env_line(), cwd.display()),
        )
        .unwrap();
        let st = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "(sleep 0.3; /bin/sh '{}' > '{}' 2>&1; echo $? > '{}.tmp'; mv '{}.tmp' '{}') </dev/null >/dev/null 2>&1 &",
                script.display(),
                out.display(),
                rc.display(),
                rc.display(),
                rc.display()
            ))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap();
        assert!(st.success());
        let deadline = Instant::now() + Duration::from_secs(150);
        loop {
            if let Ok(code) = std::fs::read_to_string(&rc) {
                let text = std::fs::read_to_string(&out)
                    .unwrap_or_default()
                    .replace("\r\n", "\n");
                return (code.trim().parse().unwrap_or(-1), text);
            }
            assert!(Instant::now() < deadline, "detached command never finished");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `ms init <args>` on a pseudo-terminal, answering every review with `answer`.
    fn init_answering(&self, cwd: &Path, answer: &str, args: &str) -> (i32, String) {
        let ms = ms();
        self.outside(
            cwd,
            &format!(
                "(i=0; while [ $i -lt 200 ]; do printf '{answer}\\n'; sleep 0.3; i=$((i+1)); done) | script -q /dev/null '{}' init --no-connect {args}",
                ms.display()
            ),
        )
    }

    /// `ms init <args>` with no terminal at all.
    fn init_plain(&self, cwd: &Path, args: &str) -> (i32, String) {
        self.outside(
            cwd,
            &format!("'{}' init --no-connect {args}", ms().display()),
        )
    }

    /// `ms <args>` from this process (read-only requests answer agents too).
    fn ms(&self, args: &[&str]) -> (i32, String) {
        let o = Command::new(ms())
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home())
            .env("MORSEC_SOCKET", self.socket())
            .env("MORSEC_DEV_UNVERIFIED_DAEMON", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr),
        )
    }

    /// A copy of `ms` named `claude`: whatever it runs is inside a Claude Code session.
    fn fake_agent(&self) -> PathBuf {
        let p = self.base().join("bin/claude");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(ms(), &p).unwrap();
        p
    }

    /// The SPEC criterion 2 fixture project, `shop`.
    fn shop(&self) -> PathBuf {
        let root = self.base().join("shop");
        for d in ["apps/web", "node_modules/x", "src"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("package.json"), "{\"name\":\"shop\"}\n").unwrap();
        std::fs::write(
            root.join(".env"),
            format!(
                "# shop\nSTRIPE_SECRET_KEY={T_ROOT}\nOPENAI_API_KEY=\"{OAI}\"\nSESSION_SECRET={SESSION}\nPORT=3000\n"
            ),
        )
        .unwrap();
        std::fs::write(
            root.join(".env.production"),
            format!("STRIPE_SECRET_KEY={T_PROD}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("apps/web/.env"),
            format!("OPENAI_API_KEY={OAI}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join(".env.example"),
            "STRIPE_SECRET_KEY=\nOPENAI_API_KEY=\nSESSION_SECRET=\n",
        )
        .unwrap();
        std::fs::write(
            self.base().join("outside/.env"),
            format!("STRIPE_SECRET_KEY={LINK_CANARY}\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink("../outside/.env", root.join(".env.link")).unwrap();
        std::fs::write(
            root.join("node_modules/x/.env"),
            format!("STRIPE_SECRET_KEY={NM_CANARY}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("src/stripe.ts"),
            format!("import Stripe from 'stripe';\n\n// TODO move\nconst stripe = new Stripe(\"{CODE_CANARY}\");\n"),
        )
        .unwrap();
        std::fs::write(root.join("CLAUDE.md"), "# Shop\n\nUse pnpm.\n").unwrap();
        root
    }

    /// Every file under `dir` with its bytes.
    fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let ft = e.file_type().unwrap();
                if ft.is_dir() {
                    stack.push(e.path());
                } else if ft.is_file() {
                    out.push((e.path(), std::fs::read(e.path()).unwrap_or_default()));
                }
            }
        }
        out
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

/// Every vault value the fixture stores.
const VALUES: [&str; 4] = [T_ROOT, T_PROD, OAI, SESSION];

// protects=SPEC criterion 1: ms init in $HOME (a git repo holding a .env), in / and in an
// unmarked folder of a dotfiles $HOME runs machine steps only: no walk call at all (the walk's
// audit file is never written), no key stored, the .env untouched, no project row;
// fails_when=any of those runs the walk, stores a key or rewrites a file; no_claim=doctor's own
// reads of agent settings (morsec's own configuration)
#[test]
fn init_in_home_is_machine_mode() {
    let fx = Fx::new();
    let home = fx.home();
    std::fs::write(home.join(".env"), format!("STRIPE_SECRET_KEY={T_ROOT}\n")).unwrap();
    std::fs::create_dir_all(home.join("notes")).unwrap();
    std::fs::write(home.join("notes/todo.txt"), "x\n").unwrap();
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .status();
    let git_repo = git.is_ok_and(|s| s.success());
    for cwd in [home.clone(), PathBuf::from("/"), home.join("notes")] {
        let (code, out) = fx.init_plain(&cwd, "");
        assert_eq!(code, 0, "{}: {out}", cwd.display());
        assert!(out.contains("morsec is on."), "{out}");
        assert!(!out.contains("Project "), "{}: {out}", cwd.display());
    }
    assert!(
        !fx.audit().exists(),
        "the walk ran in machine mode: {}",
        std::fs::read_to_string(fx.audit()).unwrap_or_default()
    );
    assert_eq!(
        read(&home.join(".env")),
        format!("STRIPE_SECRET_KEY={T_ROOT}\n")
    );
    let (_, list) = fx.ms(&["projects"]);
    assert!(list.contains("No projects yet"), "{list}");
    let (_, status) = fx.ms(&["status"]);
    assert!(status.contains("0 secrets protected"), "{status}");
    // --project at $HOME is refused, not scanned.
    let (code, out) = fx.init_plain(&home, "--project");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("home folder"), "{out}");
    assert!(!fx.audit().exists());
    let _ = git_repo;
}

// protects=SPEC criterion 2 end to end: the three real env files are imported and nothing from
// .env.example, the .env.link symlink target or node_modules; keys are <slug>/<var>, the
// .env.production clash gets <slug>/production/<var> at production tier, the value shared with
// apps/web/.env is one key; the files hold refs only; one approval (one review screen) gives the
// known swap keys their catalog hosts while the unknown key still allows nothing; the code canary
// is reported as src/stripe.ts:4 and is in no other file, receipt, record or output, and no
// value is; fails_when=any of those breaks; no_claim=the real Touch ID sheet (--test-touch-id
// stands in), real provider calls
#[test]
fn init_project_end_to_end() {
    let fx = Fx::new();
    let root = fx.shop();
    let stripe_ts = std::fs::read(root.join("src/stripe.ts")).unwrap();
    let example = std::fs::read(root.join(".env.example")).unwrap();
    let (code, out) = fx.init_answering(&root, "o", "");
    assert_eq!(code, 0, "{out}");

    assert_eq!(out.matches("Approval request").count(), 1, "{out}");
    for want in [
        "morsec is on.",
        "Project    shop  (",
        "Found      5 secrets in 3 files",
        "Protected  3, ready to use",
        "Needs you  1 has no known service yet: ms rules shop/session-secret --add-host <host>",
        "In code    1 key written straight into src/stripe.ts:4",
        "See everything: ms projects shop",
    ] {
        assert!(out.contains(want), "missing {want:?}:\n{out}");
    }
    assert!(!out.contains("dashboard"), "{out}");

    assert_eq!(
        read(&root.join(".env")),
        "# shop\nSTRIPE_SECRET_KEY=ms://shop/stripe-secret-key\nOPENAI_API_KEY=\"ms://shop/openai-api-key\"\nSESSION_SECRET=ms://shop/session-secret\nPORT=3000\n"
    );
    assert_eq!(
        read(&root.join(".env.production")),
        "STRIPE_SECRET_KEY=ms://shop/production/stripe-secret-key\n"
    );
    assert_eq!(
        read(&root.join("apps/web/.env")),
        "OPENAI_API_KEY=ms://shop/openai-api-key\n"
    );
    assert_eq!(std::fs::read(root.join(".env.example")).unwrap(), example);
    assert_eq!(
        std::fs::read(root.join("src/stripe.ts")).unwrap(),
        stripe_ts
    );
    assert!(contains(
        &std::fs::read(fx.base().join("outside/.env")).unwrap(),
        LINK_CANARY
    ));
    assert!(contains(
        &std::fs::read(root.join("node_modules/x/.env")).unwrap(),
        NM_CANARY
    ));

    let (code, detail) = fx.ms(&["projects", "shop"]);
    assert_eq!(code, 0, "{detail}");
    for want in [
        "shop/stripe-secret-key  swap  test  ready  api.stripe.com",
        "shop/production/stripe-secret-key  swap  production  ready  api.stripe.com",
        "shop/openai-api-key  swap  production  ready  api.openai.com",
        "shop/session-secret  swap  production  needs you  -",
        "src/stripe.ts:4  stripe  sk_live_…",
    ] {
        assert!(detail.contains(want), "missing {want:?}:\n{detail}");
    }
    assert_eq!(
        detail.matches("swap").count(),
        4,
        "exactly four keys: {detail}"
    );
    let (_, list) = fx.ms(&["projects"]);
    assert!(
        list.contains("shop") && list.contains(&root.display().to_string()),
        "{list}"
    );

    // No canary or value in any output, state file (receipts, rules, projects.toml) or any other
    // project file.
    let state = Fx::files_under(&fx.base().join("state"));
    assert!(state.iter().any(|(p, _)| p.ends_with("projects.toml")));
    let mut blobs: Vec<(String, Vec<u8>)> = vec![
        ("ms init output".into(), out.into_bytes()),
        ("ms projects".into(), detail.into_bytes()),
    ];
    blobs.extend(state.into_iter().map(|(p, b)| (p.display().to_string(), b)));
    blobs.extend(
        Fx::files_under(&root)
            .into_iter()
            .filter(|(p, _)| {
                !p.ends_with("src/stripe.ts") && !p.starts_with(root.join("node_modules"))
            })
            .map(|(p, b)| (p.display().to_string(), b)),
    );
    for (what, bytes) in &blobs {
        for needle in [CODE_CANARY, LINK_CANARY, NM_CANARY]
            .iter()
            .chain(VALUES.iter())
        {
            assert!(!contains(bytes, needle), "{needle} leaked into {what}");
        }
    }
}

// protects=SPEC criterion 3: declining the one approval leaves the keys stored and inert, the
// files rewritten and a summary line saying to run ms init again; running it again asks once more
// and finishes with the keys ready; fails_when=a declined run applies a rule, loses the keys or
// the files, or the re-run doesn't ask; no_claim=timeouts (same NeedsApproval path as a denial)
#[test]
fn declined_approval_then_init_again() {
    let fx = Fx::new();
    let root = fx.shop();
    let (code, out) = fx.init_answering(&root, "d", "");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Run ms init again to approve"), "{out}");
    assert!(out.contains("Protected  0, ready to use"), "{out}");
    assert!(read(&root.join(".env")).contains("ms://shop/stripe-secret-key"));
    let (_, detail) = fx.ms(&["projects", "shop"]);
    assert!(
        detail.contains("shop/stripe-secret-key  swap  test  needs you  -"),
        "{detail}"
    );

    let (code, out) = fx.init_answering(&root, "o", "");
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.matches("Approval request").count(), 1, "{out}");
    assert!(out.contains("Protected  3, ready to use"), "{out}");
    assert!(!out.contains("Run ms init again"), "{out}");
    let (_, detail) = fx.ms(&["projects", "shop"]);
    assert!(
        detail.contains("shop/stripe-secret-key  swap  test  ready  api.stripe.com"),
        "{detail}"
    );
}

// protects=SPEC criterion 4: a second ms init with no new values imports nothing, asks no
// approval (it runs with no terminal, so a request would time out and fail) and says "already
// protected"; the files and keys are unchanged; fails_when=it re-imports, renames a key or asks;
// no_claim=new values added between runs (they import like the first run)
#[test]
fn reinit_is_idempotent() {
    let fx = Fx::new();
    let root = fx.shop();
    let (code, out) = fx.init_answering(&root, "o", "");
    assert_eq!(code, 0, "{out}");
    let before: Vec<(PathBuf, Vec<u8>)> = Fx::files_under(&root);
    let (_, detail_before) = fx.ms(&["projects", "shop"]);

    let started = Instant::now();
    let (code, out) = fx.init_plain(&root, "");
    assert_eq!(code, 0, "{out}");
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "it waited for an approval"
    );
    assert!(
        out.contains("nothing new; 3 already protected, 1 still needs you"),
        "{out}"
    );
    assert!(!out.contains("needs your approval"), "{out}");
    assert_eq!(Fx::files_under(&root), before);
    let (_, detail_after) = fx.ms(&["projects", "shop"]);
    let keys = |d: &str| -> Vec<String> {
        d.lines()
            .filter(|l| l.starts_with("shop/"))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(keys(&detail_after), keys(&detail_before));
}

// protects=SPEC criterion 8: the hint block is appended once to the existing CLAUDE.md, never
// creates AGENTS.md, and is not duplicated on re-run; fails_when=a second block, a created file,
// or the user's text changes; no_claim=removal on Undo (L33)
#[test]
fn hint_block_once_and_never_created() {
    let fx = Fx::new();
    let root = fx.shop();
    let (code, out) = fx.init_answering(&root, "o", "");
    assert_eq!(code, 0, "{out}");
    let text = read(&root.join("CLAUDE.md"));
    assert!(
        text.starts_with("# Shop\n\nUse pnpm.\n\n<!-- morsec:begin -->\n"),
        "{text}"
    );
    assert_eq!(text.matches("<!-- morsec:begin -->").count(), 1);
    assert!(text.contains("ms://shop/..."), "{text}");
    assert!(!root.join("AGENTS.md").exists());
    let (code, out) = fx.init_plain(&root, "");
    assert_eq!(code, 0, "{out}");
    assert_eq!(read(&root.join("CLAUDE.md")), text);
    assert!(!root.join("AGENTS.md").exists());
}

// protects=design §4.5 code findings: a key written into source is reported with file:line and a
// masked form, and is never stored (no key for it), never rewritten (byte-identical file) and
// never printed; fails_when=the source file changes, a key holds it, or it appears in output or
// msd's files; no_claim=keys of providers the catalog doesn't know (not detected)
#[test]
fn code_finding_never_stored_or_rewritten() {
    let fx = Fx::new();
    let root = fx.base().join("app");
    std::fs::create_dir_all(root.join("lib")).unwrap();
    std::fs::write(root.join("go.mod"), "module app\n").unwrap();
    let src = format!("package lib\n\nvar key = \"{CODE_CANARY}\"\n");
    std::fs::write(root.join("lib/pay.go"), &src).unwrap();
    let (code, out) = fx.init_plain(&root, "");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("In code    1 key written straight into lib/pay.go:3"),
        "{out}"
    );
    assert!(out.contains("no secrets in this project"), "{out}");
    assert_eq!(read(&root.join("lib/pay.go")), src);
    let (_, detail) = fx.ms(&["projects", "app"]);
    assert!(
        detail.contains("lib/pay.go:3  stripe  sk_live_…"),
        "{detail}"
    );
    assert!(!detail.contains("app/"), "no key was stored: {detail}");
    let (_, status) = fx.ms(&["status"]);
    assert!(status.contains("0 secrets protected"), "{status}");
    for (p, b) in Fx::files_under(&fx.base().join("state")) {
        assert!(!contains(&b, CODE_CANARY), "{}", p.display());
    }
    assert!(!out.contains(CODE_CANARY) && !detail.contains(CODE_CANARY));
}

// protects=design §8 "Agent drives ProjectInit": ms init in a project from inside an agent
// session refuses before reading or changing anything (no walk, no key, no rewrite);
// fails_when=an agent's ms init imports or reaches msd's ProjectSave; no_claim=msd's own refusal
// (daemon project_requests_refused_in_agent_session)
#[test]
fn agent_session_cannot_init_a_project() {
    let fx = Fx::new();
    let root = fx.shop();
    let env_before = read(&root.join(".env"));
    let o = Command::new(fx.fake_agent())
        .args(["init", "--no-connect"])
        .current_dir(&root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fx.home())
        .env("MORSEC_SOCKET", fx.socket())
        .env("MORSEC_DEV_UNVERIFIED_DAEMON", "1")
        .env("MORSEC_TEST_WALK_AUDIT", fx.audit())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&o.stderr).into_owned() + &String::from_utf8_lossy(&o.stdout);
    assert!(!o.status.success(), "{text}");
    assert!(text.contains("own terminal"), "{text}");
    assert_eq!(read(&root.join(".env")), env_before);
    assert!(!fx.audit().exists());
    let (_, status) = fx.ms(&["status"]);
    assert!(status.contains("0 secrets protected"), "{status}");
}

// protects=review R1: keys stored by a run that never saved its record (here: `ms import --name
// shop/...`, the same state a Ctrl-C at the approval leaves behind with no record) are found by
// their refs on the next ms init, recorded with their provider from the variable name, and given
// their services after one approval; and the record is saved before the approval is asked, so a
// denial still leaves them listed; fails_when=the next ms init says it found nothing, or the keys
// stay unrecorded or inert; no_claim=refs to keys outside the project's slug (never adopted)
#[test]
fn orphaned_keys_are_adopted_on_reinit() {
    let fx = Fx::new();
    let root = fx.base().join("shop");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("package.json"), "{}\n").unwrap();
    std::fs::write(
        root.join(".env"),
        format!("STRIPE_SECRET_KEY={T_ROOT}\nOPENAI_API_KEY={OAI}\nSESSION_SECRET={SESSION}\nOTHER=ms://other/key\n"),
    )
    .unwrap();
    let (code, out) = fx.outside(
        &root,
        &format!(
            "'{}' import --yes --name STRIPE_SECRET_KEY=shop/stripe-secret-key --name OPENAI_API_KEY=shop/openai-api-key --name SESSION_SECRET=shop/session-secret .env",
            ms().display()
        ),
    );
    assert_eq!(code, 0, "{out}");
    assert!(read(&root.join(".env")).contains("ms://shop/stripe-secret-key"));

    // Denied: the record is already saved, so the keys are listed (inert).
    let (code, out) = fx.init_answering(&root, "d", "");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("Recovered  3 keys an earlier run stored"),
        "{out}"
    );
    assert!(out.contains("Run ms init again to approve"), "{out}");
    let (_, detail) = fx.ms(&["projects", "shop"]);
    assert!(
        detail.contains("shop/stripe-secret-key  swap  test  needs you  -"),
        "{detail}"
    );
    assert!(!detail.contains("other/key"), "{detail}");

    let (code, out) = fx.init_answering(&root, "o", "");
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.matches("Approval request").count(), 1, "{out}");
    assert!(
        out.contains("nothing new; 2 already protected, 1 still needs you"),
        "{out}"
    );
    let (_, detail) = fx.ms(&["projects", "shop"]);
    for want in [
        "shop/stripe-secret-key  swap  test  ready  api.stripe.com",
        "shop/openai-api-key  swap  production  ready  api.openai.com",
        "shop/session-secret  swap  production  needs you  -",
    ] {
        assert!(detail.contains(want), "missing {want:?}:\n{detail}");
    }
}

// protects=review R3: file-derived names never make the record invalid: an env file whose name
// has a control character is left byte-identical and listed as skipped (its secret stays out of
// the vault, so no key exists without a record entry), a --name with control characters is
// cleaned for display, and everything else is imported and approved once; fails_when=ProjectSave
// is Invalid, the odd file is rewritten or its value stored, or a control character reaches the
// terminal; no_claim=the path budget and secret cap (ms-projects client_side_fits_the_limits)
#[test]
fn unrecordable_file_is_left_untouched() {
    let fx = Fx::new();
    let root = fx.shop();
    let odd = root.join(".env.\u{1}odd");
    let odd_text = format!("STRIPE_SECRET_KEY={T_PROD}x\n");
    std::fs::write(&odd, &odd_text).unwrap();
    let (code, out) = fx.init_answering(&root, "o", "--name \"$(printf 'my\\tshop')\"");
    assert_eq!(code, 0, "{out}");
    assert_eq!(read(&odd), odd_text);
    assert!(
        out.contains("Skipped    .env.odd: can't be recorded"),
        "{out}"
    );
    assert!(!out.contains('\u{1}') && !out.contains('\t'), "{out:?}");
    assert!(out.contains("Project    myshop  ("), "{out}");
    assert!(out.contains("Protected  3, ready to use"), "{out}");
    assert!(!out.contains("Record "), "{out}");
    let (_, detail) = fx.ms(&["projects", "my-shop"]);
    assert!(detail.contains("Project  my-shop (myshop)"), "{detail}");
    assert_eq!(detail.matches("swap").count(), 4, "{detail}");
}
