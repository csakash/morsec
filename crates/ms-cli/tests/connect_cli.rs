//! `ms connect` / `ms disconnect` end to end: the built `ms` and a dev `msd` (memory vault), with
//! a temp HOME, so the real `~/.claude` is never touched.
//!
//! These tests may run inside an agent session (the gate is often run by one). "Your own
//! terminal" is a process detached from this test's tree (reparented to PID 1); "inside an
//! agent" is a copy of `ms` named `claude`, which morsec takes for a Claude Code session.

// `ms connect --rules` (used here to feed test hosts) exists only in debug builds (SPEC A1).
#![cfg(debug_assertions)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A settings file whose last env entry holds a value of the user's own (a canary): the preview
/// must never print it.
const TYPICAL: &str = "{\n  \"model\": \"claude-opus-5-5\",\n  \"env\": {\n    \"BASH_DEFAULT_TIMEOUT_MS\": \"300000\",\n    \"OPENAI_API_KEY\": \"sk-live-CANARY-L08\"\n  }\n}\n";
const RULES: &str = "version = 3\n\n[keys.\"stripe/test\"]\nmode = \"swap\"\ntier = \"test\"\nhosts = [\"api.stripe.com\", \"*.stripe.com\"]\n";

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

/// `msd` from the same build (scripts/check.sh builds the workspace before testing).
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

struct Fx {
    dir: tempfile::TempDir,
    port: u16,
    _d: Option<Daemon>,
}

impl Fx {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("home")).unwrap();
        std::fs::write(dir.path().join("rules.toml"), RULES).unwrap();
        let port = free_port();
        // msd wants its socket in a private directory.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.path().join("run"))
            .unwrap();
        let socket = dir.path().join("run/msd.sock");
        let child = Command::new(msd())
            .args(["--foreground", "--vault", "memory", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.path().join("state"))
            .args(["--proxy-port", &port.to_string()])
            .env("MORSEC_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let d = Daemon(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "msd never came up");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        Self {
            dir,
            port,
            _d: Some(d),
        }
    }
    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }
    fn socket(&self) -> PathBuf {
        self.dir.path().join("run/msd.sock")
    }
    fn settings(&self) -> PathBuf {
        self.home().join(".claude/settings.json")
    }
    fn cmd(&self, bin: &Path) -> Command {
        let mut c = Command::new(bin);
        c.env("HOME", self.home())
            .env("MORSEC_SOCKET", self.socket())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CLAUDE_ENV_FILE")
            .stdin(Stdio::null());
        c
    }
    /// Runs `ms <args>` here; returns (code, stdout, stderr).
    fn ms(&self, args: &[&str]) -> (i32, String, String) {
        out(self.cmd(&ms()).args(args))
    }
    /// Runs `ms <args> --rules <fixture>`.
    fn connect(&self, args: &[&str]) -> (i32, String, String) {
        let rules = self.dir.path().join("rules.toml");
        let mut all = vec!["connect", "claude-code", "--rules", rules.to_str().unwrap()];
        all.extend_from_slice(args);
        self.ms(&all)
    }
    /// Runs `ms <args>` detached from this test's process tree: outside any agent session.
    fn own_terminal(&self, args: &str) -> (i32, String) {
        let d = self.dir.path();
        let (o, rc) = (d.join("t.out"), d.join("t.rc"));
        let _ = std::fs::remove_file(&rc);
        let st = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "(sleep 0.3; HOME='{h}' MORSEC_SOCKET='{s}' '{ms}' {args} > '{o}' 2>&1 </dev/null; echo $? > '{rc}') </dev/null >/dev/null 2>&1 &",
                h = self.home().display(),
                s = self.socket().display(),
                ms = ms().display(),
                o = o.display(),
                rc = rc.display()
            ))
            .status()
            .unwrap();
        assert!(st.success());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(code) = std::fs::read_to_string(&rc)
                && !code.trim().is_empty()
            {
                return (
                    code.trim().parse().unwrap_or(-1),
                    std::fs::read_to_string(&o).unwrap_or_default(),
                );
            }
            assert!(Instant::now() < deadline, "detached ms never finished");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    /// A copy of `ms` named `claude`: whatever it runs is inside a Claude Code session.
    fn fake_agent(&self) -> PathBuf {
        let p = self.dir.path().join("bin/claude");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(ms(), &p).unwrap();
        p
    }
}

fn out(c: &mut Command) -> (i32, String, String) {
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

// protects=SPEC acceptance 10: against a real dev msd, --dry-run and a non-terminal run without
// --yes write nothing; --yes writes the block with msd's own proxy port; a re-run is a no-op and
// keeps earlier --env refs; the SessionStart hook's --session-env appends the PATH line; a
// disconnect from the user's own terminal restores the file byte for byte; fails_when=any write
// happens early, the port isn't msd's, or the restore differs
#[test]
fn connect_and_disconnect_end_to_end() {
    let fx = Fx::new();
    std::fs::create_dir_all(fx.home().join(".claude")).unwrap();
    std::fs::write(fx.settings(), TYPICAL).unwrap();

    let (code, stdout, _) = fx.connect(&["--dry-run", "--env", "STRIPE_API_KEY=ms://stripe/test"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"httpProxyPort\"") && stdout.contains("dry run"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("claude-opus-5-5"),
        "unchanged lines are not shown:\n{stdout}"
    );
    assert!(
        !stdout.contains("CANARY"),
        "a user value was printed:\n{stdout}"
    );
    assert_eq!(std::fs::read_to_string(fx.settings()).unwrap(), TYPICAL);
    assert!(!fx.home().join(".morsec").exists());

    let (code, _, stderr) = fx.connect(&[]);
    assert_eq!(code, 1);
    assert!(stderr.contains("--yes"), "{stderr}");
    assert_eq!(std::fs::read_to_string(fx.settings()).unwrap(), TYPICAL);

    let (code, stdout, stderr) = fx.connect(&["--yes", "--env", "STRIPE_API_KEY=ms://stripe/test"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let s = std::fs::read_to_string(fx.settings()).unwrap();
    assert!(
        s.contains(&format!("\"httpProxyPort\": {},", fx.port)),
        "{s}"
    );
    assert!(
        s.contains("\"STRIPE_API_KEY\": \"ms://stripe/test\""),
        "{s}"
    );
    assert!(s.contains("\"*.stripe.com\"") && s.contains(fx.socket().to_str().unwrap()));
    assert!(s.contains("\"BASH_DEFAULT_TIMEOUT_MS\": \"300000\""));
    assert!(
        !stdout.contains("CANARY"),
        "a user value was printed:\n{stdout}"
    );

    // A re-run without --env keeps the ref and changes nothing.
    let (code, stdout, _) = fx.connect(&["--yes"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("already connected"), "{stdout}");
    assert_eq!(std::fs::read_to_string(fx.settings()).unwrap(), s);

    let (code, stdout, _) = fx.ms(&["connect"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("claude-code  connected"), "{stdout}");

    // The SessionStart hook.
    let envf = fx.dir.path().join("claude-env");
    let (code, _, _) = out(fx
        .cmd(&ms())
        .args(["connect", "claude-code", "--session-env"])
        .env("CLAUDE_ENV_FILE", &envf));
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(&envf).unwrap(),
        format!(
            "export PATH='{}':\"$PATH\"\n",
            fx.home().join(".morsec/shims").display()
        )
    );

    let (code, text) = fx.own_terminal("disconnect claude-code --yes");
    assert_eq!(code, 0, "{text}");
    assert!(
        !text.contains("CANARY"),
        "a user value was printed:\n{text}"
    );
    assert_eq!(std::fs::read_to_string(fx.settings()).unwrap(), TYPICAL);
    assert!(!fx.home().join(".morsec/connect/claude-code.json").exists());
    let (code, text) = fx.own_terminal("disconnect claude-code --yes");
    assert_eq!(code, 0);
    assert!(text.contains("not connected"), "{text}");
}

// protects=SPEC D10 / SDLC-4: an agent can't remove its own sandbox or change the user's own
// settings: `ms disconnect`, `ms connect --force` and `--wrap` refuse inside an agent session and change nothing; fails_when=either runs
// from inside an agent
#[test]
fn agent_cannot_disconnect_or_force() {
    let fx = Fx::new();
    let (code, _, e) = fx.connect(&["--yes"]);
    assert_eq!(code, 0, "{e}");
    let before = std::fs::read_to_string(fx.settings()).unwrap();
    let agent = fx.fake_agent();
    let (code, _, stderr) = out(fx.cmd(&agent).args(["disconnect", "claude-code", "--yes"]));
    assert_eq!(code, 1);
    assert!(stderr.contains("inside an agent session"), "{stderr}");
    let rules = fx.dir.path().join("rules.toml");
    let (code, _, stderr) = out(fx.cmd(&agent).args([
        "connect",
        "claude-code",
        "--force",
        "--yes",
        "--rules",
        rules.to_str().unwrap(),
    ]));
    assert_eq!(code, 1);
    assert!(stderr.contains("--force"), "{stderr}");
    let (code, _, stderr) = out(fx.cmd(&agent).args([
        "connect",
        "claude-code",
        "--wrap",
        "--yes",
        "--rules",
        rules.to_str().unwrap(),
    ]));
    assert_eq!(code, 1);
    assert!(
        stderr.contains("--wrap") && stderr.contains("inside an agent"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(fx.settings()).unwrap(), before);
}

// protects=fail closed: with msd down, connect stops with the start-the-daemon fix and writes
// nothing; a raw --env value is refused before anything is written; other agents name their
// loop and exit 69; fails_when=any file is written or the exit codes change
#[test]
fn refusals() {
    let fx = Fx::new();
    let (code, _, stderr) = out(fx
        .cmd(&ms())
        .args(["connect", "claude-code", "--yes"])
        .env("MORSEC_SOCKET", fx.dir.path().join("nope.sock")));
    assert_eq!(code, 1);
    assert!(stderr.contains("ms start"), "{stderr}");
    let (code, _, stderr) = fx.connect(&["--yes", "--env", "OPENAI_API_KEY=sk-live-abc"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("ms://") && !stderr.contains("sk-live-abc"),
        "{stderr}"
    );
    assert!(!fx.home().join(".claude").exists() && !fx.home().join(".morsec").exists());
    let (code, _, _) = fx.ms(&["connect", "codex"]);
    assert_eq!(code, 69);
    let (code, _, _) = fx.ms(&["connect", "nope"]);
    assert_eq!(code, 2);
}

// protects=review R10: a partial disconnect (unreadable ~/.claude.json) exits non-zero, says it
// is partial, keeps the record, and `ms connect` lists it as partly disconnected;
// fails_when=it reports success or the list says connected/not connected
#[test]
fn partial_disconnect_fails_loudly() {
    let fx = Fx::new();
    let (code, _, e) = fx.connect(&["--yes", "--with-mcp"]);
    assert_eq!(code, 0, "{e}");
    std::fs::write(fx.home().join(".claude.json"), "{ broken").unwrap();
    let (code, text) = fx.own_terminal("disconnect claude-code --yes");
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("partly disconnected") && text.contains("keep "),
        "{text}"
    );
    assert!(!fx.settings().exists(), "settings.json not restored");
    let (_, stdout, _) = fx.ms(&["connect"]);
    assert!(stdout.contains("partly disconnected"), "{stdout}");
}
