//! `ms connect codex` / `ms disconnect codex` end to end (L13): the built `ms` and a dev `msd`
//! (memory vault), with a temp HOME and no CODEX_HOME, so the real `~/.codex` is never touched.
//!
//! These tests may run inside an agent session (the gate is often run by one). "Your own
//! terminal" is a process detached from this test's tree (reparented to PID 1); "inside an
//! agent" is a copy of `ms` named `claude`, which morsec takes for a Claude Code session.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A config whose MCP server holds a value of the user's own (a canary): the preview must never
/// print it, and morsec must never keep it.
const TYPICAL: &str = "# my codex config\nmodel = \"gpt-5-codex\" # keep\n\n[mcp_servers.github]\ncommand = \"npx\"\nargs = [\"-y\", \"gh-mcp\"]\n\n[mcp_servers.github.env]\nGITHUB_TOKEN = \"ghp_CANARY_L13\"\n\n[projects.\"/w\"]\ntrust_level = \"trusted\"\n";

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
    fn config(&self) -> PathBuf {
        self.home().join(".codex/config.toml")
    }
    fn cmd(&self, bin: &Path) -> Command {
        let mut c = Command::new(bin);
        c.env("HOME", self.home())
            .env("MORSEC_SOCKET", self.socket())
            .env_remove("CODEX_HOME")
            .stdin(Stdio::null());
        c
    }
    /// Runs `ms <args>` here; returns (code, stdout, stderr).
    fn ms(&self, args: &[&str]) -> (i32, String, String) {
        out(self.cmd(&ms()).args(args))
    }
    /// Runs `ms connect codex <args>`.
    fn connect(&self, args: &[&str]) -> (i32, String, String) {
        let mut all = vec!["connect", "codex"];
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
                "(sleep 0.3; HOME='{h}' CODEX_HOME= MORSEC_SOCKET='{s}' '{ms}' {args} > '{o}' 2>&1 </dev/null; echo $? > '{rc}') </dev/null >/dev/null 2>&1 &",
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

// protects=SPEC acceptance 1/2/4/8: against a real dev msd, --dry-run and a non-terminal run
// without --yes write nothing; the preview never prints the user's token; --yes writes msd's
// own proxy port and the reference; a re-run (with no flags) is a no-op that keeps the
// references; `ms connect` lists codex as connected; a disconnect from the user's own terminal
// removes morsec's keys (the replaced token is not brought back, by design) and keeps the rest
// byte for byte; fails_when=any write happens early, a canary is printed or stored, or the
// restore differs
#[test]
fn connect_and_disconnect_end_to_end() {
    let fx = Fx::new();
    std::fs::create_dir_all(fx.config().parent().unwrap()).unwrap();
    std::fs::write(fx.config(), TYPICAL).unwrap();
    let args = [
        "--env",
        "STRIPE_API_KEY=ms://stripe/test",
        "--mcp-env",
        "github:GITHUB_TOKEN=ms://github/token",
    ];
    let mut dry = vec!["--dry-run"];
    dry.extend_from_slice(&args);
    let (code, stdout, stderr) = fx.connect(&dry);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("dry run") && stdout.contains("ms://github/token"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("http://127.0.0.1:{}", fx.port)),
        "{stdout}"
    );
    assert!(stdout.contains("GITHUB_TOKEN = \"…\""), "{stdout}");
    assert!(!stdout.contains("CANARY") && !stderr.contains("CANARY"));
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), TYPICAL);
    let (code, _, stderr) = fx.connect(&args);
    assert_eq!(code, 1, "no --yes and no terminal must change nothing");
    assert!(stderr.contains("--yes"), "{stderr}");
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), TYPICAL);

    let mut yes = vec!["--yes"];
    yes.extend_from_slice(&args);
    let (code, stdout, stderr) = fx.connect(&yes);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains("network turned off"), "{stderr}");
    assert!(!stdout.contains("CANARY") && !stderr.contains("CANARY"));
    let written = std::fs::read_to_string(fx.config()).unwrap();
    assert!(written.contains(&format!("HTTPS_PROXY = \"http://127.0.0.1:{}\"", fx.port)));
    assert!(written.contains("GITHUB_TOKEN = \"ms://github/token\""));
    assert!(written.contains("STRIPE_API_KEY = \"ms://stripe/test\""));
    assert!(written.starts_with("# my codex config\nmodel = \"gpt-5-codex\" # keep\n"));
    for f in [
        fx.home().join(".morsec/connect/codex.json"),
        fx.home().join(".morsec/codex-ca-bundle.pem"),
    ] {
        assert!(
            !std::fs::read_to_string(&f).unwrap().contains("CANARY"),
            "{}",
            f.display()
        );
    }

    let (code, stdout, _) = fx.connect(&["--yes"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("already connected"), "{stdout}");
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), written);
    let (_, stdout, _) = fx.ms(&["connect"]);
    assert!(stdout.contains("codex        connected"), "{stdout}");

    let (code, text) = fx.own_terminal("disconnect codex --yes");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("didn't keep it"), "{text}");
    let back = std::fs::read_to_string(fx.config()).unwrap();
    assert_eq!(
        back,
        TYPICAL.replace("GITHUB_TOKEN = \"ghp_CANARY_L13\"\n", "")
    );
    assert!(!fx.home().join(".morsec/connect/codex.json").exists());
}

// protects=SPEC D4 through the CLI: with nothing of the user's replaced, connect then
// disconnect gives back the exact bytes, and a config connect created is removed again;
// fails_when=a byte differs or a file is left
#[test]
fn byte_identical_restore() {
    let fx = Fx::new();
    let (code, _, e) = fx.connect(&["--yes", "--with-mcp"]);
    assert_eq!(code, 0, "{e}");
    assert!(
        std::fs::read_to_string(fx.config())
            .unwrap()
            .contains("[mcp_servers.ms]")
    );
    let (code, text) = fx.own_terminal("disconnect codex --yes");
    assert_eq!(code, 0, "{text}");
    assert!(!fx.config().exists());

    let t = "model = \"o3\"\n[tui]\ntheme = 'dark' # mine";
    std::fs::write(fx.config(), t).unwrap();
    let (code, _, e) = fx.connect(&["--yes", "--env", "A_KEY=ms://a/b"]);
    assert_eq!(code, 0, "{e}");
    let (code, text) = fx.own_terminal("disconnect codex --yes");
    assert_eq!(code, 0, "{text}");
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), t);
}

// protects=SPEC D10 / SDLC-4: an agent can't remove morsec from its own setup or override the
// user's settings: `ms disconnect codex` and `ms connect codex --force` refuse inside an agent
// session and change nothing; fails_when=either runs from inside an agent
#[test]
fn agent_cannot_disconnect_or_force() {
    let fx = Fx::new();
    let (code, _, e) = fx.connect(&["--yes"]);
    assert_eq!(code, 0, "{e}");
    let before = std::fs::read_to_string(fx.config()).unwrap();
    let agent = fx.fake_agent();
    let (code, _, stderr) = out(fx.cmd(&agent).args(["disconnect", "codex", "--yes"]));
    assert_eq!(code, 1);
    assert!(stderr.contains("inside an agent session"), "{stderr}");
    let (code, _, stderr) = out(fx
        .cmd(&agent)
        .args(["connect", "codex", "--force", "--yes"]));
    assert_eq!(code, 1);
    assert!(stderr.contains("--force"), "{stderr}");
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), before);
}

// protects=fail closed: msd down, a raw --env value, a raw --mcp-env value, an unknown MCP
// server, --wrap for codex and a broken config.toml all stop before anything is written;
// fails_when=any file is written or a raw value is echoed
#[test]
fn refusals() {
    let fx = Fx::new();
    let (code, _, stderr) = out(fx
        .cmd(&ms())
        .args(["connect", "codex", "--yes"])
        .env("MORSEC_SOCKET", fx.dir.path().join("nope.sock")));
    assert_eq!(code, 1);
    assert!(stderr.contains("ms start"), "{stderr}");
    for args in [
        vec!["--yes", "--env", "OPENAI_API_KEY=sk-live-abc"],
        vec!["--yes", "--mcp-env", "github:T=sk-live-abc"],
        vec!["--yes", "--mcp-env", "nope:T=ms://a/b"],
        vec!["--yes", "--wrap"],
    ] {
        let (code, _, stderr) = fx.connect(&args);
        assert_eq!(code, 1, "{args:?}");
        assert!(!stderr.contains("sk-live-abc"), "{stderr}");
    }
    assert!(!fx.home().join(".codex").exists() && !fx.home().join(".morsec").exists());
    std::fs::create_dir_all(fx.config().parent().unwrap()).unwrap();
    std::fs::write(fx.config(), "model = \n").unwrap();
    let (code, _, stderr) = fx.connect(&["--yes"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("not valid TOML"), "{stderr}");
    assert_eq!(std::fs::read_to_string(fx.config()).unwrap(), "model = \n");
    let (code, _, stderr) = fx.ms(&["connect", "claude-code", "--mcp-env", "a:B=ms://c/d"]);
    assert_eq!(code, 1, "{stderr}");
}
