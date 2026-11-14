//! `ms doctor` end to end (L17), against a throwaway msd.
//!
//! Every test starts its own `msd --vault memory` with a temp socket, state directory and
//! `HOME`, so the real `~/.claude`, `~/.codex` and login keychain are never used; the suite also
//! checks the real files are untouched. No real agent runs here (live runs spend tokens): this
//! binary is its own fake agent. Copied as `claude` or `codex`, it reads the probe command out of
//! the prompt `ms doctor --live` gives it and acts according to `FAKE_<AGENT>_MODE`:
//!
//! - `blocked`: runs the probe like a sandbox that routes through msd and blocks direct egress;
//! - `open`: the same, but direct egress is open;
//! - `liar`: prints a passing probe line without running anything;
//! - `says-open`: prints a probe line saying direct egress is open, without running anything.
//! - `forge`: a detached process also called `claude` sends a passing canary and report first
//!   (security review S1); the agent itself runs nothing.
//!
//! Commands that must come from the user's own terminal (`ms connect`, `ms doctor --live`) run
//! detached (reparented to PID 1), so they are outside any agent session even when an agent runs
//! the gate.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ms_ipc::{Client, RequestBody, ResponseBody};

type Test = (&'static str, fn());

const TESTS: &[Test] = &[
    (
        "healthy_setup_has_no_problems",
        healthy_setup_has_no_problems,
    ),
    ("broken_connector_is_reported", broken_connector_is_reported),
    ("daemon_down_is_reported", daemon_down_is_reported),
    (
        "probe_open_egress_fails_loudly",
        probe_open_egress_fails_loudly,
    ),
    ("live_with_fake_agents", live_with_fake_agents),
    ("live_refused_inside_an_agent", live_refused_inside_an_agent),
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let name = Path::new(&args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();
    if name == "claude" || name == "codex" {
        return fake_agent(&name, &args);
    }
    if args.iter().any(|a| a == "--list") {
        for (t, _) in TESTS {
            println!("{t}: test");
        }
        return ExitCode::SUCCESS;
    }
    let real = RealAgentFiles::snapshot();
    let filter = args[1..].iter().find(|a| !a.starts_with('-'));
    let chosen: Vec<&Test> = TESTS
        .iter()
        .filter(|(t, _)| filter.is_none_or(|f| t.contains(f.as_str())))
        .collect();
    println!("running {} tests", chosen.len());
    for (t, f) in chosen {
        f();
        println!("test {t} ... ok");
    }
    real.assert_unchanged();
    ExitCode::SUCCESS
}

/// The fake agent. `claude -c <cmd>` / `codex -c <cmd>` run a shell command as its child (for
/// in-agent checks); anything else is a headless run from `ms doctor --live`.
fn fake_agent(name: &str, args: &[String]) -> ExitCode {
    let sh = |cmd: &str| {
        let st = Command::new("/bin/sh").arg("-c").arg(cmd).status();
        ExitCode::from(st.ok().and_then(|s| s.code()).unwrap_or(1) as u8)
    };
    if args.get(1).map(String::as_str) == Some("-c") {
        return sh(&args[2]);
    }
    let Some(cmd) = args
        .iter()
        .flat_map(|a| a.lines())
        .find(|l| l.contains(" doctor --probe --nonce "))
        .map(str::trim)
    else {
        eprintln!("fake {name}: no probe command in {args:?}");
        return ExitCode::FAILURE;
    };
    let nonce = cmd.rsplit(' ').next().unwrap_or("");
    let var = format!("FAKE_{}_MODE", name.to_uppercase());
    let mode = std::env::var(var).unwrap_or_default();
    let proxy = std::env::var("FAKE_PROXY").unwrap_or_default();
    let target = |which: &str| std::env::var(which).unwrap_or_default();
    match mode.as_str() {
        // The sandbox's proxy variable, as the connector or the sandbox sets it. A real agent
        // keeps running a while after the command (it writes its reply): so does this one.
        "blocked" => sh(&format!(
            "HTTPS_PROXY='{proxy}' {cmd} --direct-target {}; s=$?; sleep 1; exit $s",
            target("FAKE_CLOSED")
        )),
        "open" => sh(&format!(
            "HTTPS_PROXY='{proxy}' {cmd} --direct-target {}; s=$?; sleep 1; exit $s",
            target("FAKE_OPEN")
        )),
        // Security review S1: another process, detached (reparented to launchd) and also called
        // `claude`, sends a passing canary and report for this nonce first; the agent itself
        // never runs the probe.
        "forge" => {
            let me = std::env::current_exe().unwrap();
            sh(&format!(
                "( '{}' -c \"HTTPS_PROXY='{proxy}' {cmd} --direct-target {}; sleep 2\" >/dev/null 2>&1 & ) ; sleep 3",
                me.display(),
                target("FAKE_CLOSED")
            ))
        }
        "liar" => {
            println!("morsec-probe nonce={nonce} proxy=reached direct=blocked");
            ExitCode::SUCCESS
        }
        "says-open" => {
            println!("morsec-probe nonce={nonce} proxy=no direct=OPEN");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("fake {name}: unknown mode {other:?}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Harness

/// mtimes of the real agent settings, to show the suite never touches them (SPEC acceptance 8).
struct RealAgentFiles(Vec<(PathBuf, Option<SystemTime>)>);

impl RealAgentFiles {
    fn snapshot() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        Self(
            [
                ".claude/settings.json",
                ".claude.json",
                ".codex/config.toml",
                ".morsec/connect/claude-code.json",
                ".morsec/connect/codex.json",
            ]
            .iter()
            .map(|r| {
                let p = home.join(r);
                let m = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
                (p, m)
            })
            .collect(),
        )
    }

    fn assert_unchanged(&self) {
        for (p, before) in &self.0 {
            // ~/.claude.json is rewritten by any running Claude Code (including one running this
            // gate), so only show it was not created or removed by us.
            let now = std::fs::metadata(p).and_then(|m| m.modified()).ok();
            if p.ends_with(".claude.json") {
                assert_eq!(
                    before.is_some(),
                    now.is_some(),
                    "{} appeared or vanished",
                    p.display()
                );
            } else {
                assert_eq!(
                    *before,
                    now,
                    "{} changed during the doctor suite",
                    p.display()
                );
            }
        }
    }
}

fn built(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe.parent().unwrap().parent().unwrap().join(name);
    assert!(
        p.exists(),
        "{} not built; run cargo build --workspace first (scripts/check.sh does)",
        p.display()
    );
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A port nothing listens on (bound, then released).
fn closed_port() -> u16 {
    free_port()
}

struct Msd(Child);
impl Drop for Msd {
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
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

/// A throwaway morsec with both connectors applied in a temp HOME.
struct World {
    dir: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    sock: PathBuf,
    proxy_port: u16,
    _msd: Msd,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("msdoctor")
            .tempdir_in("/tmp")
            .unwrap();
        let home = dir.path().join("home");
        let bin = dir.path().join("bin");
        for d in [&home, &bin, &dir.path().join("tmp")] {
            std::fs::create_dir_all(d).unwrap();
        }
        // The fake agents, on PATH as `claude` and `codex`.
        for a in ["claude", "codex"] {
            std::fs::copy(std::env::current_exe().unwrap(), bin.join(a)).unwrap();
        }
        let sock = dir.path().join("run/msd.sock");
        let proxy_port = free_port();
        let log = std::fs::File::create(dir.path().join("msd.log")).unwrap();
        let mut cmd = Command::new(built("msd"));
        cmd.args(["--foreground", "--vault", "memory", "--socket"])
            .arg(&sock)
            .arg("--state-dir")
            .arg(dir.path().join("state"))
            .args(["--proxy-port", &proxy_port.to_string()])
            .stdout(Stdio::null())
            .stderr(log)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("TMPDIR", dir.path().join("tmp"))
            .env("LANG", "C")
            .env("MORSEC_LOG", "info");
        let msd = Msd(cmd.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&sock).is_err() {
            assert!(Instant::now() < deadline, "msd is not accepting");
            std::thread::sleep(Duration::from_millis(20));
        }
        match ipc(&sock, RequestBody::Status) {
            ResponseBody::Status { mode, .. } => assert_eq!(mode, "dev-memory"),
            other => panic!("{other:?}"),
        }
        let w = World {
            dir,
            home,
            bin,
            sock,
            proxy_port,
            _msd: msd,
        };
        // Wait for the proxy to listen, then connect both agents from "the user's terminal".
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect(("127.0.0.1", proxy_port)).is_err() {
            assert!(Instant::now() < deadline, "msd's proxy is not listening");
            std::thread::sleep(Duration::from_millis(20));
        }
        let (code, out) = w.outside("ms connect claude-code --yes && ms connect codex --yes", "");
        assert_eq!(code, 0, "ms connect failed: {out}");
        w
    }

    fn path_var(&self) -> String {
        format!(
            "{}:{}:/usr/bin:/bin",
            self.bin.display(),
            built("ms").parent().unwrap().display()
        )
    }

    /// Runs `command` detached from this process tree, as the user's own terminal would, with
    /// extra `exports` (shell syntax). Returns (exit code, stdout + stderr).
    fn outside(&self, command: &str, exports: &str) -> (i32, String) {
        let n = RUNS.fetch_add(1, Ordering::Relaxed);
        let d = self.dir.path();
        let script = d.join(format!("outside{n}.sh"));
        let out = d.join(format!("outside{n}.out"));
        let rc = d.join(format!("outside{n}.rc"));
        std::fs::write(
            &script,
            format!(
                "export PATH='{}' HOME='{}' MORSEC_SOCKET='{}' TMPDIR='{}/tmp' LANG=C\nunset CLAUDE_CONFIG_DIR CODEX_HOME\n{exports}\ncd '{}'\n{command}\n",
                self.path_var(),
                self.home.display(),
                self.sock.display(),
                d.display(),
                self.home.display()
            ),
        )
        .unwrap();
        let st = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "(sleep 0.5; /bin/sh '{}' > '{}' 2>&1; echo $? > '{}.tmp'; mv '{}.tmp' '{}') </dev/null >/dev/null 2>&1 &",
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
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(code) = std::fs::read_to_string(&rc) {
                let text = std::fs::read_to_string(&out).unwrap_or_default();
                return (code.trim().parse().unwrap_or(-1), text);
            }
            assert!(Instant::now() < deadline, "detached command never finished");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Runs `command` inside the fake Claude Code. Returns (exit code, stdout, stderr).
    fn in_agent(&self, command: &str) -> (i32, String, String) {
        let mut cmd = Command::new(self.bin.join("claude"));
        cmd.arg("-c")
            .arg(command)
            .current_dir(&self.home)
            .env_clear()
            .env("PATH", self.path_var())
            .env("HOME", &self.home)
            .env("TMPDIR", self.dir.path().join("tmp"))
            .env("LANG", "C")
            .env("MORSEC_SOCKET", &self.sock);
        let out = cmd.output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn doctor(&self, exports: &str) -> (i32, String) {
        self.outside("ms doctor", exports)
    }
}

fn ipc(sock: &Path, body: RequestBody) -> ResponseBody {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async { Client::connect(sock).await.unwrap().request(body).await })
        .unwrap()
}

fn line_with<'a>(out: &'a str, needle: &str) -> &'a str {
    out.lines()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?} in:\n{out}"))
}

// ---------------------------------------------------------------------------------------------
// Tests

// protects=SPEC acceptance 1/4: with msd up and both connectors applied (temp HOME), doctor finds
// no problems, checks every connector item and the port against msd, and reports the ms mcp
// catalog hash as not checked yet without failing; fails_when=a healthy setup exits non-zero or a check is missing;
// no_claim=a signed release build (dev builds are ad-hoc: a warning)
fn healthy_setup_has_no_problems() {
    let w = World::new();
    let (code, out) = w.doctor("");
    assert_eq!(code, 0, "{out}");
    for want in [
        "✓ msd running · dev-memory vault",
        "✓ vault reachable · 0 secrets",
        "- no morsec CA yet",
        "✓ Claude Code connected",
        "✓ Claude Code sandbox uses the morsec proxy",
        "✓ Codex commands use the morsec proxy",
        "- ms mcp tool catalog hash not checked yet",
    ] {
        line_with(&out, want);
    }
    assert_eq!(out.matches("✓ proxy port matches msd").count(), 2, "{out}");
    assert!(!out.contains('✗'), "{out}");
    assert!(out.contains("No problems"), "{out}");
}

// protects=SPEC acceptance 2 (the card's Verify): removing the proxy setting from a connector is
// reported as a problem naming that check and its fix, and doctor exits 1; fails_when=a broken
// connector passes; no_claim=other edits (each connector's verify tests cover them)
fn broken_connector_is_reported() {
    let w = World::new();
    // Claude Code: the sandbox proxy port removed.
    let settings = w.home.join(".claude/settings.json");
    let s = std::fs::read_to_string(&settings).unwrap();
    let port_line = format!("\"httpProxyPort\": {},\n", w.proxy_port);
    assert!(s.contains(&port_line), "{s}");
    std::fs::write(&settings, s.replace(&port_line, "")).unwrap();
    // Codex: HTTPS_PROXY removed from shell_environment_policy.set.
    let config = w.home.join(".codex/config.toml");
    let c = std::fs::read_to_string(&config).unwrap();
    let kept: String = c
        .lines()
        .filter(|l| !l.starts_with("HTTPS_PROXY ="))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_ne!(kept, c, "no HTTPS_PROXY line in {c}");
    std::fs::write(&config, kept).unwrap();

    let (code, out) = w.doctor("");
    assert_eq!(code, 1, "{out}");
    let l = line_with(&out, "✗ Claude Code sandbox uses the morsec proxy");
    assert!(l.contains("ms connect claude-code"), "{l}");
    let l = line_with(&out, "✗ Codex commands use the morsec proxy");
    assert!(l.contains("ms connect codex"), "{l}");
    assert!(out.contains("2 problems"), "{out}");
}

// protects=SPEC acceptance 3: with no daemon on the socket, doctor says msd is not running,
// still checks the connectors, exits 1 and does not hang; fails_when=it passes, hangs or
// crashes; no_claim=launchd
fn daemon_down_is_reported() {
    let w = World::new();
    let started = Instant::now();
    let (code, out) = w.doctor(&format!(
        "export MORSEC_SOCKET='{}/none.sock'",
        w.dir.path().display()
    ));
    assert_eq!(code, 1, "{out}");
    line_with(&out, "✗ msd not running");
    line_with(&out, "✓ Claude Code connected");
    assert!(started.elapsed() < Duration::from_secs(30));
}

// protects=SPEC acceptance 5 (the card's Verify): inside an agent, when direct egress is open
// the probe fails loudly (banner, direct=OPEN, exit 1) and msd holds both the canary sighting
// from that agent's session and the report saying open; a malformed target is refused rather
// than counted as blocked; fails_when=open egress exits 0, is not reported to msd, or a typo
// reads as "blocked"; no_claim=a real sandbox
fn probe_open_egress_fails_loudly() {
    let w = World::new();
    let open = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = open.local_addr().unwrap().port();
    let nonce = "00112233445566778899aabbccddeeff";
    let (code, out, err) = w.in_agent(&format!(
        "HTTPS_PROXY=http://127.0.0.1:{} ms doctor --probe --nonce {nonce} --direct-target 127.0.0.1:{open_port}",
        w.proxy_port
    ));
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("DIRECT INTERNET IS OPEN"), "{err}");
    line_with(&out, "✓ canary reached morsec through the proxy");
    line_with(
        &out,
        &format!("morsec-probe nonce={nonce} proxy=reached direct=OPEN"),
    );
    match ipc(
        &w.sock,
        RequestBody::DoctorProbe {
            nonce: Some(nonce.into()),
            report: None,
        },
    ) {
        ResponseBody::Probe {
            canaries, reports, ..
        } => {
            assert_eq!(
                (canaries.len(), reports.len()),
                (1, 1),
                "{canaries:?} {reports:?}"
            );
            let (r, by) = &reports[0];
            assert!(r.direct_open && r.proxy_reached, "{r:?}");
            let s = canaries[0].session.clone().expect("canary from a session");
            assert_eq!(s.agent, ms_core::AgentKind::ClaudeCode);
            assert_eq!(by.session, Some(s));
        }
        other => panic!("{other:?}"),
    }

    // Blocked: exit 0.
    let closed = closed_port();
    let (code, out, err) = w.in_agent(&format!(
        "HTTPS_PROXY=http://127.0.0.1:{} ms doctor --probe --direct-target 127.0.0.1:{closed}",
        w.proxy_port
    ));
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("direct=blocked"), "{out}");

    // A typo is not "blocked".
    let (code, _, err) = w.in_agent("ms doctor --probe --direct-target 127.0.0.1:");
    assert_eq!(code, 2, "{err}");
    drop(open);
}

// protects=SPEC acceptance 6 (INJ-4): --live runs each connected agent with the fixed prompt and
// judges by what msd saw: a sandbox that routes through msd and blocks direct egress passes; an
// open one fails loudly; an agent that only claims success fails (no canary, no report); an
// agent whose output says direct=OPEN fails loudly; fails_when=any of those verdicts is wrong;
// no_claim=real agents (QA runs one live check by hand)
fn live_with_fake_agents() {
    let w = World::new();
    let open = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!(
        "export FAKE_PROXY='http://127.0.0.1:{}' FAKE_OPEN='127.0.0.1:{}' FAKE_CLOSED='127.0.0.1:{}'",
        w.proxy_port,
        open.local_addr().unwrap().port(),
        closed_port()
    );
    let live = |claude: &str, codex: &str| {
        w.outside(
            "ms doctor --live",
            &format!("{base} FAKE_CLAUDE_MODE={claude} FAKE_CODEX_MODE={codex}"),
        )
    };

    let (code, out) = live("blocked", "open");
    assert_eq!(code, 1, "{out}");
    let claude = out.split("live: claude-code").nth(1).unwrap();
    let claude = claude.split("live: codex").next().unwrap();
    assert!(
        claude.contains("✓ canary reached morsec's proxy from the agent doctor started"),
        "{out}"
    );
    assert!(
        claude.contains("✓ direct internet blocked in claude-code's sandbox"),
        "{out}"
    );
    let codex = out.split("live: codex").nth(1).unwrap();
    assert!(codex.contains("✓ canary reached morsec's proxy"), "{out}");
    assert!(
        codex.contains("✗ DIRECT INTERNET IS OPEN in codex's sandbox"),
        "{out}"
    );
    assert!(
        out.contains("!!! DIRECT INTERNET IS OPEN"),
        "loud banner missing: {out}"
    );

    let (code, out) = live("liar", "says-open");
    assert_eq!(code, 1, "{out}");
    let claude = out.split("live: claude-code").nth(1).unwrap();
    let claude = claude.split("live: codex").next().unwrap();
    assert!(
        claude.contains("✗ commands in claude-code's sandbox did not reach morsec's proxy"),
        "{out}"
    );
    assert!(
        claude.contains("✗ the probe did not report to msd"),
        "{out}"
    );
    let codex = out.split("live: codex").nth(1).unwrap();
    assert!(
        codex.contains("✗ DIRECT INTERNET IS OPEN in codex's sandbox"),
        "{out}"
    );

    let (code, out) = live("blocked", "blocked");
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains('✗'), "{out}");

    // Security review S1: a detached process called `claude` forges a passing canary and report
    // for the nonce; it is not the agent doctor started, so nothing passes.
    let (code, out) = live("forge", "blocked");
    assert_eq!(code, 1, "{out}");
    let claude = out.split("live: claude-code").nth(1).unwrap();
    let claude = claude.split("live: codex").next().unwrap();
    assert!(
        claude.contains("✗ a canary reached morsec's proxy, but not from the agent doctor started"),
        "{out}"
    );
    assert!(
        claude.contains("✗ a probe report arrived, but not from the agent doctor started"),
        "{out}"
    );
    assert!(!claude.contains('✓'), "{out}");
    drop(open);
}

// protects=SPEC acceptance 7: --live is refused inside an agent session (it spends tokens and
// would be mis-attributed to the outer agent); fails_when=it runs; no_claim=the static checks,
// which are allowed inside an agent
fn live_refused_inside_an_agent() {
    let w = World::new();
    let (code, _, err) = w.in_agent("ms doctor --live");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("runs only from your own terminal"), "{err}");
}
