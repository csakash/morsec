//! A throwaway dev msd for the L33 end-to-end tests (`set_rm_undo.rs`, `dash_actions.rs`): the
//! built `ms` and `msd`, the memory vault, `--test-touch-id allow` standing in for the Touch ID
//! sheet only, `--test-open-to` and `--test-pasteboard-to` writing to files instead of a browser
//! and the pasteboard, a temp HOME. Never the login keychain, never the real state directory.
//!
//! The gate often runs inside an agent session, which is what msd refuses. So everything that
//! plays "the user" runs detached from this test's process tree, as the user's own terminal and
//! browser would; "the agent" is a tiny C program named `claude` (as in `dashboard.rs`).

#![allow(dead_code)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

pub fn msd() -> PathBuf {
    let p = ms().with_file_name("msd");
    assert!(p.exists(), "{} not built", p.display());
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A port below the ephemeral range, free now.
fn quiet_port() -> u16 {
    static N: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = std::process::id()
            .wrapping_mul(2_654_435_761)
            .wrapping_add(n * 7919 + 101);
        let port = 20_000 + u16::try_from(seed % 25_000).unwrap();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

pub struct Daemon(Child);
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

pub struct Fx {
    dir: tempfile::TempDir,
    _d: Daemon,
}

impl Fx {
    pub fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("msl33")
            .tempdir_in("/tmp")
            .unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        for d in ["home", "tmp", "bin"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join("run"))
            .unwrap();
        let socket = base.join("run/msd.sock");
        let log = std::fs::File::create(base.join("msd.log")).unwrap();
        let child = Command::new(msd())
            .args(["--foreground", "--vault", "memory", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(base.join("state"))
            .args(["--proxy-port", &free_port().to_string()])
            .args(["--dash-port", &quiet_port().to_string()])
            .args(["--test-touch-id", "allow"])
            .arg("--test-open-to")
            .arg(base.join("opened.txt"))
            .arg("--test-pasteboard-to")
            .arg(base.join("paste.txt"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", base.join("home"))
            .env("TMPDIR", base.join("tmp"))
            .env("MORSEC_LOG", "info")
            .stdout(Stdio::null())
            .stderr(log)
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

    pub fn base(&self) -> PathBuf {
        std::fs::canonicalize(self.dir.path()).unwrap()
    }

    fn env_line(&self) -> String {
        let b = self.base();
        format!(
            "export PATH='/usr/bin:/bin' HOME='{h}' MORSEC_SOCKET='{b}/run/msd.sock' TMPDIR='{b}/tmp' LANG=C MORSEC_DEV_UNVERIFIED_DAEMON=1 MS='{ms}'",
            h = b.join("home").display(),
            b = b.display(),
            ms = ms().display()
        )
    }

    /// Runs `command` in `cwd`, detached from this test's process tree (the user's own
    /// terminal). Returns (exit code, output).
    pub fn outside(&self, cwd: &Path, command: &str) -> (i32, String) {
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

    /// `command` on a pseudo-terminal (`script`), fed `typed` lines first and then `o` (approve
    /// once) every 0.3 s, as a person answering the inline review would.
    pub fn at_terminal(&self, cwd: &Path, typed: &[&str], command: &str) -> (i32, String) {
        let mut feed = String::new();
        for t in typed {
            // After the prompt has turned echo off, as a person would type.
            feed.push_str(&format!("sleep 1; printf '%s\\n' '{t}'; "));
        }
        self.outside(
            cwd,
            &format!(
                "({feed}i=0; while [ $i -lt 200 ]; do printf 'o\\n'; sleep 0.3; i=$((i+1)); done) | script -q /dev/null {command}"
            ),
        )
    }

    /// A program named `claude` that runs its arguments as a child and waits.
    pub fn fake_agent(&self) -> PathBuf {
        let p = self.base().join("bin/claude");
        if !p.exists() {
            let src = self.base().join("bin/claude.c");
            std::fs::write(
                &src,
                "#include <unistd.h>\n#include <sys/wait.h>\nint main(int c, char **v) {\n  if (c < 2) return 2;\n  pid_t p = fork();\n  if (p == 0) { execvp(v[1], v + 1); _exit(127); }\n  int st = 0; waitpid(p, &st, 0);\n  return WIFEXITED(st) ? WEXITSTATUS(st) : 1;\n}\n",
            )
            .unwrap();
            let st = Command::new("cc")
                .arg("-o")
                .arg(&p)
                .arg(&src)
                .status()
                .expect("cc builds the fake agent");
            assert!(st.success());
        }
        p
    }

    /// The last URL msd "opened in the browser".
    pub fn url(&self) -> String {
        std::fs::read_to_string(self.base().join("opened.txt"))
            .unwrap_or_default()
            .lines()
            .last()
            .unwrap_or_default()
            .to_owned()
    }

    pub fn receipts(&self) -> String {
        let mut out = String::new();
        if let Ok(rd) = std::fs::read_dir(self.base().join("state/receipts")) {
            for e in rd.flatten() {
                out.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
            }
        }
        out
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.base().join("msd.log")).unwrap_or_default()
    }

    /// Sets up project `shop` with `ms init` (answering every question), from the user's
    /// terminal. `env` is the `.env` text.
    pub fn init_shop(&self, env: &str) -> PathBuf {
        let root = self.base().join("shop");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("package.json"), "{\"name\":\"shop\"}\n").unwrap();
        std::fs::write(root.join(".env"), env).unwrap();
        let (code, out) = self.outside(
            &root,
            r#"(i=0; while [ $i -lt 200 ]; do printf 'o\n'; sleep 0.3; i=$((i+1)); done) | script -q /dev/null "$MS" init --no-connect --no-open"#,
        );
        assert_eq!(code, 0, "{out}");
        root
    }
}

/// `(port, token)` from an opened URL `http://127.0.0.1:<port>/#t=<token>[&v=<view>]`.
pub fn parse_url(u: &str) -> (u16, String) {
    let rest = u
        .strip_prefix("http://127.0.0.1:")
        .unwrap_or_else(|| panic!("{u}"));
    let (port, frag) = rest.split_once("/#t=").unwrap_or_else(|| panic!("{u}"));
    let token = frag.split_once("&v=").map_or(frag, |(t, _)| t);
    (port.parse().unwrap(), token.to_owned())
}

/// Shell (run outside) that signs in with `$TOKEN` on `$PORT` and defines `post NAME PATH BODY`
/// (the page's headers: Origin, JSON, cookie, CSRF, Sec-Fetch-Site) writing
/// `<base>/act/NAME.json` and `.code`.
pub fn session_script(base: &Path) -> String {
    let act = base.join("act");
    format!(
        r#"mkdir -p '{act}'
H="Host: 127.0.0.1:$PORT"
O="Origin: http://127.0.0.1:$PORT"
curl -s -D '{act}/session.hdr' -o '{act}/session.json' -H "$H" -H "$O" -H 'Content-Type: application/json' --data "{{\"token\":\"$TOKEN\"}}" "http://127.0.0.1:$PORT/api/session"
COOKIE=$(grep -i '^set-cookie:' '{act}/session.hdr' | sed 's/.*ms_dash=\([0-9a-f]*\).*/\1/')
CSRF=$(sed 's/.*"csrf":"\([0-9a-f]*\)".*/\1/' '{act}/session.json')
post() {{ curl -s -o "{act}/$1.json" -w '%{{http_code}}' -H "$H" -H "$O" -H 'Content-Type: application/json' -H "Cookie: ms_dash=$COOKIE" -H "X-Morsec-CSRF: $CSRF" -H 'Sec-Fetch-Site: same-origin' --data "$3" "http://127.0.0.1:$PORT$2" > "{act}/$1.code"; sleep 0.25; }}
get() {{ curl -s -o "{act}/$1.json" -w '%{{http_code}}' -H "$H" -H "Cookie: ms_dash=$COOKIE" -H "X-Morsec-CSRF: $CSRF" "http://127.0.0.1:$PORT$2" > "{act}/$1.code"; }}
"#,
        act = act.display()
    )
}
