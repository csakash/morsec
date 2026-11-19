//! `ms dashboard` end to end (L32 dash-core): the built `ms` and a dev `msd` (memory vault,
//! `--test-touch-id allow` standing in for the Touch ID sheet only), a temp HOME, curl as the
//! browser.
//!
//! The gate is often run inside an agent session, and that is exactly what the dashboard refuses.
//! So everything that plays "the user" runs detached from this test's process tree (reparented to
//! PID 1), as the user's own terminal and browser would; "the agent" is a tiny C program named
//! `claude`. `MORSEC_TEST_OPEN` (debug builds only) replaces `open(1)` with a script that saves
//! the URL, so no browser starts.

// `--test-touch-id` and `MORSEC_TEST_OPEN` exist only in debug builds.
#![cfg(debug_assertions)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Values that must never reach the page, split so secret scanners don't take them for keys.
const T_STRIPE: &str = concat!("sk_test_", "51DASHvalueDASHvalueDASHvalue00");
const OAI: &str = concat!("sk-", "proj-", "DASHoaiDASHoaiDASHoaiDASHoai0123");
const SESSION: &str = "d4a9c2e7b1d84f6a9c0e2b4d6f8a1c3e";
const CODE_CANARY: &str = concat!("sk_live_", "DASHCODEcanary0a1b2c3d4e5f6g7h8");

fn ms() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ms"))
}

fn msd() -> PathBuf {
    let p = ms().with_file_name("msd");
    assert!(p.exists(), "{} not built", p.display());
    p
}

/// A port below the ephemeral range (macOS: 49152 and up), where client sockets of parallel
/// tests keep landing and leave ports in TIME_WAIT. Bound and returned held.
fn quiet_listener() -> std::net::TcpListener {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    loop {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = std::process::id()
            .wrapping_mul(2_654_435_761)
            .wrapping_add(n * 7919);
        let port = 20_000 + u16::try_from(seed % 25_000).unwrap();
        if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            return l;
        }
    }
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
    dash_port: u16,
    _squatter: std::net::TcpListener,
    _d: Daemon,
}

impl Fx {
    /// A dev msd whose dashboard range starts at a port this fixture already holds, so msd must
    /// take the next one.
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("msdash")
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
        let squatter = quiet_listener();
        let dash_port = squatter.local_addr().unwrap().port();
        let socket = base.join("run/msd.sock");
        let child = Command::new(msd())
            .args(["--foreground", "--vault", "memory", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(base.join("state"))
            .args(["--proxy-port", &free_port().to_string()])
            .args(["--dash-port", &dash_port.to_string()])
            .args(["--test-touch-id", "allow"])
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
        // The opener: saves the URL instead of starting a browser.
        let opener = base.join("bin/opener.sh");
        std::fs::write(
            &opener,
            format!(
                "#!/bin/sh\nprintf '%s' \"$1\" > '{}/url.txt'\n",
                base.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            dash_port,
            _squatter: squatter,
            _d: d,
        }
    }

    fn base(&self) -> PathBuf {
        std::fs::canonicalize(self.dir.path()).unwrap()
    }

    fn env_line(&self) -> String {
        let b = self.base();
        format!(
            "export PATH='/usr/bin:/bin' HOME='{h}' MORSEC_SOCKET='{b}/run/msd.sock' TMPDIR='{b}/tmp' LANG=C MORSEC_DEV_UNVERIFIED_DAEMON=1 MORSEC_TEST_OPEN='{b}/bin/opener.sh' MS='{ms}'",
            h = b.join("home").display(),
            b = b.display(),
            ms = ms().display()
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

    /// A program named `claude` that runs its arguments as a child and waits: whatever it runs
    /// is inside a Claude Code session. Built with the C compiler cargo links with (copies of
    /// /bin binaries are killed by macOS outside their home).
    fn fake_agent(&self) -> PathBuf {
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
                .expect("cc (the linker cargo uses) builds the fake agent");
            assert!(st.success());
        }
        p
    }

    fn url(&self) -> String {
        std::fs::read_to_string(self.base().join("url.txt")).unwrap_or_default()
    }

    fn receipts(&self) -> String {
        let mut out = String::new();
        if let Ok(rd) = std::fs::read_dir(self.base().join("state/receipts")) {
            for e in rd.flatten() {
                out.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
            }
        }
        out
    }

    /// A small project with real-looking values and a key written into code.
    fn shop(&self) -> PathBuf {
        let root = self.base().join("shop");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("package.json"), "{\"name\":\"shop\"}\n").unwrap();
        std::fs::write(
            root.join(".env"),
            format!(
                "STRIPE_SECRET_KEY={T_STRIPE}\nOPENAI_API_KEY=\"{OAI}\"\nSESSION_SECRET={SESSION}\nPORT=3000\n"
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/pay.ts"),
            format!("const s = new Stripe(\"{CODE_CANARY}\");\n"),
        )
        .unwrap();
        root
    }
}

/// `(port, token, view)` from an opened URL `http://127.0.0.1:<port>/#t=<token>[&v=<view>]`.
fn parse_url(u: &str) -> (u16, String, Option<String>) {
    let rest = u
        .strip_prefix("http://127.0.0.1:")
        .unwrap_or_else(|| panic!("{u}"));
    let (port, frag) = rest.split_once("/#t=").unwrap_or_else(|| panic!("{u}"));
    let (token, view) = match frag.split_once("&v=") {
        Some((t, v)) => (t.to_owned(), Some(v.to_owned())),
        None => (frag.to_owned(), None),
    };
    (port.parse().unwrap(), token, view)
}

/// A shell snippet (run outside) that signs in with `$TOKEN` on `$PORT` and fetches every API
/// route into `<base>/api/<name>.json`, writing each status into `<base>/api/<name>.code`.
fn fetch_all_script(base: &Path) -> String {
    let api = base.join("api");
    format!(
        r#"mkdir -p '{api}'
H="Host: 127.0.0.1:$PORT"
O="Origin: http://127.0.0.1:$PORT"
curl -s -D '{api}/session.hdr' -o '{api}/session.json' -H "$H" -H "$O" -H 'Content-Type: application/json' --data "{{\"token\":\"$TOKEN\"}}" "http://127.0.0.1:$PORT/api/session"
COOKIE=$(grep -i '^set-cookie:' '{api}/session.hdr' | sed 's/.*ms_dash=\([0-9a-f]*\).*/\1/')
CSRF=$(sed 's/.*"csrf":"\([0-9a-f]*\)".*/\1/' '{api}/session.json')
get() {{ curl -s -o "{api}/$1.json" -w '%{{http_code}}' -H "$H" -H "Cookie: ms_dash=$COOKIE" -H "X-Morsec-CSRF: $CSRF" "http://127.0.0.1:$PORT$2" > "{api}/$1.code"; }}
get home /api/home
get projects /api/projects
get project /api/projects/shop
get stripe /api/keys/shop%2Fstripe-secret-key
get openai /api/keys/shop%2Fopenai-api-key
get session-secret /api/keys/shop%2Fsession-secret
get activity '/api/activity?since=30d'
get verify /api/activity/verify
get export-json '/api/activity/export?format=json'
get export-csv '/api/activity/export?format=csv'
get agents /api/agents
get scan /api/scan
curl -s -o '{api}/page.html' -D '{api}/page.hdr' -H "$H" "http://127.0.0.1:$PORT/"
curl -s -o /dev/null -w '%{{http_code}}' -H "$H" "http://127.0.0.1:$PORT/api/home" > '{api}/nocookie.code'
"#,
        api = api.display()
    )
}

// protects=design §6.1, §8 (port squatting) and criterion 13: `ms dashboard` opens exactly the
// port msd reports holding (msd skipped the port this test squats), on 127.0.0.1, with the token
// only in the fragment and never printed, and that port serves the dashboard with its CSP; the
// token signs in once; fails_when=the URL names another port or host, the token is in the path
// or the output, or the page there is not ours; no_claim=a real browser (the browser pass)
#[test]
fn dashboard_opens_the_port_msd_bound() {
    let fx = Fx::new();
    let base = fx.base();
    let (code, out) = fx.outside(&base, r#""$MS" dashboard"#);
    assert_eq!(code, 0, "{out}");
    let url = fx.url();
    let (port, token, view) = parse_url(&url);
    assert_ne!(port, fx.dash_port, "the squatted port is not opened");
    assert!(port > fx.dash_port && port < fx.dash_port + 10, "{url}");
    assert_eq!(token.len(), 64, "{url}");
    assert_eq!(view, None);
    assert!(!out.contains(&token), "the token is never printed: {out}");
    assert!(out.contains(&format!("http://127.0.0.1:{port}")), "{out}");
    let (code, out) = fx.outside(
        &base,
        &format!(
            "PORT={port}; TOKEN={token}\n{}\nT2=$(curl -s -o /dev/null -w '%{{http_code}}' -H \"$H\" -H \"$O\" -H 'Content-Type: application/json' --data \"{{\\\"token\\\":\\\"$TOKEN\\\"}}\" \"http://127.0.0.1:$PORT/api/session\"); echo \"second=$T2\"",
            fetch_all_script(&base)
        ),
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("second=403"),
        "the launch token works once: {out}"
    );
    let api = base.join("api");
    let page_hdr = std::fs::read_to_string(api.join("page.hdr")).unwrap();
    assert!(page_hdr.starts_with("HTTP/1.1 200"), "{page_hdr}");
    assert!(
        page_hdr
            .to_ascii_lowercase()
            .contains("content-security-policy: default-src 'none'"),
        "{page_hdr}"
    );
    assert_eq!(
        std::fs::read_to_string(api.join("home.code")).unwrap(),
        "200"
    );
    assert_eq!(
        std::fs::read_to_string(api.join("nocookie.code")).unwrap(),
        "401"
    );

    // A project name opens its page.
    let (code, out) = fx.outside(&base, r#""$MS" dashboard shop"#);
    assert_eq!(code, 0, "{out}");
    let (port2, _, view) = parse_url(&fx.url());
    assert_eq!(port2, port, "the listener is reused");
    assert_eq!(view.as_deref(), Some("project/shop"));
}

// protects=design §6.2.1 and §8 (agent curls the dashboard; agent runs ms dashboard): from a
// real agent process tree (a process named `claude` running curl as its child) the connection is closed with no
// byte, msd records a blocked receipt under morsec/dashboard charged to the claude-code session,
// and `ms dashboard` refuses before asking msd; the user's own curl is served; fails_when=the
// agent's curl gets any HTTP response, no receipt names the session, or the agent gets a URL;
// no_claim=a detached same-user process (it is not an agent session: T-04)
#[test]
fn dash_refuses_agent_process_tree() {
    let fx = Fx::new();
    let base = fx.base();
    let (code, out) = fx.outside(&base, r#""$MS" dashboard"#);
    assert_eq!(code, 0, "{out}");
    let (port, _, _) = parse_url(&fx.url());
    let agent = fx.fake_agent();
    let (_, out) = fx.outside(
        &base,
        &format!(
            "'{}' curl -s -o '{}/agent.out' -w 'code=%{{http_code}}' -H 'Host: 127.0.0.1:{port}' http://127.0.0.1:{port}/; echo \" rc=$?\"",
            agent.display(),
            base.display()
        ),
    );
    assert!(out.contains("code=000"), "the agent got a response: {out}");
    let got = std::fs::read(base.join("agent.out")).unwrap_or_default();
    assert!(got.is_empty(), "{}", String::from_utf8_lossy(&got));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let r = fx.receipts();
        if r.contains("morsec/dashboard") {
            assert!(r.contains("claude_code"), "{r}");
            assert!(r.contains("a connection from an agent session"), "{r}");
            break;
        }
        assert!(Instant::now() < deadline, "no refusal receipt: {r}");
        std::thread::sleep(Duration::from_millis(50));
    }
    // The user's own curl, outside the agent, is served.
    let (_, out) = fx.outside(
        &base,
        &format!(
            "curl -s -o /dev/null -w 'code=%{{http_code}}' -H 'Host: 127.0.0.1:{port}' http://127.0.0.1:{port}/"
        ),
    );
    assert!(out.contains("code=200"), "{out}");
    // ms dashboard inside the agent refuses before asking msd.
    std::fs::remove_file(base.join("url.txt")).unwrap();
    let (_, out) = fx.outside(
        &base,
        &format!("'{}' \"$MS\" dashboard; echo \" rc=$?\"", agent.display()),
    );
    assert!(out.contains("agent session"), "{out}");
    assert!(out.contains("rc=1"), "{out}");
    assert!(!base.join("url.txt").exists(), "an agent got a URL");
}

// protects=SPEC criteria 9, 10 and 13 end to end: after a real `ms init` of a project (values in
// .env, a key written into code), `ms dashboard` signs in and every API route answers 200 with
// the project's names, files, keys, hosts and the code finding's place, and no value (the three
// env values, the code canary) appears in any response, export included; fails_when=a route
// fails or any value or its tail is served; no_claim=what a browser renders (the browser pass)
#[test]
fn dashboard_end_to_end() {
    let fx = Fx::new();
    let base = fx.base();
    let root = fx.shop();
    let (code, out) = fx.outside(
        &root,
        r#"(i=0; while [ $i -lt 200 ]; do printf 'o\n'; sleep 0.3; i=$((i+1)); done) | script -q /dev/null "$MS" init --no-connect --no-open"#,
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Dashboard  ms dashboard"), "{out}");
    let (code, out) = fx.outside(&root, r#""$MS" dashboard shop"#);
    assert_eq!(code, 0, "{out}");
    let (port, token, view) = parse_url(&fx.url());
    assert_eq!(view.as_deref(), Some("project/shop"));
    let (code, out) = fx.outside(
        &base,
        &format!("PORT={port}; TOKEN={token}\n{}", fetch_all_script(&base)),
    );
    assert_eq!(code, 0, "{out}");
    let api = base.join("api");
    let mut all = String::new();
    for name in [
        "home",
        "projects",
        "project",
        "stripe",
        "openai",
        "session-secret",
        "activity",
        "verify",
        "export-json",
        "export-csv",
        "agents",
        "scan",
    ] {
        let code = std::fs::read_to_string(api.join(format!("{name}.code"))).unwrap();
        let body = std::fs::read_to_string(api.join(format!("{name}.json"))).unwrap();
        assert_eq!(code, "200", "{name}: {body}");
        all.push_str(&body);
        all.push('\n');
    }
    for want in [
        "shop/stripe-secret-key",
        "STRIPE_SECRET_KEY",
        "api.stripe.com",
        "src/pay.ts",
        "needs a website",
    ] {
        assert!(all.contains(want), "missing {want}");
    }
    for value in [T_STRIPE, OAI, SESSION, CODE_CANARY] {
        assert!(!all.contains(value), "a value was served");
        assert!(
            !all.contains(&value[value.len() - 12..]),
            "a value's tail was served"
        );
    }
    let project: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(api.join("project.json")).unwrap()).unwrap();
    assert_eq!(project["rows"].as_array().unwrap().len(), 3, "{project}");
}
