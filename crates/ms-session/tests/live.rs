//! Live tests against real processes and sockets.
//!
//! This binary is its own fake agent: it copies itself to a temp dir as `claude`, `codex` and
//! `helper`. The kernel names a process after the file it exec'd, so the copies run as fake
//! agents. When started under one of those names it acts as a helper (see [`helper_main`]);
//! otherwise it runs the tests.
//!
//! Each fake tree is started **detached** (reparented to PID 1). Otherwise the outermost-agent
//! rule would, correctly, attribute it to whatever real agent is running the tests.
#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use ms_core::AgentKind;
use ms_session::{
    Caller, OsProcessTable, PortResolver, ProcessTable, Resolver, SessionError, SocketTable,
    cross_check,
};

const HELPER_NAMES: [&str; 3] = ["claude", "codex", "helper"];

// ---------------------------------------------------------------------------------------------
// Helper mode
// ---------------------------------------------------------------------------------------------

/// `detach <cmd…>`: start cmd in a new process group and exit, so it reparents to PID 1.
/// `run <pidfile> [cmd…]`: write own PID, then run cmd and wait (or sleep).
/// `connect <port> <pidfile>`: connect to 127.0.0.1:port, write PID, hold the socket.
fn helper_main(args: &[String]) -> ExitCode {
    let write_pid = |file: &str| {
        let mut f = std::fs::File::create(file).expect("pidfile");
        writeln!(f, "{}", std::process::id()).expect("write pid");
    };
    match args.first().map(String::as_str) {
        Some("detach") => {
            // Deliberately not waited on: this process exits so the child reparents to PID 1,
            // which reaps it.
            #[allow(clippy::zombie_processes)]
            Command::new(&args[1])
                .args(&args[2..])
                .stdin(Stdio::null())
                .process_group(0)
                .spawn()
                .expect("spawn detached");
            ExitCode::SUCCESS
        }
        Some("run") => {
            write_pid(&args[1]);
            if args.len() > 2 {
                let _ = Command::new(&args[2]).args(&args[3..]).status();
            } else {
                std::thread::sleep(Duration::from_secs(60));
            }
            ExitCode::SUCCESS
        }
        Some("connect") => {
            let port: u16 = args[1].parse().expect("port");
            let _s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            write_pid(&args[2]);
            std::thread::sleep(Duration::from_secs(60));
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(2),
    }
}

// ---------------------------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------------------------

struct Fakes {
    dir: tempfile::TempDir,
}

impl Fakes {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let me = std::env::current_exe().expect("current_exe");
        for n in HELPER_NAMES {
            std::fs::copy(&me, dir.path().join(n)).expect("copy self");
        }
        Self { dir }
    }
    fn bin(&self, n: &str) -> String {
        self.dir.path().join(n).display().to_string()
    }
    fn file(&self, n: &str) -> String {
        self.dir.path().join(n).display().to_string()
    }
}

fn read_pid(path: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = std::fs::read_to_string(path)
            && s.ends_with('\n')
            && let Ok(p) = s.trim().parse()
        {
            return p;
        }
        assert!(Instant::now() < deadline, "never written: {path}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A detached tree. Killed (whole process group) on drop.
struct Tree {
    root: u32,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.root)])
            .stderr(Stdio::null())
            .status();
    }
}

/// Starts `argv` detached and waits for its root (which must write `root_pidfile`) to be
/// reparented to PID 1.
fn detached(f: &Fakes, argv: &[String], root_pidfile: &str) -> Tree {
    let status = Command::new(f.bin("helper"))
        .arg("detach")
        .args(argv)
        .status()
        .expect("launcher");
    assert!(status.success());
    let root = read_pid(root_pidfile);
    let tree = Tree { root };
    let deadline = Instant::now() + Duration::from_secs(10);
    while OsProcessTable
        .info(root)
        .map(|i| i.ppid != 1)
        .unwrap_or(true)
    {
        assert!(Instant::now() < deadline, "root {root} never reparented");
        std::thread::sleep(Duration::from_millis(10));
    }
    tree
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

// protects=live process reads (pid, ppid, start time, name); fails_when=the platform layer
// returns wrong fields for a real process; no_claim=other users' processes
fn reads_this_process() {
    let me = OsProcessTable.info(std::process::id()).expect("self");
    assert_eq!(me.pid, std::process::id());
    assert_eq!(me.ppid, std::os::unix::process::parent_id());
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    assert!(me.started_unix_ms <= now && me.started_unix_ms > now - 3_600_000);
    assert_eq!(me.uid, OsProcessTable.info(std::process::id()).unwrap().uid);
    assert!(!me.name.is_empty());
}

// protects=AUTH-1 nested fake-agent tree; fails_when=a leaf under claude -> helper -> codex ->
// helper is not attributed to the outer claude; no_claim=real agent binaries (QA covers those)
fn nested_fake_agents_resolve_to_the_outermost() {
    let f = Fakes::new();
    let (root, mid, inner, leaf) = (f.file("r"), f.file("m"), f.file("i"), f.file("l"));
    let argv = s(&[
        &f.bin("claude"),
        "run",
        &root,
        &f.bin("helper"),
        "run",
        &mid,
        &f.bin("codex"),
        "run",
        &inner,
        &f.bin("helper"),
        "run",
        &leaf,
    ]);
    let tree = detached(&f, &argv, &root);
    let leaf = read_pid(&leaf);
    let inner = read_pid(&inner);
    let r = Resolver::new(OsProcessTable);
    let want = OsProcessTable.info(tree.root).unwrap();
    assert_eq!(want.name, "claude");
    for pid in [leaf, inner, read_pid(&mid), tree.root] {
        let c = r.resolve(pid).expect("resolve");
        let sid = c.session().expect("agent session");
        assert_eq!(sid.agent, AgentKind::ClaudeCode, "pid {pid}");
        assert_eq!(sid.pid, tree.root, "pid {pid}");
        assert_eq!(sid.started_unix_ms, want.started_unix_ms);
    }
    // The impostor `codex` really is named codex; the outermost rule is what overrides it.
    assert_eq!(OsProcessTable.info(inner).unwrap().name, "codex");
}

// protects=agent kind from the tree; fails_when=a codex tree resolves as another agent or as
// unattributed; no_claim=codex's real process layout
fn codex_tree_resolves_to_codex() {
    let f = Fakes::new();
    let (root, leaf) = (f.file("r"), f.file("l"));
    let argv = s(&[
        &f.bin("codex"),
        "run",
        &root,
        &f.bin("helper"),
        "run",
        &leaf,
    ]);
    let tree = detached(&f, &argv, &root);
    let c = Resolver::new(OsProcessTable)
        .resolve(read_pid(&leaf))
        .unwrap();
    let sid = c.session().expect("agent session");
    assert_eq!(sid.agent, AgentKind::Codex);
    assert_eq!(sid.pid, tree.root);
}

// protects=detached processes are unattributed; fails_when=a process with no agent ancestor
// gets a session; no_claim=that unattributed means a person
fn detached_helper_is_unattributed() {
    let f = Fakes::new();
    let root = f.file("r");
    let tree = detached(&f, &s(&[&f.bin("helper"), "run", &root]), &root);
    let c = Resolver::new(OsProcessTable).resolve(tree.root).unwrap();
    assert!(
        matches!(c, Caller::Unattributed { pid, .. } if pid == tree.root),
        "{c:?}"
    );
}

// protects=PID reuse is a new session, live; fails_when=two agent processes give equal
// SessionIds or a respawn keeps the old start time; no_claim=forcing the kernel to reuse a PID
fn sessions_differ_by_start_time() {
    let f = Fakes::new();
    let (a, b) = (f.file("a"), f.file("b"));
    let ta = detached(&f, &s(&[&f.bin("codex"), "run", &a]), &a);
    std::thread::sleep(Duration::from_millis(5));
    let tb = detached(&f, &s(&[&f.bin("codex"), "run", &b]), &b);
    let r = Resolver::new(OsProcessTable);
    let (Caller::Agent(sa), Caller::Agent(sb)) =
        (r.resolve(ta.root).unwrap(), r.resolve(tb.root).unwrap())
    else {
        panic!("both are codex sessions");
    };
    assert_ne!(sa, sb);
    assert!(sa.started_unix_ms < sb.started_unix_ms);
}

// protects=the runner's own ancestry; fails_when=a child of this process is not attributed to
// the same caller as this process (outermost rule, live); no_claim=which agent runs the tests
fn child_inherits_the_runners_caller() {
    let f = Fakes::new();
    let root = f.file("r");
    let mut child = Command::new(f.bin("claude"))
        .args(["run", &root])
        .spawn()
        .unwrap();
    let pid = read_pid(&root);
    let r = Resolver::new(OsProcessTable);
    let me = r.resolve(std::process::id()).unwrap();
    let them = r.resolve(pid).unwrap();
    match &me {
        // Under a real agent: the fake `claude` child is inside that session.
        Caller::Agent(_) => assert_eq!(me, them),
        // Not under an agent: the fake `claude` child is its own session.
        Caller::Unattributed { .. } => assert_eq!(them.session().unwrap().pid, pid),
    }
    let _ = child.kill();
    let _ = child.wait();
}

// protects=macOS sysctl reads of root-owned processes (so the walk can pass login/launchd);
// fails_when=pid 1 is unreadable or misparsed; no_claim=Linux hidepid setups
fn reads_root_owned_processes() {
    let init = OsProcessTable.info(1).expect("pid 1 readable");
    assert_eq!(init.pid, 1);
    assert_eq!(init.uid, 0);
    assert_eq!(init.ppid, 0);
    #[cfg(target_os = "macos")]
    assert_eq!(init.name, "launchd");
    assert!(matches!(
        OsProcessTable.info(99_999_999).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput)
    ));
}

// protects=socket table reads incl. the darwin socket_fdinfo address and port offsets;
// fails_when=the client end is not found by its exact address pair, a different loopback
// address or swapped orientation matches the wrong end, or a closed socket still resolves;
// no_claim=IPv6 loopback (parser unit tests)
fn socket_table_live() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap();
    let client = TcpStream::connect(proxy).unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
    let me = std::process::id();

    let t0 = Instant::now();
    let owners = OsProcessTable.owners(peer, proxy).unwrap();
    let scan = t0.elapsed();
    assert_eq!(owners, vec![me], "client end owner");
    // Reversed orientation is the accepted (daemon-side) socket.
    assert_eq!(OsProcessTable.owners(proxy, peer).unwrap(), vec![me]);
    assert!(OsProcessTable.holds(me, peer, proxy).unwrap());
    // Same ports, different loopback address: not this connection.
    let other: std::net::SocketAddr = format!("127.0.0.2:{}", peer.port()).parse().unwrap();
    assert!(OsProcessTable.owners(other, proxy).unwrap().is_empty());
    println!("    full scan {scan:?}");

    // The resolver never answers with its own process.
    let pr = PortResolver::new(OsProcessTable, OsProcessTable);
    assert!(matches!(
        pr.resolve(peer, proxy),
        Err(SessionError::NoSocketOwner { .. })
    ));
    drop(client);
    drop(accepted);
    assert!(OsProcessTable.owners(peer, proxy).unwrap().is_empty());
}

// protects=AUTH-1 proxy path end to end; fails_when=a fake claude tree's connection does not
// resolve to that claude session, passes a codex username cross-check, or still resolves
// (from cache) after the client is gone; no_claim=the L05 proxy's Proxy-Authorization parsing
fn proxy_client_in_fake_agent_tree() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap();
    let f = Fakes::new();
    let (root, leaf) = (f.file("r"), f.file("l"));
    let argv = s(&[
        &f.bin("claude"),
        "run",
        &root,
        &f.bin("helper"),
        "connect",
        &proxy.port().to_string(),
        &leaf,
    ]);
    let tree = detached(&f, &argv, &root);
    let (_conn, peer) = listener.accept().unwrap();
    let leaf_pid = read_pid(&leaf);
    let pr = PortResolver::new(OsProcessTable, OsProcessTable);
    let t0 = Instant::now();
    let c = pr.resolve(peer, proxy).unwrap();
    let first = t0.elapsed();
    let sid = c.session().expect("agent");
    assert_eq!(sid.agent, AgentKind::ClaudeCode);
    assert_eq!(sid.pid, tree.root);
    assert_eq!(OsProcessTable.owners(peer, proxy).unwrap(), vec![leaf_pid]);
    assert!(cross_check(&c, "claude-code").is_ok());
    assert!(cross_check(&c, "codex").is_err());
    let t1 = Instant::now();
    assert_eq!(pr.resolve(peer, proxy).unwrap(), c);
    println!("    first {first:?}, cached+verified {:?}", t1.elapsed());

    drop(tree);
    let deadline = Instant::now() + Duration::from_secs(10);
    while OsProcessTable.info(leaf_pid).is_ok() {
        assert!(Instant::now() < deadline, "leaf never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pr.resolve(peer, proxy).is_err(), "stale cache answered");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let name = Path::new(&args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    if HELPER_NAMES.contains(&name.as_str()) {
        return helper_main(&args[1..]);
    }
    let filter: Option<&String> = args.iter().skip(1).find(|a| !a.starts_with('-'));
    let tests: &[(&str, fn())] = &[
        ("reads_this_process", reads_this_process),
        (
            "nested_fake_agents_resolve_to_the_outermost",
            nested_fake_agents_resolve_to_the_outermost,
        ),
        ("codex_tree_resolves_to_codex", codex_tree_resolves_to_codex),
        (
            "detached_helper_is_unattributed",
            detached_helper_is_unattributed,
        ),
        (
            "sessions_differ_by_start_time",
            sessions_differ_by_start_time,
        ),
        (
            "child_inherits_the_runners_caller",
            child_inherits_the_runners_caller,
        ),
        ("reads_root_owned_processes", reads_root_owned_processes),
        ("socket_table_live", socket_table_live),
        (
            "proxy_client_in_fake_agent_tree",
            proxy_client_in_fake_agent_tree,
        ),
    ];
    let mut failed = 0;
    let mut ran = 0;
    for (n, t) in tests {
        if filter.is_some_and(|f| !n.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        println!("test {n} ...");
        if std::panic::catch_unwind(t).is_err() {
            println!("test {n} ... FAILED");
            failed += 1;
        } else {
            println!("test {n} ... ok");
        }
    }
    println!("live: {ran} run, {failed} failed");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
