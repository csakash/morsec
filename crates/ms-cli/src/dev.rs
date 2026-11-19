//! `ms dev -- <cmd…>` (L34): run your own command (`npm run dev`) so the `ms://` refs in your
//! project work, the way they do for agents.
//!
//! `ms dev` asks msd for a dev session (`DevStart`), then runs the command as its own child in
//! your terminal with `HTTPS_PROXY` pointing at msd's swap proxy (the session's credential as the
//! proxy username), the CA variables pointing at a bundle with morsec's CA, and the real values of
//! the project's run-mode keys (database URLs) in the environment. msd serves the credential only
//! to processes under this `ms dev` process. The session ends when the command exits.
//!
//! Exit status: the command's own (128 + signal when a signal ended it); 77 refused, 69 the daemon
//! is not running, 64 usage error, 70 morsec failed.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use ms_core::SecretBytes;
use ms_ipc::{Client, ErrorCode, RequestBody, ResponseBody};
use ms_run::client::{EXIT_INTERNAL, EXIT_REFUSED, EXIT_UNAVAILABLE, EXIT_USAGE};

use crate::terminal_safe;

/// How long `DevStart` may wait (a Touch ID approval can take up to 120 s).
const START_TIMEOUT: Duration = Duration::from_secs(150);
/// The CA variables connectors point at their bundle (design §7.3).
pub(crate) const CA_VARS: [&str; 4] = [
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
];
/// Loopback names that must never go to the proxy (its SSRF guard refuses them).
const LOCAL: [&str; 4] = ["localhost", "127.0.0.1", "::1", ".localhost"];
/// macOS system roots, the base of the CA bundle.
const SYSTEM_ROOTS: &str = "/etc/ssl/cert.pem";
/// Programs that mean "this is a Node app" for the version warning.
const NODE_TOOLS: [&str; 5] = ["node", "npm", "npx", "pnpm", "yarn"];

#[derive(Debug, Args)]
#[command(after_help = "\
Runs your own command (for example your app's dev server) so the ms:// references in your \
project's .env files work: requests to your keys' services go through morsec, which swaps the \
real key in, and run-mode values (database URLs) are put in the command's environment.

  ms dev -- npm run dev

Run it inside a project you set up with ms init, from your own terminal (not inside an agent). \
Each run asks you once (Touch ID), on this terminal or with ms approve. Node needs version 24 or later \
to send its requests through morsec (ms dev sets NODE_USE_ENV_PROXY=1).

Exit status: the command's own; 77 refused, 69 the daemon is not running, 64 usage error, 70 \
morsec failed.")]
pub(crate) struct DevArgs {
    /// The command and its arguments, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CMD"
    )]
    command: Vec<OsString>,
}

/// `ms dev`.
pub(crate) fn run(a: &DevArgs) -> ExitCode {
    match dev(a) {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err((msg, code)) => {
            eprintln!("{}", terminal_safe(&msg));
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
    }
}

/// The agent `argv0` names (design §7.1), by the name given and by the file it resolves to on
/// `path` after following symlinks. `None` when it is none of them.
pub(crate) fn agent_binary(argv0: &OsStr, path: Option<&OsStr>) -> Option<String> {
    let given = Path::new(argv0);
    let mut names: Vec<OsString> = given.file_name().map(OsStr::to_owned).into_iter().collect();
    let found = if given.components().count() > 1 {
        Some(given.to_path_buf())
    } else {
        path.and_then(|p| {
            std::env::split_paths(p)
                .map(|d| d.join(given))
                .find(|c| c.is_file())
        })
    };
    let real = found.and_then(|f| std::fs::canonicalize(f).ok());
    if let Some(n) = real.as_deref().and_then(Path::file_name) {
        names.push(n.to_owned());
    }
    if let Some(n) = names
        .iter()
        .filter_map(|n| n.to_str())
        .find(|n| ms_session::agent_kind(n).is_some())
    {
        return Some(n.to_owned());
    }
    // Review N2: a versioned native binary (`~/.local/share/claude/versions/2.0.5`) or an npm
    // package path says it is an agent only by where it lives.
    [Some(given), real.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|p| p.to_str())
        .find_map(ms_session::agent_install_path)
        .map(|k| format!("{k:?}"))
}

/// The major version in `node --version` output (`v22.3.0` → 22).
pub(crate) fn node_major(out: &str) -> Option<u32> {
    out.trim()
        .strip_prefix('v')?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// The warning for a Node command whose `node --version` said `version` (None: unknown).
pub(crate) fn node_warning(argv0: &OsStr, version: Option<&str>) -> Option<String> {
    let name = Path::new(argv0).file_name()?.to_str()?;
    if !NODE_TOOLS.contains(&name) {
        return None;
    }
    match version.and_then(node_major) {
        Some(m) if m >= 24 => None,
        Some(m) => Some(format!(
            "Node {m} ignores HTTPS_PROXY, so calls to your keys' services will send the ms:// reference and fail. Use Node 24 or later"
        )),
        None => Some(
            "couldn't tell which Node this runs; Node older than 24 ignores HTTPS_PROXY, so calls would send the ms:// reference and fail".into(),
        ),
    }
}

fn node_version(path: Option<&OsStr>) -> Option<String> {
    let node = path.and_then(|p| {
        std::env::split_paths(p)
            .map(|d| d.join("node"))
            .find(|c| c.is_file())
    })?;
    let mut child = std::process::Command::new(node)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    Some(out)
}

/// What msd answered to `DevStart`.
pub(crate) struct Started {
    pub session: String,
    pub credential: String,
    pub proxy_port: u16,
    pub project: String,
    pub root: String,
    pub env: Vec<String>,
    pub swapped: Vec<String>,
    pub notes: Vec<String>,
}

/// The variables `ms dev` sets on the child (design §7.3), from the user's own environment
/// `current`: proxy, `NO_PROXY` with loopback added, `NODE_USE_ENV_PROXY`, the CA variables when
/// there is a `bundle`, and each run-mode value unless the user already set that variable to
/// something that is not an `ms://` ref. Returns the variables and notes (names only).
pub(crate) fn child_env(
    s: &Started,
    values: Vec<SecretBytes>,
    bundle: Option<&Path>,
    current: &[(OsString, OsString)],
) -> (Vec<(OsString, OsString)>, Vec<String>) {
    let get = |n: &str| {
        current
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.to_string_lossy().into_owned())
    };
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    let mut notes = Vec::new();
    let proxy = format!("http://{}@127.0.0.1:{}", s.credential, s.proxy_port);
    for n in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
        out.push((n.into(), proxy.clone().into()));
    }
    let mut no_proxy: Vec<String> = get("NO_PROXY")
        .or_else(|| get("no_proxy"))
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    for l in LOCAL {
        if !no_proxy.iter().any(|x| x == l) {
            no_proxy.push(l.to_owned());
        }
    }
    let no_proxy = no_proxy.join(",");
    out.push(("NO_PROXY".into(), no_proxy.clone().into()));
    out.push(("no_proxy".into(), no_proxy.into()));
    out.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    if let Some(b) = bundle {
        for v in CA_VARS {
            out.push((v.into(), b.as_os_str().to_owned()));
        }
    }
    for (name, value) in s.env.iter().zip(values) {
        match get(name) {
            Some(mine) if ms_core::SecretRef::parse(&mine).is_err() && !mine.is_empty() => {
                notes.push(format!(
                    "{name} is already set in your shell, so your value was kept (unset it to use the project's)"
                ));
            }
            _ => out.push((name.into(), OsStr::from_bytes(value.expose()).to_owned())),
        }
    }
    (out, notes)
}

/// Writes `~/.morsec/dev-ca-bundle.pem`: the system roots and msd's CA (public).
fn write_bundle(ca_pem: &str) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or("HOME is not set")?;
    let roots = std::fs::read_to_string(SYSTEM_ROOTS)
        .map_err(|e| format!("can't read the system roots {SYSTEM_ROOTS}: {e}"))?;
    let p = PathBuf::from(home).join(".morsec/dev-ca-bundle.pem");
    let text = format!(
        "# morsec CA bundle for ms dev: the system roots and the morsec proxy CA. Written by ms dev.\n{roots}\n{ca_pem}\n"
    );
    ms_connect::claude::fsio::atomic_write(&p, &text, 0o644)?;
    Ok(p)
}

fn refused(r: &ResponseBody) -> (String, i32) {
    match r {
        ResponseBody::Error { code, message } => (
            message.clone(),
            match code {
                ErrorCode::Denied | ErrorCode::NeedsApproval | ErrorCode::Busy => EXIT_REFUSED,
                ErrorCode::Invalid => EXIT_USAGE,
                _ => EXIT_INTERNAL,
            },
        ),
        _ => (
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)".into(),
            EXIT_INTERNAL,
        ),
    }
}

fn dev(a: &DevArgs) -> Result<i32, (String, i32)> {
    let usage = |m: &str| (m.to_owned(), EXIT_USAGE);
    let Some(argv0) = a.command.first() else {
        return Err(usage(
            "morsec: give the command after --, e.g. ms dev -- npm run dev",
        ));
    };
    // Before anything is asked of msd (design §7.1).
    if let Some(who) = crate::connect::inside_agent() {
        return Err((
            format!(
                "morsec: ms dev runs your own command with your project's keys, so it runs only from your own terminal, not inside an agent session ({who})"
            ),
            EXIT_REFUSED,
        ));
    }
    let path = std::env::var_os("PATH");
    if let Some(name) = agent_binary(argv0, path.as_deref()) {
        return Err((
            format!(
                "morsec: ms dev doesn't start coding agents ({name}): an agent would get your project's run-mode values. Start agents normally; morsec swaps keys for them"
            ),
            EXIT_REFUSED,
        ));
    }
    let argv = a
        .command
        .iter()
        .map(|s| s.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| usage("morsec: an argument is not valid UTF-8"))?;
    let cwd = std::env::current_dir()
        .map_err(|e| usage(&format!("morsec: can't read the current directory: {e}")))?;
    let socket = ms_ipc::default_socket_path().map_err(|e| (e.to_string(), EXIT_UNAVAILABLE))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (format!("morsec: {e}"), EXIT_INTERNAL))?;

    // A project with a production key needs one approval: reviewed here, on this terminal.
    let review = crate::approve::inline_review_once_only("ms dev");
    let (reply, values) = rt.block_on(async {
        let mut c = Client::connect(&socket)
            .await
            .map_err(|e| (e.to_string(), EXIT_UNAVAILABLE))?;
        c.request_with_values(
            RequestBody::DevStart {
                argv: argv.clone(),
                cwd: cwd.clone(),
            },
            START_TIMEOUT,
        )
        .await
        .map_err(|e| (e.to_string(), EXIT_INTERNAL))
    })?;
    drop(review);
    let (started, ca_pem) = match reply {
        ResponseBody::DevStarted {
            session,
            credential,
            proxy_port,
            project,
            root,
            ca_pem,
            env,
            swapped,
            notes,
        } => (
            Started {
                session,
                credential,
                proxy_port,
                project,
                root,
                env,
                swapped,
                notes,
            },
            ca_pem,
        ),
        other => return Err(refused(&other)),
    };

    let mut notes = started.notes.clone();
    let bundle = match ca_pem.as_deref().map(write_bundle) {
        Some(Ok(p)) => Some(p),
        Some(Err(e)) => {
            notes.push(format!(
                "the CA bundle could not be written ({e}), so HTTPS through morsec will fail certificate checks"
            ));
            None
        }
        None => None,
    };
    let current: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let (set, more) = child_env(&started, values, bundle.as_deref(), &current);
    // Review R6: name only the variables the child really gets.
    let env_names: Vec<String> = started
        .env
        .iter()
        .filter(|n| set.iter().any(|(k, _)| k == n.as_str()))
        .cloned()
        .collect();
    notes.extend(more);
    if let Some(w) = node_warning(argv0, node_version(path.as_deref()).as_deref()) {
        notes.push(w);
    }

    eprintln!(
        "{}",
        terminal_safe(&format!(
            "morsec dev: project {} ({})",
            started.project, started.root
        ))
    );
    let list = |v: &[String]| {
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.join(", ")
        }
    };
    eprintln!(
        "{}",
        terminal_safe(&format!(
            "  swapped through the proxy: {}",
            list(&started.swapped)
        ))
    );
    eprintln!(
        "{}",
        terminal_safe(&format!(
            "  values in the environment: {}",
            list(&env_names)
        ))
    );
    eprintln!("  NODE_USE_ENV_PROXY=1 is set (Node 24 or later sends requests through morsec)");
    for n in &notes {
        eprintln!("{}", terminal_safe(&format!("  note: {n}")));
    }

    let code = rt.block_on(run_child(&a.command, set));
    // Best effort: msd also ends the session once this process is gone.
    rt.block_on(async {
        if let Ok(mut c) = Client::connect(&socket).await {
            let _ = c
                .request(RequestBody::DevEnd {
                    session: started.session.clone(),
                })
                .await;
        }
    });
    code
}

/// Runs the child in this process group (it keeps the terminal and gets Ctrl-C from it),
/// forwards SIGTERM and SIGHUP, ignores SIGINT and SIGQUIT here (the terminal already sent them
/// to the child), and returns its exit status as a shell reports it.
async fn run_child(
    command: &[OsString],
    env: Vec<(OsString, OsString)>,
) -> Result<i32, (String, i32)> {
    use std::os::unix::process::ExitStatusExt;
    use tokio::signal::unix::{SignalKind, signal};
    let sig = |k| signal(k).map_err(|e| (format!("morsec: signals: {e}"), EXIT_INTERNAL));
    // Handlers before the spawn, so an early Ctrl-C can't kill ms dev and orphan the child.
    // Handled signals are reset to their defaults in the child at exec.
    let (mut term, mut hup, mut int, mut quit) = (
        sig(SignalKind::terminate())?,
        sig(SignalKind::hangup())?,
        sig(SignalKind::interrupt())?,
        sig(SignalKind::quit())?,
    );
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]).envs(env);
    let mut child = cmd.spawn().map_err(|e| {
        (
            format!(
                "morsec: could not start {}: {e}",
                terminal_safe(&command[0].to_string_lossy())
            ),
            if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            },
        )
    })?;
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));
    // Review R7: the child is polled here (try_wait), never reaped on another thread, so a
    // signal is forwarded only while it is known not to be reaped: its PID can't be reused yet.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
    let forward = |child: &mut std::process::Child, s: rustix::process::Signal| {
        if matches!(child.try_wait(), Ok(None))
            && let Some(p) = pid
        {
            let _ = rustix::process::kill_process(p, s);
        }
    };
    let status = loop {
        tokio::select! {
            _ = tick.tick() => match child.try_wait() {
                Ok(Some(st)) => break Ok(st),
                Ok(None) => {}
                Err(e) => break Err(e),
            },
            _ = term.recv() => forward(&mut child, rustix::process::Signal::TERM),
            _ = hup.recv() => forward(&mut child, rustix::process::Signal::HUP),
            _ = int.recv() => {}
            _ = quit.recv() => {}
        }
    };
    match status {
        Ok(st) => Ok(st
            .code()
            .or_else(|| st.signal().map(|s| 128 + s))
            .unwrap_or(1)),
        _ => Err(("morsec: lost track of the command".into(), EXIT_INTERNAL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=L34 SPEC criterion 2 (design §7.1): ms dev refuses an agent by bare name, by
    // path, through a symlink with another name found on PATH, and by an agent's install path
    // (review N2); a plain program is fine;
    // fails_when=claude, codex, cursor-agent or gemini reach DevStart under any of those names;
    // no_claim=wrappers (npx claude, a script that runs claude; SPEC residual)
    #[test]
    fn dev_refused_for_agent_binary() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for n in ["claude", "node"] {
            std::fs::write(bin.join(n), "#!/bin/sh\n").unwrap();
        }
        std::os::unix::fs::symlink(bin.join("claude"), bin.join("helper")).unwrap();
        let path = bin.as_os_str();
        for argv0 in ["claude", "codex", "cursor-agent", "gemini", "/opt/x/codex"] {
            assert!(
                agent_binary(OsStr::new(argv0), Some(path)).is_some(),
                "{argv0}"
            );
        }
        assert_eq!(
            agent_binary(OsStr::new("helper"), Some(path)).as_deref(),
            Some("claude")
        );
        let full = bin.join("helper");
        assert!(agent_binary(full.as_os_str(), None).is_some());
        assert_eq!(agent_binary(OsStr::new("node"), Some(path)), None);
        // Review N2: by install path, given or behind a symlink with a plain name.
        let versions = d.path().join("share/claude/versions");
        std::fs::create_dir_all(&versions).unwrap();
        std::fs::write(versions.join("2.0.5"), "#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(versions.join("2.0.5"), bin.join("cc")).unwrap();
        assert!(agent_binary(versions.join("2.0.5").as_os_str(), None).is_some());
        assert!(agent_binary(OsStr::new("cc"), Some(path)).is_some());
        assert_eq!(agent_binary(OsStr::new("npm"), Some(path)), None);
    }

    // protects=design §7.5 residual: Node older than 24 (or unknown) is warned about for Node
    // tools; Node 24+ and non-Node commands are not; fails_when=Node 22 gets no warning;
    // no_claim=that the warning reaches every Node app (best effort)
    #[test]
    fn node_version_warning() {
        assert_eq!(node_major("v22.3.0\n"), Some(22));
        assert_eq!(node_major("24.0.0"), None);
        let npm = OsStr::new("npm");
        assert!(
            node_warning(npm, Some("v22.3.0"))
                .unwrap()
                .contains("Node 22")
        );
        assert!(node_warning(npm, Some("v24.1.0")).is_none());
        assert!(node_warning(npm, None).is_some());
        assert!(node_warning(OsStr::new("/usr/local/bin/node"), Some("v18.0.0")).is_some());
        assert!(node_warning(OsStr::new("python3"), None).is_none());
    }

    // protects=L34 SPEC behaviour 3 / design §7.3: the child gets the proxy (credential as the
    // username) in all four spellings, NO_PROXY with loopback added to the user's list,
    // NODE_USE_ENV_PROXY=1, the CA variables when there is a bundle, and each run-mode value under
    // its own name; a user's explicit non-ref value is kept with a note that names the variable
    // only; fails_when=a proxy variable is missing, loopback goes to the proxy, a value lands in
    // another variable or in a note; no_claim=that the child honours them (e2e)
    #[test]
    fn child_env_is_built_from_names() {
        let s = Started {
            session: "s".into(),
            credential: format!("ms-dev-{}", "ab".repeat(32)),
            proxy_port: 4401,
            project: "shop".into(),
            root: "/p/shop".into(),
            env: vec![
                "DATABASE_URL".into(),
                "REDIS_URL".into(),
                "CACHE_URL".into(),
            ],
            swapped: Vec::new(),
            notes: Vec::new(),
        };
        let v = |x: &str| SecretBytes::new(x.as_bytes().to_vec());
        let current: Vec<(OsString, OsString)> = vec![
            ("NO_PROXY".into(), "corp.internal, localhost".into()),
            ("REDIS_URL".into(), "redis://mine".into()),
            ("CACHE_URL".into(), "ms://shop/cache-url".into()),
        ];
        let (set, notes) = child_env(
            &s,
            vec![
                v("postgres://CANARY"),
                v("redis://CANARY"),
                v("cache://CANARY"),
            ],
            Some(Path::new("/h/.morsec/dev-ca-bundle.pem")),
            &current,
        );
        let get = |n: &str| {
            set.iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.to_string_lossy().into_owned())
        };
        let proxy = format!("http://{}@127.0.0.1:4401", s.credential);
        for n in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
            assert_eq!(get(n).as_deref(), Some(proxy.as_str()), "{n}");
        }
        assert_eq!(
            get("NO_PROXY").as_deref(),
            Some("corp.internal,localhost,127.0.0.1,::1,.localhost")
        );
        assert_eq!(get("NODE_USE_ENV_PROXY").as_deref(), Some("1"));
        for n in CA_VARS {
            assert_eq!(get(n).as_deref(), Some("/h/.morsec/dev-ca-bundle.pem"));
        }
        assert_eq!(get("DATABASE_URL").as_deref(), Some("postgres://CANARY"));
        assert_eq!(get("CACHE_URL").as_deref(), Some("cache://CANARY"));
        assert_eq!(get("REDIS_URL"), None, "the user's own value is kept");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("REDIS_URL") && !notes[0].contains("CANARY"));
        let (set, _) = child_env(&s, Vec::new(), None, &[]);
        assert!(set.iter().all(|(k, _)| k != "SSL_CERT_FILE"));
        assert!(set.iter().all(|(k, _)| k != "DATABASE_URL"));
    }
}
