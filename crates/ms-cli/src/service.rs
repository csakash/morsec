//! `ms status`, `ms stop`, `ms start` and `ms init` (L07).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use clap::Args;
use ms_core::Error;
use ms_ipc::{Client, RequestBody, ResponseBody};

use crate::terminal_safe;

/// The LaunchAgent label.
pub const LABEL: &str = "cc.morsec.msd";
const PLIST_TEMPLATE: &str = include_str!("../../msd/launchd/cc.morsec.msd.plist");
/// `msd --init` exit code for "already set up".
const MSD_ALREADY: i32 = 10;

/// `ms init [options]`
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Start over: new internal keys, empty rules, a new receipts file. Stored keys and old
    /// receipts stop verifying (they are kept, renamed, for inspection).
    #[arg(long)]
    force: bool,
    /// Don't install or load the LaunchAgent; start msd yourself.
    #[arg(long)]
    no_launchd: bool,
    /// Add the morsec CA certificate to your login keychain's trust settings (macOS asks you).
    #[arg(long, conflicts_with_all = ["force", "resume"])]
    trust: bool,
    /// Old name for `ms start` (kept so scripts keep working; it needs Touch ID now).
    #[arg(long, conflicts_with_all = ["force", "trust"], hide = true)]
    resume: bool,
    /// Set up this Mac only, even inside a project.
    #[arg(long, conflicts_with_all = ["project", "trust", "resume"])]
    machine: bool,
    /// Protect this project (default: the current folder's project).
    #[arg(long, value_name = "PATH", num_args = 0..=1, conflicts_with_all = ["force", "trust", "resume"])]
    project: Option<Option<PathBuf>>,
    /// The project's name (default: its folder's name).
    #[arg(long, value_name = "NAME", conflicts_with_all = ["machine", "force", "trust", "resume"])]
    name: Option<String>,
    /// Don't connect the coding agents found on this Mac.
    #[arg(long)]
    no_connect: bool,
    /// Don't open the dashboard afterwards (it never opens when output isn't a terminal).
    #[arg(long)]
    no_open: bool,
}

/// `ms status [--open]`
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Also open the dashboard in your browser.
    #[arg(long)]
    open: bool,
}

fn say(s: &str) {
    for line in s.lines() {
        println!("{}", terminal_safe(line));
    }
}

fn fail(s: &str) -> ExitCode {
    eprintln!("{}", terminal_safe(s));
    ExitCode::FAILURE
}

async fn request(body: RequestBody) -> ms_core::Result<ResponseBody> {
    let path = ms_ipc::default_socket_path()?;
    Client::connect(&path).await?.request(body).await
}

fn plural(n: u32) -> &'static str {
    if n == 1 { "secret" } else { "secrets" }
}

/// The status line for a reply: the mockup's pill text.
pub(crate) fn status_line(resp: &ResponseBody) -> Option<String> {
    let ResponseBody::Status {
        version,
        running,
        keys,
        ..
    } = resp
    else {
        return None;
    };
    let protected = keys.map(|k| format!(" · {k} {} protected", plural(k)));
    Some(match running {
        Some(false) => format!(
            "morsec stopped{} · resume with: ms start",
            protected.unwrap_or_default()
        ),
        Some(true) => format!("morsec on{}", protected.unwrap_or_default()),
        None => format!("morsec on · daemon {version}"),
    })
}

pub(crate) async fn status(a: &StatusArgs) -> ExitCode {
    let code = status_only().await;
    if !a.open || code != ExitCode::SUCCESS {
        return code;
    }
    // DashOpen drives its own IPC runtime, which can't start inside this one.
    let opened = std::thread::spawn(|| crate::dashboard::open(None))
        .join()
        .unwrap_or_else(|_| Err("morsec: opening the dashboard failed".into()));
    match opened {
        Ok(o) => {
            say(&format!("Dashboard: {}", o.line()));
            if o.opened {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => fail(&e),
    }
}

async fn status_only() -> ExitCode {
    match request(RequestBody::Status).await {
        Ok(resp @ ResponseBody::Status { .. }) => {
            if let Some(line) = status_line(&resp) {
                say(&line);
            }
            if let ResponseBody::Status { alerts, .. } = &resp {
                for a in alerts {
                    eprintln!("warning: {}", terminal_safe(a));
                }
            }
            if let Some(hint) = crate::approve::status_hint().await {
                say(&hint);
            }
            ExitCode::SUCCESS
        }
        Ok(ResponseBody::Error { message, .. }) => fail(&message),
        Ok(_) => fail(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)",
        ),
        Err(e) => fail(&e.to_string()),
    }
}

fn print_reply(resp: ms_core::Result<ResponseBody>) -> ExitCode {
    match resp {
        Ok(ResponseBody::Ok { message }) => {
            say(&message);
            ExitCode::SUCCESS
        }
        Ok(ResponseBody::Error { message, .. }) => fail(&message),
        Ok(_) => fail(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)",
        ),
        Err(e) => fail(&e.to_string()),
    }
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "morsec: HOME is not set".to_owned())
}

/// `~/Library/LaunchAgents/cc.morsec.msd.plist`.
pub(crate) fn plist_path() -> Result<PathBuf, String> {
    Ok(home()?.join(format!("Library/LaunchAgents/{LABEL}.plist")))
}

/// Starts msd through launchd when its LaunchAgent is installed, and waits for the socket.
fn kickstart() -> Result<(), String> {
    let plist = plist_path()?;
    if !plist.exists() {
        return Err("morsec: msd is not running and its LaunchAgent is not installed. Set morsec up with: ms init".into());
    }
    let st = Command::new("launchctl")
        .args(["kickstart", &format!("gui/{}/{LABEL}", uid())])
        .status()
        .map_err(|e| format!("morsec: running launchctl: {e}"))?;
    if !st.success() {
        return Err(format!(
            "morsec: launchctl could not start msd. Load it with: launchctl bootstrap gui/{} {}",
            uid(),
            plist.display()
        ));
    }
    wait_for_socket(Duration::from_secs(10))
}

fn wait_for_socket(limit: Duration) -> Result<(), String> {
    let path = ms_ipc::default_socket_path().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "morsec: msd did not start within {}s. Check ~/Library/Logs/morsec/msd.log",
        limit.as_secs()
    ))
}

pub(crate) async fn stop() -> ExitCode {
    match request(RequestBody::Stop).await {
        Err(Error::DaemonUnavailable { .. }) => {
            // Down means nothing can use a key right now, but launchd may start it again, on.
            // Start it so the stop is recorded and kept.
            match tokio::task::spawn_blocking(kickstart).await {
                Ok(Ok(())) => print_reply(request(RequestBody::Stop).await),
                Ok(Err(e)) => fail(&format!(
                    "morsec: msd is not running, so nothing can use your keys right now. It is not marked stopped, though ({})",
                    e.strip_prefix("morsec: ").unwrap_or(&e)
                )),
                Err(e) => fail(&format!("morsec: {e}")),
            }
        }
        other => print_reply(other),
    }
}

/// Like [`request`], waiting long enough for a person's approval.
async fn request_approved(body: RequestBody) -> ms_core::Result<ResponseBody> {
    let path = ms_ipc::default_socket_path()?;
    Client::connect(&path)
        .await?
        .request_within(body, crate::approve::APPROVAL_WAIT)
        .await
}

pub(crate) async fn start() -> ExitCode {
    // Resuming needs a person's approval with Touch ID (L11); review it right here.
    let _review = crate::approve::inline_review("ms start");
    let first = request_approved(RequestBody::Start { at_terminal: false }).await;
    let resp = match first {
        Err(Error::DaemonUnavailable { .. }) => {
            if let Err(e) = tokio::task::spawn_blocking(kickstart)
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
            {
                return fail(&e);
            }
            request_approved(RequestBody::Start { at_terminal: false }).await
        }
        other => other,
    };
    print_reply(resp)
}

/// Escapes text for a plist `<string>`.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The LaunchAgent for `msd` at `msd`, logging to `log`.
pub(crate) fn render_plist(msd: &Path, log: &Path) -> String {
    PLIST_TEMPLATE
        .replace("@MSD@", &xml_escape(&msd.display().to_string()))
        .replace("@LOG@", &xml_escape(&log.display().to_string()))
}

/// `msd`, installed next to `ms`, as the LaunchAgent should name it: the stable
/// `<prefix>/opt/morsec/bin/msd` in a Homebrew install (it survives `brew upgrade`), else msd's
/// own path (a dev build or a manual install).
fn msd_path() -> Result<PathBuf, String> {
    let (real, preferred) =
        crate::brew::sibling("msd").map_err(|e| format!("morsec: finding ms itself: {e}"))?;
    if !real.is_file() {
        return Err(format!(
            "morsec: msd is not installed next to ms ({}). Reinstall morsec",
            real.display()
        ));
    }
    Ok(preferred)
}

/// Where msd's LaunchAgent sends its stderr.
fn log_path(home: &Path) -> PathBuf {
    home.join("Library/Logs/morsec/msd.log")
}

/// The program a LaunchAgent plist runs: the first `ProgramArguments` string, as `ms init`
/// writes it (XML). `None` when the plist has no such entry.
pub(crate) fn plist_program(plist: &str) -> Option<String> {
    // Comments out of the way first (the template carries one), refusing an unclosed one.
    let mut text = String::with_capacity(plist.len());
    let mut rest = plist;
    while let Some(i) = rest.find("<!--") {
        text.push_str(&rest[..i]);
        rest = &rest[i + 4..][rest[i + 4..].find("-->")? + 3..];
    }
    text.push_str(rest);
    // Exactly one ProgramArguments key, followed (after whitespace only) by <array>, then
    // (after whitespace only) by the first <string>. Anything else is not the form `ms init`
    // writes, and is reported as such rather than guessed at (security review S2).
    const KEY: &str = "<key>ProgramArguments</key>";
    if text.matches(KEY).count() != 1 {
        return None;
    }
    let after = text[text.find(KEY)? + KEY.len()..].trim_start();
    let after = after.strip_prefix("<array>")?.trim_start();
    let after = after.strip_prefix("<string>")?;
    let end = after.find("</string>")?;
    Some(
        after[..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

fn install_launch_agent(msd: &Path) -> Result<(), String> {
    let home = home()?;
    let log = log_path(&home);
    let log_dir = log.parent().unwrap_or(&home);
    std::fs::create_dir_all(log_dir)
        .map_err(|e| format!("morsec: creating {}: {e}", log_dir.display()))?;
    let plist = plist_path()?;
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("morsec: creating {}: {e}", dir.display()))?;
    }
    std::fs::write(&plist, render_plist(msd, &log))
        .map_err(|e| format!("morsec: writing {}: {e}", plist.display()))?;
    let domain = format!("gui/{}", uid());
    // Unload an older copy first; it is fine if none is loaded.
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{LABEL}")])
        .stderr(std::process::Stdio::null())
        .status();
    let st = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(&plist)
        .status()
        .map_err(|e| format!("morsec: running launchctl: {e}"))?;
    if !st.success() {
        return Err(format!(
            "morsec: launchctl could not load {}. Try: launchctl bootstrap {domain} {}",
            plist.display(),
            plist.display()
        ));
    }
    wait_for_socket(Duration::from_secs(10))
}

/// `ms init --trust`. The certificate comes from msd, which loaded it and checked it against the
/// CA key in the vault, never from `ca.pem` (any same-user process can replace that file). It is
/// handed to `security` from a private temp file.
async fn trust() -> ExitCode {
    let (pem, hosts) = match request(RequestBody::Status).await {
        Ok(ResponseBody::Status {
            ca_pem: Some(pem),
            ca_hosts,
            ..
        }) => (pem, ca_hosts),
        Ok(ResponseBody::Status { .. }) => {
            return fail(
                "morsec: there is no morsec CA yet. It is created when a key is first allowed a host (ms rules <key> --add-host ...)",
            );
        }
        Ok(ResponseBody::Error { message, .. }) => return fail(&message),
        Ok(_) => return fail("morsec: unexpected reply from the daemon"),
        Err(e) => return fail(&e.to_string()),
    };
    let keychain = match home() {
        Ok(h) => h.join("Library/Keychains/login.keychain-db"),
        Err(e) => return fail(&e),
    };
    let dir = std::env::temp_dir().join(format!(
        "morsec-trust-{}-{}",
        std::process::id(),
        crate::import::now_unix_ms()
    ));
    let made = {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .and_then(|()| {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dir.join("ca.pem"))?;
                f.write_all(pem.as_bytes())
            })
    };
    if let Err(e) = made {
        let _ = std::fs::remove_dir_all(&dir);
        return fail(&format!("morsec: writing a private copy of the CA: {e}"));
    }
    say(&format!(
        "The morsec CA can sign only for: {}",
        hosts.join(", ")
    ));
    say("macOS will ask you to allow adding it to your trust settings.");
    let st = Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(&keychain)
        .arg(dir.join("ca.pem"))
        .status();
    let _ = std::fs::remove_dir_all(&dir);
    match st {
        Ok(s) if s.success() => {
            say("The morsec CA is trusted.");
            ExitCode::SUCCESS
        }
        Ok(_) => fail("morsec: the CA was not added to your trust settings"),
        Err(e) => fail(&format!("morsec: running security: {e}")),
    }
}

/// Runs `f` on a fresh current-thread runtime (`ms init` runs on its own thread, because the
/// project steps drive their own IPC runtimes).
fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("starting the IPC client: {e}"))
        .block_on(f)
}

/// `git rev-parse --show-toplevel` from `dir`, canonical; `None` outside a repository. Runs git
/// without a pager, fsmonitor or prompts, like `envfile::git_history`.
fn git_top(dir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "rev-parse",
            "--show-toplevel",
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    std::fs::canonicalize(s.trim_end_matches('\n')).ok()
}

/// Which mode `ms init` runs in (design §4.1), or a refusal for `--project` at a refused root.
fn choose_mode(a: &InitArgs) -> Result<ms_projects::mode::Mode, String> {
    use ms_projects::mode::{MachineWhy, Mode, refused_root};
    if a.machine || a.force {
        return Ok(Mode::Machine(MachineWhy::Asked));
    }
    let home = std::fs::canonicalize(home()?)
        .map_err(|e| format!("morsec: finding your home folder: {e}"))?;
    let cwd = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("morsec: finding the current folder: {e}"))?;
    if let Some(p) = &a.project {
        let root = match p {
            Some(p) => {
                std::fs::canonicalize(p).map_err(|e| format!("morsec: {}: {e}", p.display()))?
            }
            None => git_top(&cwd)
                .filter(|t| *t != home && *t != Path::new("/"))
                .unwrap_or(cwd),
        };
        if !root.is_dir() {
            return Err(format!("morsec: {} is not a folder", root.display()));
        }
        if refused_root(&root, &home).is_some() {
            return Err(format!(
                "morsec: {} is your home folder, a folder above it or a system folder, so it is not scanned as a project. Run ms init inside the project",
                root.display()
            ));
        }
        return Ok(Mode::Project(root));
    }
    let has_marker = std::fs::read_dir(&cwd)
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(ms_projects::mode::is_marker)
            })
        })
        .unwrap_or(false);
    let top = git_top(&cwd);
    Ok(ms_projects::mode::detect(ms_projects::mode::Inputs {
        cwd: &cwd,
        home: &home,
        git_top: top.as_deref(),
        cwd_has_marker: has_marker,
    }))
}

/// Machine step 1: vault, LaunchAgent, msd (today's `ms init`). Skipped when msd answers.
/// `Ok(false)`: stop here (`--no-launchd`).
fn machine_setup(a: &InitArgs) -> Result<bool, ExitCode> {
    if !a.force
        && matches!(
            block(request(RequestBody::Status)),
            Ok(ResponseBody::Status { .. })
        )
    {
        say("morsec is already set up.");
        return Ok(true);
    }
    let msd = msd_path().map_err(|e| fail(&e))?;
    let mut cmd = Command::new(&msd);
    cmd.arg("--init");
    if a.force {
        cmd.arg("--force");
    }
    let code = match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => return Err(fail(&format!("morsec: running {}: {e}", msd.display()))),
    };
    match code {
        0 => say("morsec is set up: vault keys created, empty rules, receipts started."),
        MSD_ALREADY => say("morsec is already set up (ms init --force starts over)."),
        _ => {
            return Err(fail(
                "morsec: setup failed (see above). Nothing was started",
            ));
        }
    }
    if a.no_launchd {
        say(&format!(
            "Start the daemon with: {} --foreground",
            msd.display()
        ));
        return Ok(false);
    }
    install_launch_agent(&msd).map_err(|e| fail(&e))?;
    Ok(true)
}

/// Machine step 2: is the CA trusted? Asks macOS once when it isn't and there is a terminal.
fn ca_row() -> Option<String> {
    let (mode, pem) = match block(request(RequestBody::Status)) {
        Ok(ResponseBody::Status { mode, ca_pem, .. }) => (mode, ca_pem),
        _ => return None,
    };
    if mode == "dev-memory" {
        // A memory daemon's CA is new at every start: trusting it would pile up certificates.
        return Some("not trusted for a dev daemon (it changes at every start)".into());
    }
    let pem = pem?;
    match crate::doctor::ca_trusted(&pem) {
        Some(true) => None,
        _ if crate::tty::stdin_is_tty() => {
            if block(trust()) == ExitCode::SUCCESS {
                Some("trusted".into())
            } else {
                Some(
                    "not trusted: swaps for Go tools will fail until you run ms init --trust"
                        .into(),
                )
            }
        }
        _ => Some("not trusted: swaps for Go tools will fail until you run ms init --trust".into()),
    }
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.is_absolute() && d.join(bin).is_file())
    })
}

/// Machine step 3: connect the agents found on this Mac. A failure is reported, not fatal.
fn connect_agents() -> Vec<(String, bool)> {
    let Ok(home) = home() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, bin, dir) in [
        ("claude-code", "Claude Code", "claude", ".claude"),
        ("codex", "Codex", "codex", ".codex"),
    ] {
        if !on_path(bin) && !home.join(dir).exists() {
            continue;
        }
        let args = crate::connect::ConnectArgs {
            agent: Some(id.to_owned()),
            dry_run: false,
            yes: true,
            env: Vec::new(),
            mcp_env: Vec::new(),
            with_mcp: false,
            wrap: false,
            statusline: false,
            force: false,
            #[cfg(debug_assertions)]
            rules: None,
            session_env: false,
        };
        out.push((
            name.to_owned(),
            crate::connect::connect(&args) == ExitCode::SUCCESS,
        ));
    }
    out
}

pub(crate) fn init(a: &InitArgs) -> ExitCode {
    if a.trust {
        return block(trust());
    }
    if a.resume {
        eprintln!("note: ms init --resume is now ms start, which asks for Touch ID");
        return block(start());
    }
    let mode = match choose_mode(a) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    let project = match &mode {
        ms_projects::mode::Mode::Project(root) => Some(root.clone()),
        ms_projects::mode::Mode::Machine(_) => None,
    };
    if project.is_some()
        && let Some(who) = crate::connect::inside_agent()
    {
        return fail(&format!(
            "morsec: ms init moves a project's secrets and gives its keys their services, so it runs only from your own terminal, not inside an agent session ({who}). Ask the user to run it"
        ));
    }
    match machine_setup(a) {
        Ok(true) => {}
        Ok(false) => return ExitCode::SUCCESS,
        Err(code) => return code,
    }

    let mut rows: Vec<(String, String)> = Vec::new();
    let home_dir = home().ok().and_then(|h| std::fs::canonicalize(h).ok());
    let mut ok = true;
    let mut slug = None;
    if let Some(root) = &project {
        match crate::init_project::run(root, a.name.as_deref()) {
            Ok(rep) => {
                ok = rep.save_error.is_none();
                slug = Some(rep.slug.clone());
                rows.extend(crate::init_project::summary_rows(&rep, home_dir.as_deref()));
            }
            Err(e) => {
                ok = false;
                rows.push(("Project".into(), format!("not set up: {e}")));
            }
        }
    }
    if let Some(ca) = ca_row() {
        rows.push(("CA".into(), ca));
    }
    if !a.no_connect {
        let agents = connect_agents();
        let done: Vec<&str> = agents
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(n, _)| n.as_str())
            .collect();
        let failed: Vec<&str> = agents
            .iter()
            .filter(|(_, ok)| !*ok)
            .map(|(n, _)| n.as_str())
            .collect();
        if !done.is_empty() {
            rows.push(("Agents".into(), format!("{} connected", done.join(", "))));
        }
        if !failed.is_empty() {
            rows.push((
                "Agents".into(),
                format!(
                    "{} could not be connected (see above): ms connect <agent>",
                    failed.join(", ")
                ),
            ));
        }
    }
    let problems = crate::doctor::static_problems();
    if !problems.is_empty() {
        rows.push((
            "Checks".into(),
            format!("{} from ms doctor:", problems.len()),
        ));
        for p in problems {
            rows.push((String::new(), p));
        }
    }

    println!();
    match block(request(RequestBody::Status)) {
        Ok(ResponseBody::Status {
            running: Some(false),
            ..
        }) => say("morsec is stopped: resume with ms start (Touch ID)."),
        _ => say("morsec is on."),
    }
    if !rows.is_empty() {
        println!();
    }
    for (label, text) in &rows {
        say(&format!("{label:<10} {text}"));
    }
    // The dashboard (L32): opened on the project's page when a person is watching; the line
    // never holds the launch token.
    if let Some(slug) = slug.as_deref().filter(|_| ok) {
        use std::io::IsTerminal;
        let text = if a.no_open || !std::io::stdout().is_terminal() {
            "ms dashboard".to_owned()
        } else {
            match crate::dashboard::open(crate::dashboard::view_for(Some(slug)).as_deref()) {
                Ok(o) => o.line(),
                Err(e) => format!("not opened ({e}); run ms dashboard"),
            }
        };
        say(&format!("{:<10} {text}", "Dashboard"));
    }
    if let Some(slug) = slug.filter(|_| ok) {
        println!();
        say(&format!("See everything: ms projects {slug}"));
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=the status pill text: on/stopped with the protected-key count, and the pre-L07
    // form for an old daemon; fails_when=a stopped daemon reads as on; no_claim=terminal colour
    #[test]
    fn status_lines() {
        let mut r = ResponseBody::status("msd", "0.0.0", "keychain");
        assert_eq!(status_line(&r).unwrap(), "morsec on · daemon 0.0.0");
        if let ResponseBody::Status { running, keys, .. } = &mut r {
            *running = Some(true);
            *keys = Some(1);
        }
        assert_eq!(status_line(&r).unwrap(), "morsec on · 1 secret protected");
        if let ResponseBody::Status { running, keys, .. } = &mut r {
            *running = Some(false);
            *keys = Some(3);
        }
        assert_eq!(
            status_line(&r).unwrap(),
            "morsec stopped · 3 secrets protected · resume with: ms start"
        );
    }

    // protects=the LaunchAgent runs exactly msd --foreground from an absolute path, with no
    // environment block, and paths are XML-escaped; fails_when=an EnvironmentVariables key or an
    // unescaped path appears; no_claim=launchctl loading it (manual check in the evidence)
    #[test]
    fn plist_renders() {
        let p = render_plist(Path::new("/opt/m&s/msd"), Path::new("/tmp/msd.log"));
        assert!(p.contains("<string>/opt/m&amp;s/msd</string>"), "{p}");
        assert!(p.contains("<string>--foreground</string>"));
        assert!(!p.contains("@MSD@") && !p.contains("@LOG@"));
        assert!(!p.contains("<key>EnvironmentVariables</key>"));
        assert_eq!(plist_program(&p).as_deref(), Some("/opt/m&s/msd"));
    }

    // protects=ms init names msd by the stable opt path in a Homebrew install and by its own
    // path otherwise; the plist it renders reads back to that path; fails_when=a Cellar
    // (versioned) path lands in the LaunchAgent while opt points at the same keg;
    // no_claim=launchctl loading it
    #[test]
    fn launch_agent_uses_opt_path() {
        use crate::brew::tests::{FakeBrew, shim_bytes};
        let b = FakeBrew::new();
        let v1 = b.install("1.0.0", &shim_bytes("1"));
        b.point_opt("1.0.0");
        let chosen = crate::brew::preferred(&v1.join("msd"));
        assert_eq!(chosen, b.opt_bin("msd"));
        let plist = render_plist(&chosen, &log_path(Path::new("/Users/x")));
        assert_eq!(
            plist_program(&plist).map(PathBuf::from),
            Some(b.opt_bin("msd"))
        );
        assert!(!plist.contains("/Cellar/"), "{plist}");
        assert!(plist.contains("/Users/x/Library/Logs/morsec/msd.log"));
        // Not a keg: unchanged.
        let dev = Path::new("/Users/x/code/morsec/target/release/msd");
        assert_eq!(crate::brew::preferred(dev), dev);
    }

    // protects=the program is read only from ProgramArguments[0]; fails_when=another string is
    // taken for it; no_claim=binary plists (doctor warns that it can't read them)
    #[test]
    fn plist_program_parsing() {
        assert_eq!(plist_program("<dict></dict>"), None);
        let other = "<key>Label</key><string>x</string><key>ProgramArguments</key>\n<array>\n  <string>/a&lt;b</string><string>--foreground</string></array>";
        assert_eq!(plist_program(other).as_deref(), Some("/a<b"));
        let not_first =
            "<key>ProgramArguments</key><array><integer>1</integer><string>/x</string></array>";
        assert_eq!(plist_program(not_first), None);
        // An empty array followed by another key's array: not taken for the program.
        let elsewhere = "<key>ProgramArguments</key><array/><key>Other</key><array><string>/msd</string></array>";
        assert_eq!(plist_program(elsewhere), None);
        let twice = "<key>ProgramArguments</key><array><string>/a</string></array><key>ProgramArguments</key><array><string>/b</string></array>";
        assert_eq!(plist_program(twice), None);
        // A commented-out entry is ignored; the real one is read.
        let commented = "<!-- <key>ProgramArguments</key><array><string>/fake</string></array> --><key>ProgramArguments</key><array><string>/x</string></array>";
        assert_eq!(plist_program(commented).as_deref(), Some("/x"));
        assert_eq!(
            plist_program("<!-- unclosed <key>ProgramArguments</key>"),
            None
        );
    }
}
