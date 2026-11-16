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

pub(crate) async fn status() -> ExitCode {
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
    let after = &plist[plist.find("<key>ProgramArguments</key>")?..];
    let array = after.find("<array>")?;
    let after = &after[array..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")? + start;
    // Nothing but whitespace between <array> and the first <string>.
    if !after["<array>".len()..start - "<string>".len()]
        .trim()
        .is_empty()
    {
        return None;
    }
    Some(
        after[start..end]
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

pub(crate) async fn init(a: &InitArgs) -> ExitCode {
    if a.trust {
        return trust().await;
    }
    if a.resume {
        eprintln!("note: ms init --resume is now ms start, which asks for Touch ID");
        return start().await;
    }
    let msd = match msd_path() {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let mut cmd = Command::new(&msd);
    cmd.arg("--init");
    if a.force {
        cmd.arg("--force");
    }
    let code = match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => return fail(&format!("morsec: running {}: {e}", msd.display())),
    };
    match code {
        0 => say("morsec is set up: vault keys created, empty rules, receipts started."),
        MSD_ALREADY => say("morsec is already set up (ms init --force starts over)."),
        _ => return fail("morsec: setup failed (see above). Nothing was started"),
    }
    if a.no_launchd {
        say(&format!(
            "Start the daemon with: {} --foreground",
            msd.display()
        ));
        return ExitCode::SUCCESS;
    }
    if let Err(e) = tokio::task::spawn_blocking(move || install_launch_agent(&msd))
        .await
        .unwrap_or_else(|e| Err(e.to_string()))
    {
        return fail(&e);
    }
    status().await
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
    }
}
