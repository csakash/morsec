//! `ms dashboard` (L32 dash-core): asks msd for the dashboard (`DashOpen`) and opens it in the
//! browser with `open(1)`. msd binds first and reports the port it holds, so this never opens a
//! port something else holds; the single-use launch token rides in the URL fragment, so it never
//! reaches a request line, a log or a `Referer` (design §6.1, §6.2.2). The token is never printed.

use std::process::{Command, ExitCode};

use clap::Args;
use ms_ipc::{Client, RequestBody, ResponseBody};

use crate::terminal_safe;

/// `ms dashboard [PROJECT]`
#[derive(Debug, Args)]
pub struct DashboardArgs {
    /// Open this project's page (its name, as `ms projects` lists it).
    #[arg(value_name = "PROJECT")]
    project: Option<String>,
}

/// The page to open on: `project/<slug>` for a valid slug, else Home.
pub(crate) fn view_for(project: Option<&str>) -> Option<String> {
    project
        .filter(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .map(|p| format!("project/{p}"))
}

/// The URL `open(1)` gets. The token is only in the fragment.
pub(crate) fn launch_url(port: u16, token: &str, view: Option<&str>) -> String {
    match view {
        Some(v) => format!("http://127.0.0.1:{port}/#t={token}&v={v}"),
        None => format!("http://127.0.0.1:{port}/#t={token}"),
    }
}

/// Runs the browser opener. Debug builds only: `MORSEC_TEST_OPEN` names a program to run instead
/// of `/usr/bin/open`, so tests can capture the URL without starting a browser.
fn open_url(url: &str) -> Result<(), String> {
    #[cfg(debug_assertions)]
    let program = std::env::var_os("MORSEC_TEST_OPEN")
        .unwrap_or_else(|| std::ffi::OsString::from("/usr/bin/open"));
    #[cfg(not(debug_assertions))]
    let program = std::ffi::OsString::from("/usr/bin/open");
    let st = Command::new(&program)
        .arg(url)
        .status()
        .map_err(|e| format!("running open: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("open exited with {st}"))
    }
}

/// Asks msd for the dashboard and opens it on `view`. Returns the port msd holds.
pub(crate) fn open(view: Option<&str>) -> Result<u16, String> {
    if let Some(who) = crate::connect::inside_agent() {
        return Err(format!(
            "morsec: the dashboard can't be opened from inside an agent session ({who}). Ask the user to run ms dashboard in their own terminal"
        ));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting the IPC client: {e}"))?;
    let reply = rt
        .block_on(async {
            let path = ms_ipc::default_socket_path()?;
            Client::connect(&path)
                .await?
                .request(RequestBody::DashOpen)
                .await
        })
        .map_err(|e| e.to_string())?;
    match reply {
        ResponseBody::Dash { port, launch_token } => {
            if launch_token.len() != 64 || !launch_token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("morsec: the daemon sent a malformed launch token".into());
            }
            open_url(&launch_url(port, &launch_token, view))?;
            Ok(port)
        }
        ResponseBody::Error { message, .. } => Err(message),
        _ => Err(
            "morsec: unexpected reply from the daemon. Make sure ms and msd are the same version (ms --version)".into(),
        ),
    }
}

/// `ms dashboard`.
pub(crate) fn run(a: &DashboardArgs) -> ExitCode {
    let view = view_for(a.project.as_deref());
    if a.project.is_some() && view.is_none() {
        eprintln!("morsec: that is not a project name. List them with: ms projects");
        return ExitCode::from(2);
    }
    match open(view.as_deref()) {
        Ok(port) => {
            println!(
                "{}",
                terminal_safe(&format!(
                    "Opening the dashboard: http://127.0.0.1:{port} (the sign-in link works once, for a minute)"
                ))
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}", terminal_safe(&e));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=design §6.2.2: the launch token goes only in the URL fragment, on 127.0.0.1 and
    // the port msd reported, and the view is a fixed route with a validated slug;
    // fails_when=the token reaches the path or query, another host is used, or a crafted project
    // name reaches the URL; no_claim=open(1) itself
    #[test]
    fn url_keeps_token_in_fragment() {
        let u = launch_url(7312, "ab12", view_for(Some("shop")).as_deref());
        assert_eq!(u, "http://127.0.0.1:7312/#t=ab12&v=project/shop");
        let (before, after) = u.split_once('#').unwrap();
        assert!(!before.contains("ab12") && after.contains("ab12"));
        assert_eq!(launch_url(1, "t", None), "http://127.0.0.1:1/#t=t");
        for bad in ["Shop", "a/b", "a&v=x", "", "../x", "x#y"] {
            assert_eq!(view_for(Some(bad)), None, "{bad}");
        }
    }
}
