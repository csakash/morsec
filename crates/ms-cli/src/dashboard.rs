//! `ms dashboard` (L32 dash-core): asks msd to open the dashboard (`DashOpen`). msd binds the
//! port, mints the single-use sign-in link and opens it in the user's browser through
//! LaunchServices itself: the link never reaches this process, its output or any argv (SPEC D-12,
//! security review S1). This prints the port and whether msd opened it.

use std::process::ExitCode;

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

/// The page to open on: `project/<slug>` for a valid slug, else Home. msd checks it again.
pub(crate) fn view_for(project: Option<&str>) -> Option<String> {
    project
        .map(|p| format!("project/{p}"))
        .filter(|v| ms_dash_view_ok(v))
}

/// The same rule msd applies (`ms_dash::valid_view`); `ms` doesn't link `ms-dash`.
fn ms_dash_view_ok(v: &str) -> bool {
    v.strip_prefix("project/").is_some_and(|slug| {
        !slug.is_empty()
            && slug.len() <= 64
            && slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// What `DashOpen` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Opened {
    /// The port msd holds on 127.0.0.1.
    pub port: u16,
    /// msd handed the sign-in link to the browser.
    pub opened: bool,
}

impl Opened {
    /// One line for people. Never a token: msd keeps it (SPEC D-12).
    pub(crate) fn line(&self) -> String {
        if self.opened {
            format!("http://127.0.0.1:{}  (opened in your browser)", self.port)
        } else {
            format!(
                "http://127.0.0.1:{}  (msd could not open a browser: run ms dashboard while you are logged in to this Mac's desktop)",
                self.port
            )
        }
    }
}

/// Asks msd to open the dashboard on `view`. msd mints the sign-in link and opens it in the
/// browser itself, so this process never holds it.
pub(crate) fn open(view: Option<&str>) -> Result<Opened, String> {
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
                .request(RequestBody::DashOpen {
                    view: view.map(str::to_owned),
                })
                .await
        })
        .map_err(|e| e.to_string())?;
    match reply {
        ResponseBody::Dash { port, opened } => Ok(Opened { port, opened }),
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
        Ok(o) => {
            println!("{}", terminal_safe(&format!("Dashboard: {}", o.line())));
            if o.opened {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
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

    // protects=only a fixed route with a validated slug reaches DashOpen, and the printed line
    // has no token (there is none to print); fails_when=a crafted project name passes, or the
    // line suggests a sign-in link; no_claim=msd's own check (daemon dash_open_refused_*)
    #[test]
    fn view_and_line() {
        assert_eq!(view_for(Some("shop")).as_deref(), Some("project/shop"));
        for bad in ["Shop", "a/b", "a&v=x", "", "../x", "x#y"] {
            assert_eq!(view_for(Some(bad)), None, "{bad}");
        }
        let l = Opened {
            port: 7312,
            opened: true,
        }
        .line();
        assert_eq!(l, "http://127.0.0.1:7312  (opened in your browser)");
        assert!(!l.contains("#t="));
        assert!(
            Opened {
                port: 1,
                opened: false
            }
            .line()
            .contains("could not open a browser")
        );
    }
}
