//! CLI parity (design §6.5): every `ms` subcommand has a dashboard screen or an exemption with its
//! reason. The test that walks clap's subcommands is `ms-cli`'s
//! `dash_parity_covers_every_subcommand` (this crate can't see the CLI's parser); the test here
//! checks every screen named exists in the page.

/// Where a subcommand lives in the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// The screen (hash route) that shows it.
    Screen(&'static str),
    /// Not in the dashboard, and why.
    Exempt(&'static str),
}

/// The page's screens (its hash routes).
pub const SCREENS: &[&str] = &[
    "/",
    "/projects",
    "/project",
    "/secret",
    "/activity",
    "/agents",
    "/scan",
];

/// Every subcommand, current or planned in Wave 7.
pub const PARITY: &[(&str, Parity)] = &[
    ("status", Parity::Screen("/")),
    ("stats", Parity::Screen("/")),
    ("projects", Parity::Screen("/projects")),
    ("rules", Parity::Screen("/secret")),
    ("log", Parity::Screen("/activity")),
    ("doctor", Parity::Screen("/agents")),
    ("scan", Parity::Screen("/scan")),
    (
        "init",
        Parity::Exempt(
            "L33: Add project. Machine-mode steps stay CLI only: they install the daemon that serves the page",
        ),
    ),
    ("add", Parity::Exempt("L33: Secret, Add (hidden field)")),
    ("import", Parity::Exempt("L33: Add project and re-scan")),
    ("connect", Parity::Exempt("L33: Agents, Connect")),
    ("disconnect", Parity::Exempt("L33: Agents, Disconnect")),
    (
        "stop",
        Parity::Exempt("L33: Home, Stop (Home shows on or stopped now)"),
    ),
    ("start", Parity::Exempt("L33: Home, Start (Touch ID)")),
    (
        "approve",
        Parity::Exempt("L33: Home, Approve or deny (Home shows the pending request now)"),
    ),
    ("set", Parity::Exempt("L33: Secret, Replace")),
    ("rm", Parity::Exempt("L33: Secret, Delete")),
    ("undo", Parity::Exempt("L33: Project and Secret, Undo")),
    (
        "run",
        Parity::Exempt("agent run-time path; a person never calls it"),
    ),
    (
        "mcp",
        Parity::Exempt("agent run-time path; a person never calls it"),
    ),
    (
        "dev",
        Parity::Exempt("L34: needs the user's own terminal to run their app"),
    ),
    ("dashboard", Parity::Exempt("opens the dashboard itself")),
    ("help", Parity::Exempt("clap's built-in help")),
];

/// The entry for `name`, if any.
pub fn lookup(name: &str) -> Option<Parity> {
    PARITY.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=every screen the parity table names is a real route in the page's router, and
    // every exemption gives a reason; fails_when=a route is renamed or removed from dash.js, or
    // an exemption is empty; no_claim=that the screen shows everything the command does (browser
    // pass)
    #[test]
    fn parity_routes_exist() {
        let js = crate::assets::DASH_JS;
        for s in SCREENS {
            assert!(
                js.contains(&format!("'{s}'")),
                "screen {s} is not routed in dash.js"
            );
        }
        for (name, p) in PARITY {
            match p {
                Parity::Screen(s) => assert!(SCREENS.contains(s), "{name}: {s}"),
                Parity::Exempt(why) => assert!(why.len() > 8, "{name} needs a reason"),
            }
        }
    }
}
