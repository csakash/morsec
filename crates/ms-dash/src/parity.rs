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

/// Every subcommand (L33 SPEC D-26).
pub const PARITY: &[(&str, Parity)] = &[
    ("status", Parity::Screen("/")),
    ("stats", Parity::Screen("/")),
    ("stop", Parity::Screen("/")),
    ("start", Parity::Screen("/")),
    ("approve", Parity::Screen("/")),
    ("projects", Parity::Screen("/projects")),
    ("set", Parity::Screen("/secret")),
    ("rm", Parity::Screen("/secret")),
    ("add", Parity::Screen("/secret")),
    ("rules", Parity::Screen("/secret")),
    ("undo", Parity::Screen("/project")),
    ("log", Parity::Screen("/activity")),
    ("doctor", Parity::Screen("/agents")),
    ("scan", Parity::Screen("/scan")),
    // L35: run from the dashboard behind msd's Touch ID (SPEC D-18). Project mode only; the
    // machine steps of `ms init` stay in the terminal (they install the daemon that serves the
    // page), and `ms import`'s one-file, custom-name form stays there too.
    ("init", Parity::Screen("/projects")),
    ("import", Parity::Screen("/projects")),
    ("connect", Parity::Screen("/agents")),
    ("disconnect", Parity::Screen("/agents")),
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
        Parity::Exempt(
            "needs the user's own terminal to run their app; the Project screen shows the command",
        ),
    ),
    ("dashboard", Parity::Exempt("opens the dashboard itself")),
    ("help", Parity::Exempt("clap's built-in help")),
];

/// The action routes behind each "Screen" subcommand that changes something (`doctor`'s is
/// Re-check; `status`, `stats`, `projects`, `log` only read).
pub const ACTIONS: &[(&str, &[&str])] = &[
    ("stop", &["/api/stop"]),
    ("start", &["/api/start"]),
    (
        "approve",
        &["/api/approvals/{id}/approve", "/api/approvals/{id}/deny"],
    ),
    ("set", &["/api/keys/{key}/replace"]),
    ("rm", &["/api/keys/{key}/delete"]),
    ("add", &["/api/keys"]),
    ("rules", &["/api/keys/{key}/rules"]),
    (
        "undo",
        &["/api/projects/{slug}/undo", "/api/keys/{key}/undo"],
    ),
    ("doctor", &["/api/agents/recheck"]),
    (
        "connect",
        &[
            "/api/agents/{agent}/connect/preview",
            "/api/agents/{agent}/connect",
        ],
    ),
    (
        "disconnect",
        &[
            "/api/agents/{agent}/disconnect/preview",
            "/api/agents/{agent}/disconnect",
        ],
    ),
    ("init", &["/api/projects/preview", "/api/projects/add"]),
    ("import", &["/api/projects/preview", "/api/projects/add"]),
    ("scan", &["/api/scan/run"]),
];

/// The entry for `name`, if any.
pub fn lookup(name: &str) -> Option<Parity> {
    PARITY.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=every screen the parity table names is a real route in the page's router, every
    // exemption gives a reason, and (L33 D-26) each "Screen" subcommand that changes something
    // has its action route in http's route table and the page posts to it; fails_when=a route
    // is renamed or removed from dash.js or the route table, or an exemption is empty;
    // no_claim=that the screen shows everything the command does (browser pass)
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
        for (name, routes) in ACTIONS {
            assert!(
                matches!(lookup(name), Some(Parity::Screen(_))),
                "{name} has actions but no screen"
            );
            for r in *routes {
                assert!(
                    crate::actions::ACTION_ROUTES.iter().any(|(p, _)| p == r),
                    "{name}: {r} is not in the route table"
                );
                // The page builds the path from its fixed prefix.
                let prefix = r.split('{').next().unwrap_or(r);
                assert!(js.contains(prefix), "{name}: dash.js never posts to {r}");
            }
        }
    }
}
