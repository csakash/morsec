//! The local dashboard (L32 `dash-core`, design `docs/design/guided-setup-dashboard.md` §6).
//!
//! msd serves it itself: this crate holds the listener, every security check, the read-only API
//! and the embedded page. msd plugs in through [`DashData`], whose methods only read (the one
//! write is a receipt for a refusal), so nothing the page can ask changes anything and no view has
//! a field that could carry a secret value (SPEC D-3).
//!
//! Who may connect (design §6.2), all checked here or in msd, none in the page:
//!
//! 1. per TCP connection, [`DashData::check_connection`] maps the connection to its process and
//!    refuses agent process trees and other users before a byte is read;
//! 2. a single-use launch token, minted by [`Dash::open`] (msd's `DashOpen`, refused in agent
//!    sessions), valid 60 s, carried in the URL fragment;
//! 3. `POST /api/session` trades it for an `HttpOnly; SameSite=Strict` cookie and a CSRF token
//!    held in page memory;
//! 4. Host, Origin, `Sec-Fetch-Site`, CSRF (on every API request, GET too: SPEC D-4), JSON bodies
//!    up to 64 KiB;
//! 5. the security headers on every response ([`http::security_headers`]);
//! 6. 20 requests/s per session.

pub mod actions;
pub mod api;
pub mod assets;
pub mod auth;
pub mod data;
pub mod http;
pub mod parity;
pub mod server;
pub mod shell;

pub use actions::{Action, ActionCode, ActionError, ActionOk, Actor, DashActions, Revealed};
pub use data::{ApiError, DashData, Refusal};
pub use server::{Dash, DashConfig, Opened, valid_view};

/// The first port the dashboard tries (design §6.1).
pub const DEFAULT_PORT: u16 = 7311;
/// How many ports it tries: 7311 to 7320.
pub const PORT_SPAN: u16 = 10;
/// The key refusal receipts are recorded under (SPEC D-9).
pub const DASH_KEY: &str = "morsec/dashboard";
