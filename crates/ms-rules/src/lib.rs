//! Rules and the policy decision function (L03).
//!
//! - [`model`]: per-key rules (mode, tier, hosts, commands, mint scopes, session TTL, read-only)
//!   and the `rules.toml` format.
//! - [`store`]: the rules file MAC'd with a vault key; anything that fails verification fails
//!   closed.
//! - [`project`]: a project's `.morsec.toml`, merged so it can only tighten.
//! - [`edit`]: one rule edit, shared by `ms rules` and the dashboard (L33).
//! - [`change`]: classifies a rules change as tightening or loosening (loosening needs approval).
//! - [`decide`] (frozen signature) and [`decide_run`]: the pure policy function.

pub mod change;
pub mod edit;
mod error;
pub mod model;
pub mod pattern;
mod policy;
pub mod project;
pub mod store;

pub use change::{Change, classify, classify_rule};
pub use error::{Result, RulesError};
pub use model::{
    KeyRule, Rules, SshHostKey, is_reserved, validate_env_name, validate_root, within_root,
};
pub use pattern::{CommandPattern, HostPattern, NormalHost};
pub use policy::{argv_hash, decide, decide_run, permissiveness};
pub use project::{KeyLimit, PROJECT_FILE, ProjectRules, effective, merge};
pub use store::{DEFAULT_MAC_KEY, RulesStore};
