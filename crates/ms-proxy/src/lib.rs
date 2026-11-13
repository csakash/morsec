//! Swap proxy (`docs/PLAN.md` §3.2, loop L05).
//!
//! The agent holds `ms://stripe/test`. Its `HTTPS_PROXY` points here. For a host a key is bound
//! to, the proxy terminates TLS with a leaf from the name-constrained morsec CA, puts the real
//! value where the provider expects it, strips any other credential, and forwards over a fresh
//! TLS connection to an address the SSRF guard checked. Allowlisted hosts are tunnelled
//! uninspected; everything else is refused. A placeholder headed anywhere it isn't bound is
//! blocked and recorded.
//!
//! `msd` (L07) runs [`Proxy`] with the real vault, rules, receipts, sessions and approvals; this
//! crate only depends on their traits.

mod ca;
mod config;
mod deps;
mod error;
mod idle;
mod rewrite;
mod server;
pub mod ssrf;
mod tls;
mod upstream;

#[cfg(test)]
mod itests;

pub use ca::Ca;
pub use config::{BasicField, Binding, Limits, Location, ProxyConfig, UpstreamRoots};
pub use deps::{BlockEvent, BlockKind, Deps, EgressObserver, LogObserver, Policy, SessionResolver};
pub use error::ProxyError;
pub use server::Proxy;
