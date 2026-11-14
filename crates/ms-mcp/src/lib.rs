//! `ms mcp`: run capabilities as typed MCP tools generated from the rules (L14).
//!
//! - [`catalog`]: one tool per run-mode command pattern, a pure function of the user rules,
//!   pinned to the rules version and hashed (MCP-2).
//! - [`schema`]: the JSON Schema validator for exactly the keywords the catalog emits.
//! - [`result`]: a run's result as inert MCP tool output.
//! - [`server`]: the stdio JSON-RPC loop, generic over a [`server::Backend`] (msd in `ms mcp`).
//!
//! msd is the authority (SPEC D3): it rebuilds the catalog from its own rules, validates each
//! call's arguments and builds the argv with [`catalog::Tool::call`]. This crate never resolves a
//! value.

pub mod catalog;
pub mod result;
pub mod schema;
pub mod server;

pub use catalog::{Call, Catalog, DESCRIPTION_VERSION, Tool};
