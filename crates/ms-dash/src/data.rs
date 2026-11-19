//! What the dashboard needs from msd. Every method reads; none changes the vault, the rules or
//! the project records (SPEC D-3). msd implements it over its live state.

use std::net::SocketAddr;

use ms_core::{KeyName, SessionId};

use crate::api::{
    ActivityQuery, ActivityView, AgentsView, ExportFormat, HomeView, ProjectView, ProjectsView,
    ScanView, SecretView, VerifyView,
};

/// An API answer that is not a view: the HTTP status and a message for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// 404, 409 (projects unreadable), 500, 503.
    pub status: u16,
    /// Shown in the page through `textContent`.
    pub message: String,
}

impl ApiError {
    /// Not found.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            message: message.into(),
        }
    }

    /// msd failed.
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            message: message.into(),
        }
    }

    /// The data exists but can't be shown (a tampered `projects.toml`, fails closed).
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: 503,
            message: message.into(),
        }
    }
}

/// A connection or request the dashboard refused, for a `blocked` receipt (SPEC D-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The agent session when the caller is in one (so it counts towards LOG-2); otherwise
    /// `other("dashboard")` with the owning process.
    pub session: SessionId,
    /// Why, in a few words (no request data beyond header names).
    pub why: String,
}

/// msd's side of the dashboard.
pub trait DashData: Send + Sync + 'static {
    /// The process check for one accepted connection (design §6.2.1). `peer` is the client's
    /// address and `local` the listener's, as `accept()` reports them. `Ok` names who connected
    /// (used for later refusal receipts); `Err` closes the connection before any byte is read.
    /// Blocking: may scan the process table.
    fn check_connection(&self, peer: SocketAddr, local: SocketAddr) -> Result<SessionId, Refusal>;

    /// Writes a `blocked` receipt for a refusal. Blocking. Called at most 30 times a minute per
    /// session (the caller throttles).
    fn record_refused(&self, refusal: &Refusal);

    /// Home.
    fn home(&self) -> Result<HomeView, ApiError>;
    /// Projects, and keys in no project.
    fn projects(&self) -> Result<ProjectsView, ApiError>;
    /// One project.
    fn project(&self, slug: &str) -> Result<ProjectView, ApiError>;
    /// One key.
    fn secret(&self, key: &KeyName) -> Result<SecretView, ApiError>;
    /// Receipts, filtered.
    fn activity(&self, q: &ActivityQuery) -> Result<ActivityView, ApiError>;
    /// The filtered receipts as a file: (file name, content type, body).
    fn export(
        &self,
        q: &ActivityQuery,
        format: ExportFormat,
    ) -> Result<(String, &'static str, Vec<u8>), ApiError>;
    /// Checks the receipt chain (and MACs, msd holds the key).
    fn verify(&self) -> Result<VerifyView, ApiError>;
    /// Agents and msd's own checks.
    fn agents(&self) -> Result<AgentsView, ApiError>;
    /// The last leak scan msd ran, if any.
    fn scan(&self) -> Result<ScanView, ApiError>;
}
