//! Shared morsec types.
//!
//! Everything here is frozen by loop L00 (`docs/PLAN.md` §4). Later loops build against these
//! types; changing one needs its own loop.

mod error;
mod key;
mod secret;
mod types;

pub use error::{Error, Result};
pub use key::{KeyName, MAX_KEY_NAME_LEN, MAX_SEGMENT_LEN, MAX_SEGMENTS, SecretRef};
pub use secret::SecretBytes;
pub use types::{
    AgentKind, ApprovalRequest, Decision, KeyMeta, Mode, Reason, ReceiptEvent, ReceiptResult,
    Request, SessionId, Tier,
};
