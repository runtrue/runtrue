//! Durable SQLite control-plane state and transactional domain operations.
//!
//! This crate intentionally has no HTTP or executor dependency. It persists
//! signed capsules, lifecycle state, fencing, approvals, runner enrollment,
//! background work, metadata snapshots, and a tamper-evident audit chain.

mod error;
mod store;
mod types;

pub use error::ControlPlaneError;
pub use store::{
    artifact_promotion_subject_digest, artifact_scan_subject_digest,
    authoritative_runner_posture_digest, cache_promotion_subject_digest, ControlPlane,
};
pub use types::*;
