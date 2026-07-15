//! Immutable, secret-free replay manifests for local/remote capsule parity.
//!
//! Replay bundles intentionally contain the exact execution capsule and only
//! structural execution outcomes. Captured output, credentials, and provider
//! envelopes are never part of this format.

mod bundle;
mod error;
mod model;
mod outcome;
mod validation;

pub use error::ReplayError;
pub use model::{
    ReplayAttemptOutcome, ReplayBundle, ReplayEnvelope, ReplayJobOutcome, ReplayOutcome,
    ReplayStepOutcome, MAX_REPLAY_BUNDLE_BYTES, REPLAY_SCHEMA_VERSION,
};
