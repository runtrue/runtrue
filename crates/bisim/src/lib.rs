//! Bisim: local/remote and cross-backend behavioral conformance.
//!
//! Bisim uses the shared engine and removes only explicitly
//! nondeterministic timing fields. Capsules, lifecycle events, terminal states,
//! output bytes, truncation flags, and errors remain exact. Observations can be
//! serialized by a runner and compared with a local execution without inventing
//! a second execution model.

mod backend;
mod comparison;
mod errors;
mod evidence_binding;
mod model;
mod secret_scan;
mod validation;

pub use backend::observe_backend;
pub use comparison::{compare_bisim, compare_bisim_with};
pub use errors::BisimError;
pub use evidence_binding::{
    evidence_producer_identity_digest, portable_evidence_payload_digest,
    portable_evidence_payload_size, BisimPortableEvidence,
};
pub use model::{
    BackendIdentity, BisimComparison, BisimObservation, BisimResultBinding,
    BISIM_OBSERVATION_VERSION, MAX_BISIM_CANARIES, MAX_BISIM_CANARY_BYTES, MAX_BISIM_RESULT_BYTES,
    MIN_BISIM_CANARY_BYTES,
};
pub use secret_scan::SecretCanary;

#[cfg(test)]
mod tests;
