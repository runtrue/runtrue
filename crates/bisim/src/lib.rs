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
mod model;
mod secret_scan;
mod validation;

pub use backend::observe_backend;
pub use comparison::compare_bisim;
pub use errors::BisimError;
pub use model::{
    BackendIdentity, BisimComparison, BisimObservation, BISIM_OBSERVATION_VERSION,
    MAX_BISIM_CANARIES, MAX_BISIM_CANARY_BYTES, MAX_BISIM_RESULT_BYTES, MIN_BISIM_CANARY_BYTES,
};
pub use secret_scan::SecretCanary;

#[cfg(test)]
mod tests;
