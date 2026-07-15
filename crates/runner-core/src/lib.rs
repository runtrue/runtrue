//! Runner-side admission for signed capsules and fenced execution leases.
//!
//! This crate deliberately contains no transport client and no executor. It is
//! the trust boundary between an authenticated control-plane connection and a
//! runner supervisor: exact canonical capsule bytes, signatures, capabilities,
//! deadlines, installation epochs, and fencing generations are checked before
//! any workspace or backend is touched.

mod admission;
mod completion;
mod error;
mod lease;
mod profile;
mod trust_store;
mod validation;

pub use admission::{RunnerAdmission, DEFAULT_MAX_CANONICAL_CAPSULE_BYTES};
pub use completion::LeaseCompletion;
pub use error::RunnerAdmissionError;
pub use lease::{AdmittedLease, LeaseExecutionGuard, LeaseExecutionState};
pub use profile::VerifiedRunnerProfile;
pub use trust_store::CapsuleTrustStore;

#[cfg(test)]
mod tests;
