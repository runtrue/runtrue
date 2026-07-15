//! Stable public Rust facade for Runtrue execution artifacts.
//!
//! This crate intentionally exposes the product-level vocabulary while the
//! implementation remains split into focused internal crates.

/// Immutable execution artifacts and their canonical identity.
pub mod capsule {
    pub use runtrue_model::ContentDigest;
    pub use runtrue_workflow_ir::{ExecutionCapsule, CAPSULE_SCHEMA_VERSION};
}

/// Exact Capsule approval evidence.
pub mod seal {
    pub use runtrue_policy::CapsuleSeal;
}

/// Portable, secret-free local reproduction artifacts.
pub mod replay {
    pub use runtrue_replay::{ReplayBundle, ReplayEnvelope, ReplayError};
}

/// Shared-engine behavioral conformance primitives.
pub mod bisim {
    pub use runtrue_bisim::{
        compare_bisim, observe_backend, BackendIdentity, BisimComparison, BisimError,
        BisimObservation, SecretCanary,
    };
}

pub use capsule::{ContentDigest, ExecutionCapsule, CAPSULE_SCHEMA_VERSION};
pub use replay::{ReplayBundle, ReplayEnvelope, ReplayError};
pub use seal::CapsuleSeal;
