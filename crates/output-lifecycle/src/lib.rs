//! Bounded artifact scanning and authoritative CAS lifecycle coordination.
//!
//! This crate is deliberately outside the control-plane persistence crate. A
//! scanner adapter receives only an immutable, tenant-bound digest request;
//! implementations are expected to cross a supervised process boundary and
//! never receive runner or object-store credentials.

mod error;
mod gc;
mod object_graph;
mod promotion;
mod scanner;
mod worker;

pub use error::LifecycleError;
pub use object_graph::verify_authoritative_object_graph;
pub use promotion::execute_artifact_promotion;
pub use scanner::{ArtifactScannerClient, ScanRequest, ScanVerdict, ScannerFailure};
pub use worker::{GcSummary, LifecycleLimits, OutputLifecycleWorker};
