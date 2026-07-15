//! Protected-environment deployment gates and rollback-safe state transitions.
//!
//! A deployment approval binds immutable capsule, source, artifact, provenance,
//! target, environment-policy, and fencing identities. Promotion/deployment
//! records refer to artifact bytes; this crate never executes quarantined or
//! promoted content.

mod environment;
mod errors;
mod gate;
mod policy;
mod record;
mod request;
mod subject;
mod validation;

pub use environment::EnvironmentStatus;
pub use errors::DeploymentError;
pub use gate::DeploymentGate;
pub use policy::EnvironmentPolicy;
pub use record::{DeploymentRecord, DeploymentStatus};
pub use request::{
    CreateDeploymentRequest, CreateDeploymentResult, DeploymentRequest, DeploymentRequestStatus,
};
pub use subject::DeploymentSubject;

#[cfg(test)]
use subject::DEPLOYMENT_SUBJECT_VERSION;
#[cfg(test)]
use validation::{validate_metadata, MAX_METADATA_VALUE_BYTES};

#[cfg(test)]
mod tests;
