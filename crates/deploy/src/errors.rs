use crate::DeploymentRequestStatus;
use runtrue_artifacts::ArtifactClassification;
use runtrue_policy::PolicyError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("environment policy is invalid")]
    InvalidEnvironmentPolicy,
    #[error("environment `{0}` already exists")]
    EnvironmentExists(String),
    #[error("environment `{0}` was not found")]
    EnvironmentNotFound(String),
    #[error("protected environment is disabled")]
    EnvironmentDisabled,
    #[error("unsupported deployment subject version")]
    InvalidSubjectVersion,
    #[error("invalid deployment subject: {0}")]
    InvalidSubject(&'static str),
    #[error("deployment subject does not match the protected environment policy")]
    EnvironmentSubjectMismatch,
    #[error("ref `{0}` is not allowed for this environment")]
    RefDenied(String),
    #[error("trust level `{0}` is not allowed for this environment")]
    TrustDenied(String),
    #[error("artifact classification `{0:?}` is not allowed for this environment")]
    ArtifactClassificationDenied(ArtifactClassification),
    #[error("verified artifact provenance is required")]
    ProvenanceRequired,
    #[error("deployment request `{0}` already exists")]
    RequestExists(String),
    #[error("deployment request `{0}` was not found")]
    RequestNotFound(String),
    #[error("deployment `{0}` already exists")]
    DeploymentExists(String),
    #[error("deployment `{0}` was not found")]
    DeploymentNotFound(String),
    #[error("idempotency key was reused with another deployment subject")]
    IdempotencyConflict,
    #[error("deployment request cannot transition from {0:?}")]
    InvalidState(DeploymentRequestStatus),
    #[error("protected environment concurrency limit reached")]
    ConcurrencyLimit,
    #[error("invalid deployment completion")]
    InvalidCompletion,
    #[error("deployment is not in progress")]
    InvalidDeploymentState,
    #[error("deployment metadata is invalid or too large")]
    InvalidMetadata,
    #[error("deployment timestamp is invalid")]
    InvalidTimestamp,
    #[error("deployment gate state is internally inconsistent")]
    CorruptState,
    #[error(transparent)]
    Approval(#[from] PolicyError),
    #[error("cannot serialize deployment subject: {0}")]
    Serialize(#[from] serde_json::Error),
}
