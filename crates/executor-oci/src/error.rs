#[derive(Debug, Error)]
pub enum OciError {
    #[error("invalid OCI executor configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid OCI execution request: {0}")]
    InvalidRequest(String),
    #[error("invalid immutable image reference: {0}")]
    InvalidImageReference(String),
    #[error("invalid seccomp profile: {0}")]
    InvalidSeccompProfile(String),
    #[error("missing locked image assignment for job `{0}`")]
    MissingImageAssignment(String),
    #[error("unused locked image assignment for job `{0}`")]
    UnusedImageAssignment(String),
    #[error("locked job image does not exactly match the approval-bound capsule for job `{0}`")]
    JobImageReferenceMismatch(String),
    #[error("missing locked image assignment for service `{job_id}.{service_id}`")]
    MissingServiceImageAssignment { job_id: String, service_id: String },
    #[error("unused locked image assignment for service `{job_id}.{service_id}`")]
    UnusedServiceImageAssignment { job_id: String, service_id: String },
    #[error("planned service image does not exactly match its lock for `{job_id}.{service_id}`")]
    ServiceImageReferenceMismatch { job_id: String, service_id: String },
    #[error("image admission provider returned data that does not exactly match the lock")]
    ImageAdmissionMismatch,
    #[error("image platform mismatch: expected `{expected}`, got `{actual}`")]
    ImagePlatformMismatch { expected: String, actual: String },
    #[error(transparent)]
    ImageAdmission(#[from] ImageAdmissionError),
    #[error("unsupported OCI isolation request `{0}`")]
    UnsupportedIsolation(String),
    #[error("unsupported OCI platform `{0}`")]
    UnsupportedPlatform(String),
    #[error("OCI backend cannot honor feature: {0}")]
    UnsupportedFeature(String),
    #[error("unsafe working directory `{0}`")]
    UnsafeWorkingDirectory(String),
    #[error("invalid environment variable name `{0}`")]
    InvalidEnvironmentName(String),
    #[error("invalid environment value for `{0}`")]
    InvalidEnvironmentValue(String),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("forbidden OCI mount `{0}`")]
    ForbiddenMount(String),
    #[error("forbidden host/container socket exposure through {0}")]
    ForbiddenSocketExposure(String),
    #[error("{kind} exceeds limit {limit} (actual {actual})")]
    LimitExceeded {
        kind: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("runtime process group cleanup could not be verified")]
    ProcessGroupLeak,
    #[error("container cleanup verification failed: expected exit {expected_exit:?}, got {actual_exit:?}")]
    CleanupVerificationFailed {
        expected_exit: Option<i32>,
        actual_exit: Option<i32>,
    },
    #[error("runtime command contract violation: {0}")]
    RuntimeContractViolation(String),
    #[error("service startup timed out")]
    ServiceStartupTimedOut,
    #[error("service startup operation `{operation}` failed with exit {exit_code:?}")]
    ServiceStartupFailed {
        operation: String,
        exit_code: Option<i32>,
    },
    #[error("service `{service_id}` remained unhealthy after {attempts} attempts")]
    ServiceUnhealthy { service_id: String, attempts: u32 },
    #[error("job lifecycle failed: {cause}; cleanup also failed: {cleanup}")]
    LifecycleCleanup { cause: String, cleanup: String },
    #[error("script content does not match its capsule digest")]
    ScriptDigestMismatch,
    #[error("invalid OCI runtime state: {0}")]
    InvalidState(String),
    #[error("unsafe {kind} path: {}", path.display())]
    UnsafePath { kind: &'static str, path: PathBuf },
    #[error("could not spawn OCI runtime: {0}")]
    Spawn(String),
    #[error("could not wait for OCI runtime: {0}")]
    Wait(String),
    #[error("OCI runtime process group cleanup failed: {0}")]
    ProcessCleanup(String),
    #[error("{operation} at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("internal OCI executor error: {0}")]
    Internal(String),
}
use crate::{io, ImageAdmissionError, PathBuf};
use thiserror::Error;
