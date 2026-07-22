use runtrue_model::ContentDigest;
use runtrue_update::UpdateError;
use thiserror::Error;
#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error(transparent)]
    Update(#[from] UpdateError),
    #[error("expected root digest must be a qualified lowercase SHA-256 digest")]
    InvalidExpectedRootDigest,
    #[error("root digest mismatch: expected {expected}, got {actual}")]
    RootDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("trusted update state is already initialized")]
    AlreadyInitialized,
    #[error("trusted update state is not initialized")]
    TrustNotInitialized,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("invalid release file `{0}`; expected normalized-name=path")]
    InvalidSubject(String),
    #[error("invalid locked Cargo dependency metadata: {0}")]
    InvalidCargoMetadata(String),
    #[error("runner component profile is not exactly signed or safely installable: {0}")]
    InvalidRunnerProfile(String),
    #[error("immutable runner staging failed during {operation} at {}: {source}", path.display())]
    StageIo {
        operation: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not encode fixed-host update state: {0}")]
    Json(#[from] serde_json::Error),
}
