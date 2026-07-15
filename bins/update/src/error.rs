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
}
