use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuestAgentError {
    #[error("invalid guest configuration: {0}")]
    InvalidConfiguration(String),
    #[error("guest I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("guest boot configuration failed: {0}")]
    Boot(#[from] runtrue_guest_core::GuestError),
    #[error("capsule trust key failed: {0}")]
    Trust(#[from] runtrue_attest::AttestError),
    #[error("guest JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("guest transport failed: {0}")]
    Transport(String),
    #[error("guest process failed: {0}")]
    Process(String),
    #[error("guest protocol violation: {0}")]
    Protocol(String),
}
