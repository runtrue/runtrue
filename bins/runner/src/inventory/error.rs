pub(super) fn io_error(path: &Path, source: io::Error) -> InventoryError {
    InventoryError::Io {
        path: path.to_owned(),
        source,
    }
}

use crate::state::StateError;
use runtrue_runner_core::RunnerAdmissionError;
use std::{
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("probed inventory omitted the required posture capability")]
    MissingPostureCapability,
    #[error("unsupported runner operating system `{0}`")]
    UnsupportedPlatform(String),
    #[error("unsupported runner architecture `{0}`")]
    UnsupportedArchitecture(String),
    #[error("unsupported advertised isolation backend `{0}`")]
    UnsupportedIsolation(String),
    #[error("local {0} probe is unsupported on this platform")]
    UnsupportedProbe(&'static str),
    #[error("could not determine logical CPU count: {0}")]
    Parallelism(io::Error),
    #[error("could not locate the runner executable: {0}")]
    CurrentExecutable(io::Error),
    #[error("local capacity overflowed while probing {0}")]
    CapacityOverflow(&'static str),
    #[error("invalid /proc memory inventory")]
    InvalidMemoryProbe,
    #[error("could not run the storage inventory probe: {0}")]
    StorageProbe(io::Error),
    #[error("storage inventory probe exceeded its deadline")]
    StorageProbeTimedOut,
    #[error("storage inventory process cleanup failed: {0}")]
    StorageCleanup(String),
    #[error("invalid storage inventory output")]
    InvalidStorageProbe,
    #[error("invalid local hostname")]
    InvalidHostname,
    #[error("unsafe inventory probe path `{0}`")]
    UnsafeProbePath(PathBuf),
    #[error("unsafe runner executable `{0}`")]
    UnsafeExecutable(PathBuf),
    #[error("runner inventory operation failed for `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runner posture encoding failed: {0}")]
    PostureEncoding(serde_json::Error),
    #[error("unsafe capsule-signing keyring `{0}`; expected a mode-0700 real directory")]
    UnsafeKeyring(PathBuf),
    #[error("capsule-signing keyring `{0}` is empty")]
    EmptyKeyring(PathBuf),
    #[error("invalid raw or hexadecimal Ed25519 public key `{path}`")]
    InvalidPublicKey { path: PathBuf },
    #[error("invalid Ed25519 public key `{path}`: {source}")]
    PublicKey {
        path: PathBuf,
        #[source]
        source: runtrue_attest::AttestError,
    },
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Admission(#[from] RunnerAdmissionError),
    #[error(transparent)]
    Protocol(#[from] runtrue_protocol::ProtocolVersionError),
    #[error(transparent)]
    Digest(#[from] runtrue_protocol::DigestConversionError),
}
