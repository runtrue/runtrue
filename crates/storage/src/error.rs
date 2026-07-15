use runtrue_model::ContentDigest;
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid storage configuration: {0}")]
    InvalidConfiguration(String),
    #[error("{operation} at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("CAS object not found at {}", .0.display())]
    NotFound(PathBuf),
    #[error("unsafe filesystem entry at {}: {kind}", path.display())]
    UnsafeFilesystemEntry { path: PathBuf, kind: &'static str },
    #[error("unsafe tree path: {0}")]
    UnsafePath(String),
    #[error("{resource} exceeds limit {limit} with value {actual}")]
    LimitExceeded {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("corrupt CAS blob: expected {expected}, computed {actual}")]
    CorruptBlob {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("unsupported content digest: {0}")]
    UnsupportedDigest(String),
    #[error("could not read object: {0}")]
    ReadObject(String),
    #[error("could not serialize tree manifest: {0}")]
    SerializeManifest(serde_json::Error),
    #[error("invalid tree manifest encoding: {0}")]
    InvalidManifestEncoding(serde_json::Error),
    #[error("invalid tree manifest: {0}")]
    Manifest(String),
    #[error("materialization destination is not empty: {}", .0.display())]
    DestinationNotEmpty(PathBuf),
    #[error("materialization would overwrite an existing path: {}", .0.display())]
    DestinationCollision(PathBuf),
}

impl StorageError {
    /// Whether the error means stored bytes or metadata failed integrity checks.
    #[must_use]
    pub const fn is_corruption(&self) -> bool {
        matches!(
            self,
            Self::CorruptBlob { .. }
                | Self::InvalidManifestEncoding(_)
                | Self::Manifest(_)
                | Self::UnsafeFilesystemEntry { .. }
        )
    }
}
