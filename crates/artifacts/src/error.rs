use runtrue_model::ContentDigest;
use runtrue_storage::StorageError;
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("invalid artifact configuration: {0}")]
    InvalidConfiguration(String),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid artifact ticket: {0}")]
    InvalidTicket(String),
    #[error("artifact ticket is expired")]
    TicketExpired,
    #[error("artifact ticket was already consumed")]
    TicketConsumed,
    #[error("artifact ticket lease does not match the active lease")]
    LeaseMismatch,
    #[error("artifact ticket fencing generation {ticket} is stale; active is {active}")]
    StaleFence { ticket: u64, active: u64 },
    #[error("artifact size {actual} exceeds bound {limit}")]
    ArtifactTooLarge { limit: u64, actual: u64 },
    #[error("artifact declared size {declared} does not match captured size {actual}")]
    ContentSizeMismatch { declared: u64, actual: u64 },
    #[error("artifact declared digest {declared} does not match captured digest {actual}")]
    ContentDigestMismatch {
        declared: ContentDigest,
        actual: ContentDigest,
    },
    #[error("artifact bytes do not match the digest bound into the ticket")]
    TicketContentMismatch,
    #[error("artifact provenance is validly signed but does not describe this producer/content")]
    ProvenanceMismatch,
    #[error("unsafe artifact name `{0}`")]
    UnsafeArtifactName(String),
    #[error("invalid artifact media type")]
    InvalidMediaType,
    #[error("invalid artifact retention deadline")]
    InvalidRetention,
    #[error("invalid artifact metadata: {0}")]
    InvalidMetadata(String),
    #[error("invalid artifact promotion: {0}")]
    InvalidPromotion(String),
    #[error("{kind} exceeds limit {limit} with value {actual}")]
    MetadataLimit {
        kind: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("unsafe artifact metadata path: {}", .0.display())]
    UnsafeMetadataPath(PathBuf),
    #[error("immutable artifact metadata already exists at {}", .0.display())]
    MetadataExists(PathBuf),
    #[error("{operation} at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize artifact metadata: {0}")]
    SerializeMetadata(serde_json::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Attestation(#[from] runtrue_attest::AttestError),
}
