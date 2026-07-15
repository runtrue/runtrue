use crate::{storage_is_stored_corruption, CacheHead};
use runtrue_storage::StorageError;
use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("invalid cache configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid cache identity: {0}")]
    InvalidIdentity(String),
    #[error("cache read is not allowed by the trust-domain direction rules")]
    UnauthorizedRead,
    #[error("cache write is not allowed by the trust-domain direction rules")]
    UnauthorizedWrite,
    #[error("invalid cache promotion: {0}")]
    InvalidPromotion(String),
    #[error("cache promotion source does not exist")]
    SourceNotFound,
    #[error("cache head changed; current head: {current:?}")]
    HeadConflict { current: Option<CacheHead> },
    #[error("stale fencing generation {attempted}; current generation is {current}")]
    StaleFence { current: u64, attempted: u64 },
    #[error("cache generation overflow")]
    GenerationOverflow,
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid cache write ticket: {0}")]
    InvalidTicket(String),
    #[error("cache write ticket is not valid yet")]
    TicketNotYetValid,
    #[error("cache write ticket is expired")]
    TicketExpired,
    #[error("cache write ticket was already consumed")]
    TicketConsumed,
    #[error("cache write ticket does not match the active scope")]
    TicketScopeMismatch,
    #[error("cache write ticket lease does not match the active lease")]
    LeaseMismatch,
    #[error("cache snapshot does not match the digest bound into the ticket")]
    TicketContentMismatch,
    #[error("cache content exceeds ticket limit {limit} with value {actual}")]
    CacheContentTooLarge { limit: u64, actual: u64 },
    #[error("invalid cache ticket claim: {0}")]
    InvalidTicketClaim(String),
    #[error("immutable cache metadata already exists: {}", .0.display())]
    MetadataExists(PathBuf),
    #[error("corrupt cache head: {0}")]
    CorruptHead(String),
    #[error("invalid cache manifest: {0}")]
    InvalidManifest(String),
    #[error("{kind} exceeds limit {limit} with value {actual}")]
    MetadataLimit {
        kind: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("unsafe cache metadata path: {}", .0.display())]
    UnsafeMetadataPath(PathBuf),
    #[error("{operation} at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize cache metadata: {0}")]
    SerializeMetadata(serde_json::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl CacheError {
    pub(crate) fn is_stored_corruption(&self) -> bool {
        match self {
            Self::CorruptHead(_)
            | Self::InvalidManifest(_)
            | Self::InvalidTicketClaim(_)
            | Self::MetadataLimit { .. }
            | Self::UnsafeMetadataPath(_) => true,
            Self::Storage(error) => storage_is_stored_corruption(error),
            Self::InvalidConfiguration(_)
            | Self::InvalidIdentity(_)
            | Self::UnauthorizedRead
            | Self::UnauthorizedWrite
            | Self::InvalidPromotion(_)
            | Self::SourceNotFound
            | Self::HeadConflict { .. }
            | Self::StaleFence { .. }
            | Self::GenerationOverflow
            | Self::RandomnessUnavailable
            | Self::InvalidTicket(_)
            | Self::TicketNotYetValid
            | Self::TicketExpired
            | Self::TicketConsumed
            | Self::TicketScopeMismatch
            | Self::LeaseMismatch
            | Self::TicketContentMismatch
            | Self::CacheContentTooLarge { .. }
            | Self::MetadataExists(_)
            | Self::Io { .. }
            | Self::SerializeMetadata(_) => false,
        }
    }
}
