use super::AotCacheEventKind;
use std::{io, path::PathBuf};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum AotCacheError {
    #[error("authenticated AOT caching is supported only on Unix hosts")]
    UnsupportedPlatform,
    #[error("AOT cache path must be absolute")]
    RelativeRoot,
    #[error("invalid AOT cache limits")]
    InvalidLimits,
    #[error("unsafe AOT cache path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: String },
    #[error("AOT cache I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("AOT cache metadata is malformed: {0}")]
    MalformedMetadata(#[from] serde_json::Error),
    #[error("AOT cache metadata authentication failed")]
    AuthenticationFailed,
    #[error("AOT cache entry is incompatible with the requested runtime")]
    Incompatible,
    #[error("AOT cache artifact is corrupt")]
    CorruptArtifact,
    #[error("AOT cache entry exceeds the configured byte limit")]
    EntryTooLarge,
    #[error("AOT cache storage budget is exhausted")]
    BudgetExceeded,
    #[error("AOT cache entry was concurrently published")]
    EntryAlreadyExists,
    #[error("operating system randomness is unavailable for AOT cache publication")]
    RandomnessUnavailable,
}

impl AotCacheError {
    pub(crate) const fn event_kind(&self) -> AotCacheEventKind {
        match self {
            Self::AuthenticationFailed => AotCacheEventKind::AuthenticationFailed,
            Self::Incompatible => AotCacheEventKind::Incompatible,
            Self::CorruptArtifact | Self::EntryTooLarge => AotCacheEventKind::Corrupt,
            Self::MalformedMetadata(_) => AotCacheEventKind::Malformed,
            Self::UnsafePath { .. } => AotCacheEventKind::UnsafePath,
            Self::Io { .. } => AotCacheEventKind::Io,
            Self::BudgetExceeded | Self::InvalidLimits => AotCacheEventKind::Budget,
            Self::UnsupportedPlatform => AotCacheEventKind::UnsupportedPlatform,
            Self::RandomnessUnavailable => AotCacheEventKind::RandomnessUnavailable,
            Self::RelativeRoot | Self::EntryAlreadyExists => AotCacheEventKind::UnsafePath,
        }
    }
}
