use crate::EntryKind;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("lockfile exceeds {limit} bytes (actual {actual})")]
    TooLarge { limit: usize, actual: usize },
    #[error("lockfile is not valid UTF-8: {0}")]
    Utf8(#[source] std::str::Utf8Error),
    #[error("lockfile TOML is invalid or contains duplicate/unknown fields: {0}")]
    Toml(#[source] toml::de::Error),
    #[error("unsupported lock_version {0}; expected 1")]
    UnsupportedVersion(u32),
    #[error("{kind} lock entries exceed limit {limit} (actual {actual})")]
    TooManyEntries {
        kind: EntryKind,
        limit: usize,
        actual: usize,
    },
    #[error("invalid {path}: {reason}")]
    InvalidField { path: String, reason: String },
    #[error("duplicate {kind} logical source `{value}`")]
    DuplicateSource { kind: EntryKind, value: String },
    #[error("duplicate {kind} immutable resolution `{value}`")]
    DuplicateResolution { kind: EntryKind, value: String },
    #[error("{kind} source `{logical_source}` conflicts with its immutable resolution")]
    ResolutionMismatch {
        kind: EntryKind,
        logical_source: String,
    },
    #[error("missing {kind} lock entry for planned source `{logical_source}`")]
    MissingEntry {
        kind: EntryKind,
        logical_source: String,
    },
    #[error("missing image lock entry for planned source `{logical_source}` on `{platform}`")]
    MissingImageEntry {
        logical_source: String,
        platform: String,
    },
    #[error("unused {kind} lock entry for source `{logical_source}`")]
    UnusedEntry {
        kind: EntryKind,
        logical_source: String,
    },
    #[error("unused image lock entry for source `{logical_source}` on `{platform}`")]
    UnusedImageEntry {
        logical_source: String,
        platform: String,
    },
    #[error("could not encode canonical lockfile: {0}")]
    Canonical(#[source] serde_json::Error),
}
