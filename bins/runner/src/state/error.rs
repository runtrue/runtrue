use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("unsafe runner path `{0}`")]
    UnsafePath(PathBuf),
    #[error(
        "runner file `{0}` must use mode 0600, or mode 0400/0440 as a direct trusted systemd credential"
    )]
    InsecurePermissions(PathBuf),
    #[error("runner file `{path}` exceeds its {maximum_bytes}-byte bound")]
    FileLimit { path: PathBuf, maximum_bytes: u64 },
    #[error("runner state at `{path}` failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runner state JSON is invalid: {0}")]
    Decode(serde_json::Error),
    #[error("runner state JSON could not be encoded: {0}")]
    Encode(serde_json::Error),
    #[error("runner state exceeds its durable size limit")]
    StateLimit,
    #[error("installation fencing epoch must be greater than zero")]
    InvalidEpoch,
    #[error("server installation epoch rolled back from {current} to {received}")]
    EpochRollback { current: u64, received: u64 },
    #[error("invalid persisted completion: {0}")]
    InvalidCompletion(&'static str),
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("unsafe source manifest entry `{0}`")]
    UnsafeSourceEntry(String),
    #[error("source snapshot exceeds its configured byte bound")]
    SourceLimit,
    #[error("source snapshot content failed size or digest verification")]
    SourceIntegrity,
    #[error("runner source cache failed: {0}")]
    SourceCache(String),
}
