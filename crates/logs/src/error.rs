#[derive(Debug, Error)]
pub enum LogError {
    #[error("invalid log configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid secret redaction configuration")]
    InvalidSecrets,
    #[error("input replay digest key must contain 32 to 1024 bytes")]
    InvalidInputDigestKey,
    #[error("invalid log identifier")]
    InvalidIdentifier,
    #[error("invalid lease binding")]
    InvalidBinding,
    #[error("log frame does not match the active lease/fencing generation")]
    StaleLease,
    #[error("conflicting duplicate log frame")]
    ConflictingDuplicate,
    #[error("out-of-order log frame: expected sequence {expected}, received {received}")]
    OutOfOrder { expected: u64, received: u64 },
    #[error("log stream has already finished")]
    StreamFinished,
    #[error("run is closed or was interrupted before redaction buffers were flushed")]
    RunClosedOrInterrupted,
    #[error("run still contains an open step or stream")]
    OpenStep,
    #[error("per-stream frame count limit reached")]
    FrameCountLimit,
    #[error("journal record exceeds its configured limit")]
    JournalRecordLimit,
    #[error("journal size {actual} exceeds configured limit {limit}")]
    JournalLimit { limit: u64, actual: u64 },
    #[error("log journal integrity verification failed: {0}")]
    Integrity(String),
    #[error("unsafe log journal path: {}", .0.display())]
    UnsafeJournalPath(PathBuf),
    #[error("{operation} at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize log metadata: {0}")]
    Serialize(serde_json::Error),
}
use std::{io, path::PathBuf};
use thiserror::Error;
