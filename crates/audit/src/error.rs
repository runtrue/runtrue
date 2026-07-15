use crate::{MAX_AUDIT_LINE_BYTES, MAX_METADATA_FIELDS};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("invalid or oversized audit text field `{0}`")]
    InvalidText(&'static str),
    #[error("audit metadata has {0} fields; maximum is {MAX_METADATA_FIELDS}")]
    TooManyMetadataFields(usize),
    #[error("audit event line has {0} bytes; maximum is {MAX_AUDIT_LINE_BYTES}")]
    LineTooLarge(usize),
    #[error("audit event {0} has an invalid genesis/previous-hash link")]
    InvalidSequenceLink(u64),
    #[error("audit event {0} hash does not match its content")]
    EventHashMismatch(u64),
    #[error("expected audit sequence {expected}, found {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("audit event {0} changes installation identity")]
    InstallationChanged(u64),
    #[error("audit event {0} does not bind the preceding hash")]
    PreviousHashMismatch(u64),
    #[error("cannot checkpoint an empty audit chain")]
    EmptyCheckpoint,
    #[error("audit checkpoint does not match the supplied chain")]
    CheckpointMismatch,
    #[error("audit file does not use canonical event encoding")]
    NonCanonicalLine,
    #[error("audit path is a symlink or is not a regular file")]
    NotRegularFile,
    #[error("audit file has insecure Unix mode {0:o}; expected exactly 600")]
    InsecureFileMode(u32),
    #[error("audit parent path is a symlink or is not a directory")]
    UnsafeParentDirectory,
    #[error("audit file belongs to another installation")]
    WrongInstallation,
    #[error("audit sequence overflow")]
    SequenceOverflow,
    #[error("audit mutex is poisoned")]
    Poisoned,
    #[error("audit I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("invalid audit JSON: {0}")]
    Json(#[from] serde_json::Error),
}
