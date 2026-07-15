//! Structured, lease-fenced, redacted, bounded log persistence.
//!
//! The journal never contains raw input chunks. It records a digest for exact
//! replay detection and output only after streaming redaction. Redaction keeps
//! every suffix that could begin a registered secret until the next chunk, so
//! a canary split across arbitrary frame boundaries cannot leak.

mod error;
mod journal;
mod limits;
mod model;
mod pipeline;
mod quota;
mod redaction;
mod secrets;
mod secure_io;
mod validation;

pub use error::LogError;
pub use limits::LogLimits;
pub use model::{
    AppendOutcome, BindOutcome, FinishOutcome, LeaseBinding, LogInputFrame, LogPayload, LogStream,
    StoredFrameKind, StoredLogFrame, TruncationScope,
};
pub use pipeline::LogPipeline;
pub use secrets::{InputDigestKey, SecretSet};
