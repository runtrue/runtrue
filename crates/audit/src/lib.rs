//! Append-only, tamper-evident audit events.
//!
//! The local file implementation acknowledges an append only after flushing
//! it to the operating system. Each event binds the complete previous event
//! hash, installation identity, sequence, actor, resource, result, and bounded
//! metadata. Purpose-separated Ed25519 keys can sign exported checkpoints
//! while retaining this exact verification contract.

mod canonical;
mod chain;
mod checkpoint;
mod error;
mod file_log;
mod model;
mod signed;
mod validation;

pub use chain::verify_chain;
pub use checkpoint::{checkpoint, AuditCheckpoint};
pub use error::AuditError;
pub use file_log::{FileAuditLog, MAX_AUDIT_LINE_BYTES};
pub use model::{AuditEvent, AuditEventData, AuditPrincipal, AuditResource, AuditValue};
pub use signed::{
    AuditCheckpointSigningKey, AuditCheckpointVerifyingKey, AuditSignatureError,
    SignedAuditCheckpoint, AUDIT_CHECKPOINT_MEDIA_TYPE, AUDIT_CHECKPOINT_SIGNATURE_ALGORITHM,
};
pub use validation::{MAX_METADATA_FIELDS, MAX_TEXT_BYTES};
