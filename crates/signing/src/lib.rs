//! Non-exportable, approval-bound signing operation broker.
//!
//! Workloads submit immutable digests and execution identity. The broker
//! verifies capability grants and approvals, signs a domain-separated payload,
//! and records mandatory audit events without exposing key bytes.

mod audit;
mod authorization;
mod broker;
mod canonical;
mod envelope;
mod error;
pub mod ledger;
mod local;
mod model;
mod signer;
mod validation;

pub use audit::{SigningAuditEvent, SigningAuditKind, SigningAuditSink};
pub use authorization::SigningAuthorizer;
pub use broker::SigningBroker;
pub use envelope::SignatureEnvelope;
pub use error::SigningError;
pub use ledger::{LedgerState, MemorySigningLedger, SigningLedger, SqliteSigningLedger};
pub use local::{
    LocalEd25519Signer, LocalSignerMetrics, LocalSigningKey, MAX_LOCAL_SIGNER_PAYLOAD_BYTES,
};
pub use model::{
    SigningApproval, SigningApprovalSubject, SigningGrant, SigningOperation, SigningRequest,
};
pub use signer::{NonExportableSigner, RawSignature, SignerPayload};

pub(crate) use audit::audit_event;
pub(crate) use canonical::{canonical_bytes, SIGNING_DOMAIN};
pub(crate) use envelope::ENVELOPE_VERSION;
pub(crate) use validation::{
    validate_approval, validate_grant, validate_identifier, validate_request_shape,
    validate_request_time, MAX_APPROVERS, MAX_SIGNATURE_BYTES,
};

#[cfg(test)]
mod tests;
