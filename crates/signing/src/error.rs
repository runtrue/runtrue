use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SigningError {
    #[error("invalid signing broker configuration")]
    InvalidConfiguration,
    #[error("invalid signing request")]
    InvalidRequest,
    #[error("signing capability is denied or stale")]
    Unauthorized,
    #[error("signing approval is missing, stale, or does not bind this request")]
    InvalidApproval,
    #[error("signing request id was reused with different content")]
    IdempotencyConflict,
    #[error("signing request is already in progress")]
    InProgress,
    #[error("non-exportable signer failed")]
    Signer,
    #[error("non-exportable signer returned an invalid response")]
    InvalidSignatureResponse,
    #[error("durable signing ledger failed")]
    Ledger,
    #[error("mandatory signing audit failed")]
    Audit,
    #[error("failed to serialize signing identity")]
    Serialize,
}
