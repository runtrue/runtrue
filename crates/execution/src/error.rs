use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutionModelError {
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} contains too many entries; maximum is {maximum}")]
    TooManyEntries { field: &'static str, maximum: usize },
    #[error("{field} contains duplicate or conflicting identity `{identity}`")]
    ConflictingIdentity {
        field: &'static str,
        identity: String,
    },
    #[error("capsule kind does not match its canonical type")]
    CapsuleKindMismatch,
    #[error("Seal does not bind the exact ApprovalSubject and Capsule identity")]
    SealSubjectMismatch,
    #[error("Seal is not valid before its issuance time")]
    SealNotYetValid,
    #[error("Seal has expired")]
    SealExpired,
    #[error("Seal revocation generation {actual} does not match current generation {expected}")]
    SealRevoked { expected: u64, actual: u64 },
    #[error("delegated child violates containment for {field}")]
    ContainmentViolation { field: &'static str },
    #[error("idempotency key was already used for different canonical content")]
    IdempotencyConflict,
    #[error("Session reservation capacity is unavailable")]
    ReservationCapacityUnavailable,
    #[error("Session reservation identity conflicts with durable state")]
    ReservationIdentityConflict,
    #[error("Session reservation is unknown")]
    ReservationNotFound,
    #[error("Session reservation transition is invalid")]
    InvalidReservationTransition,
    #[error("Session fence is stale")]
    StaleSessionFence,
    #[error("workspace generation has already advanced")]
    WorkspaceGenerationConflict,
    #[error("workspace publication requires an active matching reservation")]
    WorkspaceReservationInactive,
    #[error("canonical accounting overflow or underflow")]
    AccountingFailure,
    #[error("invalid {subject} transition from {from} to {to}")]
    InvalidTransition {
        subject: &'static str,
        from: &'static str,
        to: &'static str,
    },
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),
}

impl PartialEq for ExecutionModelError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for ExecutionModelError {}
