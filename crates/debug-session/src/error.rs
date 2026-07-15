use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DebugSessionError {
    #[error("invalid debug-session configuration")]
    InvalidConfiguration,
    #[error("invalid debug-session request")]
    InvalidRequest,
    #[error("debug session is not authorized by policy")]
    PolicyDenied,
    #[error("debug session requires recent MFA, reauthentication, and scope")]
    Authentication,
    #[error("debug-session approval is invalid or stale")]
    InvalidApproval,
    #[error("secret/OIDC release could not be blocked or revoked")]
    SecretGate,
    #[error("ephemeral client identity issuance failed")]
    IdentityIssuer,
    #[error("reverse debug relay operation failed")]
    Relay,
    #[error("mandatory debug-session audit failed")]
    Audit,
    #[error("invalid or mismatched debug credential")]
    InvalidCredential,
    #[error("one-use tunnel token has already been consumed")]
    TokenUsed,
    #[error("debug session has expired")]
    Expired,
    #[error("debug session has not expired")]
    NotExpired,
    #[error("debug-session record integrity check failed")]
    Integrity,
    #[error("failed to canonicalize debug-session identity")]
    Serialize,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}
