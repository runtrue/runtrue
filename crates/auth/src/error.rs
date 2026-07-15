use crate::authorization::MAX_SCOPES;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("token scopes must contain between 1 and {MAX_SCOPES} entries")]
    InvalidScopes,
    #[error("credential lifetime is invalid or exhausted")]
    InvalidLifetime,
    #[error("session policy must use positive access <= refresh <= absolute TTLs")]
    InvalidSessionPolicy,
    #[error("authentication assertion cannot be in the future")]
    FutureAuthenticationAssertion,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("credential is expired")]
    Expired,
    #[error("credential is revoked")]
    Revoked,
    #[error("scope `{0}` is required")]
    InsufficientScope(String),
    #[error("a valid CSRF token is required")]
    CsrfRequired,
    #[error("rotated refresh token replay detected; session revoked")]
    RefreshReplay,
    #[error("session generation exhausted")]
    GenerationExhausted,
    #[error("persisted browser session record is internally inconsistent")]
    InvalidSessionRecord,
    #[error("refresh family reached its bounded rotation limit; session revoked")]
    RefreshFamilyExhausted,
    #[error("recent MFA authentication is required")]
    RecentMfaRequired,
    #[error("recent reauthentication is required")]
    RecentReauthenticationRequired,
    #[error("OIDC transaction lifetime is invalid or exceeds the configured bound")]
    InvalidOidcTransactionLifetime,
    #[error("persisted OIDC transaction record is internally inconsistent")]
    InvalidOidcTransactionRecord,
    #[error("OIDC issuer and redirect bindings must use HTTPS")]
    InsecureOidcBinding,
    #[error("OIDC transaction callback time is invalid")]
    InvalidOidcTransactionTime,
    #[error("OIDC transaction has already been used")]
    OidcTransactionAlreadyUsed,
    #[error("OIDC transaction is not awaiting identity verification")]
    OidcTransactionNotExchanging,
    #[error("OIDC issuer, client, or redirect binding changed")]
    OidcBindingMismatch,
    #[error("OIDC PKCE verifier does not match the transaction")]
    OidcPkceMismatch,
    #[error("OIDC ID-token nonce does not match the transaction")]
    OidcNonceMismatch,
}
