use thiserror::Error;

use crate::MAX_AUDIENCES;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("OIDC issuer must be HTTPS (or loopback HTTP), without query/fragment/trailing slash")]
    InvalidIssuer,
    #[error("OIDC grant fencing generation must be greater than zero")]
    InvalidFencingGeneration,
    #[error("OIDC grant must contain 1 to {MAX_AUDIENCES} audiences")]
    InvalidAudiences,
    #[error("requested OIDC audience is not granted to this step")]
    AudienceNotGranted,
    #[error("OIDC token TTL is outside the configured range")]
    InvalidTtl,
    #[error("OIDC grant is expired")]
    GrantExpired,
    #[error("OIDC token exceeds its size limit")]
    TokenTooLarge,
    #[error("OIDC token is malformed")]
    MalformedToken,
    #[error("OIDC token header is invalid")]
    InvalidHeader,
    #[error("OIDC token signature length is {0}, expected 64")]
    InvalidSignatureLength(usize),
    #[error("OIDC token signature is invalid")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("OIDC token is expired or not yet valid")]
    TokenExpiredOrNotYetValid,
    #[error("OIDC token lifetime exceeds the global verification limit")]
    InvalidTokenLifetime,
    #[error("OIDC token claims do not match the active grant")]
    ClaimMismatch,
    #[error("OIDC public key length is {0}, expected 32")]
    InvalidPublicKeyLength(usize),
    #[error("invalid OIDC public key: {0}")]
    InvalidPublicKey(#[from] ed25519_dalek::SignatureError),
    #[error("invalid OIDC JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid base64url in OIDC token: {0}")]
    Base64(#[from] base64ct::Error),
    #[error("invalid OIDC JWK")]
    InvalidJwk,
    #[error("invalid OIDC JWKS")]
    InvalidJwks,
    #[error("OIDC JWKS exceeds its size limit")]
    JwksTooLarge,
    #[error("duplicate OIDC signing key")]
    DuplicateSigningKey,
    #[error("unknown OIDC signing key")]
    UnknownSigningKey,
    #[error("OIDC discovery document is invalid")]
    InvalidDiscoveryDocument,
    #[error("OIDC discovery document exceeds its size limit")]
    DiscoveryDocumentTooLarge,
    #[error("OIDC key-ring snapshot is invalid")]
    InvalidKeyRingSnapshot,
    #[error("OIDC key-ring snapshot version is unsupported")]
    UnsupportedKeyRingSnapshotVersion,
    #[error("OIDC key-ring snapshot is not canonical JSON")]
    NonCanonicalKeyRingSnapshot,
    #[error("OIDC key-ring snapshot exceeds its size limit")]
    KeyRingSnapshotTooLarge,
    #[error("OIDC active signing key does not match durable key-ring state")]
    SigningKeyContinuityMismatch,
    #[error("OIDC signing-key overlap is outside the configured range")]
    InvalidSigningKeyOverlap,
    #[error("OIDC signing-key history is full")]
    SigningKeyHistoryFull,
    #[error("OIDC signing-key revocation history is full")]
    SigningKeyRevocationHistoryFull,
    #[error("OIDC signing key is revoked")]
    SigningKeyRevoked,
    #[error("cannot revoke the active OIDC signing key without replacing it")]
    CannotRevokeActiveSigningKey,
    #[error("OIDC signing key is outside its validity window")]
    SigningKeyOutsideValidityWindow,
    #[error("OIDC signing-key lifecycle clock moved backwards")]
    SigningKeyClockRollback,
    #[error("OIDC signing-key generation is exhausted")]
    SigningKeyGenerationExhausted,
}
