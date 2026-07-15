//! Opaque service tokens and rotating browser-session credentials.
//!
//! Persisted records contain only domain-separated keyed digests. Plaintext
//! bearer, refresh, and CSRF values are returned once in redacted zeroizing
//! wrappers. A replayed rotated refresh credential revokes the whole session.

mod authentication;
mod authorization;
mod error;
mod oidc;
mod principal;
mod token;

pub use authentication::{
    ApiTokenRecord, IssueApiToken, IssueSession, IssuedApiToken, IssuedSession,
    RotateSessionRequest, RotatedSessionTokens, SessionPolicy, SessionRecord,
};
pub use error::AuthError;
pub use oidc::*;
pub use principal::{AuthContext, AuthenticationKind};
pub use token::{SecretToken, TokenDigest, TokenHasher, MAX_USED_REFRESH_DIGESTS};
