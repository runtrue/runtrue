use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HumanOidcError {
    #[error("invalid human OIDC configuration")]
    InvalidConfiguration,
    #[error("human OIDC provider is disabled")]
    ProviderDisabled,
    #[error("invalid OIDC authorization code")]
    InvalidAuthorizationCode,
    #[error("OIDC transport failed")]
    Transport,
    #[error("OIDC token endpoint rejected the exchange")]
    TokenEndpointRejected,
    #[error("GitHub rejected the authenticated user API request")]
    ProviderApiRejected,
    #[error("OIDC JWKS endpoint rejected the request")]
    JwksEndpointRejected,
    #[error("OIDC response exceeded its bound")]
    ResponseTooLarge,
    #[error("invalid OIDC token response")]
    InvalidTokenResponse,
    #[error("invalid OIDC ID token")]
    InvalidIdToken,
    #[error("unsupported OIDC ID-token signing algorithm")]
    UnsupportedIdTokenAlgorithm,
    #[error("invalid OIDC JWKS")]
    InvalidJwks,
    #[error("OIDC ID-token signing key is unknown")]
    UnknownSigningKey,
    #[error("OIDC ID-token signature is invalid")]
    InvalidIdTokenSignature,
    #[error("OIDC ID-token claims are invalid")]
    InvalidIdTokenClaims,
    #[error("invalid OIDC MFA claim configuration")]
    InvalidMfaClaimConfiguration,
    #[error("browser cookie is invalid")]
    InvalidCookie,
    #[error("browser cookie exceeds its bound")]
    CookieTooLarge,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}
