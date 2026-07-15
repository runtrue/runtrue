use crate::human_oidc::HumanOidcError;
use runtrue_model::ContentDigest;
use std::time::Duration;
use ureq::http::Uri;
use zeroize::Zeroize as _;

pub const MAX_SEALED_COOKIE_BYTES: usize = 4096;
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 8192;
pub const MAX_ID_TOKEN_BYTES: usize = 64 * 1024;
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_HUMAN_JWKS_BYTES: usize = 64 * 1024;
pub const MAX_HUMAN_JWKS_KEYS: usize = 32;
pub const MAX_OIDC_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_ID_TOKEN_LIFETIME_SECONDS: u64 = 2 * 60 * 60;
pub const ID_TOKEN_CLOCK_SKEW_SECONDS: u64 = 60;

pub fn validate_human_oidc_public_origin(value: &str) -> Result<(), HumanOidcError> {
    let uri: Uri = value
        .parse()
        .map_err(|_| HumanOidcError::InvalidConfiguration)?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || value.ends_with('/')
        || value.len() > 4096
        || value.contains('@')
        || value.contains('#')
        || value.contains('\\')
    {
        return Err(HumanOidcError::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanOidcLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub maximum_concurrent_exchanges: usize,
}

impl Default for HumanOidcLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            maximum_concurrent_exchanges: 8,
        }
    }
}

impl HumanOidcLimits {
    pub fn validate(self) -> Result<Self, HumanOidcError> {
        if self.connect_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.connect_timeout > self.request_timeout
            || self.request_timeout > Duration::from_secs(60)
            || self.maximum_concurrent_exchanges == 0
            || self.maximum_concurrent_exchanges > 64
        {
            return Err(HumanOidcError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Claims released only after signature, issuer, audience, time, and shape
/// verification. The caller still verifies the nonce against the durable
/// transaction's keyed digest before creating a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHumanIdentity {
    pub issuer: String,
    pub subject: String,
    pub nonce: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub claims_digest: ContentDigest,
    pub mfa_authenticated: bool,
}

/// Identity returned by GitHub's OAuth user API after the access token has
/// been exchanged and consumed inside the adapter.
pub struct GitHubAccessToken(zeroize::Zeroizing<String>);

impl GitHubAccessToken {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for GitHubAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GitHubAccessToken([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubUserRepository {
    pub repository_id: u64,
    pub owner_id: u64,
    pub owner: String,
    pub name: String,
    pub visibility: String,
    pub default_branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubUserCatalog {
    pub organizations: Vec<String>,
    pub repositories: Vec<GitHubUserRepository>,
}

#[derive(Debug)]
pub struct VerifiedGitHubIdentity {
    pub user_id: u64,
    pub login: String,
    pub display_name: String,
    pub email: Option<String>,
    pub claims_digest: ContentDigest,
    pub access_token: GitHubAccessToken,
}

impl Drop for VerifiedGitHubIdentity {
    fn drop(&mut self) {
        self.login.zeroize();
        self.display_name.zeroize();
        if let Some(email) = &mut self.email {
            email.zeroize();
        }
    }
}

impl Drop for VerifiedHumanIdentity {
    fn drop(&mut self) {
        self.issuer.zeroize();
        self.subject.zeroize();
        self.nonce.zeroize();
        if let Some(value) = &mut self.display_name {
            value.zeroize();
        }
        if let Some(value) = &mut self.email {
            value.zeroize();
        }
    }
}
