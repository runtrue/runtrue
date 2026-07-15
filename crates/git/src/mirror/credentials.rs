use super::{
    now_unix_ms, GitError, NormalizedOrigin, RepositoryIdentity, MAX_CREDENTIAL_BYTES,
    MAX_CREDENTIAL_TTL,
};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    pub identity: RepositoryIdentity,
    pub origin: NormalizedOrigin,
    pub repository_read_only: bool,
}

pub trait GitCredentialProvider: Send + Sync {
    fn credential(&self, request: &CredentialRequest) -> Result<GitCredential, GitError>;
}

pub struct GitCredential {
    authorization_header: Zeroizing<String>,
    expires_unix_ms: u64,
}

impl GitCredential {
    pub fn new(
        authorization_header: impl Into<String>,
        expires_unix_ms: u64,
    ) -> Result<Self, GitError> {
        let authorization_header = authorization_header.into();
        let authorization_value = authorization_header
            .strip_prefix("Authorization: ")
            .ok_or(GitError::InvalidCredential)?;
        let now = now_unix_ms()?;
        let maximum = now
            .checked_add(u64::try_from(MAX_CREDENTIAL_TTL.as_millis()).unwrap_or(u64::MAX))
            .ok_or(GitError::InvalidCredential)?;
        if authorization_header.len() > MAX_CREDENTIAL_BYTES
            || authorization_value.is_empty()
            || authorization_value.trim() != authorization_value
            || authorization_header
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || expires_unix_ms <= now
            || expires_unix_ms > maximum
        {
            return Err(GitError::InvalidCredential);
        }
        Ok(Self {
            authorization_header: Zeroizing::new(authorization_header),
            expires_unix_ms,
        })
    }

    pub(super) fn header(&self) -> &str {
        &self.authorization_header
    }

    pub(super) fn value(&self) -> &str {
        self.authorization_header
            .strip_prefix("Authorization: ")
            .expect("validated authorization header")
    }

    pub(super) fn ensure_live(&self) -> Result<(), GitError> {
        if now_unix_ms()? >= self.expires_unix_ms {
            return Err(GitError::InvalidCredential);
        }
        Ok(())
    }
}

impl fmt::Debug for GitCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitCredential(<redacted>)")
    }
}
