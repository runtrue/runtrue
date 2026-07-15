use super::{GitError, MAX_IDENTITY_BYTES};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIdentity {
    tenant_id: String,
    repository_id: String,
}

impl RepositoryIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        repository_id: impl Into<String>,
    ) -> Result<Self, GitError> {
        let identity = Self {
            tenant_id: tenant_id.into(),
            repository_id: repository_id.into(),
        };
        validate_identity_field(&identity.tenant_id)?;
        validate_identity_field(&identity.repository_id)?;
        Ok(identity)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"runtrue.git-mirror.identity.v1\0");
        append_identity_field(&mut hasher, &self.tenant_id);
        append_identity_field(&mut hasher, &self.repository_id);
        ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
            .expect("SHA-256 formatting is valid")
    }
}

impl fmt::Debug for RepositoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryIdentity")
            .field("tenant_id", &self.tenant_id)
            .field("repository_id", &self.repository_id)
            .finish()
    }
}

fn append_identity_field(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn validate_identity_field(value: &str) -> Result<(), GitError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
    {
        return Err(GitError::InvalidRepositoryIdentity);
    }
    Ok(())
}
