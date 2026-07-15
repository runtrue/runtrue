use crate::{CacheError, CacheIdentity, CacheLimits, CachePlatform, TrustDomain};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

/// Trust-neutral material used by both local and remote execution to derive a
/// cache identity. Trust scope is deliberately absent: only the server-side
/// access decision may add it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKeyMaterial {
    pub tenant_id: String,
    pub repository_id: String,
    pub purpose: String,
    pub platform: CachePlatform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<ContentDigest>,
    pub definition: ContentDigest,
    pub declared_inputs: ContentDigest,
    pub policy_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_suffix: Option<String>,
}

/// Hash canonical definition material with the same domain separation in
/// local and remote adapters.
pub fn cache_definition_digest<T: Serialize>(value: &T) -> Result<ContentDigest, CacheError> {
    let bytes = serde_json::to_vec(&("runtrue.cache-definition.v1", value))
        .map_err(CacheError::SerializeMetadata)?;
    Ok(ContentDigest::sha256(bytes))
}

impl CacheKeyMaterial {
    pub fn validate(&self, limits: CacheLimits) -> Result<(), CacheError> {
        let identity = self.with_trust_domain(TrustDomain::RunPrivate {
            installation_id: "validation".to_owned(),
            tenant_id: self.tenant_id.clone(),
            repository_id: self.repository_id.clone(),
            run_id: "validation".to_owned(),
        });
        identity.validate(limits)
    }

    /// Domain-separated identity for the trust-neutral content key. This is
    /// stable between local and remote adapters and must not be used as an
    /// authorization token or cache entry id.
    pub fn digest(&self, limits: CacheLimits) -> Result<ContentDigest, CacheError> {
        self.validate(limits)?;
        let bytes = serde_json::to_vec(&("runtrue.cache-key-material.v1", self))
            .map_err(CacheError::SerializeMetadata)?;
        Ok(ContentDigest::sha256(bytes))
    }

    #[must_use]
    pub fn with_trust_domain(&self, trust_domain: TrustDomain) -> CacheIdentity {
        CacheIdentity {
            tenant_id: self.tenant_id.clone(),
            repository_id: self.repository_id.clone(),
            purpose: self.purpose.clone(),
            trust_domain,
            platform: self.platform.clone(),
            compiler_or_toolchain: self.toolchain.clone(),
            definition: self.definition.clone(),
            declared_inputs: self.declared_inputs.clone(),
            policy_epoch: self.policy_epoch,
            user_suffix: self.user_suffix.clone(),
        }
    }
}

impl From<&CacheIdentity> for CacheKeyMaterial {
    fn from(identity: &CacheIdentity) -> Self {
        Self {
            tenant_id: identity.tenant_id.clone(),
            repository_id: identity.repository_id.clone(),
            purpose: identity.purpose.clone(),
            platform: identity.platform.clone(),
            toolchain: identity.compiler_or_toolchain.clone(),
            definition: identity.definition.clone(),
            declared_inputs: identity.declared_inputs.clone(),
            policy_epoch: identity.policy_epoch,
            user_suffix: identity.user_suffix.clone(),
        }
    }
}
