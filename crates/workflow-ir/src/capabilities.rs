use crate::{Access, CacheRead, CacheWrite, NetworkPermission, SigningCapability};
use runtrue_model::SecretReference;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepCapabilitySet {
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub network: NetworkPermission,
    pub secrets: Vec<SecretReference>,
    pub checks: Access,
    pub artifacts: Access,
    pub cache_read: CacheRead,
    pub cache_write: CacheWrite,
    pub oidc_audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing: Vec<SigningCapability>,
}

impl Default for StepCapabilitySet {
    fn default() -> Self {
        Self {
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            network: NetworkPermission::Deny,
            secrets: Vec::new(),
            checks: Access::Deny,
            artifacts: Access::Deny,
            cache_read: CacheRead::Deny,
            cache_write: CacheWrite::Deny,
            oidc_audiences: Vec::new(),
            signing: Vec::new(),
        }
    }
}

impl StepCapabilitySet {
    #[must_use]
    pub fn allows_signing(&self, capability: &SigningCapability) -> bool {
        self.signing.contains(capability)
    }
}
