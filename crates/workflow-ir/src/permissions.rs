use runtrue_model::SecretReference;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSet {
    pub repository: Access,
    #[serde(default, skip_serializing_if = "ScmPermissions::is_denied")]
    pub scm: ScmPermissions,
    pub checks: Access,
    pub artifacts: Access,
    pub registry: Access,
    pub network: NetworkPermission,
    pub oidc_audiences: Vec<String>,
    pub cache_read: CacheRead,
    pub cache_write: CacheWrite,
    pub secrets: Vec<SecretReference>,
    pub signing: Vec<SigningCapability>,
}

impl Default for PermissionSet {
    fn default() -> Self {
        Self {
            repository: Access::Deny,
            scm: ScmPermissions::default(),
            checks: Access::Deny,
            artifacts: Access::Deny,
            registry: Access::Deny,
            network: NetworkPermission::Deny,
            oidc_audiences: Vec::new(),
            cache_read: CacheRead::Deny,
            cache_write: CacheWrite::Deny,
            secrets: Vec::new(),
            signing: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmPermissions {
    pub contents: Access,
    pub issues: Access,
    #[serde(rename = "pull-requests")]
    pub pull_requests: Access,
    pub checks: Access,
    pub statuses: Access,
}

impl ScmPermissions {
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self.contents, Access::Deny)
            && matches!(self.issues, Access::Deny)
            && matches!(self.pull_requests, Access::Deny)
            && matches!(self.checks, Access::Deny)
            && matches!(self.statuses, Access::Deny)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Deny,
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum NetworkPermission {
    Deny,
    Allow {
        dns: DnsPolicy,
        deny_private_ranges: bool,
        destinations: Vec<NetworkDestination>,
        listen: Vec<u16>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsPolicy {
    Deny,
    Restricted,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    pub host: String,
    pub port: u16,
    pub protocol: NetworkProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheRead {
    Deny,
    Public,
    Verified,
    Branch,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheWrite {
    Deny,
    Quarantine,
    Branch,
    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCapability {
    pub purpose: String,
    pub operation: SigningOperation,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningOperation {
    SignDigest,
    SignAttestation,
}
