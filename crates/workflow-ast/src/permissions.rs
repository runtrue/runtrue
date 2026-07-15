use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub repository: Access,
    #[serde(default, skip_serializing_if = "ScmPermissions::is_denied")]
    pub scm: ScmPermissions,
    #[serde(default)]
    pub checks: Access,
    #[serde(default)]
    pub artifacts: Access,
    #[serde(default)]
    pub registry: Access,
    #[serde(default)]
    pub network: NetworkPermission,
    #[serde(default)]
    pub oidc: OidcPermission,
    #[serde(default)]
    pub cache: CachePermissions,
    #[serde(default)]
    pub secrets: Vec<SecretRequest>,
    #[serde(default)]
    pub signing: Vec<SigningRequest>,
}

/// Provider-neutral source-control API permissions retained in the signed
/// capsule. A provider adapter maps these operations to its own token scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmPermissions {
    #[serde(default)]
    pub contents: Access,
    #[serde(default)]
    pub issues: Access,
    #[serde(default, rename = "pull-requests")]
    pub pull_requests: Access,
    #[serde(default)]
    pub checks: Access,
    #[serde(default)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NetworkPermission {
    Keyword(String),
    Policy(NetworkPolicy),
}

impl Default for NetworkPermission {
    fn default() -> Self {
        Self::Keyword("deny".to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OidcPermission {
    Keyword(String),
    Allow(OidcAllow),
}

impl Default for OidcPermission {
    fn default() -> Self {
        Self::Keyword("deny".to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcAllow {
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub dns: DnsPolicy,
    #[serde(default = "default_true", rename = "deny-private-ranges")]
    pub deny_private_ranges: bool,
    #[serde(default)]
    pub allow: Vec<NetworkDestination>,
    #[serde(default)]
    pub listen: Vec<u16>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsPolicy {
    #[default]
    Deny,
    Restricted,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: NetworkProtocol,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachePermissions {
    #[serde(default)]
    pub read: CacheRead,
    #[serde(default)]
    pub write: CacheWrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheRead {
    #[default]
    Deny,
    Public,
    Verified,
    Branch,
    Run,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheWrite {
    #[default]
    Deny,
    Quarantine,
    Branch,
    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequest {
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub purpose: String,
    pub operation: SigningOperation,
    /// Server-owned signer-policy identity. This is not a provider key
    /// reference and cannot be supplied to a signing backend directly.
    #[serde(
        default,
        rename = "key-policy",
        skip_serializing_if = "String::is_empty"
    )]
    pub key_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningOperation {
    SignDigest,
    SignAttestation,
}
