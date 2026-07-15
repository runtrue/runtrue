use crate::{CacheError, CacheLimits};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

/// Platform is a mandatory part of a native cache key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachePlatform {
    pub os: String,
    pub architecture: String,
}

/// Explicit cache trust domain and its complete scope identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustDomain {
    PublicVerified,
    InstallationVerified {
        installation_id: String,
    },
    TenantVerified {
        installation_id: String,
        tenant_id: String,
    },
    RepositoryMainVerified {
        installation_id: String,
        tenant_id: String,
        repository_id: String,
    },
    RepositoryBranchVerified {
        installation_id: String,
        tenant_id: String,
        repository_id: String,
        branch: String,
    },
    PullRequestQuarantine {
        installation_id: String,
        tenant_id: String,
        repository_id: String,
        change_id: String,
    },
    RunPrivate {
        installation_id: String,
        tenant_id: String,
        repository_id: String,
        run_id: String,
    },
}

impl TrustDomain {
    /// Directional read rule. Verified ancestors may flow down into more
    /// restricted repository jobs, but quarantine/branch/run state never flows
    /// upward or sideways implicitly.
    #[must_use]
    pub fn can_read_from(&self, source: &Self) -> bool {
        if self == source || matches!(source, Self::PublicVerified) {
            return true;
        }
        match source {
            Self::PublicVerified => true,
            Self::InstallationVerified { installation_id } => {
                self.installation_id() == Some(installation_id.as_str())
            }
            Self::TenantVerified {
                installation_id,
                tenant_id,
            } => {
                self.installation_id() == Some(installation_id.as_str())
                    && self.tenant_id() == Some(tenant_id.as_str())
            }
            Self::RepositoryMainVerified {
                installation_id,
                tenant_id,
                repository_id,
            } => {
                self.installation_id() == Some(installation_id.as_str())
                    && self.tenant_id() == Some(tenant_id.as_str())
                    && self.repository_id() == Some(repository_id.as_str())
                    && matches!(
                        self,
                        Self::RepositoryMainVerified { .. }
                            | Self::RepositoryBranchVerified { .. }
                            | Self::PullRequestQuarantine { .. }
                            | Self::RunPrivate { .. }
                    )
            }
            Self::RepositoryBranchVerified { .. }
            | Self::PullRequestQuarantine { .. }
            | Self::RunPrivate { .. } => false,
        }
    }

    /// Ordinary writes never change trust scope. Promotion is a separate,
    /// evidence-bearing operation.
    #[must_use]
    pub fn can_write_to(&self, target: &Self) -> bool {
        self == target
    }

    /// Conservative promotion graph. Public sharing remains disabled; a caller
    /// must move through scoped verified domains with evidence at every edge.
    #[must_use]
    pub fn can_promote_to(&self, target: &Self) -> bool {
        match (self, target) {
            (
                Self::RunPrivate {
                    installation_id: source_installation,
                    tenant_id: source_tenant,
                    repository_id: source_repository,
                    ..
                }
                | Self::PullRequestQuarantine {
                    installation_id: source_installation,
                    tenant_id: source_tenant,
                    repository_id: source_repository,
                    ..
                },
                Self::RepositoryBranchVerified {
                    installation_id,
                    tenant_id,
                    repository_id,
                    ..
                }
                | Self::RepositoryMainVerified {
                    installation_id,
                    tenant_id,
                    repository_id,
                },
            ) => {
                source_installation == installation_id
                    && source_tenant == tenant_id
                    && source_repository == repository_id
            }
            (
                Self::RepositoryBranchVerified {
                    installation_id: source_installation,
                    tenant_id: source_tenant,
                    repository_id: source_repository,
                    ..
                },
                Self::RepositoryMainVerified {
                    installation_id,
                    tenant_id,
                    repository_id,
                },
            ) => {
                source_installation == installation_id
                    && source_tenant == tenant_id
                    && source_repository == repository_id
            }
            (
                Self::RepositoryMainVerified {
                    installation_id: source_installation,
                    tenant_id: source_tenant,
                    ..
                },
                Self::TenantVerified {
                    installation_id,
                    tenant_id,
                },
            ) => source_installation == installation_id && source_tenant == tenant_id,
            (
                Self::TenantVerified {
                    installation_id: source_installation,
                    ..
                },
                Self::InstallationVerified { installation_id },
            ) => source_installation == installation_id,
            _ => false,
        }
    }

    fn installation_id(&self) -> Option<&str> {
        match self {
            Self::PublicVerified => None,
            Self::InstallationVerified { installation_id }
            | Self::TenantVerified {
                installation_id, ..
            }
            | Self::RepositoryMainVerified {
                installation_id, ..
            }
            | Self::RepositoryBranchVerified {
                installation_id, ..
            }
            | Self::PullRequestQuarantine {
                installation_id, ..
            }
            | Self::RunPrivate {
                installation_id, ..
            } => Some(installation_id),
        }
    }

    fn tenant_id(&self) -> Option<&str> {
        match self {
            Self::TenantVerified { tenant_id, .. }
            | Self::RepositoryMainVerified { tenant_id, .. }
            | Self::RepositoryBranchVerified { tenant_id, .. }
            | Self::PullRequestQuarantine { tenant_id, .. }
            | Self::RunPrivate { tenant_id, .. } => Some(tenant_id),
            Self::PublicVerified | Self::InstallationVerified { .. } => None,
        }
    }

    fn repository_id(&self) -> Option<&str> {
        match self {
            Self::RepositoryMainVerified { repository_id, .. }
            | Self::RepositoryBranchVerified { repository_id, .. }
            | Self::PullRequestQuarantine { repository_id, .. }
            | Self::RunPrivate { repository_id, .. } => Some(repository_id),
            Self::PublicVerified
            | Self::InstallationVerified { .. }
            | Self::TenantVerified { .. } => None,
        }
    }

    pub(crate) fn validate(&self, limits: CacheLimits) -> Result<(), CacheError> {
        match self {
            Self::PublicVerified => Ok(()),
            Self::InstallationVerified { installation_id } => {
                validate_identifier("installation_id", installation_id, limits)
            }
            Self::TenantVerified {
                installation_id,
                tenant_id,
            } => {
                validate_identifier("installation_id", installation_id, limits)?;
                validate_identifier("tenant_id", tenant_id, limits)
            }
            Self::RepositoryMainVerified {
                installation_id,
                tenant_id,
                repository_id,
            } => validate_repository_scope(installation_id, tenant_id, repository_id, limits),
            Self::RepositoryBranchVerified {
                installation_id,
                tenant_id,
                repository_id,
                branch,
            } => {
                validate_repository_scope(installation_id, tenant_id, repository_id, limits)?;
                validate_identifier("branch", branch, limits)
            }
            Self::PullRequestQuarantine {
                installation_id,
                tenant_id,
                repository_id,
                change_id,
            } => {
                validate_repository_scope(installation_id, tenant_id, repository_id, limits)?;
                validate_identifier("change_id", change_id, limits)
            }
            Self::RunPrivate {
                installation_id,
                tenant_id,
                repository_id,
                run_id,
            } => {
                validate_repository_scope(installation_id, tenant_id, repository_id, limits)?;
                validate_identifier("run_id", run_id, limits)
            }
        }
    }
}

/// Structured native cache key. The opaque suffix cannot remove mandatory
/// scope, platform, definition, input, or policy fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheIdentity {
    pub tenant_id: String,
    pub repository_id: String,
    pub purpose: String,
    pub trust_domain: TrustDomain,
    pub platform: CachePlatform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_or_toolchain: Option<ContentDigest>,
    pub definition: ContentDigest,
    pub declared_inputs: ContentDigest,
    pub policy_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_suffix: Option<String>,
}
impl CacheIdentity {
    pub fn validate(&self, limits: CacheLimits) -> Result<(), CacheError> {
        validate_identifier("tenant_id", &self.tenant_id, limits)?;
        validate_identifier("repository_id", &self.repository_id, limits)?;
        validate_identifier("purpose", &self.purpose, limits)?;
        validate_identifier("platform.os", &self.platform.os, limits)?;
        validate_identifier("platform.architecture", &self.platform.architecture, limits)?;
        if let Some(suffix) = &self.user_suffix {
            validate_identifier("user_suffix", suffix, limits)?;
        }
        self.trust_domain.validate(limits)?;
        if self
            .trust_domain
            .tenant_id()
            .is_some_and(|tenant| tenant != self.tenant_id)
        {
            return Err(CacheError::InvalidIdentity(
                "trust-domain tenant does not match cache identity".to_owned(),
            ));
        }
        if self
            .trust_domain
            .repository_id()
            .is_some_and(|repository| repository != self.repository_id)
        {
            return Err(CacheError::InvalidIdentity(
                "trust-domain repository does not match cache identity".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self, limits: CacheLimits) -> Result<ContentDigest, CacheError> {
        self.validate(limits)?;
        let bytes = serde_json::to_vec(self).map_err(CacheError::SerializeMetadata)?;
        Ok(ContentDigest::sha256(bytes))
    }

    #[must_use]
    pub fn with_trust_domain(&self, trust_domain: TrustDomain) -> Self {
        let mut identity = self.clone();
        identity.trust_domain = trust_domain;
        identity
    }

    pub(crate) fn same_content_key_except_trust(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.repository_id == other.repository_id
            && self.purpose == other.purpose
            && self.platform == other.platform
            && self.compiler_or_toolchain == other.compiler_or_toolchain
            && self.definition == other.definition
            && self.declared_inputs == other.declared_inputs
            && self.policy_epoch == other.policy_epoch
            && self.user_suffix == other.user_suffix
    }
}

pub(crate) fn validate_repository_scope(
    installation_id: &str,
    tenant_id: &str,
    repository_id: &str,
    limits: CacheLimits,
) -> Result<(), CacheError> {
    validate_identifier("installation_id", installation_id, limits)?;
    validate_identifier("tenant_id", tenant_id, limits)?;
    validate_identifier("repository_id", repository_id, limits)
}

pub(crate) fn validate_identifier(
    field: &'static str,
    value: &str,
    limits: CacheLimits,
) -> Result<(), CacheError> {
    if value.is_empty()
        || value.len() > limits.max_identifier_bytes
        || value.chars().any(char::is_control)
    {
        return Err(CacheError::InvalidIdentity(format!(
            "{field} must be non-empty, bounded UTF-8 without control characters"
        )));
    }
    Ok(())
}
