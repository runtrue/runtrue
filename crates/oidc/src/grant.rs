use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{validation::validate_identifier, OidcError, MAX_AUDIENCES};

/// Immutable grant produced after workflow/policy/lease authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcGrant {
    pub grant_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub step_id: String,
    pub capsule_digest: ContentDigest,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub trust: String,
    /// Actual durable runner pool, derived by the control plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_pool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    pub source_commit: String,
    /// Exact approval subject consumed before this workload grant was derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_subject_digest: Option<ContentDigest>,
    /// Server-derived posture bound to enrollment inventory and durable pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_posture_digest: Option<ContentDigest>,
    pub allowed_audiences: BTreeSet<String>,
    pub expires_unix_seconds: u64,
}

impl OidcGrant {
    pub fn validate(&self) -> Result<(), OidcError> {
        for (kind, value) in [
            ("grant id", self.grant_id.as_str()),
            ("tenant id", self.tenant_id.as_str()),
            ("repository id", self.repository_id.as_str()),
            ("run id", self.run_id.as_str()),
            ("job id", self.job_id.as_str()),
            ("step id", self.step_id.as_str()),
            ("execution lease id", self.execution_lease_id.as_str()),
            ("trust", self.trust.as_str()),
            ("source commit", self.source_commit.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        if self.fencing_generation == 0 {
            return Err(OidcError::InvalidFencingGeneration);
        }
        if let Some(environment) = &self.environment {
            validate_identifier("environment", environment)?;
        }
        if let Some(pool_id) = &self.runner_pool_id {
            validate_identifier("runner pool id", pool_id)?;
        }
        if let Some(ref_name) = &self.ref_name {
            validate_identifier("ref name", ref_name)?;
        }
        if self.allowed_audiences.is_empty() || self.allowed_audiences.len() > MAX_AUDIENCES {
            return Err(OidcError::InvalidAudiences);
        }
        for audience in &self.allowed_audiences {
            validate_identifier("OIDC audience", audience)?;
        }
        Ok(())
    }
}
