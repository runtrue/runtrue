use crate::{validation::validate_identifier, DeploymentError, EnvironmentStatus};
use runtrue_artifacts::ArtifactClassification;
use runtrue_model::ContentDigest;
use runtrue_policy::ApprovalRule;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    pub id: String,
    pub version: u64,
    pub tenant_id: String,
    pub repository_id: String,
    pub name: String,
    pub status: EnvironmentStatus,
    pub allowed_refs: BTreeSet<String>,
    pub allowed_trust: BTreeSet<String>,
    pub allowed_artifact_classifications: BTreeSet<ArtifactClassification>,
    pub approval_rule: ApprovalRule,
    pub approval_ttl_ms: u64,
    pub wait_timer_ms: u64,
    pub concurrency_limit: u16,
    pub require_provenance: bool,
}

impl EnvironmentPolicy {
    pub fn validate(&self) -> Result<(), DeploymentError> {
        for (kind, value) in [
            ("environment policy id", self.id.as_str()),
            ("tenant id", self.tenant_id.as_str()),
            ("repository id", self.repository_id.as_str()),
            ("environment name", self.name.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        if self.version == 0
            || self.approval_ttl_ms == 0
            || self.concurrency_limit == 0
            || self.allowed_refs.is_empty()
            || self.allowed_trust.is_empty()
            || self.allowed_artifact_classifications.is_empty()
        {
            return Err(DeploymentError::InvalidEnvironmentPolicy);
        }
        for value in &self.allowed_refs {
            validate_identifier("allowed ref", value)?;
        }
        for value in &self.allowed_trust {
            validate_identifier("allowed trust", value)?;
        }
        self.approval_rule
            .validate()
            .map_err(DeploymentError::Approval)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, DeploymentError> {
        self.validate()?;
        Ok(ContentDigest::sha256(serde_json::to_vec(self)?))
    }
}
