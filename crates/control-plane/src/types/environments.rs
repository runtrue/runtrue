use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentProtectionRules {
    pub require_approval: bool,
    pub minimum_approvals: u32,
    pub approval_ttl_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_rule_digest: Option<ContentDigest>,
    pub require_signed_artifact: bool,
    pub required_artifact_classification: String,
    pub require_passed_scan: bool,
    pub require_promotion_evidence: bool,
    pub allowed_deployment_actors: Vec<String>,
    pub allowed_signing_purposes: Vec<String>,
    pub allowed_signer_policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRecord {
    pub id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub name: String,
    pub deployment_target_reference: String,
    pub deployment_target_digest: ContentDigest,
    pub status: String,
    pub protection_rules: EnvironmentProtectionRules,
    pub protection_rules_digest: ContentDigest,
    pub wait_timer_ms: u64,
    pub concurrency_limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_provider_configuration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_provider_configuration_id: Option<String>,
    pub required_policy_epoch: u64,
    pub last_concurrency_fence: u64,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub version: u64,
}

impl EnvironmentRecord {
    pub fn expected_protection_rules_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        let mut bytes = b"runtrue.environment-protection-rules.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&self.protection_rules)?);
        Ok(ContentDigest::sha256(bytes))
    }

    #[must_use]
    pub fn expected_deployment_target_digest(&self) -> ContentDigest {
        let mut bytes = b"runtrue.environment-deployment-target.v1\0".to_vec();
        bytes.extend_from_slice(self.deployment_target_reference.as_bytes());
        ContentDigest::sha256(bytes)
    }
}
