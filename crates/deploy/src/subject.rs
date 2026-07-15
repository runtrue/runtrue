use crate::{validation::validate_identifier, DeploymentError, EnvironmentPolicy};
use runtrue_artifacts::ArtifactClassification;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

pub(crate) const DEPLOYMENT_SUBJECT_VERSION: u32 = 1;

/// Immutable inputs whose digest is the deployment approval subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSubject {
    pub subject_version: u32,
    pub tenant_id: String,
    pub repository_id: String,
    pub environment_id: String,
    pub environment_policy_digest: ContentDigest,
    pub run_id: String,
    pub job_id: String,
    pub capsule_digest: ContentDigest,
    pub source_commit: String,
    pub ref_name: String,
    pub trust: String,
    pub artifact_id: ContentDigest,
    pub artifact_content_digest: ContentDigest,
    pub artifact_classification: ArtifactClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_statement_digest: Option<ContentDigest>,
    pub deployment_target_digest: ContentDigest,
    pub policy_version_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of: Option<String>,
}

impl DeploymentSubject {
    pub fn validate(&self, environment: &EnvironmentPolicy) -> Result<(), DeploymentError> {
        if self.subject_version != DEPLOYMENT_SUBJECT_VERSION {
            return Err(DeploymentError::InvalidSubjectVersion);
        }
        for (kind, value) in [
            ("subject tenant id", self.tenant_id.as_str()),
            ("subject repository id", self.repository_id.as_str()),
            ("subject environment id", self.environment_id.as_str()),
            ("subject run id", self.run_id.as_str()),
            ("subject job id", self.job_id.as_str()),
            ("subject source commit", self.source_commit.as_str()),
            ("subject ref", self.ref_name.as_str()),
            ("subject trust", self.trust.as_str()),
        ] {
            validate_identifier(kind, value)?;
        }
        if let Some(rollback_of) = &self.rollback_of {
            validate_identifier("rollback source deployment", rollback_of)?;
        }
        if self.policy_version_ids.is_empty() {
            return Err(DeploymentError::InvalidSubject(
                "at least one policy version is required",
            ));
        }
        let mut sorted_policies = self.policy_version_ids.clone();
        for policy in &sorted_policies {
            validate_identifier("policy version", policy)?;
        }
        sorted_policies.sort();
        sorted_policies.dedup();
        if sorted_policies != self.policy_version_ids {
            return Err(DeploymentError::InvalidSubject(
                "policy versions must be sorted and unique",
            ));
        }
        if self.tenant_id != environment.tenant_id
            || self.repository_id != environment.repository_id
            || self.environment_id != environment.id
            || self.environment_policy_digest != environment.digest()?
        {
            return Err(DeploymentError::EnvironmentSubjectMismatch);
        }
        if !environment.allowed_refs.contains(&self.ref_name) {
            return Err(DeploymentError::RefDenied(self.ref_name.clone()));
        }
        if !environment.allowed_trust.contains(&self.trust) {
            return Err(DeploymentError::TrustDenied(self.trust.clone()));
        }
        if !environment
            .allowed_artifact_classifications
            .contains(&self.artifact_classification)
        {
            return Err(DeploymentError::ArtifactClassificationDenied(
                self.artifact_classification,
            ));
        }
        if environment.require_provenance && self.provenance_statement_digest.is_none() {
            return Err(DeploymentError::ProvenanceRequired);
        }
        Ok(())
    }

    pub fn digest(
        &self,
        environment: &EnvironmentPolicy,
    ) -> Result<ContentDigest, DeploymentError> {
        self.validate(environment)?;
        Ok(ContentDigest::sha256(serde_json::to_vec(self)?))
    }
}
