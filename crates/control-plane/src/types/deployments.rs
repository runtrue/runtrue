use runtrue_model::ContentDigest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentRequestStatus {
    WaitingTimer,
    AwaitingApproval,
    AwaitingConcurrency,
    Ready,
    Leased,
    InProgress,
    Succeeded,
    Failed,
    Canceled,
}

impl DeploymentRequestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingTimer => "waiting-timer",
            Self::AwaitingApproval => "awaiting-approval",
            Self::AwaitingConcurrency => "awaiting-concurrency",
            Self::Ready => "ready",
            Self::Leased => "leased",
            Self::InProgress => "in-progress",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRequestRecord {
    pub id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub environment_version: u64,
    pub policy_epoch: u64,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub job_attempt: u32,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_artifact_id: Option<String>,
    pub artifact_source_run_id: String,
    pub artifact_source_job_id: String,
    pub artifact_source_job_attempt: u32,
    pub artifact_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub deployment_capsule_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub approval_subject_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of_deployment_id: Option<String>,
    pub status: DeploymentRequestStatus,
    pub wait_until_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_fence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_fencing_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_fencing_epoch: Option<u64>,
    pub actor_id: String,
    pub audit_correlation_id: String,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
    pub version: u64,
}

impl DeploymentRequestRecord {
    pub fn expected_request_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            id: &'a str,
            tenant_id: &'a str,
            environment_id: &'a str,
            environment_version: u64,
            policy_epoch: u64,
            repository_id: &'a str,
            run_id: &'a str,
            job_id: &'a str,
            job_attempt: u32,
            artifact_id: &'a str,
            promoted_artifact_id: &'a Option<String>,
            artifact_source_run_id: &'a str,
            artifact_source_job_id: &'a str,
            artifact_source_job_attempt: u32,
            artifact_digest: &'a ContentDigest,
            manifest_digest: &'a ContentDigest,
            provenance_digest: &'a ContentDigest,
            target_digest: &'a ContentDigest,
            deployment_capsule_digest: &'a ContentDigest,
            approval_request_id: &'a Option<String>,
            rollback_of_deployment_id: &'a Option<String>,
        }
        let material = Material {
            id: &self.id,
            tenant_id: &self.tenant_id,
            environment_id: &self.environment_id,
            environment_version: self.environment_version,
            policy_epoch: self.policy_epoch,
            repository_id: &self.repository_id,
            run_id: &self.run_id,
            job_id: &self.job_id,
            job_attempt: self.job_attempt,
            artifact_id: &self.artifact_id,
            promoted_artifact_id: &self.promoted_artifact_id,
            artifact_source_run_id: &self.artifact_source_run_id,
            artifact_source_job_id: &self.artifact_source_job_id,
            artifact_source_job_attempt: self.artifact_source_job_attempt,
            artifact_digest: &self.artifact_digest,
            manifest_digest: &self.manifest_digest,
            provenance_digest: &self.provenance_digest,
            target_digest: &self.target_digest,
            deployment_capsule_digest: &self.deployment_capsule_digest,
            approval_request_id: &self.approval_request_id,
            rollback_of_deployment_id: &self.rollback_of_deployment_id,
        };
        let mut bytes = b"runtrue.deployment-request.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }

    pub fn expected_approval_subject_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Subject<'a> {
            tenant_id: &'a str,
            environment_id: &'a str,
            environment_version: u64,
            policy_epoch: u64,
            repository_id: &'a str,
            run_id: &'a str,
            job_id: &'a str,
            job_attempt: u32,
            deployment_capsule_digest: &'a ContentDigest,
            artifact_source_run_id: &'a str,
            promoted_artifact_id: &'a Option<String>,
            artifact_source_job_id: &'a str,
            artifact_source_job_attempt: u32,
            artifact_digest: &'a ContentDigest,
            manifest_digest: &'a ContentDigest,
            provenance_digest: &'a ContentDigest,
            target_digest: &'a ContentDigest,
            rollback_of_deployment_id: &'a Option<String>,
        }
        let subject = Subject {
            tenant_id: &self.tenant_id,
            environment_id: &self.environment_id,
            environment_version: self.environment_version,
            policy_epoch: self.policy_epoch,
            repository_id: &self.repository_id,
            run_id: &self.run_id,
            job_id: &self.job_id,
            job_attempt: self.job_attempt,
            deployment_capsule_digest: &self.deployment_capsule_digest,
            artifact_source_run_id: &self.artifact_source_run_id,
            promoted_artifact_id: &self.promoted_artifact_id,
            artifact_source_job_id: &self.artifact_source_job_id,
            artifact_source_job_attempt: self.artifact_source_job_attempt,
            artifact_digest: &self.artifact_digest,
            manifest_digest: &self.manifest_digest,
            provenance_digest: &self.provenance_digest,
            target_digest: &self.target_digest,
            rollback_of_deployment_id: &self.rollback_of_deployment_id,
        };
        let mut bytes = b"runtrue.environment-deployment-approval.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&subject)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireEnvironmentGate {
    pub tenant_id: String,
    pub deployment_request_id: String,
    pub installation_fencing_epoch: u64,
    pub gate_lease_id: String,
    pub gate_expires_unix_ms: u64,
    pub actor_id: String,
    pub audit_correlation_id: String,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConcurrencyLeaseRecord {
    pub id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub deployment_request_id: String,
    pub concurrency_fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_fencing_generation: Option<u64>,
    pub installation_fencing_epoch: u64,
    pub state: String,
    pub acquired_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDeploymentLease {
    pub tenant_id: String,
    pub deployment_request_id: String,
    pub execution_lease_id: String,
    pub lease_fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRecord {
    pub id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub deployment_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of_deployment_id: Option<String>,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_artifact_id: Option<String>,
    pub artifact_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub deployment_capsule_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_result_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,
    pub status: String,
    pub result_digest: ContentDigest,
    pub metadata: Value,
    pub metadata_digest: ContentDigest,
    pub started_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_unix_ms: Option<u64>,
}

impl DeploymentRecord {
    pub fn expected_metadata_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        let mut bytes = b"runtrue.deployment-metadata.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&self.metadata)?);
        Ok(ContentDigest::sha256(bytes))
    }

    pub fn expected_result_digest(&self) -> Result<ContentDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct Material<'a> {
            id: &'a str,
            tenant_id: &'a str,
            environment_id: &'a str,
            deployment_request_id: &'a str,
            rollback_of_deployment_id: &'a Option<String>,
            artifact_id: &'a str,
            promoted_artifact_id: &'a Option<String>,
            artifact_digest: &'a ContentDigest,
            manifest_digest: &'a ContentDigest,
            provenance_digest: &'a ContentDigest,
            target_digest: &'a ContentDigest,
            deployment_capsule_digest: &'a ContentDigest,
            signing_request_id: &'a Option<String>,
            signing_result_digest: &'a Option<ContentDigest>,
            signer_key_id: &'a Option<String>,
            signing_algorithm: &'a Option<String>,
            signature_digest: &'a Option<ContentDigest>,
            certificate_digest: &'a Option<ContentDigest>,
            attestation_digest: &'a Option<ContentDigest>,
            external_reference: &'a Option<String>,
            status: &'a str,
            metadata_digest: &'a ContentDigest,
            started_unix_ms: u64,
            completed_unix_ms: &'a Option<u64>,
        }
        let material = Material {
            id: &self.id,
            tenant_id: &self.tenant_id,
            environment_id: &self.environment_id,
            deployment_request_id: &self.deployment_request_id,
            rollback_of_deployment_id: &self.rollback_of_deployment_id,
            artifact_id: &self.artifact_id,
            promoted_artifact_id: &self.promoted_artifact_id,
            artifact_digest: &self.artifact_digest,
            manifest_digest: &self.manifest_digest,
            provenance_digest: &self.provenance_digest,
            target_digest: &self.target_digest,
            deployment_capsule_digest: &self.deployment_capsule_digest,
            signing_request_id: &self.signing_request_id,
            signing_result_digest: &self.signing_result_digest,
            signer_key_id: &self.signer_key_id,
            signing_algorithm: &self.signing_algorithm,
            signature_digest: &self.signature_digest,
            certificate_digest: &self.certificate_digest,
            attestation_digest: &self.attestation_digest,
            external_reference: &self.external_reference,
            status: &self.status,
            metadata_digest: &self.metadata_digest,
            started_unix_ms: self.started_unix_ms,
            completed_unix_ms: &self.completed_unix_ms,
        };
        let mut bytes = b"runtrue.deployment-result.v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(&material)?);
        Ok(ContentDigest::sha256(bytes))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMetrics {
    pub requests: u64,
    pub requests_ready: u64,
    pub active_concurrency_leases: u64,
    pub deployments_succeeded: u64,
    pub deployments_failed: u64,
    pub secret_releases_pending_revoke: u64,
    pub signing_results_replayed: u64,
}
