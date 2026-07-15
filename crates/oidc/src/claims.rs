use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::OidcGrant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "iat")]
    pub issued_unix_seconds: u64,
    #[serde(rename = "nbf")]
    pub not_before_unix_seconds: u64,
    #[serde(rename = "exp")]
    pub expires_unix_seconds: u64,
    pub jti: String,
    pub runtrue_tenant_id: String,
    pub runtrue_repository_id: String,
    pub runtrue_run_id: String,
    pub runtrue_job_id: String,
    pub runtrue_step_id: String,
    pub runtrue_capsule_digest: ContentDigest,
    pub runtrue_execution_lease_id: String,
    pub runtrue_fencing_generation: u64,
    pub runtrue_trust: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtrue_environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtrue_ref: Option<String>,
    pub runtrue_source_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtrue_approval_subject_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtrue_runner_posture_digest: Option<ContentDigest>,
    pub runtrue_grant_id: String,
}

impl JwtClaims {
    pub(crate) fn from_grant(
        issuer: &str,
        grant: &OidcGrant,
        audience: String,
        issued_unix_seconds: u64,
        expires_unix_seconds: u64,
        jti: String,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            subject: format!(
                "repo:{}:run:{}:job:{}:step:{}",
                grant.repository_id, grant.run_id, grant.job_id, grant.step_id
            ),
            audience,
            issued_unix_seconds,
            not_before_unix_seconds: issued_unix_seconds,
            expires_unix_seconds,
            jti,
            runtrue_tenant_id: grant.tenant_id.clone(),
            runtrue_repository_id: grant.repository_id.clone(),
            runtrue_run_id: grant.run_id.clone(),
            runtrue_job_id: grant.job_id.clone(),
            runtrue_step_id: grant.step_id.clone(),
            runtrue_capsule_digest: grant.capsule_digest.clone(),
            runtrue_execution_lease_id: grant.execution_lease_id.clone(),
            runtrue_fencing_generation: grant.fencing_generation,
            runtrue_trust: grant.trust.clone(),
            runtrue_environment: grant.environment.clone(),
            runtrue_ref: grant.ref_name.clone(),
            runtrue_source_commit: grant.source_commit.clone(),
            runtrue_approval_subject_digest: grant.approval_subject_digest.clone(),
            runtrue_runner_posture_digest: grant.runner_posture_digest.clone(),
            runtrue_grant_id: grant.grant_id.clone(),
        }
    }
}
