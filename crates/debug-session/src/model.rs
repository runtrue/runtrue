use crate::{
    canonical_digest, validate_identifier, DebugSessionError, EphemeralClientIdentity,
    OneUseTunnelToken, TunnelDirection, TunnelTokenDigest, MAX_DURATION_MS,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const SESSION_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    NonProduction,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadTrust {
    PublicUntrusted,
    InternalUntrusted,
    Trusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    NeverReleased,
    Released,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptMode {
    Disabled,
    MetadataOnly,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionGate {
    FreshTrustedRebuildOrPolicyException,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub capsule_digest: ContentDigest,
    pub actor_id: String,
    pub environment: EnvironmentClass,
    pub workload_trust: WorkloadTrust,
    pub secret_state: SecretState,
    pub retain_existing_secrets: bool,
    pub requested_duration_ms: u64,
    pub reason: String,
    pub requested_unix_ms: u64,
}

impl DebugSessionRequest {
    pub fn approval_subject(&self) -> Result<DebugApprovalSubject, DebugSessionError> {
        Ok(DebugApprovalSubject {
            tenant_id: self.tenant_id.clone(),
            repository_id: self.repository_id.clone(),
            run_id: self.run_id.clone(),
            job_id: self.job_id.clone(),
            execution_lease_id: self.execution_lease_id.clone(),
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            capsule_digest: self.capsule_digest.clone(),
            actor_id: self.actor_id.clone(),
            environment: self.environment,
            workload_trust: self.workload_trust,
            secret_state: self.secret_state,
            retain_existing_secrets: self.retain_existing_secrets,
            requested_duration_ms: self.requested_duration_ms,
            reason_digest: ContentDigest::sha256(self.reason.as_bytes()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugApprovalSubject {
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub capsule_digest: ContentDigest,
    pub actor_id: String,
    pub environment: EnvironmentClass,
    pub workload_trust: WorkloadTrust,
    pub secret_state: SecretState,
    pub retain_existing_secrets: bool,
    pub requested_duration_ms: u64,
    pub reason_digest: ContentDigest,
}

impl DebugApprovalSubject {
    pub fn digest(&self) -> Result<ContentDigest, DebugSessionError> {
        canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugApproval {
    pub approval_id: String,
    pub subject_digest: ContentDigest,
    pub approver_id: String,
    pub allow_production: bool,
    pub allow_public_untrusted: bool,
    pub allow_secret_retention: bool,
    pub approved_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugSessionState {
    Active,
    Connected,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionRecord {
    pub version: u32,
    pub session_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub job_id: String,
    pub execution_lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub capsule_digest: ContentDigest,
    pub actor_id: String,
    pub approver_id: String,
    pub approval_id: String,
    pub approval_subject: DebugApprovalSubject,
    pub approval_subject_digest: ContentDigest,
    pub reason_digest: ContentDigest,
    pub state: DebugSessionState,
    pub tunnel_token_digest: TunnelTokenDigest,
    pub token_used: bool,
    pub certificate_serial: String,
    pub tunnel_direction: TunnelDirection,
    pub public_runner_listener: bool,
    pub relay_registration_digest: ContentDigest,
    pub future_secret_block_receipt: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_secret_revocation_receipt: Option<ContentDigest>,
    pub retained_existing_secrets: bool,
    pub transcript_mode: TranscriptMode,
    pub promotion_gate: PromotionGate,
    pub created_unix_ms: u64,
    pub expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_unix_ms: Option<u64>,
    pub terminal_audit_recorded: bool,
}

impl DebugSessionRecord {
    #[must_use]
    pub const fn permits_direct_artifact_promotion(&self) -> bool {
        false
    }

    pub fn verify_integrity(&self) -> Result<(), DebugSessionError> {
        let subject_digest = self.approval_subject.digest()?;
        if self.version != SESSION_VERSION
            || self.fencing_generation == 0
            || self.installation_fencing_epoch == 0
            || self.expires_unix_ms <= self.created_unix_ms
            || self.expires_unix_ms - self.created_unix_ms > MAX_DURATION_MS
            || self.tunnel_direction != TunnelDirection::ReverseOnly
            || self.public_runner_listener
            || self.connected_unix_ms.is_some() != self.token_used
            || (self.state == DebugSessionState::Active && self.token_used)
            || (self.state == DebugSessionState::Connected && !self.token_used)
            || (matches!(
                self.state,
                DebugSessionState::Revoked | DebugSessionState::Expired
            ) != self.revoked_unix_ms.is_some())
            || (!matches!(
                self.state,
                DebugSessionState::Revoked | DebugSessionState::Expired
            ) && self.terminal_audit_recorded)
            || subject_digest != self.approval_subject_digest
            || self.approval_subject.tenant_id != self.tenant_id
            || self.approval_subject.repository_id != self.repository_id
            || self.approval_subject.run_id != self.run_id
            || self.approval_subject.job_id != self.job_id
            || self.approval_subject.execution_lease_id != self.execution_lease_id
            || self.approval_subject.fencing_generation != self.fencing_generation
            || self.approval_subject.installation_fencing_epoch != self.installation_fencing_epoch
            || self.approval_subject.capsule_digest != self.capsule_digest
            || self.approval_subject.actor_id != self.actor_id
            || self.approval_subject.reason_digest != self.reason_digest
            || self.approval_subject.retain_existing_secrets != self.retained_existing_secrets
            || self.approval_subject.requested_duration_ms
                != self.expires_unix_ms - self.created_unix_ms
        {
            return Err(DebugSessionError::Integrity);
        }
        for identifier in [
            &self.session_id,
            &self.tenant_id,
            &self.repository_id,
            &self.run_id,
            &self.job_id,
            &self.execution_lease_id,
            &self.actor_id,
            &self.approver_id,
            &self.approval_id,
            &self.certificate_serial,
        ] {
            validate_identifier(identifier)?;
        }
        Ok(())
    }
}

pub struct IssuedDebugSession {
    pub record: DebugSessionRecord,
    pub tunnel_token: OneUseTunnelToken,
    pub client_identity: EphemeralClientIdentity,
}

impl fmt::Debug for IssuedDebugSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedDebugSession")
            .field("record", &self.record)
            .field("tunnel_token", &"[REDACTED]")
            .field("client_identity", &"[REDACTED]")
            .finish()
    }
}
