use crate::{
    canonical::{validate_collection_size, validate_identifier},
    ContractGenerationRange, DeployedProviderGeneration, EvidencePage, EvidenceRangeRequest,
    FailureResolution, FeatureRequirement, ProviderContractError, ProviderDescriptor,
    RuntimeInventoryEntry,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotentMutation {
    pub tenant_id: String,
    pub principal_digest: ContentDigest,
    pub idempotency_key: String,
}

impl IdempotentMutation {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("operation tenant id", &self.tenant_id)?;
        validate_identifier("operation idempotency key", &self.idempotency_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequest {
    pub mutation: IdempotentMutation,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub program_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub required_profiles: Vec<FeatureRequirement>,
    /// Empty means the policy did not restrict the eligible Provider identity.
    pub allowed_provider_identity_digests: BTreeSet<ContentDigest>,
}

impl AdmissionRequest {
    pub fn validate_against(
        &self,
        descriptor: &ProviderDescriptor,
    ) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        validate_collection_size(self.allowed_provider_identity_digests.len())?;
        descriptor.require_profiles(&self.required_profiles)?;
        let identity = descriptor.deployed_generation.provider.digest()?;
        if !self.allowed_provider_identity_digests.is_empty()
            && !self.allowed_provider_identity_digests.contains(&identity)
        {
            return Err(ProviderContractError::InvalidOperation(
                "deployed Provider identity is not allowed by the Seal",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub admission_id: String,
    pub tenant_id: String,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub deployed_provider_generation_digest: ContentDigest,
    pub accepted_profiles: BTreeSet<crate::FeatureProfileId>,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl AdmissionReceipt {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("admission id", &self.admission_id)?;
        validate_identifier("admission tenant id", &self.tenant_id)?;
        validate_collection_size(self.accepted_profiles.len())?;
        for profile in &self.accepted_profiles {
            profile.validate()?;
        }
        if self.expires_unix_ms <= self.issued_unix_ms {
            return Err(ProviderContractError::InvalidOperation(
                "admission receipt does not have a positive lifetime",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExecutionRequest {
    pub mutation: IdempotentMutation,
    pub admission_id: String,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
}

impl CreateExecutionRequest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        validate_identifier("admission id", &self.admission_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Proposed,
    Admitted,
    Queued,
    Leased,
    Running,
    Finalizing,
    Terminal,
}

impl ExecutionState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSnapshot {
    pub execution_id: String,
    pub tenant_id: String,
    pub state: ExecutionState,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub program_digest: ContentDigest,
    pub deployed_provider: DeployedProviderGeneration,
    pub lease_id: Option<String>,
    pub fence_generation: Option<u64>,
    pub terminal_outcome: Option<TerminalOutcome>,
    pub failure: Option<FailureResolution>,
    pub evidence_sequence: u64,
    pub evidence_event_digest: ContentDigest,
}

impl ExecutionSnapshot {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Execution id", &self.execution_id)?;
        validate_identifier("Execution tenant id", &self.tenant_id)?;
        self.deployed_provider.validate()?;
        if let Some(lease_id) = &self.lease_id {
            validate_identifier("Execution lease id", lease_id)?;
        }
        if self.lease_id.is_some() != self.fence_generation.is_some()
            || self.fence_generation == Some(0)
            || self.evidence_sequence == 0
            || self.state.is_terminal() != self.terminal_outcome.is_some()
            || (self.terminal_outcome == Some(TerminalOutcome::Failed)) != self.failure.is_some()
        {
            return Err(ProviderContractError::InvalidOperation(
                "Execution state, lease, failure, or Evidence fields disagree",
            ));
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelExecutionRequest {
    pub mutation: IdempotentMutation,
    pub execution_id: String,
    pub expected_evidence_event_digest: ContentDigest,
    pub reason_digest: ContentDigest,
}

impl CancelExecutionRequest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        validate_identifier("Execution id", &self.execution_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Proposed,
    Admitted,
    Provisioning,
    Active,
    Suspending,
    Suspended,
    Restoring,
    Destroying,
    Terminal,
}

impl SessionState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub mutation: IdempotentMutation,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub sterile_template_digest: ContentDigest,
    pub required_profiles: Vec<FeatureRequirement>,
}

impl CreateSessionRequest {
    pub fn validate_against(
        &self,
        descriptor: &ProviderDescriptor,
    ) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        descriptor.require_profiles(&self.required_profiles)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOperationRequest {
    pub mutation: IdempotentMutation,
    pub session_id: String,
    pub operation_id: String,
    pub operation_digest: ContentDigest,
    pub expected_checkpoint_digest: Option<ContentDigest>,
}

macro_rules! subject_mutation_request {
    ($name:ident, $kind:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub mutation: IdempotentMutation,
            pub subject_id: String,
            pub expected_evidence_event_digest: ContentDigest,
            pub parameters_digest: ContentDigest,
        }

        impl $name {
            pub fn validate(&self) -> Result<(), ProviderContractError> {
                self.mutation.validate()?;
                validate_identifier($kind, &self.subject_id)
            }
        }
    };
}

subject_mutation_request!(RenewSessionRequest, "Session id");
subject_mutation_request!(SuspendSessionRequest, "Session id");
subject_mutation_request!(RestoreSessionRequest, "Session id");
subject_mutation_request!(DestroySessionRequest, "Session id");
subject_mutation_request!(CreateChildExecutionRequest, "parent Session id");
subject_mutation_request!(CreateCheckpointRequest, "checkpoint subject id");
subject_mutation_request!(RevokeSealRequest, "Seal id");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceipt {
    pub checkpoint_id: String,
    pub checkpoint_manifest_digest: ContentDigest,
    pub evidence_event_digest: ContentDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishedObjectKind {
    Program,
    Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishObjectRequest {
    pub mutation: IdempotentMutation,
    pub kind: PublishedObjectKind,
    pub object_digest: ContentDigest,
    pub metadata_digest: ContentDigest,
    pub size_bytes: u64,
}

impl PublishObjectRequest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        if self.size_bytes == 0 {
            return Err(ProviderContractError::InvalidOperation(
                "published object size must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedObjectReceipt {
    pub kind: PublishedObjectKind,
    pub object_digest: ContentDigest,
    pub metadata_digest: ContentDigest,
    pub evidence_event_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportRequest {
    pub mutation: IdempotentMutation,
    pub range: EvidenceRangeRequest,
    pub export_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportReceipt {
    pub export_digest: ContentDigest,
    pub evidence_checkpoint_digest: ContentDigest,
    pub event_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleConstructionRequest {
    pub mutation: IdempotentMutation,
    pub program_digest: ContentDigest,
    pub normalized_inputs_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub constraints_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleConstructionReceipt {
    pub capsule_digest: ContentDigest,
    pub canonical_manifest_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubjectRequest {
    pub mutation: IdempotentMutation,
    pub capsule_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub provider_constraints_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSubjectReceipt {
    pub approval_subject_digest: ContentDigest,
    pub canonical_bytes_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionRequest {
    pub mutation: IdempotentMutation,
    pub action: String,
    pub resource_identity_digest: ContentDigest,
    pub approval_subject_digest: ContentDigest,
    pub context_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionRecord {
    pub decision_id: String,
    pub allowed: bool,
    pub policy_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub evidence_event_digest: ContentDigest,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealRecord {
    pub seal_id: String,
    pub seal_digest: ContentDigest,
    pub approval_subject_digest: ContentDigest,
    pub signer_identity_digest: ContentDigest,
    pub revoked: bool,
    pub expires_unix_ms: u64,
}

impl SessionOperationRequest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        self.mutation.validate()?;
        validate_identifier("Session id", &self.session_id)?;
        validate_identifier("Session operation id", &self.operation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub tenant_id: String,
    pub state: SessionState,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub deployed_provider: DeployedProviderGeneration,
    pub checkpoint_digest: Option<ContentDigest>,
    pub terminal_outcome: Option<TerminalOutcome>,
    pub failure: Option<FailureResolution>,
    pub evidence_sequence: u64,
    pub evidence_event_digest: ContentDigest,
}

impl SessionSnapshot {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_identifier("Session id", &self.session_id)?;
        validate_identifier("Session tenant id", &self.tenant_id)?;
        self.deployed_provider.validate()?;
        if self.evidence_sequence == 0
            || self.state.is_terminal() != self.terminal_outcome.is_some()
            || (self.terminal_outcome == Some(TerminalOutcome::Failed)) != self.failure.is_some()
        {
            return Err(ProviderContractError::InvalidOperation(
                "Session state, failure, or Evidence fields disagree",
            ));
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        Ok(())
    }
}

pub trait ProviderMetadataOperations {
    type Error;

    fn supported_contract_generations(&self) -> Result<ContractGenerationRange, Self::Error>;
    fn descriptor(&self) -> Result<ProviderDescriptor, Self::Error>;
    fn runtime_inventory(&self) -> Result<Vec<RuntimeInventoryEntry>, Self::Error>;
}

pub trait ExecutionOperations {
    type Error;

    fn admit_execution(&self, request: &AdmissionRequest) -> Result<AdmissionReceipt, Self::Error>;
    fn create_execution(
        &self,
        request: &CreateExecutionRequest,
    ) -> Result<ExecutionSnapshot, Self::Error>;
    fn inspect_execution(&self, execution_id: &str) -> Result<ExecutionSnapshot, Self::Error>;
    fn cancel_execution(
        &self,
        request: &CancelExecutionRequest,
    ) -> Result<ExecutionSnapshot, Self::Error>;
}

pub trait SessionOperations {
    type Error;

    fn create_session(
        &self,
        request: &CreateSessionRequest,
    ) -> Result<SessionSnapshot, Self::Error>;
    fn inspect_session(&self, session_id: &str) -> Result<SessionSnapshot, Self::Error>;
    fn apply_session_operation(
        &self,
        request: &SessionOperationRequest,
    ) -> Result<SessionSnapshot, Self::Error>;
    fn renew_session(&self, request: &RenewSessionRequest) -> Result<SessionSnapshot, Self::Error>;
    fn suspend_session(
        &self,
        request: &SuspendSessionRequest,
    ) -> Result<SessionSnapshot, Self::Error>;
    fn restore_session(
        &self,
        request: &RestoreSessionRequest,
    ) -> Result<SessionSnapshot, Self::Error>;
    fn destroy_session(
        &self,
        request: &DestroySessionRequest,
    ) -> Result<SessionSnapshot, Self::Error>;
    fn create_child_execution(
        &self,
        request: &CreateChildExecutionRequest,
    ) -> Result<ExecutionSnapshot, Self::Error>;
}

pub trait ProviderEvidenceOperations {
    type Error;

    fn evidence(&self, request: &EvidenceRangeRequest) -> Result<EvidencePage, Self::Error>;
    fn stream_evidence(&self, request: &EvidenceRangeRequest) -> Result<EvidencePage, Self::Error>;
    fn export_evidence(
        &self,
        request: &EvidenceExportRequest,
    ) -> Result<EvidenceExportReceipt, Self::Error>;
}

pub trait CheckpointOperations {
    type Error;

    fn create_checkpoint(
        &self,
        request: &CreateCheckpointRequest,
    ) -> Result<CheckpointReceipt, Self::Error>;
    fn retrieve_checkpoint(&self, checkpoint_id: &str) -> Result<CheckpointReceipt, Self::Error>;
}

pub trait PortableObjectOperations {
    type Error;

    fn publish_program(
        &self,
        request: &PublishObjectRequest,
    ) -> Result<PublishedObjectReceipt, Self::Error>;
    fn retrieve_program(
        &self,
        digest: &ContentDigest,
    ) -> Result<PublishedObjectReceipt, Self::Error>;
    fn publish_artifact(
        &self,
        request: &PublishObjectRequest,
    ) -> Result<PublishedObjectReceipt, Self::Error>;
    fn retrieve_artifact(
        &self,
        digest: &ContentDigest,
    ) -> Result<PublishedObjectReceipt, Self::Error>;
}

pub trait TrustBoundaryOperations {
    type Error;

    fn construct_capsule(
        &self,
        request: &CapsuleConstructionRequest,
    ) -> Result<CapsuleConstructionReceipt, Self::Error>;
    fn construct_approval_subject(
        &self,
        request: &ApprovalSubjectRequest,
    ) -> Result<ApprovalSubjectReceipt, Self::Error>;
    fn verify_approval_subject(
        &self,
        request: &ApprovalSubjectRequest,
        expected: &ApprovalSubjectReceipt,
    ) -> Result<(), Self::Error>;
    fn authorize(
        &self,
        request: &AuthorizationDecisionRequest,
    ) -> Result<AuthorizationDecisionRecord, Self::Error>;
    fn retrieve_seal(&self, seal_id: &str) -> Result<SealRecord, Self::Error>;
    fn verify_seal(
        &self,
        seal: &SealRecord,
        expected_approval_subject_digest: &ContentDigest,
    ) -> Result<(), Self::Error>;
    fn revoke_seal(&self, request: &RevokeSealRequest) -> Result<SealRecord, Self::Error>;
}

/// Marker implemented by full local or remote Provider adapters. The contract
/// intentionally says nothing about transport, SCM, workflow syntax, or GitHub.
pub trait Provider:
    ProviderMetadataOperations
    + ExecutionOperations
    + SessionOperations
    + ProviderEvidenceOperations
    + CheckpointOperations
    + PortableObjectOperations
    + TrustBoundaryOperations
{
}

impl<T> Provider for T where
    T: ProviderMetadataOperations
        + ExecutionOperations
        + SessionOperations
        + ProviderEvidenceOperations
        + CheckpointOperations
        + PortableObjectOperations
        + TrustBoundaryOperations
{
}
