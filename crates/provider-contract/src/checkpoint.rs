use crate::{
    canonical::{
        canonical_bytes, canonical_digest, validate_collection_size, validate_identifier,
        validate_profile_name,
    },
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const CHECKPOINT_DOMAIN: &[u8] = b"runtrue.provider.checkpoint-manifest.v1\0";
const REPLAY_BUNDLE_DOMAIN: &[u8] = b"runtrue.provider.replay-bundle-manifest.v1\0";
const CHECKPOINT_STORAGE_DOMAIN: &[u8] = b"runtrue.provider.checkpoint-storage-envelope.v1\0";
const REPLAY_GRADE_PROOF_DOMAIN: &[u8] = b"runtrue.provider.replay-grade-proof.v1\0";

pub trait ReplayGradeProofSignatureVerifier {
    fn verify_replay_grade_proof_signature(
        &self,
        issuer_identity_digest: &ContentDigest,
        signing_key_id: &ContentDigest,
        signing_key_generation: u64,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointCompatibilityGrade {
    Exact,
    Compatible,
    DiagnosticOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGrade {
    Hermetic,
    Exact,
    EvidenceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayGradeProof {
    pub proof_version: u32,
    pub declared_grade: ReplayGrade,
    pub checkpoint_state_digest: ContentDigest,
    pub credential_exclusion_evidence_digest: Option<ContentDigest>,
    pub effect_safety_evidence_digest: Option<ContentDigest>,
    pub determinism_evidence_digest: Option<ContentDigest>,
    pub object_graph_evidence_digest: Option<ContentDigest>,
    pub evidence_chain_checkpoint_digest: Option<ContentDigest>,
    pub recorded_interaction_contract_digest: Option<ContentDigest>,
    pub issuer_identity_digest: ContentDigest,
    pub signing_key_id: ContentDigest,
    pub signing_key_generation: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
}

impl ReplayGradeProof {
    pub fn validate_structure_for(
        &self,
        grade: ReplayGrade,
        checkpoint_state_digest: &ContentDigest,
    ) -> Result<(), ProviderContractError> {
        validate_profile_name(&self.signature_algorithm)?;
        let positive_proofs_present = self.credential_exclusion_evidence_digest.is_some()
            && self.effect_safety_evidence_digest.is_some()
            && self.determinism_evidence_digest.is_some()
            && self.object_graph_evidence_digest.is_some()
            && self.evidence_chain_checkpoint_digest.is_some();
        let valid = match grade {
            ReplayGrade::Hermetic => {
                positive_proofs_present && self.recorded_interaction_contract_digest.is_none()
            }
            ReplayGrade::Exact => {
                positive_proofs_present && self.recorded_interaction_contract_digest.is_some()
            }
            ReplayGrade::EvidenceOnly => true,
        };
        if self.proof_version != 1
            || self.declared_grade != grade
            || &self.checkpoint_state_digest != checkpoint_state_digest
            || self.signing_key_generation == 0
            || self.issued_unix_ms == 0
            || self.expires_unix_ms <= self.issued_unix_ms
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
            || !valid
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "Replay grade lacks authenticated credential, effect, determinism, object, Evidence, or interaction proof",
            ));
        }
        Ok(())
    }

    pub fn signature_message(
        &self,
        grade: ReplayGrade,
        checkpoint_state_digest: &ContentDigest,
    ) -> Result<Vec<u8>, ProviderContractError> {
        self.validate_structure_for(grade, checkpoint_state_digest)?;
        let canonical = canonical_bytes(&(
            self.proof_version,
            self.declared_grade,
            &self.checkpoint_state_digest,
            &self.credential_exclusion_evidence_digest,
            &self.effect_safety_evidence_digest,
            &self.determinism_evidence_digest,
            &self.object_graph_evidence_digest,
            &self.evidence_chain_checkpoint_digest,
            &self.recorded_interaction_contract_digest,
            &self.issuer_identity_digest,
            &self.signing_key_id,
            self.signing_key_generation,
            self.issued_unix_ms,
            self.expires_unix_ms,
            &self.signature_algorithm,
        ))?;
        let mut message = Vec::with_capacity(REPLAY_GRADE_PROOF_DOMAIN.len() + canonical.len());
        message.extend_from_slice(REPLAY_GRADE_PROOF_DOMAIN);
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub fn verify_for(
        &self,
        grade: ReplayGrade,
        checkpoint_state_digest: &ContentDigest,
        now_unix_ms: u64,
        verifier: &impl ReplayGradeProofSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        let message = self.signature_message(grade, checkpoint_state_digest)?;
        if now_unix_ms < self.issued_unix_ms
            || now_unix_ms >= self.expires_unix_ms
            || !verifier.verify_replay_grade_proof_signature(
                &self.issuer_identity_digest,
                &self.signing_key_id,
                self.signing_key_generation,
                &self.signature_algorithm,
                &message,
                &self.signature,
            )
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "Replay grade proof is expired or failed signature verification",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceGeneration {
    pub workspace_id_digest: ContentDigest,
    pub base_generation: u64,
    pub current_generation: u64,
    pub content_digest: ContentDigest,
}

impl WorkspaceGeneration {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.base_generation == 0 || self.current_generation < self.base_generation {
            return Err(ProviderContractError::InvalidObjectContract(
                "invalid checkpoint workspace generation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectLedgerFrontier {
    pub through_sequence: u64,
    pub terminal_effect_digest: Option<ContentDigest>,
}

impl EffectLedgerFrontier {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if (self.through_sequence == 0) != self.terminal_effect_digest.is_none() {
            return Err(ProviderContractError::InvalidObjectContract(
                "effect ledger sequence and digest disagree",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemainingExecutionBudget {
    pub remaining_cpu_milliseconds: u64,
    pub remaining_effect_uses: u64,
    pub remaining_effect_bytes: u64,
    pub deadline_unix_ms: u64,
}

impl RemainingExecutionBudget {
    pub fn validate(&self, created_unix_ms: u64) -> Result<(), ProviderContractError> {
        if self.deadline_unix_ms <= created_unix_ms {
            return Err(ProviderContractError::InvalidObjectContract(
                "checkpoint deadline had already elapsed when captured",
            ));
        }
        Ok(())
    }
}

/// Portable identity of deterministic state. Live Provider identity, lease,
/// fence, transport connections, and host handles are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifest {
    pub manifest_version: u32,
    pub tenant_id: String,
    pub program_digest: ContentDigest,
    pub dependency_digests: BTreeSet<ContentDigest>,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub object_graph_root_digest: ContentDigest,
    pub sanitization_evidence_digest: ContentDigest,
    pub credential_exclusion_evidence_digest: ContentDigest,
    pub effect_quiescence_evidence_digest: ContentDigest,
    pub capability_revocation_evidence_digest: ContentDigest,
    pub workspace_generations: Vec<WorkspaceGeneration>,
    pub deterministic_guest_state_digest: ContentDigest,
    /// Deterministic usage/accounting state only. Invocation handles and live
    /// authority are excluded and must be freshly issued after restore.
    pub capability_accounting_digest: ContentDigest,
    pub effect_ledger_frontier: EffectLedgerFrontier,
    pub remaining_budget: RemainingExecutionBudget,
    pub compatibility_grade: CheckpointCompatibilityGrade,
    pub created_unix_ms: u64,
}

impl CheckpointManifest {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        if self.manifest_version != 1 || self.created_unix_ms == 0 {
            return Err(ProviderContractError::InvalidObjectContract(
                "unsupported checkpoint manifest or zero creation time",
            ));
        }
        validate_identifier("checkpoint tenant", &self.tenant_id)?;
        if self.dependency_digests.is_empty() || self.workspace_generations.is_empty() {
            return Err(ProviderContractError::InvalidObjectContract(
                "checkpoint dependencies and workspace generations cannot be empty",
            ));
        }
        validate_collection_size(self.dependency_digests.len())?;
        validate_collection_size(self.workspace_generations.len())?;
        for workspace in &self.workspace_generations {
            workspace.validate()?;
        }
        self.effect_ledger_frontier.validate()?;
        self.remaining_budget.validate(self.created_unix_ms)?;
        if self.compatibility_grade == CheckpointCompatibilityGrade::DiagnosticOnly {
            return Err(ProviderContractError::InvalidObjectContract(
                "diagnostic state is not a resumable Checkpoint",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(CHECKPOINT_DOMAIN, self)
    }
}

/// Randomized authenticated storage identity kept separate from logical
/// tenant state. Key rotation or re-encryption changes this digest without
/// changing the Checkpoint state digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointStorageEnvelope {
    pub envelope_version: u32,
    pub tenant_id: String,
    pub checkpoint_state_digest: ContentDigest,
    pub encryption_key_generation: u64,
    pub encryption_algorithm: String,
    pub encrypted_envelope_digest: ContentDigest,
    pub associated_data_digest: ContentDigest,
    pub object_metadata_digest: ContentDigest,
}

impl CheckpointStorageEnvelope {
    pub fn validate_against(
        &self,
        manifest: &CheckpointManifest,
    ) -> Result<(), ProviderContractError> {
        validate_identifier("checkpoint storage tenant", &self.tenant_id)?;
        validate_profile_name(&self.encryption_algorithm)?;
        let expected_associated_data = canonical_digest(
            b"runtrue.provider.checkpoint-storage-associated-data.v1\0",
            &(
                self.envelope_version,
                &self.tenant_id,
                &self.checkpoint_state_digest,
                self.encryption_key_generation,
                &self.encryption_algorithm,
                &self.object_metadata_digest,
            ),
        )?;
        if self.envelope_version != 1
            || self.tenant_id != manifest.tenant_id
            || self.checkpoint_state_digest != manifest.digest()?
            || self.encryption_key_generation == 0
            || self.associated_data_digest != expected_associated_data
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "checkpoint encrypted storage identity differs from logical tenant state",
            ));
        }
        Ok(())
    }

    pub fn storage_digest(
        &self,
        manifest: &CheckpointManifest,
    ) -> Result<ContentDigest, ProviderContractError> {
        self.validate_against(manifest)?;
        canonical_digest(CHECKPOINT_STORAGE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundleManifest {
    pub manifest_version: u32,
    pub declared_grade: ReplayGrade,
    pub grade_proof: ReplayGradeProof,
    pub checkpoint_manifest_digest: ContentDigest,
    pub program_digest: ContentDigest,
    pub dependency_digests: BTreeSet<ContentDigest>,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub evidence_checkpoint_digest: ContentDigest,
    pub evidence_event_digests: Vec<ContentDigest>,
    pub included_object_digests: BTreeMap<String, ContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundleMaterial {
    pub evidence_checkpoint_digest: ContentDigest,
    pub evidence_event_digests: Vec<ContentDigest>,
    pub included_object_digests: BTreeMap<String, ContentDigest>,
}

impl ReplayBundleManifest {
    pub fn from_checkpoint(
        checkpoint: &CheckpointManifest,
        declared_grade: ReplayGrade,
        grade_proof: ReplayGradeProof,
        material: ReplayBundleMaterial,
        now_unix_ms: u64,
        verifier: &impl ReplayGradeProofSignatureVerifier,
    ) -> Result<Self, ProviderContractError> {
        checkpoint.validate()?;
        grade_proof.verify_for(declared_grade, &checkpoint.digest()?, now_unix_ms, verifier)?;
        let manifest = Self {
            manifest_version: 1,
            declared_grade,
            grade_proof,
            checkpoint_manifest_digest: checkpoint.digest()?,
            program_digest: checkpoint.program_digest.clone(),
            dependency_digests: checkpoint.dependency_digests.clone(),
            capsule_digest: checkpoint.capsule_digest.clone(),
            seal_digest: checkpoint.seal_digest.clone(),
            policy_digest: checkpoint.policy_digest.clone(),
            runtime_compatibility_digest: checkpoint.runtime_compatibility_digest.clone(),
            evidence_checkpoint_digest: material.evidence_checkpoint_digest,
            evidence_event_digests: material.evidence_event_digests,
            included_object_digests: material.included_object_digests,
        };
        manifest.validate_against(checkpoint, now_unix_ms, verifier)?;
        Ok(manifest)
    }

    pub fn validate_against(
        &self,
        checkpoint: &CheckpointManifest,
        now_unix_ms: u64,
        verifier: &impl ReplayGradeProofSignatureVerifier,
    ) -> Result<(), ProviderContractError> {
        checkpoint.validate()?;
        self.grade_proof.verify_for(
            self.declared_grade,
            &checkpoint.digest()?,
            now_unix_ms,
            verifier,
        )?;
        if self.manifest_version != 1
            || self.checkpoint_manifest_digest != checkpoint.digest()?
            || self.program_digest != checkpoint.program_digest
            || self.dependency_digests != checkpoint.dependency_digests
            || self.capsule_digest != checkpoint.capsule_digest
            || self.seal_digest != checkpoint.seal_digest
            || self.policy_digest != checkpoint.policy_digest
            || self.runtime_compatibility_digest != checkpoint.runtime_compatibility_digest
            || self.evidence_event_digests.is_empty()
            || self.included_object_digests.is_empty()
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "Replay Bundle identity differs from its checkpoint",
            ));
        }
        validate_collection_size(self.evidence_event_digests.len())?;
        validate_collection_size(self.included_object_digests.len())?;
        for name in self.included_object_digests.keys() {
            validate_profile_name(name)?;
        }
        Ok(())
    }

    pub fn digest(
        &self,
        checkpoint: &CheckpointManifest,
        now_unix_ms: u64,
        verifier: &impl ReplayGradeProofSignatureVerifier,
    ) -> Result<ContentDigest, ProviderContractError> {
        self.validate_against(checkpoint, now_unix_ms, verifier)?;
        canonical_digest(REPLAY_BUNDLE_DOMAIN, self)
    }
}
