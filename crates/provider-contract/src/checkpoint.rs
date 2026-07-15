use crate::{
    canonical::{canonical_digest, validate_collection_size, validate_profile_name},
    ProviderContractError,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const CHECKPOINT_DOMAIN: &[u8] = b"runtrue.provider.checkpoint-manifest.v1\0";
const REPLAY_BUNDLE_DOMAIN: &[u8] = b"runtrue.provider.replay-bundle-manifest.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointCompatibilityGrade {
    Exact,
    Compatible,
    DiagnosticOnly,
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTaint {
    pub contains_credentials: bool,
    pub unresolved_external_effect: bool,
    pub nondeterministic_guest_state: bool,
    pub reasons: BTreeSet<String>,
}

impl CheckpointTaint {
    pub fn validate(&self) -> Result<(), ProviderContractError> {
        validate_collection_size(self.reasons.len())?;
        for reason in &self.reasons {
            validate_profile_name(reason)?;
        }
        if (self.contains_credentials
            || self.unresolved_external_effect
            || self.nondeterministic_guest_state)
            == self.reasons.is_empty()
        {
            return Err(ProviderContractError::InvalidObjectContract(
                "checkpoint taint flags and reasons disagree",
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
    pub program_digest: ContentDigest,
    pub dependency_digests: BTreeSet<ContentDigest>,
    pub capsule_digest: ContentDigest,
    pub seal_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub runtime_compatibility_digest: ContentDigest,
    pub workspace_generations: Vec<WorkspaceGeneration>,
    pub deterministic_guest_state_digest: ContentDigest,
    pub capability_state_digest: ContentDigest,
    pub effect_ledger_frontier: EffectLedgerFrontier,
    pub remaining_budget: RemainingExecutionBudget,
    pub taint: CheckpointTaint,
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
        self.taint.validate()
    }

    pub fn digest(&self) -> Result<ContentDigest, ProviderContractError> {
        self.validate()?;
        canonical_digest(CHECKPOINT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundleManifest {
    pub manifest_version: u32,
    pub declared_grade: CheckpointCompatibilityGrade,
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

impl ReplayBundleManifest {
    pub fn from_checkpoint(
        checkpoint: &CheckpointManifest,
        declared_grade: CheckpointCompatibilityGrade,
        evidence_checkpoint_digest: ContentDigest,
        evidence_event_digests: Vec<ContentDigest>,
        included_object_digests: BTreeMap<String, ContentDigest>,
    ) -> Result<Self, ProviderContractError> {
        checkpoint.validate()?;
        if checkpoint.taint.contains_credentials {
            return Err(ProviderContractError::InvalidObjectContract(
                "credential-tainted checkpoint cannot enter a Replay Bundle",
            ));
        }
        if declared_grade != checkpoint.compatibility_grade {
            return Err(ProviderContractError::InvalidObjectContract(
                "Replay Bundle grade differs from checkpoint grade",
            ));
        }
        let manifest = Self {
            manifest_version: 1,
            declared_grade,
            checkpoint_manifest_digest: checkpoint.digest()?,
            program_digest: checkpoint.program_digest.clone(),
            dependency_digests: checkpoint.dependency_digests.clone(),
            capsule_digest: checkpoint.capsule_digest.clone(),
            seal_digest: checkpoint.seal_digest.clone(),
            policy_digest: checkpoint.policy_digest.clone(),
            runtime_compatibility_digest: checkpoint.runtime_compatibility_digest.clone(),
            evidence_checkpoint_digest,
            evidence_event_digests,
            included_object_digests,
        };
        manifest.validate_against(checkpoint)?;
        Ok(manifest)
    }

    pub fn validate_against(
        &self,
        checkpoint: &CheckpointManifest,
    ) -> Result<(), ProviderContractError> {
        checkpoint.validate()?;
        if checkpoint.taint.contains_credentials
            || self.manifest_version != 1
            || self.declared_grade != checkpoint.compatibility_grade
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
    ) -> Result<ContentDigest, ProviderContractError> {
        self.validate_against(checkpoint)?;
        canonical_digest(REPLAY_BUNDLE_DOMAIN, self)
    }
}
