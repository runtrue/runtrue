use crate::{validation, BisimError, BisimPortableEvidence};
use runtrue_engine::ExecutionResult;
use runtrue_model::ContentDigest;
use runtrue_provider_contract::BisimPortableObservation;
use runtrue_workflow_ir::{Isolation, ParityGrade};
use serde::{Deserialize, Serialize};

pub const BISIM_OBSERVATION_VERSION: u32 = 1;
pub const MAX_BISIM_RESULT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_BISIM_CANARIES: usize = 128;
pub const MIN_BISIM_CANARY_BYTES: usize = 8;
pub const MAX_BISIM_CANARY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub name: String,
    pub version: String,
    pub isolation: Isolation,
    pub parity: ParityGrade,
}

impl BackendIdentity {
    pub fn validate(&self) -> Result<(), BisimError> {
        validation::validate_backend(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimObservation {
    pub observation_version: u32,
    pub backend: BackendIdentity,
    pub capsule_digest: ContentDigest,
    pub normalized_result_digest: ContentDigest,
    pub event_digest: ContentDigest,
    pub portable: BisimPortableObservation,
    pub portable_evidence: BisimPortableEvidence,
    pub normalized_result: ExecutionResult,
}

impl BisimObservation {
    #[must_use]
    pub fn result_binding(&self) -> BisimResultBinding {
        BisimResultBinding {
            observation_version: self.observation_version,
            backend: self.backend.clone(),
            capsule_digest: self.capsule_digest.clone(),
            normalized_result_digest: self.normalized_result_digest.clone(),
            event_digest: self.event_digest.clone(),
        }
    }

    pub fn verify(&self) -> Result<(), BisimError> {
        validation::verify_observation(self)
    }

    pub fn verify_with(
        &self,
        verifier: &impl runtrue_provider_contract::EvidenceSignatureVerifier,
    ) -> Result<(), BisimError> {
        self.verify()?;
        self.portable_evidence
            .verify_with(&self.portable, &self.result_binding(), verifier)
    }
}

/// Immutable engine result material that the Provider must include in the
/// signed portable Evidence payload after the backend execution completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimResultBinding {
    pub observation_version: u32,
    pub backend: BackendIdentity,
    pub capsule_digest: ContentDigest,
    pub normalized_result_digest: ContentDigest,
    pub event_digest: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimComparison {
    pub matches: bool,
    pub same_capsule: bool,
    pub same_result: bool,
    pub same_events: bool,
    pub same_portable: bool,
    pub differences: Vec<String>,
}
