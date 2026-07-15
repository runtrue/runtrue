use crate::{validation, BisimError};
use runtrue_engine::ExecutionResult;
use runtrue_model::ContentDigest;
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
    pub normalized_result: ExecutionResult,
}

impl BisimObservation {
    pub fn verify(&self) -> Result<(), BisimError> {
        validation::verify_observation(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisimComparison {
    pub matches: bool,
    pub same_capsule: bool,
    pub same_result: bool,
    pub same_events: bool,
    pub differences: Vec<String>,
}
