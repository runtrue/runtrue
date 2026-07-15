use crate::{validation::validate_identifier, RunnerAdmissionError};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
use std::collections::BTreeSet;

/// Locally verified runner posture. Self-reported inventory must not be used to
/// populate this structure without a separate verification step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRunnerProfile {
    pub runner_id: String,
    pub os: OperatingSystem,
    pub architecture: Architecture,
    pub logical_cpus: u32,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub isolation_backends: BTreeSet<Isolation>,
    pub capabilities: BTreeSet<String>,
    pub region: Option<String>,
    pub posture_digest: ContentDigest,
}

impl VerifiedRunnerProfile {
    pub fn validate(&self) -> Result<(), RunnerAdmissionError> {
        validate_identifier("runner id", &self.runner_id)?;
        if self.logical_cpus == 0 || self.memory_bytes == 0 || self.storage_bytes == 0 {
            return Err(RunnerAdmissionError::InvalidProfile(
                "CPU, memory, and storage must be greater than zero".to_owned(),
            ));
        }
        if self.isolation_backends.is_empty() {
            return Err(RunnerAdmissionError::InvalidProfile(
                "at least one verified isolation backend is required".to_owned(),
            ));
        }
        for capability in &self.capabilities {
            validate_identifier("runner capability", capability)?;
        }
        if let Some(region) = &self.region {
            validate_identifier("runner region", region)?;
        }
        Ok(())
    }
}
