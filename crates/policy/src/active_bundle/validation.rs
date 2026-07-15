use super::model::{PolicySimulationCase, MAX_IDENTIFIER_BYTES};
use crate::CedarAuthorizationError;
use std::collections::BTreeMap;
use thiserror::Error;
pub(super) fn validate_cases(
    stored: &[PolicySimulationCase],
    caller: &[PolicySimulationCase],
) -> Result<(), ActivePolicyError> {
    let mut ids = BTreeMap::new();
    for case in stored.iter().chain(caller) {
        validate_identifier("policy simulation case id", &case.id)?;
        if ids.insert(case.id.as_str(), ()).is_some() {
            return Err(ActivePolicyError::DuplicateSimulationCase(case.id.clone()));
        }
    }
    Ok(())
}
pub(super) fn validate_identifier(
    kind: &'static str,
    value: &str,
) -> Result<(), ActivePolicyError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ActivePolicyError::InvalidIdentifier(kind));
    }
    Ok(())
}
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ActivePolicyError {
    #[error("invalid {0}")]
    InvalidIdentifier(&'static str),
    #[error("policy source is empty or exceeds its canonical byte bound")]
    InvalidPolicySource,
    #[error("policy source could not be canonicalized")]
    CanonicalPolicy,
    #[error("persisted policy draft digest or lifecycle state is corrupt")]
    CorruptPolicyDraft,
    #[error("persisted policy draft is not canonical JSON")]
    NonCanonicalPolicyDraft,
    #[error("policy draft belongs to another tenant")]
    CrossTenantDraft,
    #[error("policy lifecycle transition is not allowed")]
    InvalidLifecycleTransition,
    #[error("policy simulation case count exceeds its bound or is empty")]
    SimulationCaseLimit,
    #[error("policy simulation corpus exceeds its serialized byte bound")]
    SimulationByteLimit,
    #[error("policy shadow case count exceeds its bound or is empty")]
    ShadowCaseLimit,
    #[error("duplicate policy simulation case `{0}`")]
    DuplicateSimulationCase(String),
    #[error("policy simulation digest changed")]
    SimulationDigestMismatch,
    #[error("policy activation evidence does not match the exact draft and simulation")]
    ActivationEvidenceMismatch,
    #[error("policy author cannot independently activate the draft")]
    SeparationOfDuties,
    #[error("policy activation approval predates the draft")]
    InvalidActivationTime,
    #[error("stale policy epoch: expected {expected}, received {actual}")]
    StalePolicyEpoch { expected: u64, actual: u64 },
    #[error("stale decision-cache generation: expected {expected}, received {actual}")]
    StaleCacheGeneration { expected: u64, actual: u64 },
    #[error("policy epoch or cache generation is exhausted")]
    EpochExhausted,
    #[error("policy simulation report is inconsistent or has an invalid digest")]
    InvalidSimulationReport,
    #[error("active policy state is internally inconsistent")]
    CorruptActivePolicyState,
    #[error(transparent)]
    Cedar(#[from] CedarAuthorizationError),
}
