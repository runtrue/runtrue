use crate::{
    comparison::normalize_result, BackendIdentity, BisimError, BisimObservation,
    BISIM_OBSERVATION_VERSION, MAX_BISIM_RESULT_BYTES,
};
use runtrue_model::ContentDigest;
use runtrue_provider_contract::{ExecutionState, TerminalCause};
use runtrue_workflow_ir::{canonicalize_value, ParityGrade};
use serde::Serialize;

pub(crate) fn validate_backend(backend: &BackendIdentity) -> Result<(), BisimError> {
    validate_identifier("backend name", &backend.name)?;
    validate_identifier("backend version", &backend.version)
}

pub(crate) fn verify_observation(observation: &BisimObservation) -> Result<(), BisimError> {
    if observation.observation_version != BISIM_OBSERVATION_VERSION {
        return Err(BisimError::UnsupportedObservationVersion(
            observation.observation_version,
        ));
    }
    observation.backend.validate()?;
    observation.portable.validate()?;
    if observation.portable.capsule_digest != observation.capsule_digest {
        return Err(BisimError::CapsuleDigestChanged);
    }
    let normalized = normalize_result(observation.normalized_result.clone());
    if normalized != observation.normalized_result {
        return Err(BisimError::ObservationContainsTiming);
    }
    let result_bytes = canonical_bytes(&normalized)?;
    if result_bytes.len() > MAX_BISIM_RESULT_BYTES {
        return Err(BisimError::ObservationTooLarge(result_bytes.len()));
    }
    if ContentDigest::sha256(&result_bytes) != observation.normalized_result_digest {
        return Err(BisimError::ResultDigestMismatch);
    }
    let event_bytes = canonical_bytes(&normalized.events)?;
    if ContentDigest::sha256(event_bytes) != observation.event_digest {
        return Err(BisimError::EventDigestMismatch);
    }
    verify_portable_result(&observation.portable, &normalized)?;
    observation
        .portable_evidence
        .verify_structure(&observation.portable, &observation.result_binding())?;
    Ok(())
}

fn verify_portable_result(
    portable: &runtrue_provider_contract::BisimPortableObservation,
    result: &runtrue_engine::ExecutionResult,
) -> Result<(), BisimError> {
    let lifecycle = &portable.lifecycle;
    let expected_cause_matches = if result.succeeded() {
        lifecycle.terminal_cause == Some(TerminalCause::Succeeded)
    } else {
        matches!(lifecycle.terminal_cause, Some(TerminalCause::Failed(_)))
    };
    if !result.state.is_terminal()
        || lifecycle.execution_state != Some(ExecutionState::Terminal)
        || lifecycle.session_state.is_some()
        || !expected_cause_matches
    {
        return Err(BisimError::PortableResultMismatch);
    }
    Ok(())
}

pub(crate) fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, BisimError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonicalize_value(value))?)
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), BisimError> {
    if value.is_empty() || value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BisimError::InvalidIdentifier(kind));
    }
    Ok(())
}

pub(crate) const fn parity_rank(parity: ParityGrade) -> u8 {
    match parity {
        ParityGrade::AExact => 0,
        ParityGrade::BEnvironmentEquivalent => 1,
        ParityGrade::CPlatformSpecific => 2,
        ParityGrade::DNonReplayable => 3,
    }
}
