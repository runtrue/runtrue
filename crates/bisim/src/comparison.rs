use crate::{BisimComparison, BisimError, BisimObservation};
use runtrue_engine::ExecutionResult;
use runtrue_provider_contract::EvidenceSignatureVerifier;

/// Compare normalized observations from two execution backends.
///
/// This is behavioral conformance, not merely Capsule digest comparison.
pub fn compare_bisim(
    left: &BisimObservation,
    right: &BisimObservation,
) -> Result<BisimComparison, BisimError> {
    left.verify()?;
    right.verify()?;
    compare_verified(left, right)
}

/// Compare observations after cryptographically authenticating both Provider
/// Evidence chains and checkpoints. Active conformance decisions must use this
/// entry point; `compare_bisim` is only a structural/offline diagnostic.
pub fn compare_bisim_with(
    left: &BisimObservation,
    right: &BisimObservation,
    evidence_verifier: &impl EvidenceSignatureVerifier,
) -> Result<BisimComparison, BisimError> {
    left.verify_with(evidence_verifier)?;
    right.verify_with(evidence_verifier)?;
    compare_verified(left, right)
}

fn compare_verified(
    left: &BisimObservation,
    right: &BisimObservation,
) -> Result<BisimComparison, BisimError> {
    let same_capsule = left.capsule_digest == right.capsule_digest;
    let same_result = left.normalized_result_digest == right.normalized_result_digest
        && left.normalized_result == right.normalized_result;
    let same_events = left.event_digest == right.event_digest
        && left.normalized_result.events == right.normalized_result.events;
    let same_portable = left.portable.require_equivalent(&right.portable).is_ok();
    let mut differences = Vec::new();
    if !same_capsule {
        differences.push("capsule_digest".to_owned());
    }
    if !same_result {
        differences.push("execution_result".to_owned());
    }
    if !same_events {
        differences.push("lifecycle_events".to_owned());
    }
    if !same_portable {
        differences.push("portable_provider_observation".to_owned());
    }
    Ok(BisimComparison {
        matches: same_capsule && same_result && same_events && same_portable,
        same_capsule,
        same_result,
        same_events,
        same_portable,
        differences,
    })
}

pub(crate) fn normalize_result(mut result: ExecutionResult) -> ExecutionResult {
    for job in result.jobs.values_mut() {
        for attempt in &mut job.attempts {
            for step in attempt.steps.iter_mut().chain(&mut attempt.finalizers) {
                if let Some(output) = &mut step.output {
                    output.duration_ms = 0;
                }
            }
        }
    }
    result
}
