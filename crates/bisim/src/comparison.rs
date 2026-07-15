use crate::{BisimComparison, BisimError, BisimObservation};
use runtrue_engine::ExecutionResult;

/// Compare normalized observations from two execution backends.
///
/// This is behavioral conformance, not merely Capsule digest comparison.
pub fn compare_bisim(
    left: &BisimObservation,
    right: &BisimObservation,
) -> Result<BisimComparison, BisimError> {
    left.verify()?;
    right.verify()?;
    let same_capsule = left.capsule_digest == right.capsule_digest;
    let same_result = left.normalized_result_digest == right.normalized_result_digest
        && left.normalized_result == right.normalized_result;
    let same_events = left.event_digest == right.event_digest
        && left.normalized_result.events == right.normalized_result.events;
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
    Ok(BisimComparison {
        matches: same_capsule && same_result && same_events,
        same_capsule,
        same_result,
        same_events,
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
