use crate::{
    comparison::normalize_result,
    secret_scan::{scan_result_secrets, scan_secret_bytes},
    validation::{canonical_bytes, parity_rank},
    BackendIdentity, BisimError, BisimObservation, SecretCanary, BISIM_OBSERVATION_VERSION,
    MAX_BISIM_CANARIES, MAX_BISIM_RESULT_BYTES,
};
use runtrue_engine::{Engine, Executor};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::ExecutionCapsule;

/// Execute one Capsule through a backend and produce a normalized Bisim observation.
pub fn observe_backend<E: Executor>(
    capsule: &ExecutionCapsule,
    backend: BackendIdentity,
    executor: E,
    secret_canaries: &[SecretCanary],
) -> Result<BisimObservation, BisimError> {
    backend.validate()?;
    if secret_canaries.len() > MAX_BISIM_CANARIES {
        return Err(BisimError::TooManyCanaries(secret_canaries.len()));
    }
    if let Some(job) = capsule
        .jobs
        .iter()
        .find(|job| job.runner.isolation != backend.isolation)
    {
        return Err(BisimError::BackendIsolationMismatch {
            job_id: job.id.clone(),
            requested: job.runner.isolation,
            backend: backend.isolation,
        });
    }
    if parity_rank(backend.parity) > parity_rank(capsule.expected_parity) {
        return Err(BisimError::BackendParityInsufficient {
            capsule: capsule.expected_parity,
            backend: backend.parity,
        });
    }
    let canonical_capsule = capsule.canonical_bytes()?;
    scan_secret_bytes("execution capsule", &canonical_capsule, secret_canaries)?;
    let capsule_digest = ContentDigest::sha256(&canonical_capsule);
    if capsule.digest()? != capsule_digest {
        return Err(BisimError::CapsuleDigestChanged);
    }

    let mut engine = Engine::new(executor);
    let result = engine.execute(capsule)?;
    if capsule.canonical_bytes()? != canonical_capsule {
        return Err(BisimError::CapsuleDigestChanged);
    }
    scan_result_secrets(&result, secret_canaries)?;
    let normalized_result = normalize_result(result);
    let result_bytes = canonical_bytes(&normalized_result)?;
    if result_bytes.len() > MAX_BISIM_RESULT_BYTES {
        return Err(BisimError::ObservationTooLarge(result_bytes.len()));
    }
    let event_bytes = canonical_bytes(&normalized_result.events)?;
    let observation = BisimObservation {
        observation_version: BISIM_OBSERVATION_VERSION,
        backend,
        capsule_digest,
        normalized_result_digest: ContentDigest::sha256(&result_bytes),
        event_digest: ContentDigest::sha256(event_bytes),
        normalized_result,
    };
    observation.verify()?;
    Ok(observation)
}
