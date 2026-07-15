use crate::{ReplayEnvelope, ReplayError};
use runtrue_workflow_ir::ExecutionCapsule;
use std::collections::BTreeSet;

pub(super) fn collect_secret_ids(capsule: &ExecutionCapsule) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for secret in &capsule.permissions.secrets {
        ids.insert(secret.metadata_id.clone());
    }
    for job in &capsule.jobs {
        for secret in &job.permissions.secrets {
            ids.insert(secret.metadata_id.clone());
        }
        for step in &job.steps {
            for secret in &step.capabilities.secrets {
                ids.insert(secret.metadata_id.clone());
            }
        }
    }
    ids.into_iter().collect()
}

pub(super) fn ensure_sorted_unique<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), ReplayError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ReplayError::NonCanonicalSet(field));
    }
    Ok(())
}

pub(super) fn decode_canonical_envelope(bytes: &[u8]) -> Result<ReplayEnvelope, ReplayError> {
    let envelope: ReplayEnvelope = serde_json::from_slice(bytes)?;
    if envelope.canonical_bytes()? != bytes {
        return Err(ReplayError::NonCanonical);
    }
    envelope.verify()?;
    Ok(envelope)
}
