use crate::{canonical::domain_digest, verify_chain, AuditError, AuditEvent};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};

const CHECKPOINT_DOMAIN: &[u8] = b"runtrue.audit.checkpoint.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpoint {
    pub installation_id: String,
    pub through_sequence: u64,
    pub event_hash: ContentDigest,
    pub checkpoint_hash: ContentDigest,
}

pub fn checkpoint(events: &[AuditEvent]) -> Result<AuditCheckpoint, AuditError> {
    verify_chain(events)?;
    let last = events.last().ok_or(AuditError::EmptyCheckpoint)?;
    let mut input = Vec::new();
    input.extend_from_slice(last.installation_id.as_bytes());
    input.push(0);
    input.extend_from_slice(&last.sequence.to_be_bytes());
    input.extend_from_slice(last.event_hash.as_str().as_bytes());
    Ok(AuditCheckpoint {
        installation_id: last.installation_id.clone(),
        through_sequence: last.sequence,
        event_hash: last.event_hash.clone(),
        checkpoint_hash: domain_digest(CHECKPOINT_DOMAIN, &input),
    })
}

impl AuditCheckpoint {
    pub fn verify(&self, events: &[AuditEvent]) -> Result<(), AuditError> {
        let actual = checkpoint(events)?;
        if &actual != self {
            return Err(AuditError::CheckpointMismatch);
        }
        Ok(())
    }
}
