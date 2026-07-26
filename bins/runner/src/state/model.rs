#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PersistentRunnerState {
    pub installation_fencing_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_lease: Option<ActiveLeaseMarker>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_completion: Option<PersistedCompletion>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) active_leases: BTreeMap<String, ActiveLeaseMarker>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) pending_completions: BTreeMap<String, PersistedCompletion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveLeaseMarker {
    pub lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub workspace_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedCompletion {
    pub lease_id: String,
    pub fencing_generation: u64,
    pub installation_fencing_epoch: u64,
    pub final_state: String,
    pub exit_code: Option<i32>,
    pub error_code: String,
    pub result_digest: String,
    pub artifact_ids: Vec<String>,
    pub cache_entry_ids: Vec<String>,
    pub completed_unix_ms: u64,
    #[serde(default)]
    pub final_job_attempt: u32,
    #[serde(default)]
    pub expected_log_frames: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_taint: Option<runtrue_engine::CredentialTaint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_objects: Option<Vec<PersistedCommittedObject>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PersistedCommittedObjectKind {
    Cache,
    Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedCommittedObject {
    pub kind: PersistedCommittedObjectKind,
    pub object_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_name: Option<String>,
    pub job_attempt: u32,
}

impl PersistedCompletion {
    pub fn from_wire(request: &v1::CompleteLeaseRequest) -> Result<Self, StateError> {
        let result_digest = request
            .result_digest
            .as_ref()
            .ok_or(StateError::InvalidCompletion("missing result digest"))?;
        let result_digest = ContentDigest::try_from(result_digest)
            .map_err(|_| StateError::InvalidCompletion("invalid result digest"))?;
        let completed_unix_ms = timestamp_millis(request.completed_at.as_ref())?;
        Ok(Self {
            lease_id: request.lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            final_state: request.final_state.clone(),
            exit_code: request.exit_code,
            error_code: request.error_code.clone(),
            result_digest: result_digest.to_string(),
            artifact_ids: request.artifact_ids.clone(),
            cache_entry_ids: request.cache_entry_ids.clone(),
            completed_unix_ms,
            final_job_attempt: request.final_job_attempt,
            expected_log_frames: request.expected_log_frames,
            credential_taint: None,
            committed_objects: None,
        })
    }

    pub fn to_wire(&self) -> Result<v1::CompleteLeaseRequest, StateError> {
        let digest = ContentDigest::parse(self.result_digest.clone())
            .map_err(|_| StateError::InvalidCompletion("invalid stored result digest"))?;
        Ok(v1::CompleteLeaseRequest {
            lease_id: self.lease_id.clone(),
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            final_state: self.final_state.clone(),
            exit_code: self.exit_code,
            error_code: self.error_code.clone(),
            result_digest: Some(
                v1::Digest::try_from(digest)
                    .map_err(|_| StateError::InvalidCompletion("invalid stored result digest"))?,
            ),
            artifact_ids: self.artifact_ids.clone(),
            cache_entry_ids: self.cache_entry_ids.clone(),
            completed_at: Some(timestamp(self.completed_unix_ms)),
            final_job_attempt: self.final_job_attempt,
            expected_log_frames: self.expected_log_frames,
        })
    }

    pub fn to_wire_v2(&self) -> Result<Option<v2::CompleteLeaseRequest>, StateError> {
        let Some(committed_objects) = self.committed_objects.as_ref() else {
            return Ok(None);
        };
        self.validate_committed_objects(committed_objects)?;
        let digest = ContentDigest::parse(self.result_digest.clone())
            .map_err(|_| StateError::InvalidCompletion("invalid stored result digest"))?;
        let digest = v1::Digest::try_from(digest)
            .map_err(|_| StateError::InvalidCompletion("invalid stored result digest"))?;
        let final_state = match self.final_state.as_str() {
            // Accept the legacy runner value so a condition-false completion
            // persisted by an older binary can be replayed after upgrade.
            "succeeded" | "skipped" => v2::LeaseFinalState::Succeeded,
            "failed" => v2::LeaseFinalState::Failed,
            "canceled" => v2::LeaseFinalState::Canceled,
            "timed_out" => v2::LeaseFinalState::TimedOut,
            _ => return Err(StateError::InvalidCompletion("invalid final state")),
        };
        Ok(Some(v2::CompleteLeaseRequest {
            lease_id: self.lease_id.clone(),
            fencing_generation: self.fencing_generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            final_state: final_state as i32,
            exit_code: self.exit_code,
            error_code: self.error_code.clone(),
            result_digest_algorithm: digest.algorithm,
            result_digest: digest.value,
            committed_objects: committed_objects
                .iter()
                .map(|object| v2::CommittedObject {
                    kind: match object.kind {
                        PersistedCommittedObjectKind::Cache => {
                            v2::CommittedObjectKind::Cache as i32
                        }
                        PersistedCommittedObjectKind::Artifact => {
                            v2::CommittedObjectKind::Artifact as i32
                        }
                    },
                    object_id: object.object_id.clone(),
                    declaration_name: object.declaration_name.clone(),
                    job_attempt: object.job_attempt,
                })
                .collect(),
            completed_at: Some(timestamp(self.completed_unix_ms)),
            final_job_attempt: self.final_job_attempt,
            expected_log_frames: self.expected_log_frames,
            credential_taint: match self.credential_taint {
                Some(runtrue_engine::CredentialTaint::None) => {
                    v2::CredentialTaintState::None as i32
                }
                Some(runtrue_engine::CredentialTaint::CredentialReleased) => {
                    v2::CredentialTaintState::CredentialReleased as i32
                }
                None => v2::CredentialTaintState::Unspecified as i32,
            },
        }))
    }

    pub(super) fn validate_committed_objects(
        &self,
        committed_objects: &[PersistedCommittedObject],
    ) -> Result<(), StateError> {
        let mut artifact_ids = Vec::new();
        let mut cache_ids = Vec::new();
        for object in committed_objects {
            if object.object_id.is_empty()
                || object.object_id.len() > 1024
                || object.object_id.bytes().any(|byte| byte.is_ascii_control())
                || object.job_attempt == 0
                || object.job_attempt != self.final_job_attempt
            {
                return Err(StateError::InvalidCompletion(
                    "invalid committed object binding",
                ));
            }
            match object.kind {
                PersistedCommittedObjectKind::Cache if object.declaration_name.is_none() => {
                    cache_ids.push(object.object_id.clone());
                }
                PersistedCommittedObjectKind::Artifact
                    if object.declaration_name.as_ref().is_some_and(|name| {
                        !name.is_empty()
                            && name.len() <= 1024
                            && !name.bytes().any(|byte| byte.is_ascii_control())
                    }) =>
                {
                    artifact_ids.push(object.object_id.clone());
                }
                _ => {
                    return Err(StateError::InvalidCompletion(
                        "invalid committed object kind or declaration",
                    ))
                }
            }
        }
        artifact_ids.sort();
        cache_ids.sort();
        if artifact_ids != self.artifact_ids || cache_ids != self.cache_entry_ids {
            return Err(StateError::InvalidCompletion(
                "committed objects do not match legacy completion ids",
            ));
        }
        Ok(())
    }
}

pub(super) fn timestamp(unix_ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX),
        nanos: i32::try_from((unix_ms % 1000) * 1_000_000).unwrap_or(999_000_000),
    }
}

fn timestamp_millis(timestamp: Option<&prost_types::Timestamp>) -> Result<u64, StateError> {
    let timestamp = timestamp.ok_or(StateError::InvalidCompletion(
        "missing completion timestamp",
    ))?;
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err(StateError::InvalidCompletion(
            "invalid completion timestamp",
        ));
    }
    u64::try_from(timestamp.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_add(u64::from(timestamp.nanos as u32) / 1_000_000))
        .ok_or(StateError::InvalidCompletion(
            "completion timestamp overflow",
        ))
}
use super::StateError;
use runtrue_model::ContentDigest;
use runtrue_protocol::{v1, v2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
