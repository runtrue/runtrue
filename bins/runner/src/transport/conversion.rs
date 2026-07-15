use super::TransportError;
use crate::broker::ObjectUploadBinding;
use runtrue_protocol::{v1, v2};

pub(super) fn completion_v2_to_v1(
    request: v2::CompleteLeaseRequest,
) -> Result<v1::CompleteLeaseRequest, TransportError> {
    let final_state = v2::LeaseFinalState::try_from(request.final_state)
        .map_err(|_| TransportError::InvalidBlobStream)?;
    let final_state = match final_state {
        v2::LeaseFinalState::Succeeded => "succeeded",
        v2::LeaseFinalState::Failed => "failed",
        v2::LeaseFinalState::Canceled => "canceled",
        v2::LeaseFinalState::TimedOut => "timed_out",
        v2::LeaseFinalState::Unspecified => return Err(TransportError::InvalidBlobStream),
    };
    let mut artifact_ids = Vec::new();
    let mut cache_entry_ids = Vec::new();
    for object in request.committed_objects {
        match v2::CommittedObjectKind::try_from(object.kind)
            .map_err(|_| TransportError::InvalidBlobStream)?
        {
            v2::CommittedObjectKind::Artifact if object.declaration_name.is_some() => {
                artifact_ids.push(object.object_id)
            }
            v2::CommittedObjectKind::Cache if object.declaration_name.is_none() => {
                cache_entry_ids.push(object.object_id)
            }
            _ => return Err(TransportError::InvalidBlobStream),
        }
    }
    Ok(v1::CompleteLeaseRequest {
        lease_id: request.lease_id,
        fencing_generation: request.fencing_generation,
        installation_fencing_epoch: request.installation_fencing_epoch,
        final_state: final_state.to_owned(),
        exit_code: request.exit_code,
        error_code: request.error_code,
        result_digest: Some(v1::Digest {
            algorithm: request.result_digest_algorithm,
            value: request.result_digest,
        }),
        artifact_ids,
        cache_entry_ids,
        completed_at: request.completed_at,
        final_job_attempt: request.final_job_attempt,
        expected_log_frames: request.expected_log_frames,
    })
}

pub(super) fn completion_state_v1_to_v2(
    value: &str,
) -> Result<v2::LeaseFinalState, TransportError> {
    match value {
        "succeeded" => Ok(v2::LeaseFinalState::Succeeded),
        "failed" => Ok(v2::LeaseFinalState::Failed),
        "canceled" => Ok(v2::LeaseFinalState::Canceled),
        "timed_out" => Ok(v2::LeaseFinalState::TimedOut),
        _ => Err(TransportError::InvalidBlobStream),
    }
}

pub(super) fn upload_frame_v1(
    binding: &ObjectUploadBinding,
    offset: u64,
    payload: Vec<u8>,
) -> v1::UploadBlobChunk {
    v1::UploadBlobChunk {
        execution_lease_id: binding.execution_lease_id.clone(),
        fencing_generation: binding.fencing_generation,
        job_id: binding.job_id.clone(),
        step_id: binding.step_id.clone(),
        job_attempt: binding.job_attempt,
        ticket_id: binding.ticket_id.clone(),
        ticket_kind: binding.ticket_kind.clone(),
        declared_digest: Some(binding.declared_digest.clone()),
        offset,
        payload,
    }
}
