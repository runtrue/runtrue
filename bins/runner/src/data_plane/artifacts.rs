use super::{
    patterns::normalized_path,
    session::RemoteDataPlaneSession,
    transfer::{call_after_lifecycle, temporary_cas, upload_snapshot, UploadContext},
    wire::{canonical_bytes, classification_name, snapshot_identity, wire_digest},
};
use crate::{
    daemon::RunnerError,
    state::{PersistedCommittedObject, PersistedCommittedObjectKind},
};
use runtrue_protocol::v1;
use std::time::Duration;
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

impl RemoteDataPlaneSession {
    pub(crate) fn capture_artifacts(
        &self,
        final_state: &str,
        job_attempt: u32,
    ) -> Result<Vec<PersistedCommittedObject>, RunnerError> {
        if !self.credential_taint.permits_publication() {
            return Ok(Vec::new());
        }
        if final_state != "succeeded" {
            return Ok(Vec::new());
        }
        let job = self.job()?;
        if job.outputs.is_empty() {
            return Ok(Vec::new());
        }
        let (_temporary, cas) = temporary_cas()?;
        let mut artifacts = Vec::new();
        for (name, output) in &job.outputs {
            let relative = normalized_path(&output.path)?;
            let snapshot = cas
                .capture_path_beneath(&self.workspace, &relative)
                .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            let (content_digest, size_bytes, manifest_digest, media_type) =
                snapshot_identity(&snapshot);
            let classification = classification_name(output.classification);
            let ticket_request = v1::ArtifactTicketRequest {
                execution_lease_id: self.lease.lease_id.clone(),
                fencing_generation: self.lease.fencing_generation,
                job_id: self.lease.job_id.clone(),
                step_id: "job-finalize".to_owned(),
                name: name.clone(),
                classification: classification.to_owned(),
                maximum_bytes: size_bytes.max(1),
                job_attempt,
                expected_content_digest: Some(wire_digest(&content_digest)?),
            };
            let ticket = call_after_lifecycle(|| {
                self.broker
                    .request_artifact_ticket(ticket_request.clone(), RPC_TIMEOUT)
            })?;
            upload_snapshot(
                &UploadContext {
                    broker: self.broker.as_ref(),
                    lease: &self.lease,
                    step_id: "job-finalize",
                    job_attempt,
                    ticket_id: &ticket.ticket_id,
                    kind: "artifact",
                    cas: &cas,
                },
                &snapshot,
            )?;
            let response = self
                .broker
                .commit_artifact(
                    v1::CommitArtifactRequest {
                        execution_lease_id: self.lease.lease_id.clone(),
                        fencing_generation: self.lease.fencing_generation,
                        ticket_id: ticket.ticket_id,
                        content_digest: Some(wire_digest(&content_digest)?),
                        manifest_digest: Some(wire_digest(&manifest_digest)?),
                        size_bytes,
                        media_type: media_type.to_owned(),
                        classification: classification.to_owned(),
                        job_attempt,
                        path_snapshot_json: canonical_bytes(&snapshot)?,
                        retention_until_unix_seconds: 0,
                        legal_hold: false,
                    },
                    RPC_TIMEOUT,
                )
                .map_err(|error| RunnerError::DataPlane(error.to_string()))?;
            artifacts.push(PersistedCommittedObject {
                kind: PersistedCommittedObjectKind::Artifact,
                object_id: response.artifact_id,
                declaration_name: Some(name.clone()),
                job_attempt,
            });
        }
        artifacts.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        artifacts.dedup_by(|left, right| left.object_id == right.object_id);
        Ok(artifacts)
    }
}
