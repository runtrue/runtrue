use super::super::{
    canonical_json, control_plane_status, data_status, issue_or_recover_artifact_ticket,
    now_unix_ms, proto_timestamp, reserve_or_recover_storage, AuthenticatedIdentity,
    RunnerControlService,
};
use runtrue_artifacts::{
    ArtifactClassification, ArtifactProducer, ArtifactScanState, ArtifactSnapshotCommitRequest,
    ArtifactTicketRequest, VerifiedArtifactProvenance,
};
use runtrue_attest::ProvenanceStatement;
use runtrue_control_plane::{
    RunnerDataCommit, RunnerDataCommitKind, StorageReservationState, TenantStorageReservation,
};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_storage::PathSnapshot;
use runtrue_workflow_ir::Access;
use std::collections::BTreeMap;
use tonic::Status;
impl RunnerControlService {
    pub(in crate::runner_service) async fn request_artifact_ticket_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::ArtifactTicketRequest,
    ) -> Result<v1::ArtifactTicketResponse, Status> {
        let subject = self
            .active_artifact_subject(
                authenticated,
                &request.execution_lease_id,
                request.fencing_generation,
                &request.job_id,
                request.job_attempt,
                &request.step_id,
            )
            .await?;
        let data = self.data_plane()?;
        let job = subject
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == subject.job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is missing"))?;
        let output = job
            .outputs
            .get(&request.name)
            .ok_or_else(|| Status::permission_denied("artifact output is not declared"))?;
        if job.permissions.artifacts != Access::Write {
            return Err(Status::permission_denied(
                "artifact writes are denied by the signed job permissions",
            ));
        }
        let classification = artifact_classification(&request.classification)?;
        if classification != artifact_classification_from_capsule(output.classification) {
            return Err(Status::permission_denied(
                "artifact classification differs from the signed declaration",
            ));
        }
        let expected_content_digest = request
            .expected_content_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("artifact content digest is required"))?;
        let expected_content_digest = ContentDigest::try_from(expected_content_digest)
            .map_err(|_| Status::invalid_argument("artifact content digest is invalid"))?;
        let now_ms = now_unix_ms()?;
        let reservation_identity = ContentDigest::sha256(
            serde_json::to_vec(&(
                "runtrue.artifact-ticket-storage-reservation.v2",
                &subject.repository.tenant_id,
                &subject.repository.id,
                &subject.run_id,
                &subject.lease.job_id,
                &subject.lease.id,
                subject.lease.fencing_generation,
                request.job_attempt,
                &request.step_id,
                &request.name,
                classification,
                &expected_content_digest,
                request.maximum_bytes,
            ))
            .map_err(|_| Status::internal("artifact reservation could not be encoded"))?,
        );
        let proposed = TenantStorageReservation {
            id: format!("artifact-ticket-{reservation_identity}"),
            tenant_id: subject.repository.tenant_id.clone(),
            ticket_kind: "artifact".to_owned(),
            object_digest: Some(expected_content_digest.clone()),
            reserved_bytes: request.maximum_bytes,
            reserved_objects: 1,
            state: StorageReservationState::Reserved,
            created_unix_ms: now_ms,
            expires_unix_ms: now_ms.saturating_add(300_000),
            completed_unix_ms: None,
        };
        let reservation =
            reserve_or_recover_storage(self.inner.control_plane.as_ref(), proposed, now_ms).await?;
        let ticket_request = ArtifactTicketRequest {
            tenant_id: subject.repository.tenant_id.clone(),
            repository_id: subject.repository.id.clone(),
            run_id: subject.run_id.clone(),
            job_id: subject.lease.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: request.step_id.clone(),
            lease_id: subject.lease.id.clone(),
            fencing_generation: subject.lease.fencing_generation,
            name: request.name.clone(),
            classification,
            max_bytes: request.maximum_bytes,
            expected_content_digest: Some(expected_content_digest),
            issued_at_unix_seconds: reservation.created_unix_ms / 1_000,
            expires_at_unix_seconds: reservation.expires_unix_ms / 1_000,
        };
        let ticket = issue_or_recover_artifact_ticket(
            self.inner.control_plane.as_ref(),
            &data.artifacts,
            &reservation,
            &ticket_request,
            now_ms,
        )
        .await?;
        Ok(v1::ArtifactTicketResponse {
            ticket_id: ticket.ticket_id.to_string(),
            endpoint: "runner-grpc://upload-blob".to_owned(),
            bearer_token: String::new(),
            expires_at: Some(proto_timestamp(
                ticket.expires_at_unix_seconds.saturating_mul(1000),
            )),
        })
    }

    pub(in crate::runner_service) async fn commit_artifact_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::CommitArtifactRequest,
    ) -> Result<v1::CommitArtifactResponse, Status> {
        if request.legal_hold {
            return Err(Status::permission_denied(
                "runner jobs cannot establish an artifact legal hold",
            ));
        }
        let data = self.data_plane()?;
        let ticket_id = ContentDigest::parse(request.ticket_id.clone())
            .map_err(|_| Status::invalid_argument("artifact ticket id is invalid"))?;
        let ticket = data.artifacts.ticket(&ticket_id).map_err(data_status)?;
        let (job_key, _) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&request.execution_lease_id)
            .await
            .map_err(control_plane_status)?;
        let subject = self
            .active_artifact_subject(
                authenticated,
                &request.execution_lease_id,
                request.fencing_generation,
                &job_key,
                request.job_attempt,
                &ticket.step_id,
            )
            .await?;
        if ticket.job_attempt != request.job_attempt {
            return Err(Status::failed_precondition(
                "artifact ticket attempt is stale",
            ));
        }
        let snapshot: PathSnapshot =
            canonical_json(&request.path_snapshot_json, "artifact snapshot")?;
        let content_digest = request
            .content_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("artifact content digest is required"))?;
        let content_digest = ContentDigest::try_from(content_digest)
            .map_err(|_| Status::invalid_argument("artifact content digest is invalid"))?;
        let manifest_digest = request
            .manifest_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("artifact manifest digest is required"))?;
        let manifest_digest = ContentDigest::try_from(manifest_digest)
            .map_err(|_| Status::invalid_argument("artifact manifest digest is invalid"))?;
        let snapshot_manifest = match &snapshot {
            PathSnapshot::File { digest, .. } => digest,
            PathSnapshot::Directory {
                manifest_digest, ..
            } => manifest_digest,
        };
        if *snapshot_manifest != manifest_digest {
            return Err(Status::invalid_argument(
                "artifact snapshot manifest mismatch",
            ));
        }
        let job = subject
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == subject.job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is missing"))?;
        let output = job
            .outputs
            .get(&ticket.name)
            .ok_or_else(|| Status::permission_denied("artifact output is not declared"))?;
        let producer = ArtifactProducer {
            capsule_digest: subject.lease.capsule_digest.clone(),
            workflow_digest: subject.capsule.workflow.digest.clone(),
            source_repository: format!("{}/{}", subject.repository.owner, subject.repository.name),
            source_commit: subject.capsule.context.source_commit.clone(),
            runner_id: subject.session.runner_id.clone(),
            runner_image_digest: subject.session.runner_image_digest.clone(),
            runner_attestation_digest: Some(subject.session.posture_digest.clone()),
        };
        let signed = data
            .signing_key
            .sign_provenance(&ProvenanceStatement {
                statement_version: 1,
                source_repository: producer.source_repository.clone(),
                source_commit: producer.source_commit.clone(),
                workflow_digest: producer.workflow_digest.clone(),
                capsule_digest: producer.capsule_digest.clone(),
                workflow_frontend: subject.capsule.context.workflow_frontend.clone(),
                builder_id: producer.runner_id.clone(),
                runner_image_digest: producer.runner_image_digest.clone(),
                parity_grade: subject.capsule.expected_parity,
                resolved_dependencies: Vec::new(),
                inputs: BTreeMap::new(),
                outputs: BTreeMap::from([(ticket.name.clone(), content_digest.clone())]),
                policy_version_ids: subject.capsule.context.policy_version_ids.clone(),
            })
            .map_err(|_| Status::internal("artifact provenance signing failed"))?;
        let verifying_key = data.signing_key.verifying_key();
        let retention_seconds = output.retention_ms.saturating_add(999) / 1000;
        let now = now_unix_ms()? / 1000;
        // Anchor retention to the durable ticket rather than wall-clock time at
        // the commit RPC. Otherwise an exact retry after a lost response would
        // derive different immutable metadata and be rejected as substitution.
        let retention_until = ticket
            .issued_at_unix_seconds
            .checked_add(retention_seconds)
            .ok_or_else(|| Status::out_of_range("artifact retention overflow"))?;
        if request.retention_until_unix_seconds != 0
            && request.retention_until_unix_seconds != retention_until
        {
            return Err(Status::invalid_argument(
                "artifact retention differs from the signed declaration",
            ));
        }
        let recovered = data
            .artifacts
            .claimed_artifact(&ticket)
            .map_err(data_status)?;
        let handle = if let Some(artifact_id) = recovered {
            let handle = data.artifacts.load(&artifact_id).map_err(data_status)?;
            if handle.record.content != snapshot
                || handle.record.content_digest != content_digest
                || handle.record.size_bytes != request.size_bytes
                || handle.record.media_type != request.media_type
                || (request.retention_until_unix_seconds != 0
                    && handle.record.retention_until_unix_seconds
                        != request.retention_until_unix_seconds)
            {
                return Err(Status::already_exists(
                    "artifact ticket was claimed by different immutable metadata",
                ));
            }
            handle
        } else {
            data.artifacts
                .commit_snapshot(&ArtifactSnapshotCommitRequest {
                    ticket: &ticket,
                    active_lease_id: &subject.lease.id,
                    active_fencing_generation: subject.lease.fencing_generation,
                    now_unix_seconds: now,
                    snapshot: &snapshot,
                    declared_content_digest: content_digest,
                    declared_size_bytes: request.size_bytes,
                    media_type: request.media_type,
                    retention_until_unix_seconds: retention_until,
                    legal_hold: false,
                    scan_state: ArtifactScanState::Pending,
                    producer,
                    provenance: VerifiedArtifactProvenance {
                        signed: &signed,
                        verifying_key: &verifying_key,
                    },
                })
                .map_err(data_status)?
        };
        let committed_unix_ms = now_unix_ms()?;
        self.inner
            .control_plane
            .commit_tenant_storage_ticket(
                &subject.repository.tenant_id,
                ticket.ticket_id.as_str(),
                handle.artifact_id.as_str(),
                handle.record.size_bytes,
                1,
                committed_unix_ms,
            )
            .await
            .map_err(control_plane_status)?;
        self.inner
            .control_plane
            .record_runner_data_commit_journal(
                &RunnerDataCommit {
                    kind: RunnerDataCommitKind::Artifact,
                    object_id: handle.artifact_id.to_string(),
                    tenant_id: subject.repository.tenant_id,
                    repository_id: subject.repository.id,
                    run_id: subject.run_id,
                    job_id: subject.lease.job_id,
                    job_attempt: request.job_attempt,
                    step_id: ticket.step_id,
                    output_name: Some(ticket.name),
                    lease_id: subject.lease.id,
                    fencing_generation: subject.lease.fencing_generation,
                    ticket_id: ticket.ticket_id.to_string(),
                    committed_unix_ms,
                },
                &authenticated.runner_id,
            )
            .await
            .map_err(control_plane_status)?;
        Ok(v1::CommitArtifactResponse {
            artifact_id: handle.artifact_id.to_string(),
            status: "committed".to_owned(),
        })
    }
}
pub(in crate::runner_service) fn artifact_classification(
    value: &str,
) -> Result<ArtifactClassification, Status> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| Status::invalid_argument("invalid artifact classification"))
}

pub(in crate::runner_service) const fn artifact_classification_name(
    value: ArtifactClassification,
) -> &'static str {
    match value {
        ArtifactClassification::UntrustedBuild => "untrusted-build",
        ArtifactClassification::Quarantined => "quarantined",
        ArtifactClassification::VerifiedTestOutput => "verified-test-output",
        ArtifactClassification::ReleaseCandidate => "release-candidate",
        ArtifactClassification::PromotedRelease => "promoted-release",
        ArtifactClassification::Sensitive => "sensitive",
        ArtifactClassification::Public => "public",
    }
}

pub(in crate::runner_service) const fn artifact_scan_state_name(
    value: &ArtifactScanState,
) -> &'static str {
    match value {
        ArtifactScanState::Pending => "pending",
        ArtifactScanState::Passed { .. } => "passed",
        ArtifactScanState::Failed { .. } => "failed",
        ArtifactScanState::Waived { .. } => "waived",
    }
}

pub(in crate::runner_service) const fn artifact_classification_from_capsule(
    value: runtrue_workflow_ir::ArtifactClassification,
) -> ArtifactClassification {
    match value {
        runtrue_workflow_ir::ArtifactClassification::UntrustedBuild => {
            ArtifactClassification::UntrustedBuild
        }
        runtrue_workflow_ir::ArtifactClassification::Quarantined => {
            ArtifactClassification::Quarantined
        }
        runtrue_workflow_ir::ArtifactClassification::VerifiedTestOutput => {
            ArtifactClassification::VerifiedTestOutput
        }
        runtrue_workflow_ir::ArtifactClassification::ReleaseCandidate => {
            ArtifactClassification::ReleaseCandidate
        }
        runtrue_workflow_ir::ArtifactClassification::PromotedRelease => {
            ArtifactClassification::PromotedRelease
        }
        runtrue_workflow_ir::ArtifactClassification::Sensitive => ArtifactClassification::Sensitive,
        runtrue_workflow_ir::ArtifactClassification::Public => ArtifactClassification::Public,
    }
}
