use super::{
    artifact_classification_name, artifact_scan_state_name, control_plane_status, data_status,
    fetch_capsule_response, now_unix_ms, parse_v2_digest, require_session_lease,
    validate_bounded_identifiers, validate_bounded_text, validate_capsule_binding,
    validate_identifier_status, validate_observed_timestamp, AuthenticatedIdentity,
    RunnerControlService, MAX_LIST_ITEMS,
};
use runtrue_artifacts::ArtifactClassification;
use runtrue_control_plane::{
    ArtifactCatalogRecord, ControlPlaneError, ControlPlaneStore, CredentialTaintState,
};
use runtrue_lifecycle::JobState;
use runtrue_model::ContentDigest;
use runtrue_protocol::{v1, v2};
use runtrue_scheduler::LeaseState;
use runtrue_storage::PathSnapshot;
use runtrue_workflow_ir::ExecutionCapsule;
use std::{collections::BTreeSet, sync::Arc};
use tonic::Status;

type AdaptedV2Completion = (
    v1::CompleteLeaseRequest,
    Vec<(String, String)>,
    CredentialTaintState,
);

impl RunnerControlService {
    pub(super) async fn fetch_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::FetchExecutionCapsuleRequest,
    ) -> Result<v1::FetchExecutionCapsuleResponse, Status> {
        validate_identifier_status("lease id", &request.lease_id)?;
        let session = self.authenticated_session(authenticated)?;
        require_session_lease(
            &session,
            &request.lease_id,
            request.fencing_generation,
            false,
        )?;
        let lease = self
            .bound_lease(
                &authenticated.runner_id,
                &request.lease_id,
                request.fencing_generation,
            )
            .await?;
        if lease.state != LeaseState::Offered || now_unix_ms()? >= lease.accept_by_unix_ms {
            return Err(Status::failed_precondition(
                "execution capsule is available only for a current offer",
            ));
        }
        let expected = request
            .expected_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("expected capsule digest is required"))?;
        let expected = ContentDigest::try_from(expected)
            .map_err(|_| Status::invalid_argument("expected capsule digest is invalid"))?;
        if expected != lease.capsule_digest {
            return Err(Status::failed_precondition(
                "expected capsule digest does not match the lease",
            ));
        }
        let (_, capsule) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .await
            .map_err(control_plane_status)?;
        validate_capsule_binding(&lease, &capsule)?;
        fetch_capsule_response(capsule)
    }

    pub(super) async fn complete_authenticated(
        &self,
        authenticated: &AuthenticatedIdentity,
        request: v1::CompleteLeaseRequest,
        credential_taint: CredentialTaintState,
    ) -> Result<v1::CompleteLeaseResponse, Status> {
        validate_identifier_status("lease id", &request.lease_id)?;
        validate_bounded_text("completion final state", &request.final_state, false)?;
        validate_bounded_text("completion error code", &request.error_code, true)?;
        validate_bounded_identifiers("artifact id", &request.artifact_ids)?;
        validate_bounded_identifiers("cache entry id", &request.cache_entry_ids)?;
        if request.expected_log_frames > 256 {
            return Err(Status::resource_exhausted(
                "expected log frame count exceeds its bound",
            ));
        }
        let now = now_unix_ms()?;
        validate_observed_timestamp(request.completed_at.as_ref(), now)?;
        let session = self.authenticated_session(authenticated)?;
        let lease = self
            .bound_lease(
                &authenticated.runner_id,
                &request.lease_id,
                request.fencing_generation,
            )
            .await?;
        if request.installation_fencing_epoch != lease.installation_fencing_epoch {
            return Err(Status::failed_precondition(
                "completion installation epoch is stale",
            ));
        }
        if lease.state != LeaseState::Completed {
            require_session_lease(
                &session,
                &request.lease_id,
                request.fencing_generation,
                true,
            )?;
            if session
                .state()?
                .running_steps
                .keys()
                .any(|(lease_id, _)| lease_id == &request.lease_id)
            {
                return Err(Status::failed_precondition(
                    "a running step must terminate before lease completion",
                ));
            }
            if session
                .state()?
                .current_attempts
                .get(&request.lease_id)
                .copied()
                .unwrap_or(0)
                != request.final_job_attempt
            {
                return Err(Status::failed_precondition(
                    "completion does not match the current job attempt",
                ));
            }
            let persisted_log_frames = self
                .inner
                .control_plane
                .runner_log_frame_count(&lease.id)
                .await
                .map_err(control_plane_status)?;
            if persisted_log_frames < u64::from(request.expected_log_frames) {
                return Err(Status::failed_precondition(
                    "completion logs have not been durably persisted",
                ));
            }
        }
        let result_digest = request
            .result_digest
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("completion result digest is required"))?;
        let result_digest = ContentDigest::try_from(result_digest)
            .map_err(|_| Status::invalid_argument("completion result digest is invalid"))?;
        let final_state = parse_completion_state(&request.final_state)?;
        let (job_key, signed) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .await
            .map_err(control_plane_status)?;
        validate_capsule_binding(&lease, &signed)?;
        let capsule: ExecutionCapsule = serde_json::from_slice(&signed.canonical_capsule)
            .map_err(|_| Status::data_loss("durable execution capsule is invalid"))?;
        let required_artifacts: Vec<String> = capsule
            .jobs
            .iter()
            .find(|job| job.id == job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is missing"))?
            .outputs
            .keys()
            .cloned()
            .collect();
        if lease.state != LeaseState::Completed {
            // Job-state updates and lease completion arrive on independent RPCs.
            // The completion is already authenticated and fenced to this exact
            // active lease, so accept either arrival order without requiring the
            // runner to race a control-stream update against this request.
            ensure_job_finalizing(self.inner.control_plane.as_ref(), &lease.job_id, now).await?;
        }
        let completed = self
            .inner
            .control_plane
            .complete_runner_lease(
                &lease.id,
                &authenticated.runner_id,
                lease.fencing_generation,
                lease.installation_fencing_epoch,
                &result_digest,
                final_state,
                credential_taint,
                request.final_job_attempt,
                &request.artifact_ids,
                &request.cache_entry_ids,
                &required_artifacts,
                now,
            )
            .await
            .map_err(control_plane_status)?;
        self.catalog_completed_artifacts(&request.artifact_ids, request.final_job_attempt)
            .await?;
        if self
            .authenticated_session(authenticated)
            .is_ok_and(|current| Arc::ptr_eq(&current, &session))
        {
            {
                let mut state = session.state()?;
                state.offered.remove(&completed.id);
                state.accepted.remove(&completed.id);
                state
                    .cancellation_acks
                    .remove(&(completed.id.clone(), completed.fencing_generation));
                state
                    .log_sequences
                    .retain(|(lease_id, _, _, _), _| lease_id != &completed.id);
                state
                    .running_steps
                    .retain(|(lease_id, _), _| lease_id != &completed.id);
                state
                    .terminal_steps
                    .retain(|(lease_id, _, _)| lease_id != &completed.id);
                state.current_attempts.remove(&completed.id);
            }
            self.offer_next(&session, now).await?;
        }
        Ok(v1::CompleteLeaseResponse {
            accepted: true,
            resulting_job_state: request.final_state,
        })
    }

    pub(super) async fn catalog_completed_artifacts(
        &self,
        artifact_ids: &[String],
        job_attempt: u32,
    ) -> Result<(), Status> {
        if artifact_ids.is_empty() {
            return Ok(());
        }
        let data = self.data_plane()?;
        for artifact_id in artifact_ids {
            let artifact_id = ContentDigest::parse(artifact_id.clone())
                .map_err(|_| Status::invalid_argument("artifact id is invalid"))?;
            let artifact = data.artifacts.load(&artifact_id).map_err(data_status)?;
            let record = &artifact.record;
            let manifest_digest = match &record.content {
                PathSnapshot::File { digest, .. } => digest.clone(),
                PathSnapshot::Directory {
                    manifest_digest, ..
                } => manifest_digest.clone(),
            };
            let classification = artifact_classification_name(record.classification).to_owned();
            let scan_state = artifact_scan_state_name(&record.scan_state).to_owned();
            let state = if matches!(
                record.classification,
                ArtifactClassification::UntrustedBuild | ArtifactClassification::Quarantined
            ) {
                "quarantined"
            } else {
                "available"
            };
            self.inner
                .control_plane
                .catalog_artifact(&ArtifactCatalogRecord {
                    artifact_id: artifact.artifact_id.to_string(),
                    tenant_id: record.tenant_id.clone(),
                    repository_id: record.repository_id.clone(),
                    run_id: record.run_id.clone(),
                    job_id: record.job_id.clone(),
                    job_attempt,
                    step_id: record.step_id.clone(),
                    output_name: record.name.clone(),
                    content_digest: record.content_digest.clone(),
                    manifest_digest,
                    provenance_digest: record.provenance.statement_digest.clone(),
                    size_bytes: record.size_bytes,
                    media_type: record.media_type.clone(),
                    classification,
                    scan_state,
                    retention_until_unix_seconds: record.retention_until_unix_seconds,
                    legal_hold: record.legal_hold,
                    state: state.to_owned(),
                    created_unix_ms: record.committed_at_unix_seconds.saturating_mul(1_000),
                })
                .await
                .map_err(control_plane_status)?;
        }
        Ok(())
    }
}
impl RunnerControlService {
    pub(super) fn adapt_v2_completion(
        &self,
        request: v2::CompleteLeaseRequest,
    ) -> Result<AdaptedV2Completion, Status> {
        if request.committed_objects.len() > MAX_LIST_ITEMS {
            return Err(Status::resource_exhausted(
                "committed object list exceeds its bound",
            ));
        }
        let final_state = match v2::LeaseFinalState::try_from(request.final_state)
            .map_err(|_| Status::invalid_argument("completion final state is invalid"))?
        {
            v2::LeaseFinalState::Succeeded => "succeeded",
            v2::LeaseFinalState::Failed => "failed",
            v2::LeaseFinalState::Canceled => "canceled",
            v2::LeaseFinalState::TimedOut => "timed_out",
            v2::LeaseFinalState::Unspecified => {
                return Err(Status::invalid_argument(
                    "completion final state is unspecified",
                ))
            }
        };
        let result_digest =
            parse_v2_digest(&request.result_digest_algorithm, &request.result_digest)?;
        let credential_taint = match v2::CredentialTaintState::try_from(request.credential_taint)
            .map_err(|_| Status::invalid_argument("credential taint state is invalid"))?
        {
            v2::CredentialTaintState::Unspecified => CredentialTaintState::Unknown,
            v2::CredentialTaintState::None => CredentialTaintState::None,
            v2::CredentialTaintState::CredentialReleased => {
                CredentialTaintState::CredentialReleased
            }
        };
        let mut seen = BTreeSet::new();
        let mut artifact_ids = Vec::new();
        let mut artifact_claims = Vec::new();
        let mut cache_entry_ids = Vec::new();
        for object in request.committed_objects {
            validate_identifier_status("committed object id", &object.object_id)?;
            if object.job_attempt == 0 || object.job_attempt != request.final_job_attempt {
                return Err(Status::failed_precondition(
                    "committed object attempt does not match completion",
                ));
            }
            let kind = v2::CommittedObjectKind::try_from(object.kind)
                .map_err(|_| Status::invalid_argument("committed object kind is invalid"))?;
            if !seen.insert((kind as i32, object.object_id.clone())) {
                return Err(Status::invalid_argument(
                    "committed object list contains duplicates",
                ));
            }
            match (kind, object.declaration_name) {
                (v2::CommittedObjectKind::Cache, None) => {
                    cache_entry_ids.push(object.object_id);
                }
                (v2::CommittedObjectKind::Artifact, Some(name)) => {
                    validate_identifier_status("artifact declaration name", &name)?;
                    artifact_claims.push((object.object_id.clone(), name));
                    artifact_ids.push(object.object_id);
                }
                (v2::CommittedObjectKind::Unspecified, _)
                | (v2::CommittedObjectKind::Cache, Some(_))
                | (v2::CommittedObjectKind::Artifact, None) => {
                    return Err(Status::invalid_argument(
                        "committed object kind and declaration do not match",
                    ))
                }
            }
        }
        Ok((
            v1::CompleteLeaseRequest {
                lease_id: request.lease_id,
                fencing_generation: request.fencing_generation,
                installation_fencing_epoch: request.installation_fencing_epoch,
                final_state: final_state.to_owned(),
                exit_code: request.exit_code,
                error_code: request.error_code,
                result_digest: Some(v1::Digest::try_from(&result_digest).map_err(|_| {
                    Status::invalid_argument("completion result digest is invalid")
                })?),
                artifact_ids,
                cache_entry_ids,
                completed_at: request.completed_at,
                final_job_attempt: request.final_job_attempt,
                expected_log_frames: request.expected_log_frames,
            },
            artifact_claims,
            credential_taint,
        ))
    }
}

pub(super) fn parse_completion_state(value: &str) -> Result<JobState, Status> {
    match value {
        "succeeded" => Ok(JobState::Succeeded),
        "failed" => Ok(JobState::Failed),
        "canceled" => Ok(JobState::Canceled),
        "timed_out" => Ok(JobState::TimedOut),
        _ => Err(Status::invalid_argument(
            "completion final state is unsupported",
        )),
    }
}

pub(super) async fn ensure_job_finalizing(
    control_plane: &dyn ControlPlaneStore,
    job_id: &str,
    now_unix_ms: u64,
) -> Result<(), Status> {
    match control_plane
        .transition_job_state(job_id, JobState::Finalizing, now_unix_ms)
        .await
    {
        Ok(_) => Ok(()),
        Err(ControlPlaneError::InvalidTransition {
            entity: "job",
            from: "finalizing",
            to: "finalizing",
        }) => Ok(()),
        Err(error) => Err(control_plane_status(error)),
    }
}

pub(super) const fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Created => "created",
        JobState::BlockedPolicy => "blocked_policy",
        JobState::AwaitingApproval => "awaiting_approval",
        JobState::Queued => "queued",
        JobState::Leased => "leased",
        JobState::Preparing => "preparing",
        JobState::Running => "running",
        JobState::Finalizing => "finalizing",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Canceled => "canceled",
        JobState::TimedOut => "timed_out",
        JobState::Lost => "lost",
        JobState::Rejected => "rejected",
        JobState::Skipped => "skipped",
    }
}
