use super::{
    control_plane_status, duration_millis, job_state_name, lease_offer, now_unix_ms,
    proto_duration, proto_timestamp, require_session_lease, timestamp_millis,
    validate_active_state, validate_bounded_text, validate_capsule_binding,
    validate_identifier_status, validate_observed_timestamp, validate_runner_message_identity,
    RunnerControlService, RunnerSession, MAX_ACTIVE_LEASES_PER_RUNNER, MAX_LIST_ITEMS,
    MAX_LOG_FRAMES_PER_BATCH, MAX_LOG_FRAME_BYTES,
};
use runtrue_control_plane::{AppendRunnerLogsRequest, ControlPlaneError, RunnerLogFrameRecord};
use runtrue_lifecycle::JobState;
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_scheduler::{Lease, LeaseState, RunnerStatus};
use runtrue_workflow_ir::ExecutionCapsule;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tonic::Status;
impl RunnerControlService {
    pub(super) async fn handle_heartbeat(
        &self,
        session: &Arc<RunnerSession>,
        heartbeat: &v1::Heartbeat,
    ) -> Result<(), Status> {
        validate_runner_message_identity(session, &heartbeat.runner_id)?;
        if heartbeat.connection_id != session.connection_id {
            return Err(Status::permission_denied(
                "heartbeat connection id does not match the Open session",
            ));
        }
        let now = now_unix_ms()?;
        validate_observed_timestamp(heartbeat.observed_at.as_ref(), now)?;
        self.inner
            .control_plane
            .mark_runner_connected(&session.runner_id, now)
            .map_err(control_plane_status)?;
        if heartbeat.active_leases.len() > MAX_ACTIVE_LEASES_PER_RUNNER {
            return Err(Status::resource_exhausted(
                "runner reported too many active leases",
            ));
        }
        let mut seen = BTreeSet::new();
        for active in &heartbeat.active_leases {
            validate_identifier_status("lease id", &active.lease_id)?;
            validate_active_state(&active.state)?;
            if !seen.insert((active.lease_id.clone(), active.fencing_generation)) {
                return Err(Status::invalid_argument("duplicate active lease heartbeat"));
            }
            require_session_lease(session, &active.lease_id, active.fencing_generation, true)?;
            let lease = self.bound_lease(
                &session.runner_id,
                &active.lease_id,
                active.fencing_generation,
            )?;
            if !matches!(
                lease.state,
                LeaseState::Active | LeaseState::CancelRequested
            ) {
                return Err(Status::failed_precondition("heartbeat lease is not active"));
            }
            let extension_ms = duration_millis(self.inner.config.lease_extension)?;
            let new_expiry = now
                .checked_add(extension_ms)
                .ok_or_else(|| Status::out_of_range("heartbeat lease expiry overflow"))?;
            self.inner
                .control_plane
                .heartbeat_lease(
                    &lease.id,
                    &session.runner_id,
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    now,
                    new_expiry,
                )
                .map_err(control_plane_status)?;
        }
        self.synchronize_session(session, now).await
    }

    pub(super) async fn handle_lease_decision(
        &self,
        session: &Arc<RunnerSession>,
        decision: &v1::LeaseDecision,
    ) -> Result<(), Status> {
        validate_identifier_status("lease id", &decision.lease_id)?;
        validate_bounded_text("lease rejection code", &decision.rejection_code, true)?;
        validate_bounded_text("lease decision detail", &decision.detail, true)?;
        if decision.accepted && (!decision.rejection_code.is_empty() || !decision.detail.is_empty())
        {
            return Err(Status::invalid_argument(
                "accepted lease decision cannot include rejection fields",
            ));
        }
        {
            let state = session.state()?;
            if state.accepted.get(&decision.lease_id) == Some(&decision.fencing_generation)
                && decision.accepted
            {
                return Ok(());
            }
            if state.offered.get(&decision.lease_id) != Some(&decision.fencing_generation) {
                return Err(Status::permission_denied(
                    "lease decision does not match an offer on this connection",
                ));
            }
        }
        let lease = self.bound_lease(
            &session.runner_id,
            &decision.lease_id,
            decision.fencing_generation,
        )?;
        let now = now_unix_ms()?;
        if decision.accepted {
            self.inner
                .control_plane
                .accept_lease(
                    &lease.id,
                    &session.runner_id,
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    now,
                )
                .map_err(control_plane_status)?;
            let mut state = session.state()?;
            state.offered.remove(&lease.id);
            state.accepted.insert(lease.id, lease.fencing_generation);
        } else {
            self.inner
                .control_plane
                .reject_lease_with_code(
                    &lease.id,
                    &session.runner_id,
                    lease.fencing_generation,
                    lease.installation_fencing_epoch,
                    &decision.rejection_code,
                    now,
                )
                .map_err(control_plane_status)?;
            session.state()?.offered.remove(&lease.id);
            self.offer_next(session, now).await?;
        }
        Ok(())
    }

    pub(super) fn handle_job_state(
        &self,
        session: &RunnerSession,
        update: &v1::JobStateUpdate,
    ) -> Result<(), Status> {
        validate_identifier_status("lease id", &update.lease_id)?;
        validate_bounded_text("job state", &update.state, false)?;
        validate_bounded_text("job error code", &update.error_code, true)?;
        validate_bounded_text("job state detail", &update.detail, true)?;
        validate_observed_timestamp(update.observed_at.as_ref(), now_unix_ms()?)?;
        require_session_lease(session, &update.lease_id, update.fencing_generation, true)?;
        let lease = self.bound_lease(
            &session.runner_id,
            &update.lease_id,
            update.fencing_generation,
        )?;
        let next = match update.state.as_str() {
            "preparing" => return Ok(()),
            "running" => JobState::Running,
            "finalizing" | "succeeded" | "failed" | "canceled" | "timed_out" => {
                JobState::Finalizing
            }
            _ => return Err(Status::invalid_argument("unsupported runner job state")),
        };
        match self
            .inner
            .control_plane
            .transition_job_state(&lease.job_id, next, now_unix_ms()?)
        {
            Ok(_) => Ok(()),
            Err(ControlPlaneError::InvalidTransition {
                entity: "job",
                from,
                to,
            }) if from == job_state_name(next) && to == job_state_name(next) => Ok(()),
            Err(error) => Err(control_plane_status(error)),
        }
    }

    pub(super) fn validate_step_state(
        &self,
        session: &RunnerSession,
        update: &v1::StepStateUpdate,
    ) -> Result<(), Status> {
        validate_identifier_status("lease id", &update.lease_id)?;
        validate_identifier_status("step id", &update.step_id)?;
        validate_bounded_text("step state", &update.state, false)?;
        validate_bounded_text("step error code", &update.error_code, true)?;
        validate_observed_timestamp(update.observed_at.as_ref(), now_unix_ms()?)?;
        if !matches!(
            update.state.as_str(),
            "running" | "succeeded" | "failed" | "canceled" | "timed_out" | "skipped"
        ) {
            return Err(Status::invalid_argument("unsupported runner step state"));
        }
        if let Some(output) = &update.output_digest {
            ContentDigest::try_from(output)
                .map_err(|_| Status::invalid_argument("invalid step output digest"))?;
        }
        require_session_lease(session, &update.lease_id, update.fencing_generation, true)?;
        let lease = self.bound_lease(
            &session.runner_id,
            &update.lease_id,
            update.fencing_generation,
        )?;
        if lease.state != LeaseState::Active {
            return Err(Status::failed_precondition(
                "step transitions require an active execution lease",
            ));
        }
        self.require_declared_attempt_step(&lease, update.job_attempt, &update.step_id)?;
        let key = (lease.id.clone(), update.job_attempt, update.step_id.clone());
        let mut state = session.state()?;
        let current_attempt = state.current_attempts.get(&lease.id).copied().unwrap_or(0);
        if update.job_attempt < current_attempt
            || update.job_attempt > current_attempt.saturating_add(1)
            || (update.job_attempt == current_attempt.saturating_add(1)
                && state
                    .running_steps
                    .keys()
                    .any(|(lease_id, _)| lease_id == &lease.id))
        {
            return Err(Status::failed_precondition(
                "step transition does not match the current job attempt",
            ));
        }
        if update.job_attempt > current_attempt {
            state
                .current_attempts
                .insert(lease.id.clone(), update.job_attempt);
        }
        let running_key = (lease.id.clone(), update.job_attempt);
        if update.state == "running" {
            if state.terminal_steps.contains(&key) {
                return Err(Status::failed_precondition(
                    "a terminal step cannot become running again",
                ));
            }
            match state.running_steps.get(&running_key) {
                Some(current) if current == &update.step_id => return Ok(()),
                Some(_) => {
                    return Err(Status::failed_precondition(
                        "another step is already running for this lease",
                    ));
                }
                None => {
                    state
                        .running_steps
                        .insert(running_key, update.step_id.clone());
                }
            }
        } else {
            if state.terminal_steps.contains(&key) {
                return Ok(());
            }
            match state.running_steps.get(&running_key) {
                Some(current) if current == &update.step_id => {
                    state.running_steps.remove(&running_key);
                }
                Some(_) => {
                    return Err(Status::failed_precondition(
                        "terminal transition does not match the running step",
                    ));
                }
                None if update.state == "skipped" => {}
                None => {
                    return Err(Status::failed_precondition(
                        "step was not running on this Open session",
                    ));
                }
            }
            if state.terminal_steps.len() >= MAX_LIST_ITEMS {
                return Err(Status::resource_exhausted(
                    "step transition cardinality exceeds its bound",
                ));
            }
            state.terminal_steps.insert(key);
        }
        // The Open-session transition is the fail-closed authorization source
        // for brokers. Terminal job authority remains CompleteLease.
        Ok(())
    }

    pub(super) fn validate_log_batch(
        &self,
        session: &RunnerSession,
        batch: &v1::LogBatch,
    ) -> Result<(), Status> {
        validate_identifier_status("lease id", &batch.lease_id)?;
        if batch.frames.len() > MAX_LOG_FRAMES_PER_BATCH {
            return Err(Status::resource_exhausted("log batch frame limit exceeded"));
        }
        require_session_lease(session, &batch.lease_id, batch.fencing_generation, true)?;
        let lease = self.bound_lease(
            &session.runner_id,
            &batch.lease_id,
            batch.fencing_generation,
        )?;
        let mut next_sequences = BTreeMap::new();
        let current_sequences = session.state()?.log_sequences.clone();
        for frame in &batch.frames {
            validate_identifier_status("log run id", &frame.run_id)?;
            validate_bounded_text("log job id", &frame.job_id, false)?;
            validate_identifier_status("log step id", &frame.step_id)?;
            validate_bounded_text("log stream", &frame.stream, false)?;
            validate_bounded_text("log redaction state", &frame.redaction_state, false)?;
            validate_observed_timestamp(frame.wall_time.as_ref(), now_unix_ms()?)?;
            if frame.payload.len() > MAX_LOG_FRAME_BYTES
                || !matches!(frame.stream.as_str(), "stdout" | "stderr")
                || frame.job_id.is_empty()
            {
                return Err(Status::invalid_argument("invalid bounded log frame"));
            }
            self.require_declared_attempt_step(&lease, frame.job_attempt, &frame.step_id)?;
            if session.state()?.current_attempts.get(&lease.id).copied() != Some(frame.job_attempt)
            {
                return Err(Status::failed_precondition(
                    "log frame does not match the current job attempt",
                ));
            }
            // Protocol v1 runner uses the fenced lease id as run scope because
            // LeaseOffer has no run id. Never accept a different stream scope.
            if frame.run_id != lease.id {
                return Err(Status::permission_denied(
                    "log frame does not match the fenced lease scope",
                ));
            }
            let key = (
                lease.id.clone(),
                frame.job_attempt,
                frame.step_id.clone(),
                frame.stream.clone(),
            );
            let expected = next_sequences.entry(key.clone()).or_insert_with(|| {
                current_sequences
                    .get(&key)
                    .copied()
                    .unwrap_or(frame.sequence)
            });
            if frame.sequence != *expected {
                return Err(Status::failed_precondition(
                    "log frame sequence is not the exact next value",
                ));
            }
            *expected = expected
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("log frame sequence overflow"))?;
        }
        let new_sequence_keys = next_sequences
            .keys()
            .filter(|key| !current_sequences.contains_key(*key))
            .count();
        if current_sequences.len().saturating_add(new_sequence_keys) > MAX_LIST_ITEMS {
            return Err(Status::resource_exhausted(
                "log stream sequence cardinality exceeds its bound",
            ));
        }
        let frames = batch
            .frames
            .iter()
            .map(|frame| {
                Ok(RunnerLogFrameRecord {
                    execution_lease_id: lease.id.clone(),
                    fencing_generation: lease.fencing_generation,
                    job_attempt: frame.job_attempt,
                    step_id: frame.step_id.clone(),
                    stream: frame.stream.clone(),
                    sequence: frame.sequence,
                    monotonic_nanoseconds: frame.monotonic_nanoseconds,
                    wall_time_unix_ms: timestamp_millis(frame.wall_time.as_ref())?,
                    payload: frame.payload.clone(),
                    redaction_state: frame.redaction_state.clone(),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        self.inner
            .control_plane
            .append_runner_logs(
                &AppendRunnerLogsRequest {
                    execution_lease_id: lease.id,
                    fencing_generation: lease.fencing_generation,
                    runner_id: session.runner_id.clone(),
                    frames,
                },
                now_unix_ms()?,
            )
            .map_err(control_plane_status)?;
        session.state()?.log_sequences.extend(next_sequences);
        Ok(())
    }

    pub(super) fn handle_cancellation_ack(
        &self,
        session: &RunnerSession,
        ack: &v1::CancellationAck,
    ) -> Result<(), Status> {
        validate_identifier_status("lease id", &ack.lease_id)?;
        validate_observed_timestamp(ack.observed_at.as_ref(), now_unix_ms()?)?;
        require_session_lease(session, &ack.lease_id, ack.fencing_generation, true)?;
        let lease = self.bound_lease(&session.runner_id, &ack.lease_id, ack.fencing_generation)?;
        if lease.state != LeaseState::CancelRequested {
            return Err(Status::failed_precondition(
                "cancellation acknowledgement has no active request",
            ));
        }
        session
            .state()?
            .cancellation_acks
            .insert((lease.id, lease.fencing_generation));
        Ok(())
    }

    pub(super) async fn synchronize_session(
        &self,
        session: &Arc<RunnerSession>,
        now_unix_ms: u64,
    ) -> Result<(), Status> {
        if let Some(fingerprint) = &session.certificate_fingerprint {
            self.inner
                .control_plane
                .authenticate_runner_certificate(fingerprint, now_unix_ms)
                .map_err(control_plane_status)?;
        }
        if let Some(expires_unix_ms) = session.certificate_expires_unix_ms {
            let notice_millis = duration_millis(self.inner.config.certificate_rotation_notice)?;
            let should_notify = expires_unix_ms.saturating_sub(now_unix_ms) <= notice_millis && {
                let mut state = session.state()?;
                if state.rotation_notice_sent {
                    false
                } else {
                    state.rotation_notice_sent = true;
                    true
                }
            };
            if should_notify {
                self.send_control(
                    session,
                    v1::ControlMessage {
                        body: Some(v1::control_message::Body::RotateCertificate(
                            v1::RotateCertificateNow {
                                reason: "runner certificate is nearing expiry".to_owned(),
                                deadline: Some(proto_timestamp(expires_unix_ms)),
                            },
                        )),
                    },
                )
                .await?;
            }
        }
        let recovery = self
            .inner
            .control_plane
            .recovery_state()
            .map_err(control_plane_status)?;
        if recovery.safe_mode {
            return Err(Status::unavailable(
                "installation entered restore safe mode",
            ));
        }
        let runner = self
            .inner
            .control_plane
            .runner(&session.runner_id)
            .map_err(control_plane_status)?;
        match runner.runner.status {
            RunnerStatus::Revoked | RunnerStatus::Quarantined => {
                return Err(Status::permission_denied(
                    "runner is revoked or quarantined",
                ));
            }
            RunnerStatus::Draining => {
                let grace_ms = duration_millis(self.inner.config.drain_grace_period)?;
                let deadline = now_unix_ms
                    .checked_add(grace_ms)
                    .ok_or_else(|| Status::out_of_range("drain deadline overflow"))?;
                self.send_control(
                    session,
                    v1::ControlMessage {
                        body: Some(v1::control_message::Body::DrainRunner(v1::DrainRunner {
                            reason: "runner is draining".to_owned(),
                            deadline: Some(proto_timestamp(deadline)),
                        })),
                    },
                )
                .await?;
            }
            RunnerStatus::Online | RunnerStatus::Offline => {}
        }

        let accepted = session.state()?.accepted.clone();
        for (lease_id, generation) in accepted {
            let lease = self.bound_lease(&session.runner_id, &lease_id, generation)?;
            if lease.state == LeaseState::CancelRequested
                && !session
                    .state()?
                    .cancellation_acks
                    .contains(&(lease.id.clone(), lease.fencing_generation))
            {
                self.send_control(
                    session,
                    v1::ControlMessage {
                        body: Some(v1::control_message::Body::CancelLease(v1::CancelLease {
                            lease_id: lease.id,
                            fencing_generation: lease.fencing_generation,
                            reason: "control-plane cancellation requested".to_owned(),
                            grace_period: Some(proto_duration(
                                self.inner.config.drain_grace_period,
                            )?),
                        })),
                    },
                )
                .await?;
            }
        }
        if runner.runner.status == RunnerStatus::Online {
            self.offer_next(session, now_unix_ms).await?;
        }
        Ok(())
    }

    pub(super) async fn offer_next(
        &self,
        session: &Arc<RunnerSession>,
        now_unix_ms: u64,
    ) -> Result<(), Status> {
        let _offer_guard = session.offer_lock.lock().await;
        {
            let state = session.state()?;
            if !state.offered.is_empty() || !state.accepted.is_empty() {
                return Ok(());
            }
        }
        let leases = self
            .inner
            .control_plane
            .open_leases_for_runner(&session.runner_id, MAX_ACTIVE_LEASES_PER_RUNNER + 1)
            .map_err(control_plane_status)?;
        let existing = leases.into_iter().find(|lease| {
            lease.state == LeaseState::Offered && now_unix_ms < lease.accept_by_unix_ms
        });
        let lease = match existing {
            Some(lease) => lease,
            None => match self
                .inner
                .control_plane
                .offer_next_lease_for_runner(&session.runner_id, now_unix_ms)
                .map_err(control_plane_status)?
            {
                Some(lease) => lease,
                None => return Ok(()),
            },
        };
        let (job_key, signed_capsule) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        let hard_deadline = self
            .inner
            .control_plane
            .lease_hard_deadline_unix_ms(&lease.id)
            .map_err(control_plane_status)?;
        let offer = lease_offer(
            &lease,
            hard_deadline,
            &job_key,
            &signed_capsule,
            &session.posture_digest,
        )?;
        session
            .state()?
            .offered
            .insert(lease.id.clone(), lease.fencing_generation);
        let result = self
            .send_control(
                session,
                v1::ControlMessage {
                    body: Some(v1::control_message::Body::LeaseOffer(Box::new(offer))),
                },
            )
            .await;
        if result.is_err() {
            session.state()?.offered.remove(&lease.id);
        }
        result
    }

    pub(super) fn bound_lease(
        &self,
        runner_id: &str,
        lease_id: &str,
        generation: u64,
    ) -> Result<Lease, Status> {
        let recovery = self
            .inner
            .control_plane
            .recovery_state()
            .map_err(control_plane_status)?;
        if recovery.safe_mode {
            return Err(Status::unavailable(
                "lease operations are blocked during restore safe mode",
            ));
        }
        let lease = self
            .inner
            .control_plane
            .lease(lease_id)
            .map_err(control_plane_status)?;
        if lease.runner_id != runner_id {
            return Err(Status::permission_denied("lease belongs to another runner"));
        }
        if lease.fencing_generation != generation
            || lease.installation_fencing_epoch != recovery.fencing_epoch
        {
            return Err(Status::failed_precondition(
                "lease generation or installation epoch is stale",
            ));
        }
        Ok(lease)
    }

    pub(super) fn require_declared_attempt_step(
        &self,
        lease: &Lease,
        job_attempt: u32,
        step_id: &str,
    ) -> Result<(), Status> {
        let (job_key, signed_capsule) = self
            .inner
            .control_plane
            .signed_capsule_for_lease(&lease.id)
            .map_err(control_plane_status)?;
        validate_capsule_binding(lease, &signed_capsule)?;
        let capsule: ExecutionCapsule =
            serde_json::from_slice(&signed_capsule.canonical_capsule)
                .map_err(|_| Status::internal("durable execution capsule is invalid"))?;
        let canonical = capsule
            .canonical_bytes()
            .map_err(|_| Status::internal("durable execution capsule cannot be canonicalized"))?;
        if canonical != signed_capsule.canonical_capsule
            || capsule.digest().ok() != Some(lease.capsule_digest.clone())
        {
            return Err(Status::data_loss(
                "durable signed execution capsule is not canonical",
            ));
        }
        let job = capsule
            .jobs
            .iter()
            .find(|job| job.id == job_key)
            .ok_or_else(|| Status::data_loss("signed lease job is absent from its capsule"))?;
        if job_attempt == 0 || job_attempt > job.retries.saturating_add(1) {
            return Err(Status::permission_denied(
                "job attempt exceeds the signed execution capsule",
            ));
        }
        if !job.steps.iter().any(|step| step.id == step_id) {
            return Err(Status::permission_denied(
                "step is not declared by the signed execution capsule",
            ));
        }
        Ok(())
    }
}
