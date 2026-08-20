use crate::{
    credentials::RunnerCredentialStore,
    enrollment::{generate_certificate_request, pending_rotation_response},
    state::{ActiveLeaseMarker, RunnerStateStore, WorkspaceManager},
    transport::RunnerTransport,
    VerifiedInventory,
};
use runtrue_engine::{CancellationToken, StepStateObservation, StepStateObserver};
use runtrue_model::ContentDigest;
use runtrue_protocol::{supports_protocol_version, v1};
use runtrue_runner_core::{CapsuleTrustStore, LeaseCompletion, RunnerAdmission};
use runtrue_workflow_ir::Isolation;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    sync::mpsc as tokio_mpsc,
    time::{Interval, MissedTickBehavior},
};

const LOG_BATCH_FRAMES: usize = 32;
const MAX_NATIVE_STEPS: usize = 64;
const MAX_ADVERTISED_LOCALITY_ITEMS: usize = 256;
const LEASE_SHUTDOWN_MARGIN_MILLIS: u64 = 250;
const ROTATION_SHUTDOWN_MARGIN_MILLIS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Daemon,
    Once,
}

#[derive(Debug, Clone)]
pub struct RunnerDaemonConfig {
    pub runner_id: String,
    pub inventory: VerifiedInventory,
    pub trust_store: CapsuleTrustStore,
    pub allow_trusted_native: bool,
    pub mode: RunMode,
    pub max_capsule_bytes: usize,
    pub credential_store: Option<RunnerCredentialStore>,
    /// Optional host-local gate coordinating reusable OCI image admission with
    /// lease execution. A permit is retained for the complete active lease.
    pub admission_lock: Option<PathBuf>,
    pub max_concurrent_wasm_jobs: u32,
}

use super::{
    admission_gate::{spawn_admission_bound_blocking, LeaseAdmissionGate, PermitAttempt},
    clock::failed_execution_outcome,
    clock::{
        deadline_instant, duration, now_unix_ms, random_connection_id, timestamp, timestamp_millis,
        validate_runner_id, wait_until, ServerClock,
    },
    error::RunnerError,
    executor::{JobExecutionServices, JobExecutor, PreparedContentTier},
    lifecycle::{ActiveExecution, CompletedExecution, ExecutionTaskMessage, LoopEvent},
    observations::{step_error_code, step_state_name, DaemonStepStateObserver},
    remote::offered_job,
    source::hydrate_source,
};

pub struct RunnerDaemon<T, E> {
    transport: T,
    executor: E,
    config: RunnerDaemonConfig,
    state: RunnerStateStore,
    workspaces: WorkspaceManager,
    admission_gate: Option<LeaseAdmissionGate>,
}

struct OfferPreparation<'a> {
    connection_id: &'a str,
    heartbeat_interval: &'a mut Interval,
    runner_empty: bool,
    completion_sender: tokio_mpsc::Sender<ExecutionTaskMessage>,
    lifecycle_sender: tokio_mpsc::Sender<super::observations::StepLifecycleMessage>,
}

impl<T, E> RunnerDaemon<T, E>
where
    T: RunnerTransport,
    E: JobExecutor,
{
    #[must_use]
    pub fn new(
        transport: T,
        executor: E,
        config: RunnerDaemonConfig,
        state: RunnerStateStore,
        workspaces: WorkspaceManager,
    ) -> Self {
        let admission_gate = config.admission_lock.clone().map(LeaseAdmissionGate::new);
        Self {
            transport,
            executor,
            config,
            state,
            workspaces,
            admission_gate,
        }
    }

    pub async fn run(mut self) -> Result<(), RunnerError> {
        validate_runner_id(&self.config.runner_id)?;
        if self.config.inventory.profile.runner_id != self.config.runner_id {
            return Err(RunnerError::InventoryRunnerMismatch);
        }
        if self.config.max_concurrent_wasm_jobs
            != self.config.inventory.profile.max_concurrent_wasm_jobs
        {
            return Err(RunnerError::InventoryWasmConcurrencyMismatch);
        }
        self.config.inventory.profile.validate()?;
        if let Some(gate) = self.admission_gate.as_ref() {
            gate.validate()?;
        }
        self.executor.cleanup_stale()?;
        let protocol_version = self.config.inventory.wire.protocol_version;
        if !supports_protocol_version(protocol_version) {
            return Err(RunnerError::InventoryProtocolMismatch);
        }
        self.workspaces.remove_all_stale()?;
        self.state.clear_stale_active_marker()?;
        if let Some(store) = self.config.credential_store.clone() {
            store.reconcile_pending_rotation()?;
            if store.load_pending_rotation()?.is_some() {
                self.rotate_credentials().await?;
                return Err(RunnerError::CertificateRotated);
            }
        }

        let connection_id = random_connection_id()?;
        let hello = v1::RunnerHello {
            runner_id: self.config.runner_id.clone(),
            connection_id: connection_id.clone(),
            protocol_version,
            inventory: Some(self.config.inventory.wire.clone()),
        };
        let control_hello = self.transport.open(hello).await?;
        if control_hello.connection_id != connection_id {
            return Err(RunnerError::ConnectionIdMismatch);
        }
        let heartbeat_period = duration(control_hello.heartbeat_interval.as_ref())?;
        let server_time = timestamp_millis(control_hello.server_time.as_ref())?;
        let local_time = now_unix_ms()?;
        let clock = ServerClock::new(local_time, server_time)?;
        self.state
            .accept_installation_epoch(control_hello.installation_fencing_epoch)?;
        let mut admission = RunnerAdmission::new(
            self.config.trust_store.clone(),
            self.config.inventory.profile.clone(),
            control_hello.installation_fencing_epoch,
        )?;
        admission.set_max_capsule_bytes(self.config.max_capsule_bytes)?;
        self.send_locality().await?;

        let mut interval = tokio::time::interval(heartbeat_period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut active = BTreeMap::<String, ActiveExecution>::new();
        let channel_capacity = usize::try_from(self.config.max_concurrent_wasm_jobs)
            .unwrap_or(1)
            .max(1)
            .saturating_mul(8);
        let (completion_sender, mut completion_receiver) =
            tokio_mpsc::channel::<ExecutionTaskMessage>(channel_capacity);
        let (lifecycle_sender, mut lifecycle_receiver) = tokio_mpsc::channel(channel_capacity);
        let mut draining = false;
        let mut drain_deadline = None;
        let mut rotation_requested = false;
        let mut rotation_deadline = None;
        let mut processed_one = self.state.has_pending_completions();
        let maximum_active = if self.config.mode == RunMode::Once {
            1
        } else {
            self.config.max_concurrent_wasm_jobs.max(1) as usize
        };

        loop {
            if rotation_requested && active.is_empty() {
                self.rotate_credentials().await?;
                return Err(RunnerError::CertificateRotated);
            }
            let completion_accepted = self.retry_pending_completion().await?;
            if completion_accepted {
                if self.config.mode == RunMode::Once && processed_one {
                    return Ok(());
                }
                if draining && active.is_empty() {
                    return Ok(());
                }
            }

            let lease_deadline = active
                .values()
                .filter_map(|execution| execution.hard_deadline)
                .min();
            let event = tokio::select! {
                result = completion_receiver.recv() => LoopEvent::ExecutionFinished(result),
                lifecycle = lifecycle_receiver.recv() => LoopEvent::StepLifecycle(lifecycle),
                _ = interval.tick() => LoopEvent::Heartbeat,
                _ = wait_until(lease_deadline) => LoopEvent::LeaseDeadline,
                _ = wait_until(drain_deadline) => LoopEvent::DrainDeadline,
                _ = wait_until(rotation_deadline) => LoopEvent::RotationDeadline,
                control = self.transport.next_control() => LoopEvent::Control(control?),
            };

            match event {
                LoopEvent::Heartbeat => {
                    self.send_heartbeat(&connection_id, &active).await?;
                }
                LoopEvent::Control(None) => return Err(RunnerError::ControlStreamClosed),
                LoopEvent::Control(Some(message)) => match message.body {
                    Some(v1::control_message::Body::LeaseOffer(offer)) => {
                        if rotation_requested || draining || active.len() >= maximum_active {
                            let code = if rotation_requested {
                                "certificate_rotation_pending"
                            } else if draining {
                                "runner_draining"
                            } else {
                                "runner_busy"
                            };
                            self.reject_offer(&offer, code).await?;
                        } else {
                            let execution = self
                                .prepare_offer(
                                    &admission,
                                    &clock,
                                    *offer,
                                    OfferPreparation {
                                        connection_id: &connection_id,
                                        heartbeat_interval: &mut interval,
                                        runner_empty: active.is_empty(),
                                        completion_sender: completion_sender.clone(),
                                        lifecycle_sender: lifecycle_sender.clone(),
                                    },
                                )
                                .await?;
                            if let Some(execution) = execution {
                                active.insert(execution.offer.lease_id.clone(), execution);
                                processed_one = true;
                            } else if self.config.mode == RunMode::Once {
                                self.transport.close().await?;
                                return Ok(());
                            }
                        }
                    }
                    Some(v1::control_message::Body::CancelLease(cancel)) => {
                        if let Some(execution) = active.get_mut(&cancel.lease_id) {
                            if execution.offer.fencing_generation == cancel.fencing_generation {
                                execution.guard.authorize_active(
                                    &cancel.lease_id,
                                    cancel.fencing_generation,
                                    execution.offer.installation_fencing_epoch,
                                    clock.now()?,
                                )?;
                                execution.cancellation.cancel();
                                self.send_cancellation_ack(&cancel).await?;
                            }
                        }
                    }
                    Some(v1::control_message::Body::DrainRunner(drain)) => {
                        draining = true;
                        if !rotation_requested
                            && active.is_empty()
                            && !self.state.has_pending_completions()
                        {
                            return Ok(());
                        }
                        let deadline = timestamp_millis(drain.deadline.as_ref())?;
                        match deadline_instant(&clock, deadline, 0) {
                            Ok(deadline) => drain_deadline = Some(deadline),
                            Err(RunnerError::DeadlineElapsed) => {
                                for execution in active.values() {
                                    execution.cancellation.cancel();
                                }
                                drain_deadline = None;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Some(v1::control_message::Body::RotateCertificate(rotate)) => {
                        let deadline = timestamp_millis(rotate.deadline.as_ref())?;
                        rotation_requested = true;
                        match deadline_instant(&clock, deadline, ROTATION_SHUTDOWN_MARGIN_MILLIS) {
                            Ok(deadline) => rotation_deadline = Some(deadline),
                            Err(RunnerError::DeadlineElapsed) => {
                                for execution in active.values() {
                                    execution.cancellation.cancel();
                                }
                                rotation_deadline = None;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Some(v1::control_message::Body::InvalidateContent(_)) => {
                        // This runner has no reusable content cache yet.
                    }
                    Some(v1::control_message::Body::Hello(_)) | None => {
                        return Err(RunnerError::UnexpectedControlMessage)
                    }
                },
                LoopEvent::StepLifecycle(Some(message)) => {
                    let execution = active
                        .get_mut(&message.lease_id)
                        .expect("step lifecycle event requires active execution");
                    let result = self
                        .send_step_state(&execution.offer, &message.observation)
                        .await;
                    match result {
                        Ok(()) => {
                            execution.last_job_attempt = execution
                                .last_job_attempt
                                .max(message.observation.job_attempt);
                            let _ = message.response.send(Ok(()));
                        }
                        Err(error) => {
                            let _ = message.response.send(Err(error.to_string()));
                            return Err(error);
                        }
                    }
                }
                LoopEvent::StepLifecycle(None) => return Err(RunnerError::ControlStreamClosed),
                LoopEvent::ExecutionFinished(Some(message)) => {
                    let execution = active
                        .remove(&message.lease_id)
                        .expect("active task produced event");
                    let completed = match message.result {
                        Ok(Ok(outcome)) => outcome,
                        Ok(Err(error)) => {
                            eprintln!("runner execution failed: {error}");
                            CompletedExecution {
                                outcome: failed_execution_outcome(execution.last_job_attempt),
                                committed_objects: Vec::new(),
                            }
                        }
                        Err(error) => {
                            eprintln!("runner execution task failed: {error}");
                            CompletedExecution {
                                outcome: failed_execution_outcome(execution.last_job_attempt),
                                committed_objects: Vec::new(),
                            }
                        }
                    };
                    self.finish_execution(execution, completed, &clock).await?;
                    if !rotation_requested
                        && self.config.mode == RunMode::Once
                        && !self.state.has_pending_completions()
                    {
                        return Ok(());
                    }
                    if !rotation_requested
                        && draining
                        && active.is_empty()
                        && !self.state.has_pending_completions()
                    {
                        return Ok(());
                    }
                }
                LoopEvent::ExecutionFinished(None) => return Err(RunnerError::ControlStreamClosed),
                LoopEvent::LeaseDeadline => {
                    let now = tokio::time::Instant::now();
                    for execution in active.values_mut() {
                        if execution
                            .hard_deadline
                            .is_some_and(|deadline| deadline <= now)
                        {
                            execution.hard_deadline = None;
                            execution.cancellation.cancel();
                        }
                    }
                }
                LoopEvent::DrainDeadline => {
                    drain_deadline = None;
                    for execution in active.values() {
                        execution.cancellation.cancel();
                    }
                }
                LoopEvent::RotationDeadline => {
                    rotation_deadline = None;
                    for execution in active.values() {
                        execution.cancellation.cancel();
                    }
                }
            }
        }
    }

    async fn rotate_credentials(&mut self) -> Result<(), RunnerError> {
        let store = self
            .config
            .credential_store
            .clone()
            .ok_or(RunnerError::CertificateRotationUnavailable)?;
        let current = store.load_current()?;
        if current.runner_id != self.config.runner_id {
            return Err(RunnerError::InventoryRunnerMismatch);
        }
        let pending = match store.load_pending_rotation()? {
            Some(pending) => pending,
            None => {
                let generated = generate_certificate_request()?;
                store.begin_rotation(&current, generated.private_key_pem, generated.csr_der)?
            }
        };
        if pending.runner_id != current.runner_id || pending.pool_id != current.pool_id {
            return Err(RunnerError::InventoryRunnerMismatch);
        }
        if pending.response.is_none() {
            let response = self
                .transport
                .rotate_certificate(v1::RotateCertificateRequest {
                    runner_id: self.config.runner_id.clone(),
                    certificate_signing_request: pending.csr_der.clone(),
                    attestation: None,
                })
                .await?;
            let csr_digest = ContentDigest::sha256(&pending.csr_der);
            store.record_rotation_response(pending_rotation_response(response, &csr_digest)?)?;
        }
        store.install_pending_rotation()?;
        Ok(())
    }

    async fn prepare_offer(
        &mut self,
        admission: &RunnerAdmission,
        clock: &ServerClock,
        offer: v1::LeaseOffer,
        preparation: OfferPreparation<'_>,
    ) -> Result<Option<ActiveExecution>, RunnerError> {
        let OfferPreparation {
            connection_id,
            heartbeat_interval,
            runner_empty,
            completion_sender,
            lifecycle_sender,
        } = preparation;
        if offer.runner_id != self.config.runner_id {
            self.reject_offer(&offer, "wrong_runner").await?;
            return Ok(None);
        }
        let admission_permit = match self.admission_gate.as_ref() {
            Some(gate) => match gate.try_acquire()? {
                PermitAttempt::Acquired(permit) => Some(Arc::new(permit)),
                PermitAttempt::AdmissionPending => {
                    self.reject_offer(&offer, "image_admission_pending").await?;
                    return Ok(None);
                }
            },
            None => None,
        };
        let Some(expected_digest) = offer.capsule_digest.clone() else {
            self.reject_offer(&offer, "invalid_offer").await?;
            return Ok(None);
        };
        let fetched = match self
            .transport
            .fetch_capsule(v1::FetchExecutionCapsuleRequest {
                lease_id: offer.lease_id.clone(),
                fencing_generation: offer.fencing_generation,
                expected_digest: Some(expected_digest),
            })
            .await
        {
            Ok(fetched) => fetched,
            Err(error) => {
                eprintln!(
                    "runtrue-runner: capsule fetch failed for lease `{}`: {error}",
                    offer.lease_id
                );
                self.reject_offer(&offer, "capsule_fetch_failed").await?;
                return Ok(None);
            }
        };
        let admitted = match admission.admit(&offer, &fetched, clock.now()?) {
            Ok(admitted) => admitted,
            Err(error) => {
                eprintln!(
                    "runtrue-runner: admission rejected lease `{}` for job `{}`: {error}",
                    offer.lease_id, offer.job_id
                );
                self.reject_offer(&offer, "admission_rejected").await?;
                return Ok(None);
            }
        };
        let job = admitted
            .capsule
            .jobs
            .iter()
            .find(|job| job.id == admitted.job_id)
            .ok_or_else(|| RunnerError::OfferedJobMissing(admitted.job_id.clone()))?;
        if self.config.inventory.wire.protocol_version < 2
            && admitted.capsule.context.source_tree_digest.is_some()
        {
            self.reject_offer(&offer, "protocol_generation_unsupported")
                .await?;
            return Ok(None);
        }
        if !self
            .config
            .inventory
            .profile
            .isolation_backends
            .contains(&job.runner.isolation)
        {
            self.reject_offer(&offer, "unsupported_isolation").await?;
            return Ok(None);
        }
        if !runner_empty && job.runner.isolation != Isolation::Wasm {
            self.reject_offer(&offer, "runner_busy").await?;
            return Ok(None);
        }
        if job.runner.isolation == Isolation::Native && !self.config.allow_trusted_native {
            self.reject_offer(&offer, "trusted_native_disabled").await?;
            return Ok(None);
        }
        if job.steps.len() > MAX_NATIVE_STEPS {
            self.reject_offer(&offer, "job_resource_limit").await?;
            return Ok(None);
        }
        let broker = self.transport.broker_client();
        if let Err(error) = self
            .executor
            .preflight_with_broker(&admitted, broker.clone())
        {
            let rejection_code = error.preflight_rejection_code();
            eprintln!(
                "runtrue-runner: executor preflight rejected job `{}`: {error}",
                offer.job_id
            );
            self.reject_offer(&offer, rejection_code).await?;
            return Ok(None);
        }
        if clock.now()? >= admitted.accept_by_unix_ms {
            self.reject_offer(&offer, "accept_deadline_elapsed").await?;
            return Ok(None);
        }
        let hard_deadline = match deadline_instant(
            clock,
            admitted.hard_deadline_unix_ms,
            LEASE_SHUTDOWN_MARGIN_MILLIS,
        ) {
            Ok(deadline) => deadline,
            Err(RunnerError::DeadlineElapsed) => {
                self.reject_offer(&offer, "lease_window_too_short").await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        let workspace = self
            .workspaces
            .create(&offer.lease_id, offer.fencing_generation)?;
        let workspace_name = workspace
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| RunnerError::InvalidWorkspace(workspace.clone()))?
            .to_owned();
        self.state.mark_active(ActiveLeaseMarker {
            lease_id: offer.lease_id.clone(),
            fencing_generation: offer.fencing_generation,
            installation_fencing_epoch: offer.installation_fencing_epoch,
            workspace_name,
        })?;
        let mut guard = admitted.clone().into_guard();
        guard.start(
            &offer.lease_id,
            offer.fencing_generation,
            offer.installation_fencing_epoch,
            clock.now()?,
        )?;
        if let Err(error) = self.send_decision(&offer, true, "", "").await {
            self.state.clear_active_lease(&offer.lease_id)?;
            self.workspaces.cleanup(&workspace)?;
            return Err(error);
        }
        if admitted.capsule.context.source_tree_digest.is_some() {
            self.send_job_state(&offer, "preparing", "", "source_hydration")
                .await?;
            let hydration_lease = admitted.clone();
            let hydration_workspace = workspace.clone();
            let hydration_manager = self.workspaces.clone();
            let hydration_broker = broker.clone().ok_or(RunnerError::BrokerUnavailable)?;
            let hydration_cancelled = Arc::new(AtomicBool::new(false));
            let task_cancelled = hydration_cancelled.clone();
            let hydration_admission_permit = admission_permit.clone();
            let mut hydration =
                spawn_admission_bound_blocking(hydration_admission_permit, move || {
                    hydrate_source(
                        &hydration_lease,
                        &hydration_workspace,
                        &hydration_manager,
                        hydration_broker,
                        task_cancelled,
                    )
                });
            let mut cancelled = false;
            let hydration = loop {
                tokio::select! {
                    result = &mut hydration => break result,
                    _ = heartbeat_interval.tick() => {
                        self.send_lease_heartbeat(
                            connection_id,
                            &offer,
                            "preparing",
                        ).await?;
                    }
                    control = self.transport.next_control() => {
                        let control = match control {
                            Ok(control) => control,
                            Err(error) => {
                                hydration_cancelled.store(true, Ordering::Release);
                                let _ = hydration.await;
                                return Err(error.into());
                            }
                        };
                        let Some(control) = control else {
                            hydration_cancelled.store(true, Ordering::Release);
                            let _ = hydration.await;
                            return Err(RunnerError::ControlStreamClosed);
                        };
                        match control.body {
                            Some(v1::control_message::Body::CancelLease(cancel))
                                if cancel.lease_id == offer.lease_id
                                    && cancel.fencing_generation == offer.fencing_generation =>
                            {
                                hydration_cancelled.store(true, Ordering::Release);
                                self.send_cancellation_ack(&cancel).await?;
                                cancelled = true;
                                break hydration.await;
                            }
                            _ => {
                                hydration_cancelled.store(true, Ordering::Release);
                                let _ = hydration.await;
                                return Err(RunnerError::UnexpectedControlMessage);
                            }
                        }
                    }
                }
            };
            let hydrated = match hydration {
                Ok(Ok(digest)) if !cancelled => digest,
                result => {
                    if !cancelled {
                        match &result {
                            Ok(Err(error)) => {
                                eprintln!("runtrue-runner: source hydration failed: {error}");
                            }
                            Err(error) => {
                                eprintln!("runtrue-runner: source hydration task failed: {error}");
                            }
                            Ok(Ok(_)) => {}
                        }
                    }
                    let (final_state, error_code, result_domain) = if cancelled {
                        (
                            "canceled",
                            "canceled",
                            b"runtrue.runner.source-cancelled.v1\0".as_slice(),
                        )
                    } else {
                        (
                            "failed",
                            "source_integrity",
                            b"runtrue.runner.source-integrity-failure.v1\0".as_slice(),
                        )
                    };
                    let result_digest = ContentDigest::sha256(result_domain);
                    guard.complete(
                        &offer.lease_id,
                        offer.fencing_generation,
                        offer.installation_fencing_epoch,
                        clock.now()?,
                        LeaseCompletion {
                            final_state: final_state.to_owned(),
                            result_digest: result_digest.clone(),
                        },
                    )?;
                    self.state.set_pending_completion_with_objects(
                        &v1::CompleteLeaseRequest {
                            lease_id: offer.lease_id.clone(),
                            fencing_generation: offer.fencing_generation,
                            installation_fencing_epoch: offer.installation_fencing_epoch,
                            final_state: final_state.to_owned(),
                            exit_code: None,
                            error_code: error_code.to_owned(),
                            result_digest: Some(v1::Digest::try_from(&result_digest)?),
                            artifact_ids: Vec::new(),
                            cache_entry_ids: Vec::new(),
                            completed_at: Some(timestamp(clock.now()?)),
                            final_job_attempt: 0,
                            expected_log_frames: 0,
                        },
                        Vec::new(),
                        runtrue_engine::CredentialTaint::None,
                    )?;
                    self.state.clear_active_lease(&offer.lease_id)?;
                    self.workspaces.cleanup(&workspace)?;
                    let _ = self
                        .send_job_state(&offer, final_state, error_code, "")
                        .await;
                    let _ = self.retry_pending_completion().await;
                    return Ok(None);
                }
            };
            self.send_job_state(&offer, "preparing", "", hydrated.as_str())
                .await?;
            self.send_locality().await?;
        }
        self.send_job_state(&offer, "running", "", "").await?;

        let cancellation = CancellationToken::default();
        let task_cancellation = cancellation.clone();
        let task_lease = admitted;
        let task_workspace = workspace.clone();
        let task_admission_permit = admission_permit.clone();
        let executor = self.executor.clone();
        let lifecycle_observer: Arc<dyn StepStateObserver> = Arc::new(DaemonStepStateObserver {
            lease_id: offer.lease_id.clone(),
            sender: lifecycle_sender,
        });
        let needs_data_plane = offered_job(&task_lease)?
            .steps
            .iter()
            .any(|step| step.cache.is_some())
            || !offered_job(&task_lease)?.outputs.is_empty();
        let data_session = if needs_data_plane {
            let client = broker.clone().ok_or(RunnerError::BrokerUnavailable)?;
            Some(crate::data_plane::RemoteDataPlaneSession::new(
                &task_lease,
                &task_workspace,
                client,
            ))
        } else {
            None
        };
        let observer = data_session
            .as_ref()
            .map_or(lifecycle_observer.clone(), |data| {
                data.observer(lifecycle_observer)
            });
        let services = JobExecutionServices {
            broker,
            step_state_observer: Some(observer),
        };
        let execution_task = spawn_admission_bound_blocking(task_admission_permit, move || {
            let mut outcome = executor.execute_with_services(
                &task_lease,
                &task_workspace,
                task_cancellation,
                services,
            )?;
            let mut committed_objects = Vec::new();
            if let Some(data) = data_session {
                let artifacts =
                    data.capture_artifacts(&outcome.final_state, outcome.final_job_attempt)?;
                let caches = data.committed_cache_objects()?;
                outcome.artifact_ids = artifacts
                    .iter()
                    .map(|object| object.object_id.clone())
                    .collect();
                outcome.cache_entry_ids = caches
                    .iter()
                    .map(|object| object.object_id.clone())
                    .collect();
                committed_objects.extend(artifacts);
                committed_objects.extend(caches);
            }
            Ok(CompletedExecution {
                outcome,
                committed_objects,
            })
        });
        let task_lease_id = offer.lease_id.clone();
        let task = tokio::spawn(async move {
            let result = execution_task.await;
            let _ = completion_sender
                .send(ExecutionTaskMessage {
                    lease_id: task_lease_id,
                    result,
                })
                .await;
        });
        Ok(Some(ActiveExecution {
            _admission_permit: admission_permit,
            offer,
            guard,
            cancellation,
            hard_deadline: Some(hard_deadline),
            workspace,
            task,
            last_job_attempt: 0,
        }))
    }

    async fn finish_execution(
        &mut self,
        mut execution: ActiveExecution,
        completed: CompletedExecution,
        clock: &ServerClock,
    ) -> Result<(), RunnerError> {
        let outcome = completed.outcome;
        execution.guard.complete(
            &execution.offer.lease_id,
            execution.offer.fencing_generation,
            execution.offer.installation_fencing_epoch,
            clock.now()?,
            LeaseCompletion {
                final_state: outcome.final_state.clone(),
                result_digest: outcome.result_digest.clone(),
            },
        )?;
        let completed_unix_ms = clock.now()?;
        let completion = v1::CompleteLeaseRequest {
            lease_id: execution.offer.lease_id.clone(),
            fencing_generation: execution.offer.fencing_generation,
            installation_fencing_epoch: execution.offer.installation_fencing_epoch,
            final_state: outcome.final_state.clone(),
            exit_code: outcome.exit_code,
            error_code: outcome.error_code.clone(),
            result_digest: Some(v1::Digest::try_from(&outcome.result_digest)?),
            artifact_ids: outcome.artifact_ids.clone(),
            cache_entry_ids: outcome.cache_entry_ids.clone(),
            completed_at: Some(timestamp(completed_unix_ms)),
            final_job_attempt: outcome.final_job_attempt,
            expected_log_frames: u32::try_from(outcome.log_frames.len())
                .map_err(|_| RunnerError::LogSequenceOverflow)?,
        };
        self.state.set_pending_completion_with_objects(
            &completion,
            completed.committed_objects,
            outcome.credential_taint,
        )?;
        self.workspaces.cleanup(&execution.workspace)?;

        for batch in outcome.log_frames.chunks(LOG_BATCH_FRAMES) {
            if self
                .transport
                .send(v1::RunnerMessage {
                    body: Some(v1::runner_message::Body::LogBatch(v1::LogBatch {
                        lease_id: execution.offer.lease_id.clone(),
                        fencing_generation: execution.offer.fencing_generation,
                        frames: batch.to_vec(),
                    })),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = self
            .send_job_state(
                &execution.offer,
                &outcome.final_state,
                &outcome.error_code,
                "",
            )
            .await;
        let _ = self.retry_pending_completion().await;
        Ok(())
    }

    async fn retry_pending_completion(&mut self) -> Result<bool, RunnerError> {
        let pending = self.state.pending_completion_records();
        if pending.is_empty() {
            return Ok(false);
        }
        let mut accepted_any = false;
        for persisted in pending {
            let lease_id = persisted.lease_id.clone();
            let accepted = if self.config.inventory.wire.protocol_version >= 2 {
                match persisted.to_wire_v2()? {
                    Some(request) => self
                        .transport
                        .complete_lease_v2(request)
                        .await
                        .map(|response| response.accepted),
                    None => self
                        .transport
                        .complete_lease(persisted.to_wire()?)
                        .await
                        .map(|response| response.accepted),
                }
            } else {
                self.transport
                    .complete_lease(persisted.to_wire()?)
                    .await
                    .map(|response| response.accepted)
            };
            match accepted {
                Ok(true) => {
                    self.state.clear_pending_completion_lease(&lease_id)?;
                    accepted_any = true;
                }
                Ok(false) => return Err(RunnerError::CompletionRejected),
                Err(error) => {
                    eprintln!("runner completion delivery failed: {error}");
                    return Ok(accepted_any);
                }
            }
        }
        Ok(accepted_any)
    }

    async fn send_heartbeat(
        &mut self,
        connection_id: &str,
        active: &BTreeMap<String, ActiveExecution>,
    ) -> Result<(), RunnerError> {
        let active_leases = active
            .values()
            .map(|execution| v1::ActiveLease {
                lease_id: execution.offer.lease_id.clone(),
                fencing_generation: execution.offer.fencing_generation,
                state: "running".to_owned(),
            })
            .collect();
        self.send_heartbeat_message(connection_id, active_leases)
            .await
    }

    async fn send_lease_heartbeat(
        &mut self,
        connection_id: &str,
        offer: &v1::LeaseOffer,
        state: &str,
    ) -> Result<(), RunnerError> {
        self.send_heartbeat_message(
            connection_id,
            vec![v1::ActiveLease {
                lease_id: offer.lease_id.clone(),
                fencing_generation: offer.fencing_generation,
                state: state.to_owned(),
            }],
        )
        .await
    }

    async fn send_heartbeat_message(
        &mut self,
        connection_id: &str,
        active_leases: Vec<v1::ActiveLease>,
    ) -> Result<(), RunnerError> {
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::Heartbeat(v1::Heartbeat {
                    runner_id: self.config.runner_id.clone(),
                    connection_id: connection_id.to_owned(),
                    active_leases,
                    observed_at: Some(timestamp(now_unix_ms()?)),
                })),
            })
            .await?;
        Ok(())
    }

    async fn send_locality(&mut self) -> Result<(), RunnerError> {
        let mut exact = std::collections::BTreeSet::new();
        let mut classes = Vec::new();
        let mut package_locality = Vec::new();
        for prepared in self.executor.prepared_content()? {
            let before = exact.len();
            for digest in prepared.digests {
                if exact.len() == MAX_ADVERTISED_LOCALITY_ITEMS {
                    break;
                }
                if exact.insert(digest.clone()) {
                    if let Some(tier) = prepared.tier {
                        let tier = match tier {
                            PreparedContentTier::Warmish => v1::PackagePreparationTier::Warmish,
                            PreparedContentTier::Warm => v1::PackagePreparationTier::Warm,
                        };
                        package_locality.push(v1::PackageLocality {
                            digest: Some(v1::Digest::try_from(&digest)?),
                            tier: tier.into(),
                        });
                    }
                }
            }
            let added = exact.len().saturating_sub(before);
            classes.push(v1::LocalityClass {
                kind: prepared.kind,
                bytes: 0,
                item_count: u64::try_from(added).unwrap_or(u64::MAX),
            });
        }
        let remaining = MAX_ADVERTISED_LOCALITY_ITEMS.saturating_sub(exact.len());
        let source_digests = self.workspaces.source_cache().locality(remaining)?;
        let source_count = source_digests.len();
        exact.extend(source_digests);
        classes.push(v1::LocalityClass {
            kind: "source-snapshot".to_owned(),
            bytes: 0,
            item_count: u64::try_from(source_count).unwrap_or(u64::MAX),
        });
        let content_digests = exact
            .iter()
            .map(v1::Digest::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::Locality(v1::LocalitySummary {
                    runner_id: self.config.runner_id.clone(),
                    tenant_scoped_bloom_filter: Vec::new(),
                    public_content_bloom_filter: Vec::new(),
                    classes,
                    generated_at: Some(timestamp(now_unix_ms()?)),
                    content_digests,
                    package_locality,
                })),
            })
            .await?;
        Ok(())
    }

    async fn reject_offer(
        &mut self,
        offer: &v1::LeaseOffer,
        code: &str,
    ) -> Result<(), RunnerError> {
        eprintln!(
            "runtrue-runner: rejected lease `{}` for job `{}`: {code}",
            offer.lease_id, offer.job_id
        );
        self.send_decision(offer, false, code, "runner rejected the offer")
            .await
    }

    async fn send_decision(
        &mut self,
        offer: &v1::LeaseOffer,
        accepted: bool,
        rejection_code: &str,
        detail: &str,
    ) -> Result<(), RunnerError> {
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::LeaseDecision(v1::LeaseDecision {
                    lease_id: offer.lease_id.clone(),
                    fencing_generation: offer.fencing_generation,
                    accepted,
                    rejection_code: rejection_code.to_owned(),
                    detail: detail.to_owned(),
                })),
            })
            .await?;
        Ok(())
    }

    async fn send_job_state(
        &mut self,
        offer: &v1::LeaseOffer,
        state: &str,
        error_code: &str,
        detail: &str,
    ) -> Result<(), RunnerError> {
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::JobState(v1::JobStateUpdate {
                    lease_id: offer.lease_id.clone(),
                    fencing_generation: offer.fencing_generation,
                    state: state.to_owned(),
                    observed_at: Some(timestamp(now_unix_ms()?)),
                    error_code: error_code.to_owned(),
                    detail: detail.to_owned(),
                })),
            })
            .await?;
        Ok(())
    }

    async fn send_step_state(
        &mut self,
        offer: &v1::LeaseOffer,
        observation: &StepStateObservation,
    ) -> Result<(), RunnerError> {
        if observation.job_id != offer.job_id {
            return Err(RunnerError::StepLifecycleBinding);
        }
        let state = step_state_name(observation.to);
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::StepState(v1::StepStateUpdate {
                    lease_id: offer.lease_id.clone(),
                    fencing_generation: offer.fencing_generation,
                    step_id: observation.step_id.clone(),
                    state: state.to_owned(),
                    observed_at: Some(timestamp(now_unix_ms()?)),
                    exit_code: None,
                    error_code: step_error_code(observation.to).to_owned(),
                    output_digest: None,
                    job_attempt: observation.job_attempt,
                })),
            })
            .await?;
        Ok(())
    }

    async fn send_cancellation_ack(&mut self, cancel: &v1::CancelLease) -> Result<(), RunnerError> {
        self.transport
            .send(v1::RunnerMessage {
                body: Some(v1::runner_message::Body::CancellationAck(
                    v1::CancellationAck {
                        lease_id: cancel.lease_id.clone(),
                        fencing_generation: cancel.fencing_generation,
                        observed_at: Some(timestamp(now_unix_ms()?)),
                    },
                )),
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
