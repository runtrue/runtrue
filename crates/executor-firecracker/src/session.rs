use crate::{EnvelopeTransport, FirecrackerError};
use rand_core::{OsRng, RngCore};
use runtrue_attest::CapsuleSignature;
use runtrue_engine::{CancellationToken, StepState, StepStateObservation, StepStateObserver};
use runtrue_guest_core::{
    step_capability_digest, GuestBootConfig, GuestBootstrap, GuestEvent, GuestSessionKey,
    GuestStepResult, HostCommand, HostSessionCodec, LogFrame, ResourceSample, StepSignal,
};
use runtrue_workflow_ir::{
    ExecutionCapsule, Isolation, NetworkPermission, PermissionSet, PlannedJob, Shell, StepAction,
    StepCapabilitySet, ValueBinding,
};
use std::path::PathBuf;
use zeroize::Zeroize as _;

const MAX_SESSION_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESOURCE_SAMPLES: usize = 4096;

pub struct OneJobSession {
    bootstrap: GuestBootstrap,
    boot: GuestBootConfig,
    codec: HostSessionCodec,
    canonical_capsule: Vec<u8>,
    signature: CapsuleSignature,
    job: PlannedJob,
}

impl OneJobSession {
    pub fn new(
        bootstrap: GuestBootstrap,
        capsule: &ExecutionCapsule,
        signature: CapsuleSignature,
        capsule_trust_directory: impl Into<PathBuf>,
        vsock_port: u32,
    ) -> Result<Self, FirecrackerError> {
        let canonical_capsule = capsule.canonical_bytes().map_err(|error| {
            FirecrackerError::InvalidConfiguration(format!("cannot canonicalize capsule: {error}"))
        })?;
        if runtrue_model::ContentDigest::sha256(&canonical_capsule) != bootstrap.capsule_digest
            || signature.capsule_digest != bootstrap.capsule_digest
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "bootstrap, canonical capsule, and signature digests differ".to_owned(),
            ));
        }
        let job = capsule
            .jobs
            .iter()
            .find(|job| job.id == bootstrap.job_id)
            .cloned()
            .ok_or_else(|| {
                FirecrackerError::InvalidConfiguration(
                    "bootstrap job is absent from the signed capsule".to_owned(),
                )
            })?;
        validate_one_job(&job)?;
        let mut raw_key = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut raw_key)
            .map_err(|_| FirecrackerError::RandomnessUnavailable)?;
        let boot = GuestBootConfig::new(
            bootstrap.clone(),
            &raw_key,
            capsule_trust_directory,
            vsock_port,
        )?;
        let codec = HostSessionCodec::new(
            bootstrap.session_id.clone(),
            GuestSessionKey::from_bytes(raw_key),
        )?;
        raw_key.zeroize();
        Ok(Self {
            bootstrap,
            boot,
            codec,
            canonical_capsule,
            signature,
            job,
        })
    }

    #[must_use]
    pub const fn boot_config(&self) -> &GuestBootConfig {
        &self.boot
    }

    pub fn run(
        mut self,
        transport: &mut dyn EnvelopeTransport,
        cancellation: &CancellationToken,
    ) -> Result<OneJobReport, FirecrackerError> {
        self.run_inner(transport, cancellation, None)
    }

    /// Run the authenticated one-job protocol while publishing the same
    /// Created -> Running -> terminal step transitions as the shared engine.
    /// The runner uses this to put fenced lifecycle state on its control
    /// stream before a guest step can consume any future proxied capability.
    pub fn run_with_observer(
        mut self,
        transport: &mut dyn EnvelopeTransport,
        cancellation: &CancellationToken,
        observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, FirecrackerError> {
        self.run_inner(transport, cancellation, observer)
    }

    fn run_inner(
        &mut self,
        transport: &mut dyn EnvelopeTransport,
        cancellation: &CancellationToken,
        observer: Option<&dyn StepStateObserver>,
    ) -> Result<OneJobReport, FirecrackerError> {
        let hello = self.receive(transport)?;
        match hello {
            GuestEvent::Hello {
                guest_image_digest,
                capsule_digest,
                lease_id,
                fencing_generation,
                installation_fencing_epoch,
            } if guest_image_digest == self.bootstrap.guest_image_digest
                && capsule_digest == self.bootstrap.capsule_digest
                && lease_id == self.bootstrap.lease_id
                && fencing_generation == self.bootstrap.fencing_generation
                && installation_fencing_epoch == self.bootstrap.installation_fencing_epoch => {}
            _ => {
                return Err(FirecrackerError::Protocol(
                    "guest hello does not match the protected bootstrap".to_owned(),
                ));
            }
        }

        self.send(
            transport,
            &HostCommand::StartJob {
                canonical_capsule: self.canonical_capsule.clone(),
                signature: self.signature.clone(),
            },
        )?;
        match self.receive(transport)? {
            GuestEvent::JobAccepted { job_id } if job_id == self.job.id => {}
            _ => {
                return Err(FirecrackerError::Protocol(
                    "guest did not admit the exact job".to_owned(),
                ));
            }
        }

        let mut report = OneJobReport::default();
        let mut stop_after = None;
        for (index, step) in self.job.steps.clone().into_iter().enumerate() {
            observe_step(observer, &self.job.id, &step.id, None, StepState::Created)?;
            self.send(
                transport,
                &HostCommand::StartStep {
                    step_id: step.id.clone(),
                    attempt: 1,
                    capability_digest: step_capability_digest(&step)?,
                },
            )?;
            match self.receive(transport)? {
                GuestEvent::StepReady { step_id, attempt }
                    if step_id == step.id && attempt == 1 => {}
                _ => {
                    return Err(FirecrackerError::Protocol(format!(
                        "guest was not ready for step {}",
                        step.id
                    )));
                }
            }
            observe_step(
                observer,
                &self.job.id,
                &step.id,
                Some(StepState::Created),
                StepState::Running,
            )?;

            let mut cancel_sent = false;
            let result = loop {
                if cancellation.is_cancelled() && !cancel_sent {
                    self.send(
                        transport,
                        &HostCommand::SignalStep {
                            step_id: step.id.clone(),
                            signal: StepSignal::Cancel,
                        },
                    )?;
                    cancel_sent = true;
                }
                match self.receive(transport)? {
                    GuestEvent::LogFrame(frame) if frame.step_id == step.id => {
                        report.record_log(frame)?;
                    }
                    GuestEvent::ResourceSample(sample) if sample.step_id == step.id => {
                        if report.resource_samples.len() < MAX_RESOURCE_SAMPLES {
                            report.resource_samples.push(sample);
                        }
                    }
                    GuestEvent::SignalAcknowledged { step_id, signal }
                        if cancel_sent && step_id == step.id && signal == StepSignal::Cancel =>
                    {
                        report.cancellation_acknowledged = true;
                    }
                    GuestEvent::StepResult(result)
                        if result.step_id == step.id && result.attempt == 1 && !result.skipped =>
                    {
                        if cancel_sent && !report.cancellation_acknowledged {
                            return Err(FirecrackerError::Protocol(
                                "guest reported a canceled step before acknowledging cleanup"
                                    .to_owned(),
                            ));
                        }
                        break result;
                    }
                    _ => {
                        return Err(FirecrackerError::Protocol(format!(
                            "unexpected event while step {} was running",
                            step.id
                        )));
                    }
                }
            };
            let terminal = if result.canceled {
                StepState::Canceled
            } else if result.timed_out {
                StepState::TimedOut
            } else if result.exit_code == Some(0) {
                StepState::Succeeded
            } else {
                StepState::Failed
            };
            observe_step(
                observer,
                &self.job.id,
                &step.id,
                Some(StepState::Running),
                terminal,
            )?;
            let failed = result.timed_out || result.canceled || result.exit_code != Some(0);
            report.step_results.push(result);
            if failed && !step.continue_on_error {
                stop_after = Some(index);
                break;
            }
        }

        if let Some(index) = stop_after {
            let remaining = self
                .job
                .steps
                .iter()
                .skip(index + 1)
                .map(|step| step.id.clone())
                .collect::<Vec<_>>();
            for step_id in remaining {
                observe_step(observer, &self.job.id, &step_id, None, StepState::Created)?;
                match self.receive(transport)? {
                    GuestEvent::StepResult(result)
                        if result.step_id == step_id && result.skipped && result.attempt == 0 =>
                    {
                        report.step_results.push(result);
                    }
                    _ => {
                        return Err(FirecrackerError::Protocol(
                            "guest did not skip the remaining signed steps".to_owned(),
                        ));
                    }
                }
                observe_step(
                    observer,
                    &self.job.id,
                    &step_id,
                    Some(StepState::Created),
                    StepState::Skipped,
                )?;
            }
        }
        match self.receive(transport)? {
            GuestEvent::JobResult { job_id, succeeded } if job_id == self.job.id => {
                report.succeeded = succeeded;
            }
            _ => {
                return Err(FirecrackerError::Protocol(
                    "guest did not report the terminal job result".to_owned(),
                ));
            }
        }
        self.send(transport, &HostCommand::Shutdown)?;
        if self.receive(transport)? != GuestEvent::ShutdownReady {
            return Err(FirecrackerError::Protocol(
                "guest did not acknowledge shutdown".to_owned(),
            ));
        }
        Ok(report)
    }

    fn send(
        &mut self,
        transport: &mut dyn EnvelopeTransport,
        command: &HostCommand,
    ) -> Result<(), FirecrackerError> {
        transport.send(&self.codec.command(command)?)
    }

    fn receive(
        &mut self,
        transport: &mut dyn EnvelopeTransport,
    ) -> Result<GuestEvent, FirecrackerError> {
        self.codec
            .verify_event(transport.receive()?)
            .map_err(Into::into)
    }
}

fn observe_step(
    observer: Option<&dyn StepStateObserver>,
    job_id: &str,
    step_id: &str,
    from: Option<StepState>,
    to: StepState,
) -> Result<(), FirecrackerError> {
    observer
        .map(|observer| {
            observer.observe(&StepStateObservation {
                job_id: job_id.to_owned(),
                step_id: step_id.to_owned(),
                job_attempt: 1,
                from,
                to,
            })
        })
        .transpose()
        .map_err(|message| {
            FirecrackerError::Protocol(format!(
                "step lifecycle observer rejected {job_id}.{step_id}: {message}"
            ))
        })
        .map(|_| ())
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct OneJobReport {
    pub succeeded: bool,
    pub step_results: Vec<GuestStepResult>,
    pub logs: Vec<LogFrame>,
    pub resource_samples: Vec<ResourceSample>,
    pub cancellation_acknowledged: bool,
    log_bytes: usize,
}

impl std::fmt::Debug for OneJobReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OneJobReport")
            .field("succeeded", &self.succeeded)
            .field("step_results", &self.step_results)
            .field("log_frames", &self.logs.len())
            .field("log_bytes", &self.log_bytes)
            .field("resource_samples", &self.resource_samples.len())
            .field("cancellation_acknowledged", &self.cancellation_acknowledged)
            .finish()
    }
}

impl OneJobReport {
    fn record_log(&mut self, frame: LogFrame) -> Result<(), FirecrackerError> {
        self.log_bytes = self
            .log_bytes
            .checked_add(frame.bytes.len())
            .ok_or_else(|| FirecrackerError::Protocol("session log size overflow".to_owned()))?;
        if self.log_bytes > MAX_SESSION_LOG_BYTES {
            return Err(FirecrackerError::Protocol(
                "session log bound exceeded".to_owned(),
            ));
        }
        self.logs.push(frame);
        Ok(())
    }
}

fn validate_one_job(job: &PlannedJob) -> Result<(), FirecrackerError> {
    if job.runner.isolation != Isolation::Microvm {
        return Err(FirecrackerError::InvalidConfiguration(
            "signed job does not require microVM isolation; downgrade refused".to_owned(),
        ));
    }
    if !job.services.is_empty() {
        return Err(FirecrackerError::InvalidConfiguration(
            "guest services are not implemented by the microVM adapter".to_owned(),
        ));
    }
    if job.runner.image.is_some()
        || !job.runner.capabilities.is_empty()
        || job.permissions != PermissionSet::default()
        || !job.outputs.is_empty()
        || job.steps.is_empty()
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "microVM image labels, host capabilities, data-plane permissions, outputs, and empty jobs are unsupported"
                .to_owned(),
        ));
    }
    if job.steps.iter().any(|step| step.condition.is_some()) {
        return Err(FirecrackerError::InvalidConfiguration(
            "step conditions must be resolved before the one-job guest session".to_owned(),
        ));
    }
    if job
        .steps
        .iter()
        .any(|step| !matches!(step.capabilities.network, NetworkPermission::Deny))
    {
        return Err(FirecrackerError::InvalidConfiguration(
            "microVM network access requires an executor-side policy adapter".to_owned(),
        ));
    }
    for step in &job.steps {
        if step.capabilities != StepCapabilitySet::default() || step.cache.is_some() {
            return Err(FirecrackerError::InvalidConfiguration(
                "microVM secret, OIDC, cache, artifact, filesystem, check, and network capabilities require an exact guest proxy adapter"
                    .to_owned(),
            ));
        }
        if step
            .inputs
            .values()
            .chain(step.environment.values())
            .any(|value| matches!(value, ValueBinding::Context(_)))
        {
            return Err(FirecrackerError::InvalidConfiguration(
                "microVM runtime context bindings require an exact guest adapter".to_owned(),
            ));
        }
        match &step.action {
            StepAction::Command { program, args }
                if std::path::Path::new(program).is_absolute()
                    && args
                        .iter()
                        .all(|value| matches!(value, ValueBinding::Literal(_))) => {}
            StepAction::Script {
                shell: Shell::Bash | Shell::Sh,
                ..
            } => {}
            StepAction::Command { .. }
            | StepAction::Script { .. }
            | StepAction::Component { .. } => {
                return Err(FirecrackerError::InvalidConfiguration(
                    "microVM steps require an absolute literal command or sh/bash script"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}
