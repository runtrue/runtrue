use crate::{
    authorization::{authorize_oidc, authorize_secret, mount_is_declared},
    codec::{
        sign_envelope, strict_canonical_json, verify_envelope, GUEST_MESSAGE_DOMAIN,
        HOST_MESSAGE_DOMAIN,
    },
    protocol::validate_identifier,
    step_capability_digest, AuthenticatedEnvelope, AuthorizedStep, GuestAction, GuestBootstrap,
    GuestCapsuleTrustStore, GuestError, GuestEvent, GuestSessionKey, GuestStepResult, HostCommand,
    LogFrame, LogStream, MountDescriptor, OidcEnvelope, ResourceSample, SecretEnvelope, StepSignal,
    MAX_GUEST_CAPSULE_BYTES, MAX_GUEST_MOUNTS, MAX_LOG_FRAME_BYTES,
};
use runtrue_attest::CapsuleSignature;
use runtrue_model::{normalize_relative_path, ContentDigest};
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob, PlannedStep};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestSessionState {
    AwaitingCapsule,
    Ready,
    StepRunning,
    JobFinished,
    Shutdown,
}

pub struct GuestSession {
    bootstrap: GuestBootstrap,
    key: GuestSessionKey,
    trust: GuestCapsuleTrustStore,
    state: GuestSessionState,
    next_host_sequence: u64,
    next_guest_sequence: u64,
    capsule: Option<ExecutionCapsule>,
    active_step: Option<(String, u32)>,
    completed_steps: BTreeSet<String>,
    step_results: BTreeMap<String, GuestStepResult>,
    mounts: BTreeMap<String, MountDescriptor>,
    mounted_paths: BTreeSet<String>,
    log_sequences: BTreeMap<(String, LogStream), u64>,
}

impl GuestSession {
    pub fn new(
        bootstrap: GuestBootstrap,
        key: GuestSessionKey,
        trust: GuestCapsuleTrustStore,
        now_unix_ms: u64,
    ) -> Result<Self, GuestError> {
        bootstrap.validate(now_unix_ms)?;
        if trust.is_empty() {
            return Err(GuestError::EmptyCapsuleTrustStore);
        }
        Ok(Self {
            bootstrap,
            key,
            trust,
            state: GuestSessionState::AwaitingCapsule,
            next_host_sequence: 1,
            next_guest_sequence: 1,
            capsule: None,
            active_step: None,
            completed_steps: BTreeSet::new(),
            step_results: BTreeMap::new(),
            mounts: BTreeMap::new(),
            mounted_paths: BTreeSet::new(),
            log_sequences: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn state(&self) -> GuestSessionState {
        self.state
    }

    /// The exactly signed job admitted for this one-job session.
    pub fn admitted_job(&self) -> Result<&PlannedJob, GuestError> {
        self.selected_job()
    }

    pub fn hello(&mut self) -> Result<AuthenticatedEnvelope, GuestError> {
        self.emit(&GuestEvent::Hello {
            guest_image_digest: self.bootstrap.guest_image_digest.clone(),
            capsule_digest: self.bootstrap.capsule_digest.clone(),
            lease_id: self.bootstrap.lease_id.clone(),
            fencing_generation: self.bootstrap.fencing_generation,
            installation_fencing_epoch: self.bootstrap.installation_fencing_epoch,
        })
    }

    pub fn accept(
        &mut self,
        envelope: AuthenticatedEnvelope,
        now_unix_ms: u64,
    ) -> Result<GuestAction, GuestError> {
        self.ensure_live(now_unix_ms)?;
        let command: HostCommand = verify_envelope(
            &self.key,
            HOST_MESSAGE_DOMAIN,
            &self.bootstrap.session_id,
            self.next_host_sequence,
            envelope,
        )?;
        self.next_host_sequence = self
            .next_host_sequence
            .checked_add(1)
            .ok_or(GuestError::SequenceExhausted)?;
        self.apply(command, now_unix_ms)
    }

    pub fn record_step_result(
        &mut self,
        result: GuestStepResult,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        let Some((step_id, attempt)) = self.active_step.as_ref() else {
            return Err(GuestError::NoActiveStep);
        };
        if result.step_id != *step_id || result.attempt != *attempt {
            return Err(GuestError::WrongActiveStep);
        }
        if result.skipped || (result.timed_out && result.canceled) {
            return Err(GuestError::InvalidStepResult);
        }
        self.completed_steps.insert(result.step_id.clone());
        self.step_results
            .insert(result.step_id.clone(), result.clone());
        self.active_step = None;
        self.state = GuestSessionState::Ready;
        self.emit(&GuestEvent::StepResult(result))
    }

    /// Confirm that the guest process adapter is ready to execute the active
    /// step. This is emitted only after the authenticated StartStep command has
    /// passed the exact capability-digest check.
    pub fn step_ready(&mut self, now_unix_ms: u64) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        let (step_id, attempt) = self.active_step.clone().ok_or(GuestError::NoActiveStep)?;
        self.emit(&GuestEvent::StepReady { step_id, attempt })
    }

    /// Record a conditionally skipped step without ever starting a process.
    pub fn record_step_skipped(
        &mut self,
        step_id: &str,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        if self.state != GuestSessionState::Ready || self.active_step.is_some() {
            return Err(GuestError::InvalidState("step cannot be skipped now"));
        }
        let step = self
            .selected_job()?
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .ok_or_else(|| GuestError::StepNotInCapsule(step_id.to_owned()))?;
        if self.completed_steps.contains(step_id) {
            return Err(GuestError::StepAlreadyCompleted(step_id.to_owned()));
        }
        let result = GuestStepResult {
            step_id: step.id.clone(),
            attempt: 0,
            exit_code: None,
            timed_out: false,
            canceled: false,
            skipped: true,
        };
        self.completed_steps.insert(step_id.to_owned());
        self.step_results.insert(step_id.to_owned(), result.clone());
        self.emit(&GuestEvent::StepResult(result))
    }

    /// Emit an acknowledgement only after the process adapter has actually
    /// delivered the requested signal to the complete step process group.
    pub fn acknowledge_signal(
        &mut self,
        step_id: &str,
        signal: StepSignal,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        if self.active_step.as_ref().map(|value| value.0.as_str()) != Some(step_id) {
            return Err(GuestError::WrongActiveStep);
        }
        self.emit(&GuestEvent::SignalAcknowledged {
            step_id: step_id.to_owned(),
            signal,
        })
    }

    pub fn record_log(
        &mut self,
        step_id: &str,
        stream: LogStream,
        bytes: Vec<u8>,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        let Some((active, _)) = self.active_step.as_ref() else {
            return Err(GuestError::NoActiveStep);
        };
        if active != step_id {
            return Err(GuestError::WrongActiveStep);
        }
        if bytes.len() > MAX_LOG_FRAME_BYTES {
            return Err(GuestError::LogFrameTooLarge);
        }
        let key = (step_id.to_owned(), stream);
        let sequence = self.log_sequences.get(&key).copied().unwrap_or(0);
        self.log_sequences.insert(
            key,
            sequence
                .checked_add(1)
                .ok_or(GuestError::SequenceExhausted)?,
        );
        self.emit(&GuestEvent::LogFrame(LogFrame {
            step_id: step_id.to_owned(),
            stream,
            sequence,
            bytes,
        }))
    }

    pub fn record_resource_sample(
        &mut self,
        sample: ResourceSample,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        if self.active_step.as_ref().map(|value| value.0.as_str()) != Some(sample.step_id.as_str())
        {
            return Err(GuestError::WrongActiveStep);
        }
        self.emit(&GuestEvent::ResourceSample(sample))
    }

    pub fn finish_job(&mut self, now_unix_ms: u64) -> Result<AuthenticatedEnvelope, GuestError> {
        self.ensure_live(now_unix_ms)?;
        if self.state != GuestSessionState::Ready || self.active_step.is_some() {
            return Err(GuestError::InvalidState("job cannot finish now"));
        }
        let job = self.selected_job()?;
        if job.steps.len() != self.completed_steps.len()
            || job
                .steps
                .iter()
                .any(|step| !self.completed_steps.contains(&step.id))
        {
            return Err(GuestError::IncompleteJob);
        }
        let succeeded = job.steps.iter().all(|step| {
            self.step_results.get(&step.id).is_some_and(|result| {
                result.skipped
                    || (!result.timed_out
                        && !result.canceled
                        && (result.exit_code == Some(0) || step.continue_on_error))
            })
        });
        self.state = GuestSessionState::JobFinished;
        self.emit(&GuestEvent::JobResult {
            job_id: self.bootstrap.job_id.clone(),
            succeeded,
        })
    }

    /// Acknowledge authenticated shutdown after all job state is final.
    pub fn shutdown_ready(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedEnvelope, GuestError> {
        if now_unix_ms >= self.bootstrap.expires_unix_ms {
            return Err(GuestError::SessionExpired);
        }
        if self.state != GuestSessionState::Shutdown {
            return Err(GuestError::InvalidState("shutdown was not requested"));
        }
        self.emit(&GuestEvent::ShutdownReady)
    }

    fn apply(&mut self, command: HostCommand, now_unix_ms: u64) -> Result<GuestAction, GuestError> {
        match command {
            HostCommand::StartJob {
                canonical_capsule,
                signature,
            } => self.start_job(canonical_capsule, signature),
            HostCommand::Mount(descriptor) => self.mount(descriptor),
            HostCommand::StartStep {
                step_id,
                attempt,
                capability_digest,
            } => self.start_step(step_id, attempt, capability_digest),
            HostCommand::SignalStep { step_id, signal } => {
                if self.active_step.as_ref().map(|value| value.0.as_str()) != Some(&step_id) {
                    return Err(GuestError::WrongActiveStep);
                }
                Ok(GuestAction::SignalStep { step_id, signal })
            }
            HostCommand::Secret(secret) => self.deliver_secret(secret, now_unix_ms),
            HostCommand::Oidc(token) => self.deliver_oidc(token, now_unix_ms),
            HostCommand::Shutdown => {
                if self.state != GuestSessionState::JobFinished {
                    return Err(GuestError::InvalidState(
                        "shutdown requires a reported job result",
                    ));
                }
                self.state = GuestSessionState::Shutdown;
                Ok(GuestAction::Shutdown)
            }
        }
    }

    fn start_job(
        &mut self,
        canonical_capsule: Vec<u8>,
        signature: CapsuleSignature,
    ) -> Result<GuestAction, GuestError> {
        if self.state != GuestSessionState::AwaitingCapsule {
            return Err(GuestError::InvalidState("capsule was already admitted"));
        }
        if canonical_capsule.is_empty() || canonical_capsule.len() > MAX_GUEST_CAPSULE_BYTES {
            return Err(GuestError::InvalidCapsuleSize(canonical_capsule.len()));
        }
        let digest = ContentDigest::sha256(&canonical_capsule);
        if digest != self.bootstrap.capsule_digest || signature.capsule_digest != digest {
            return Err(GuestError::CapsuleDigestMismatch);
        }
        let capsule: ExecutionCapsule = strict_canonical_json(&canonical_capsule)?;
        if capsule
            .canonical_bytes()
            .map_err(GuestError::CanonicalCapsule)?
            != canonical_capsule
        {
            return Err(GuestError::NonCanonicalCapsule);
        }
        self.trust
            .get(&signature.key_id)?
            .verify_capsule(&capsule, &signature)
            .map_err(GuestError::InvalidCapsuleSignature)?;
        if selected_job(&capsule, &self.bootstrap.job_id).is_none() {
            return Err(GuestError::JobNotInCapsule(self.bootstrap.job_id.clone()));
        }
        self.capsule = Some(capsule);
        self.state = GuestSessionState::Ready;
        let event = GuestEvent::JobAccepted {
            job_id: self.bootstrap.job_id.clone(),
        };
        Ok(GuestAction::Send(self.emit(&event)?))
    }

    fn mount(&mut self, mut descriptor: MountDescriptor) -> Result<GuestAction, GuestError> {
        if self.state != GuestSessionState::Ready || self.active_step.is_some() {
            return Err(GuestError::InvalidState(
                "mounts are accepted only while no step is running",
            ));
        }
        if self.mounts.len() >= MAX_GUEST_MOUNTS {
            return Err(GuestError::MountLimitExceeded);
        }
        validate_identifier("mount id", &descriptor.mount_id)?;
        descriptor.guest_path = normalize_relative_path(&descriptor.guest_path)
            .map_err(|_| GuestError::UnsafeMountPath(descriptor.guest_path.clone()))?;
        if self.mounts.contains_key(&descriptor.mount_id)
            || self.mounted_paths.contains(&descriptor.guest_path)
        {
            return Err(GuestError::DuplicateMount);
        }
        let job = self.selected_job()?;
        if !mount_is_declared(job, &descriptor.guest_path, descriptor.read_only) {
            return Err(GuestError::UndeclaredMountCapability(
                descriptor.guest_path.clone(),
            ));
        }
        self.mounted_paths.insert(descriptor.guest_path.clone());
        let mount_id = descriptor.mount_id.clone();
        self.mounts.insert(mount_id.clone(), descriptor);
        Ok(GuestAction::Send(
            self.emit(&GuestEvent::MountAccepted { mount_id })?,
        ))
    }

    fn start_step(
        &mut self,
        step_id: String,
        attempt: u32,
        capability_digest: ContentDigest,
    ) -> Result<GuestAction, GuestError> {
        if self.state != GuestSessionState::Ready || self.active_step.is_some() || attempt == 0 {
            return Err(GuestError::InvalidState("step cannot start now"));
        }
        validate_identifier("step id", &step_id)?;
        if self.completed_steps.contains(&step_id) {
            return Err(GuestError::StepAlreadyCompleted(step_id));
        }
        let job = self.selected_job()?;
        let step = job
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .ok_or_else(|| GuestError::StepNotInCapsule(step_id.clone()))?
            .clone();
        if step_capability_digest(&step)? != capability_digest {
            return Err(GuestError::CapabilityDigestMismatch);
        }
        self.active_step = Some((step_id, attempt));
        self.state = GuestSessionState::StepRunning;
        Ok(GuestAction::StartStep(Box::new(AuthorizedStep {
            job_id: self.bootstrap.job_id.clone(),
            attempt,
            step,
        })))
    }

    fn deliver_secret(
        &self,
        secret: SecretEnvelope,
        now_unix_ms: u64,
    ) -> Result<GuestAction, GuestError> {
        let step = self.active_planned_step(&secret.step_id)?;
        authorize_secret(step, secret, now_unix_ms).map(GuestAction::DeliverSecret)
    }

    fn deliver_oidc(
        &self,
        token: OidcEnvelope,
        now_unix_ms: u64,
    ) -> Result<GuestAction, GuestError> {
        let step = self.active_planned_step(&token.step_id)?;
        authorize_oidc(step, token, now_unix_ms).map(GuestAction::DeliverOidc)
    }

    fn active_planned_step(&self, step_id: &str) -> Result<&PlannedStep, GuestError> {
        if self.active_step.as_ref().map(|value| value.0.as_str()) != Some(step_id) {
            return Err(GuestError::WrongActiveStep);
        }
        self.selected_job()?
            .steps
            .iter()
            .find(|step| step.id == step_id)
            .ok_or_else(|| GuestError::StepNotInCapsule(step_id.to_owned()))
    }

    fn selected_job(&self) -> Result<&PlannedJob, GuestError> {
        selected_job(
            self.capsule
                .as_ref()
                .ok_or(GuestError::CapsuleNotAdmitted)?,
            &self.bootstrap.job_id,
        )
        .ok_or_else(|| GuestError::JobNotInCapsule(self.bootstrap.job_id.clone()))
    }

    fn ensure_live(&self, now_unix_ms: u64) -> Result<(), GuestError> {
        if self.state == GuestSessionState::Shutdown {
            return Err(GuestError::InvalidState("session is shut down"));
        }
        if now_unix_ms >= self.bootstrap.expires_unix_ms {
            return Err(GuestError::SessionExpired);
        }
        Ok(())
    }

    fn emit(&mut self, event: &GuestEvent) -> Result<AuthenticatedEnvelope, GuestError> {
        let envelope = sign_envelope(
            &self.key,
            GUEST_MESSAGE_DOMAIN,
            &self.bootstrap.session_id,
            self.next_guest_sequence,
            event,
        )?;
        self.next_guest_sequence = self
            .next_guest_sequence
            .checked_add(1)
            .ok_or(GuestError::SequenceExhausted)?;
        Ok(envelope)
    }
}

fn selected_job<'a>(capsule: &'a ExecutionCapsule, job_id: &str) -> Option<&'a PlannedJob> {
    capsule.jobs.iter().find(|job| job.id == job_id)
}
