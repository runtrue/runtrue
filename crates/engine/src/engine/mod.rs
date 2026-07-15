//! Engine state-machine implementation.
//!
//! The engine is deliberately backend-neutral. It resolves the deterministic
//! parts of a capsule, validates lifecycle transitions, and hands prepared steps
//! to an [`Executor`]. [`NativeProcessExecutor`] is the small local backend for
//! explicitly trusted native runs; it is disabled unless opted into.

mod attempt;
mod job;
mod step;

pub use runtrue_lifecycle::{JobState, RunState, SkipReason, StepState};
#[cfg(test)]
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{expand_dynamic_job_set, ExecutionCapsule, TypedOutputValue};
#[cfg(test)]
use runtrue_workflow_ir::{
    Isolation, RunnerRequirements, ScalarValue, Shell, StepAction, StepCapabilitySet,
    StepOutputSchema, StepOutputType, ValueBinding, ENGINE_COMPATIBILITY_VERSION,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[cfg(test)]
use std::{
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

/// A defensive upper bound. The compiler is expected to impose a much lower
/// policy limit, but an engine must not trust a deserialized capsule blindly.
pub const MAX_JOB_RETRIES: u32 = 100;

/// The default amount of stdout and stderr retained independently per step.
pub const DEFAULT_MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
/// Structured outputs are control data, not an artifact transport.
pub const MAX_STRUCTURED_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_FINALIZER_TIMEOUT_MS: u64 = 600_000;
/// Defense-in-depth ceiling for static jobs plus every signed dynamic maximum.
pub const MAX_EXPANDED_JOBS: usize = 1_024;

use crate::{CancellationToken, RuntimeContext};

#[cfg(test)]
use crate::StepStateObservation;
use crate::{EngineEvent, EngineEventKind, StepStateObserver};

use crate::EngineError;
use crate::{ExecutionResult, Executor, JobResult};
#[cfg(test)]
use crate::{
    ExecutorError, ExecutorOutput, JobAttemptOutcome, PreparedAction, StepExecutionRequest,
};

/// Backend-neutral execution engine.
pub struct Engine<E> {
    executor: E,
    cancellation: CancellationToken,
    step_state_observer: Option<Arc<dyn StepStateObserver>>,
}

impl<E: Executor> Engine<E> {
    #[must_use]
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            cancellation: CancellationToken::default(),
            step_state_observer: None,
        }
    }

    #[must_use]
    pub fn with_cancellation_token(executor: E, cancellation: CancellationToken) -> Self {
        Self {
            executor,
            cancellation,
            step_state_observer: None,
        }
    }

    /// Install a synchronous step lifecycle observer.
    #[must_use]
    pub fn with_step_state_observer(mut self, observer: Arc<dyn StepStateObserver>) -> Self {
        self.step_state_observer = Some(observer);
        self
    }

    pub fn set_step_state_observer(&mut self, observer: Option<Arc<dyn StepStateObserver>>) {
        self.step_state_observer = observer;
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    #[must_use]
    pub fn executor(&self) -> &E {
        &self.executor
    }

    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    pub fn into_executor(self) -> E {
        self.executor
    }

    pub fn execute(&mut self, capsule: &ExecutionCapsule) -> Result<ExecutionResult, EngineError> {
        self.execute_with_context(capsule, &capsule.context.event_context)
    }

    /// Alias for [`Self::execute`] for command-oriented callers.
    pub fn run(&mut self, capsule: &ExecutionCapsule) -> Result<ExecutionResult, EngineError> {
        self.execute(capsule)
    }

    /// Execute exactly one scheduler-offered job from an already authenticated
    /// capsule. The complete capsule is validated first, then the selected job is
    /// preflighted and run in isolation. Dependency scheduling remains the
    /// control plane's responsibility; no other job is executed implicitly.
    pub fn execute_offered_job(
        &mut self,
        capsule: &ExecutionCapsule,
        job_id: &str,
    ) -> Result<ExecutionResult, EngineError> {
        validate_capsule(capsule)?;
        let job = capsule
            .jobs
            .iter()
            .find(|job| job.id == job_id)
            .ok_or_else(|| EngineError::SelectedJobNotFound(job_id.to_owned()))?;
        let mut selected_capsule = capsule.clone();
        let mut selected_job = job.clone();
        selected_job.needs.clear();
        selected_capsule.jobs = vec![selected_job];
        selected_capsule.dynamic_jobs.clear();
        self.execute_with_context(&selected_capsule, &capsule.context.event_context)
    }

    pub fn execute_with_context(
        &mut self,
        capsule: &ExecutionCapsule,
        runtime_context: &RuntimeContext,
    ) -> Result<ExecutionResult, EngineError> {
        validate_capsule(capsule)?;
        if !runtime_context_matches(runtime_context, &capsule.context.event_context) {
            return Err(EngineError::RuntimeContextMismatch);
        }
        let mut preflight_capsule = capsule.clone();
        preflight_capsule.jobs.extend(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| template.template.clone()),
        );
        preflight_capsule.dynamic_jobs.clear();
        self.executor
            .preflight(&preflight_capsule)
            .map_err(|error| EngineError::ExecutorPreflight(error.to_string()))?;
        let capsule_digest = capsule
            .digest()
            .map_err(|error| EngineError::DynamicMatrix {
                template_id: "capsule".to_owned(),
                message: error.to_string(),
            })?;

        let mut recorder = EventRecorder::default();
        recorder.run(None, RunState::Created);
        recorder.run(Some(RunState::Created), RunState::Running);

        let mut results = BTreeMap::new();
        let mut remaining = capsule
            .jobs
            .iter()
            .map(|job| job.id.clone())
            .collect::<BTreeSet<_>>();

        while !remaining.is_empty() {
            let mut made_progress = false;
            for job in &capsule.jobs {
                if !remaining.contains(&job.id)
                    || !job
                        .needs
                        .iter()
                        .all(|dependency| results.contains_key(dependency))
                {
                    continue;
                }

                let result = self.execute_job(
                    capsule,
                    &capsule_digest,
                    job,
                    runtime_context,
                    &results,
                    &mut recorder,
                )?;
                remaining.remove(&job.id);
                results.insert(job.id.clone(), result);
                made_progress = true;
            }

            if !made_progress {
                return Err(EngineError::DependencyCycle);
            }
        }

        for template in &capsule.dynamic_jobs {
            let producer = results
                .get(&template.source.producer_job_id)
                .ok_or_else(|| EngineError::DynamicMatrix {
                    template_id: template.id.clone(),
                    message: "producer result is unavailable".to_owned(),
                })?;
            if producer.state != JobState::Succeeded {
                recorder.job(&template.id, None, JobState::Created)?;
                recorder.job(&template.id, Some(JobState::Created), JobState::Skipped)?;
                results.insert(
                    template.id.clone(),
                    JobResult {
                        id: template.id.clone(),
                        state: JobState::Skipped,
                        skip_reason: Some(SkipReason::DependencyNotSuccessful),
                        attempts: Vec::new(),
                        outputs: BTreeMap::new(),
                    },
                );
                continue;
            }
            let record = producer
                .outputs
                .get(&template.source.output_name)
                .ok_or_else(|| EngineError::DynamicMatrix {
                    template_id: template.id.clone(),
                    message: "declared producer output is unavailable".to_owned(),
                })?;
            let TypedOutputValue::Json(input) = &record.value else {
                return Err(EngineError::DynamicMatrix {
                    template_id: template.id.clone(),
                    message: "producer output is not canonical JSON".to_owned(),
                });
            };
            let expanded = expand_dynamic_job_set(capsule_digest.clone(), template, input, 0)
                .map_err(|error| EngineError::DynamicMatrix {
                    template_id: template.id.clone(),
                    message: error.to_string(),
                })?;
            for job in &expanded.jobs {
                if results.contains_key(&job.id) {
                    return Err(EngineError::DuplicateJob(job.id.clone()));
                }
                let result = self.execute_job(
                    capsule,
                    &capsule_digest,
                    job,
                    runtime_context,
                    &results,
                    &mut recorder,
                )?;
                results.insert(job.id.clone(), result);
            }
        }

        let final_state = if self.cancellation.is_cancelled()
            || results.values().any(|job| job.state == JobState::Canceled)
        {
            RunState::Canceled
        } else if results.values().any(|job| {
            matches!(
                job.state,
                JobState::Failed | JobState::TimedOut | JobState::Lost
            )
        }) {
            RunState::Failed
        } else {
            RunState::Succeeded
        };
        recorder.run(Some(RunState::Running), final_state);

        Ok(ExecutionResult {
            state: final_state,
            jobs: results,
            events: recorder.events,
        })
    }
}

use crate::context::runtime_context_matches;

#[derive(Default)]
struct EventRecorder {
    sequence: u64,
    events: Vec<EngineEvent>,
}

use crate::validation::validate_capsule;

/// Trusted local process backend.
///
/// Only `PATH` is inherited by default. The rest of the host environment is
/// cleared before spawn so credentials and unrelated runner state do not leak
/// into a capsule accidentally. This backend cannot provide network or filesystem
/// isolation and therefore requires both `Isolation::Native` and explicit
/// `allow_native` opt-in.
#[cfg(test)]
use crate::native::{host_platform, NativeProcessExecutor};

impl EventRecorder {
    fn push(&mut self, kind: EngineEventKind) {
        self.events.push(EngineEvent {
            sequence: self.sequence,
            kind,
        });
        self.sequence = self.sequence.saturating_add(1);
    }

    fn run(&mut self, from: Option<RunState>, to: RunState) {
        self.push(EngineEventKind::RunStateChanged { from, to });
    }

    fn job(
        &mut self,
        job_id: &str,
        from: Option<JobState>,
        to: JobState,
    ) -> Result<(), EngineError> {
        if let Some(from) = from {
            if !from.can_transition_to(to) {
                return Err(EngineError::InvalidJobTransition { from, to });
            }
        }
        self.push(EngineEventKind::JobStateChanged {
            job_id: job_id.to_owned(),
            from,
            to,
        });
        Ok(())
    }

    fn attempt(&mut self, job_id: &str, attempt: u32) {
        self.push(EngineEventKind::JobAttemptStarted {
            job_id: job_id.to_owned(),
            attempt,
        });
    }

    fn step(
        &mut self,
        job_id: &str,
        step_id: &str,
        job_attempt: u32,
        from: Option<StepState>,
        to: StepState,
    ) -> Result<(), EngineError> {
        if let Some(from) = from {
            if !from.can_transition_to(to) {
                return Err(EngineError::InvalidStepTransition { from, to });
            }
        }
        self.push(EngineEventKind::StepStateChanged {
            job_id: job_id.to_owned(),
            step_id: step_id.to_owned(),
            job_attempt,
            from,
            to,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
