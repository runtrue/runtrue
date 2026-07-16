//! Step request preparation and skipped-step construction.

use crate::bindings::{resolve_binding, resolve_bindings, validate_environment};
use crate::{
    CancellationToken, EngineError, PreparedAction, RuntimeContext, SkipReason,
    StepExecutionRequest, StepResult, StepState,
};
use runtrue_workflow_ir::{PlannedJob, PlannedStep, StepAction};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub(super) fn skipped_step(step: &PlannedStep, reason: SkipReason) -> StepResult {
    StepResult {
        id: step.id.clone(),
        state: StepState::Skipped,
        continued_on_error: false,
        skip_reason: Some(reason),
        output: None,
        error: None,
        outputs: BTreeMap::new(),
    }
}

pub(super) fn prepare_request(
    job: &PlannedJob,
    step: &PlannedStep,
    attempt: u32,
    context: &RuntimeContext,
    job_started: Instant,
    job_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<StepExecutionRequest, EngineError> {
    let action = match &step.action {
        StepAction::Component { reference } => PreparedAction::Component {
            reference: reference.clone(),
            inputs: resolve_bindings(&step.inputs, context)?,
        },
        StepAction::Command { program, args } => PreparedAction::Command {
            program: program.clone(),
            args: args
                .iter()
                .map(|binding| resolve_binding(binding, context))
                .collect::<Result<_, _>>()?,
        },
        StepAction::Container { entrypoint, args } => PreparedAction::Container {
            entrypoint: entrypoint.clone(),
            args: args
                .as_ref()
                .map(|args| {
                    args.iter()
                        .map(|binding| resolve_binding(binding, context))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?,
        },
        StepAction::Script {
            shell,
            script,
            script_digest,
        } => PreparedAction::Script {
            shell: *shell,
            script: script.clone(),
            script_digest: script_digest.clone(),
        },
    };

    let mut environment = BTreeMap::new();
    // Component actions receive resolved values only through their typed input
    // object. Never synthesize the workflow variable context into an ambient
    // process environment for a Wasm component.
    if !matches!(action, PreparedAction::Component { .. }) {
        for (path, value) in context {
            let Some(name) = path.strip_prefix("vars.") else {
                continue;
            };
            if name.contains('.') {
                continue;
            }
            validate_environment(name, &value.to_string())?;
            environment.insert(name.to_owned(), value.to_string());
        }
    }
    for (name, binding) in &step.environment {
        let value = resolve_binding(binding, context)?;
        validate_environment(name, &value)?;
        environment.insert(name.clone(), value);
    }

    let remaining = job_timeout.saturating_sub(job_started.elapsed());
    let timeout = step
        .timeout_ms
        .map(Duration::from_millis)
        .map_or(remaining, |step_timeout| step_timeout.min(remaining));
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);

    Ok(StepExecutionRequest {
        job_id: job.id.clone(),
        step_id: step.id.clone(),
        job_attempt: attempt,
        runner: job.runner.clone(),
        action,
        environment,
        working_directory: step.working_directory.clone(),
        capabilities: step.capabilities.clone(),
        timeout_ms: Some(timeout_ms),
        cancellation,
    })
}

use super::EventRecorder;
use crate::conditions::evaluate_condition;
use crate::context::update_one_step_context;
use crate::outputs::decode_structured_outputs;
use crate::{CredentialTaint, Engine, Executor, JobState, StepStateObservation};
use runtrue_model::ContentDigest;

impl<E: Executor> Engine<E> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_finalizers(
        &mut self,
        job: &PlannedJob,
        capsule_digest: &ContentDigest,
        attempt: u32,
        primary_state: JobState,
        context: &mut RuntimeContext,
        recorder: &mut EventRecorder,
    ) -> Result<Vec<StepResult>, EngineError> {
        let started = Instant::now();
        let timeout = Duration::from_millis(job.finalizer_timeout_ms);
        let mut results = Vec::with_capacity(job.finalizers.len());
        for finalizer in &job.finalizers {
            let step = &finalizer.step;
            self.transition_step(
                recorder,
                &job.id,
                &step.id,
                attempt,
                None,
                StepState::Created,
            )?;
            if (primary_state == JobState::Canceled || self.cancellation.is_cancelled())
                && !finalizer.run_on_cancel
            {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::Skipped,
                )?;
                results.push(StepResult {
                    id: step.id.clone(),
                    state: StepState::Skipped,
                    continued_on_error: false,
                    skip_reason: Some(SkipReason::RunCanceled),
                    output: None,
                    error: None,
                    outputs: BTreeMap::new(),
                });
                continue;
            }
            if started.elapsed() >= timeout {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::TimedOut,
                )?;
                results.push(StepResult {
                    id: step.id.clone(),
                    state: StepState::TimedOut,
                    continued_on_error: !finalizer.required,
                    skip_reason: None,
                    output: None,
                    error: Some("finalizer cleanup deadline elapsed".to_owned()),
                    outputs: BTreeMap::new(),
                });
                continue;
            }
            if !evaluate_condition(step.condition.as_deref(), context)? {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::Skipped,
                )?;
                results.push(skipped_step(step, SkipReason::ConditionFalse));
                continue;
            }
            let cleanup_cancellation = if self.cancellation.is_cancelled() {
                CancellationToken::default()
            } else {
                self.cancellation.clone()
            };
            let request = prepare_request(
                job,
                step,
                attempt,
                context,
                started,
                timeout,
                cleanup_cancellation,
            )?;
            self.transition_step(
                recorder,
                &job.id,
                &step.id,
                attempt,
                Some(StepState::Created),
                StepState::Running,
            )?;
            let execution = self.executor.execute(&request).map(|mut output| {
                output.suppress_tainted_publication();
                output
            });
            let (state, output, error, outputs) = match execution {
                Ok(output) if output.canceled => {
                    (StepState::Canceled, Some(output), None, BTreeMap::new())
                }
                Ok(output) if output.timed_out => {
                    (StepState::TimedOut, Some(output), None, BTreeMap::new())
                }
                Ok(output) if output.succeeded() => match decode_structured_outputs(
                    capsule_digest,
                    &job.id,
                    &step.id,
                    attempt,
                    &step.outputs,
                    output.structured_output.as_deref(),
                ) {
                    Ok(outputs) => (StepState::Succeeded, Some(output), None, outputs),
                    Err(error) => (
                        StepState::Failed,
                        Some(output),
                        Some(error.to_string()),
                        BTreeMap::new(),
                    ),
                },
                Ok(output) => (StepState::Failed, Some(output), None, BTreeMap::new()),
                Err(error) => (
                    StepState::Failed,
                    None,
                    Some(error.to_string()),
                    BTreeMap::new(),
                ),
            };
            let credential_taint = output
                .as_ref()
                .map_or(CredentialTaint::None, |output| output.credential_taint);
            self.transition_step_with_taint(
                recorder,
                &job.id,
                &step.id,
                attempt,
                Some(StepState::Running),
                state,
                credential_taint,
            )?;
            let continued_on_error = !finalizer.required
                && matches!(
                    state,
                    StepState::Failed | StepState::TimedOut | StepState::Canceled
                );
            let result = StepResult {
                id: step.id.clone(),
                state,
                continued_on_error,
                skip_reason: None,
                output,
                error,
                outputs,
            };
            update_one_step_context(context, &result);
            results.push(result);
        }
        Ok(results)
    }

    pub(super) fn transition_step(
        &self,
        recorder: &mut EventRecorder,
        job_id: &str,
        step_id: &str,
        job_attempt: u32,
        from: Option<StepState>,
        to: StepState,
    ) -> Result<(), EngineError> {
        self.transition_step_with_taint(
            recorder,
            job_id,
            step_id,
            job_attempt,
            from,
            to,
            CredentialTaint::None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn transition_step_with_taint(
        &self,
        recorder: &mut EventRecorder,
        job_id: &str,
        step_id: &str,
        job_attempt: u32,
        from: Option<StepState>,
        to: StepState,
        credential_taint: CredentialTaint,
    ) -> Result<(), EngineError> {
        recorder.step(job_id, step_id, job_attempt, from, to)?;
        if let Some(observer) = &self.step_state_observer {
            observer
                .observe(&StepStateObservation {
                    job_id: job_id.to_owned(),
                    step_id: step_id.to_owned(),
                    job_attempt,
                    from,
                    to,
                    credential_taint,
                })
                .map_err(|message| EngineError::StepStateObserver {
                    job_id: job_id.to_owned(),
                    step_id: step_id.to_owned(),
                    to,
                    message,
                })?;
        }
        Ok(())
    }
}
