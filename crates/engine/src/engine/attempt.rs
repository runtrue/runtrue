//! Attempt outcome classification used by mandatory backend finalization.

use crate::{JobAttemptOutcome, JobAttemptResult, JobState};

pub(super) fn classify_attempt_outcome(
    result: &Result<JobAttemptResult, crate::EngineError>,
) -> JobAttemptOutcome {
    match result.as_ref() {
        Ok(attempt) => match super::job::conclude_attempt(attempt) {
            JobState::Succeeded => JobAttemptOutcome::Succeeded,
            JobState::TimedOut => JobAttemptOutcome::TimedOut,
            JobState::Canceled => JobAttemptOutcome::Canceled,
            JobState::Failed | JobState::Lost => JobAttemptOutcome::Failed,
            JobState::Created
            | JobState::BlockedPolicy
            | JobState::AwaitingApproval
            | JobState::Queued
            | JobState::Leased
            | JobState::Preparing
            | JobState::Running
            | JobState::Finalizing
            | JobState::Rejected
            | JobState::Skipped => JobAttemptOutcome::Aborted,
        },
        Err(_) => JobAttemptOutcome::Aborted,
    }
}

use super::{
    job::conclude_primary_steps,
    step::{prepare_request, skipped_step},
    EventRecorder,
};
use crate::conditions::evaluate_condition;
use crate::context::update_one_step_context;
use crate::outputs::decode_structured_outputs;
use crate::{
    CredentialTaint, Engine, EngineError, Executor, RuntimeContext, SkipReason, StepResult,
    StepState,
};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{PlannedJob, ScalarValue};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

impl<E: Executor> Engine<E> {
    #[allow(
        clippy::too_many_arguments,
        reason = "attempt execution keeps signed job identity, capsule digest, deadlines, runtime context, and lifecycle recorder explicit"
    )]
    pub(super) fn execute_job_attempt(
        &mut self,
        job: &PlannedJob,
        capsule_digest: &ContentDigest,
        attempt: u32,
        job_started: Instant,
        job_timeout: Duration,
        base_context: &RuntimeContext,
        recorder: &mut EventRecorder,
    ) -> Result<JobAttemptResult, EngineError> {
        let result = self.execute_job_attempt_inner(
            job,
            capsule_digest,
            attempt,
            job_started,
            job_timeout,
            base_context,
            recorder,
        );
        let outcome = classify_attempt_outcome(&result);
        if let Err(cleanup) = self.executor.finish_job_attempt(job, attempt, outcome) {
            let message = match &result {
                Ok(_) => cleanup.to_string(),
                Err(prior) => format!("{cleanup}; attempt also failed: {prior}"),
            };
            return Err(EngineError::ExecutorFinalization {
                job_id: job.id.clone(),
                attempt,
                message,
            });
        }
        result
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the inner attempt state machine must receive the same explicit security and lifecycle bounds as its cleanup wrapper"
    )]
    fn execute_job_attempt_inner(
        &mut self,
        job: &PlannedJob,
        capsule_digest: &ContentDigest,
        attempt: u32,
        job_started: Instant,
        job_timeout: Duration,
        base_context: &RuntimeContext,
        recorder: &mut EventRecorder,
    ) -> Result<JobAttemptResult, EngineError> {
        let mut context = base_context.clone();
        let mut results = Vec::with_capacity(job.steps.len());
        let mut stopped = false;

        for step in &job.steps {
            self.transition_step(
                recorder,
                &job.id,
                &step.id,
                attempt,
                None,
                StepState::Created,
            )?;

            if stopped {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::Skipped,
                )?;
                let result = skipped_step(step, SkipReason::PreviousStepFailed);
                update_one_step_context(&mut context, &result);
                results.push(result);
                continue;
            }
            if self.cancellation.is_cancelled() {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::Canceled,
                )?;
                let result = StepResult {
                    id: step.id.clone(),
                    state: StepState::Canceled,
                    continued_on_error: false,
                    skip_reason: Some(SkipReason::RunCanceled),
                    output: None,
                    error: None,
                    outputs: BTreeMap::new(),
                };
                results.push(result);
                stopped = true;
                continue;
            }
            if job_started.elapsed() >= job_timeout {
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
                    continued_on_error: false,
                    skip_reason: None,
                    output: None,
                    error: Some("job timeout elapsed before the step started".to_owned()),
                    outputs: BTreeMap::new(),
                });
                stopped = true;
                continue;
            }
            if !evaluate_condition(step.condition.as_deref(), &context)? {
                self.transition_step(
                    recorder,
                    &job.id,
                    &step.id,
                    attempt,
                    Some(StepState::Created),
                    StepState::Skipped,
                )?;
                let result = skipped_step(step, SkipReason::ConditionFalse);
                update_one_step_context(&mut context, &result);
                results.push(result);
                continue;
            }

            let request = prepare_request(
                job,
                step,
                attempt,
                &context,
                job_started,
                job_timeout,
                self.cancellation.clone(),
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
            let (state, output, error, typed_outputs) = match execution {
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

            let continued =
                step.continue_on_error && matches!(state, StepState::Failed | StepState::TimedOut);
            let result = StepResult {
                id: step.id.clone(),
                state,
                continued_on_error: continued,
                skip_reason: None,
                output,
                error,
                outputs: typed_outputs,
            };
            update_one_step_context(&mut context, &result);
            if state != StepState::Succeeded && !continued {
                stopped = true;
            }
            results.push(result);
        }

        let primary_state = if self.cancellation.is_cancelled() {
            JobState::Canceled
        } else {
            conclude_primary_steps(&results)
        };
        context.insert(
            "success".to_owned(),
            ScalarValue::Boolean(primary_state == JobState::Succeeded),
        );
        context.insert(
            "failure".to_owned(),
            ScalarValue::Boolean(matches!(
                primary_state,
                JobState::Failed | JobState::TimedOut
            )),
        );
        context.insert(
            "cancelled".to_owned(),
            ScalarValue::Boolean(primary_state == JobState::Canceled),
        );
        let finalizers = self.execute_finalizers(
            job,
            capsule_digest,
            attempt,
            primary_state,
            &mut context,
            recorder,
        )?;
        let credential_taint = results
            .iter()
            .chain(&finalizers)
            .filter_map(|step| step.output.as_ref())
            .fold(CredentialTaint::None, |taint, output| {
                taint.merge(output.credential_taint)
            });

        Ok(JobAttemptResult {
            number: attempt,
            primary_state,
            credential_taint,
            steps: results,
            finalizers,
        })
    }
}
