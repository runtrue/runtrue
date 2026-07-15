//! Job and attempt conclusion logic.

use crate::{JobAttemptResult, JobState, StepResult, StepState};

pub(super) fn conclude_attempt(attempt: &JobAttemptResult) -> JobState {
    if attempt.primary_state != JobState::Succeeded {
        return attempt.primary_state;
    }
    if attempt
        .finalizers
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::Canceled)
    {
        JobState::Canceled
    } else if attempt
        .finalizers
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::TimedOut)
    {
        JobState::TimedOut
    } else if attempt
        .finalizers
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::Failed)
    {
        JobState::Failed
    } else {
        JobState::Succeeded
    }
}

pub(super) fn conclude_primary_steps(steps: &[StepResult]) -> JobState {
    if steps
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::Canceled)
    {
        JobState::Canceled
    } else if steps
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::TimedOut)
    {
        JobState::TimedOut
    } else if steps
        .iter()
        .any(|step| !step.continued_on_error && step.state == StepState::Failed)
    {
        JobState::Failed
    } else {
        JobState::Succeeded
    }
}

use super::EventRecorder;
use crate::conditions::evaluate_condition;
use crate::context::build_job_context;
use crate::outputs::project_job_outputs;
use crate::{Engine, EngineError, Executor, JobResult, RuntimeContext, SkipReason};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob, ScalarValue};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

impl<E: Executor> Engine<E> {
    pub(super) fn execute_job(
        &mut self,
        capsule: &ExecutionCapsule,
        capsule_digest: &ContentDigest,
        job: &PlannedJob,
        runtime_context: &RuntimeContext,
        prior_results: &BTreeMap<String, JobResult>,
        recorder: &mut EventRecorder,
    ) -> Result<JobResult, EngineError> {
        recorder.job(&job.id, None, JobState::Created)?;

        if self.cancellation.is_cancelled() {
            recorder.job(&job.id, Some(JobState::Created), JobState::Canceled)?;
            return Ok(JobResult {
                id: job.id.clone(),
                state: JobState::Canceled,
                skip_reason: Some(SkipReason::RunCanceled),
                attempts: Vec::new(),
                outputs: BTreeMap::new(),
            });
        }

        if job.needs.iter().any(|dependency| {
            prior_results
                .get(dependency)
                .is_some_and(|result| result.state != JobState::Succeeded)
        }) {
            recorder.job(&job.id, Some(JobState::Created), JobState::Skipped)?;
            return Ok(JobResult {
                id: job.id.clone(),
                state: JobState::Skipped,
                skip_reason: Some(SkipReason::DependencyNotSuccessful),
                attempts: Vec::new(),
                outputs: BTreeMap::new(),
            });
        }

        let mut context = build_job_context(capsule, job, runtime_context, prior_results);
        context.insert("success".to_owned(), ScalarValue::Boolean(true));
        context.insert("failure".to_owned(), ScalarValue::Boolean(false));
        context.insert("cancelled".to_owned(), ScalarValue::Boolean(false));
        if !evaluate_condition(job.condition.as_deref(), &context)? {
            recorder.job(&job.id, Some(JobState::Created), JobState::Skipped)?;
            return Ok(JobResult {
                id: job.id.clone(),
                state: JobState::Skipped,
                skip_reason: Some(SkipReason::ConditionFalse),
                attempts: Vec::new(),
                outputs: BTreeMap::new(),
            });
        }

        recorder.job(&job.id, Some(JobState::Created), JobState::Queued)?;
        recorder.job(&job.id, Some(JobState::Queued), JobState::Preparing)?;
        recorder.job(&job.id, Some(JobState::Preparing), JobState::Running)?;

        let job_started = Instant::now();
        let job_timeout = Duration::from_millis(job.timeout_ms);
        let mut attempts = Vec::new();
        let mut conclusion = JobState::Failed;

        for attempt in 1..=job.retries.saturating_add(1) {
            if self.cancellation.is_cancelled() {
                conclusion = JobState::Canceled;
                break;
            }
            if job_started.elapsed() >= job_timeout {
                conclusion = JobState::TimedOut;
                break;
            }

            recorder.attempt(&job.id, attempt);
            let attempt_result = self.execute_job_attempt(
                job,
                capsule_digest,
                attempt,
                job_started,
                job_timeout,
                &context,
                recorder,
            )?;
            conclusion = conclude_attempt(&attempt_result);
            attempts.push(attempt_result);

            if conclusion == JobState::Succeeded || conclusion == JobState::Canceled {
                break;
            }
            if job_started.elapsed() >= job_timeout {
                conclusion = JobState::TimedOut;
                break;
            }
        }

        recorder.job(&job.id, Some(JobState::Running), JobState::Finalizing)?;
        recorder.job(&job.id, Some(JobState::Finalizing), conclusion)?;
        let outputs = attempts
            .last()
            .filter(|_| conclusion == JobState::Succeeded)
            .map(|attempt| project_job_outputs(job, attempt))
            .transpose()?
            .unwrap_or_default();
        Ok(JobResult {
            id: job.id.clone(),
            state: conclusion,
            skip_reason: None,
            attempts,
            outputs,
        })
    }
}
