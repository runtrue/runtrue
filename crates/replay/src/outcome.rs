use crate::{ReplayAttemptOutcome, ReplayJobOutcome, ReplayOutcome, ReplayStepOutcome};
use runtrue_engine::ExecutionResult;

impl From<&ExecutionResult> for ReplayOutcome {
    fn from(result: &ExecutionResult) -> Self {
        Self {
            state: result.state,
            jobs: result
                .jobs
                .values()
                .map(|job| ReplayJobOutcome {
                    id: job.id.clone(),
                    state: job.state,
                    attempts: job
                        .attempts
                        .iter()
                        .map(|attempt| ReplayAttemptOutcome {
                            number: attempt.number,
                            steps: attempt
                                .steps
                                .iter()
                                .map(|step| ReplayStepOutcome {
                                    id: step.id.clone(),
                                    state: step.state,
                                    exit_code: step
                                        .output
                                        .as_ref()
                                        .and_then(|output| output.exit_code),
                                    continued_on_error: step.continued_on_error,
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}
