pub(crate) fn scalar_text(value: &ScalarValue) -> String {
    value.to_string()
}

pub(crate) fn startup_control(
    request: &StepExecutionRequest,
    deadline: Instant,
    max_output_bytes: usize,
) -> Result<RuntimeControl, OciError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(OciError::ServiceStartupTimedOut);
    }
    Ok(RuntimeControl {
        timeout: remaining,
        cancellation: request.cancellation.clone(),
        max_output_bytes,
    })
}

pub(crate) fn setup_was_canceled(result: &RuntimeResult, cancellation: &CancellationToken) -> bool {
    result.canceled || cancellation.is_cancelled()
}

pub(crate) fn validate_setup_result(
    result: &RuntimeResult,
    operation: &str,
    output_limit: usize,
) -> Result<(), OciError> {
    validate_runtime_result(result, output_limit)?;
    if !result.process_group_clean {
        return Err(OciError::ProcessGroupLeak);
    }
    if result.timed_out {
        return Err(OciError::ServiceStartupTimedOut);
    }
    if result.exit_code != Some(0) {
        return Err(OciError::ServiceStartupFailed {
            operation: operation.to_owned(),
            exit_code: result.exit_code,
        });
    }
    Ok(())
}

pub(crate) fn wait_cancellable(
    duration: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> bool {
    let until = Instant::now()
        .checked_add(duration)
        .map_or(deadline, |until| until.min(deadline));
    while Instant::now() < until {
        if cancellation.is_cancelled() {
            return true;
        }
        thread::sleep(
            Duration::from_millis(10).min(until.saturating_duration_since(Instant::now())),
        );
    }
    cancellation.is_cancelled()
}

pub(crate) fn record_first_error(first: &mut Option<OciError>, error: OciError) {
    if first.is_none() {
        *first = Some(error);
    }
}

pub(crate) fn validate_runtime_result(
    result: &RuntimeResult,
    limit: usize,
) -> Result<(), OciError> {
    if result.stdout.len() > limit || result.stderr.len() > limit {
        return Err(OciError::RuntimeContractViolation(
            "runtime returned output beyond the requested bound".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_cleanup_result(
    result: &RuntimeResult,
    expected_exit: Option<i32>,
) -> Result<(), OciError> {
    validate_runtime_result(result, 64 * 1024)?;
    if !result.process_group_clean {
        return Err(OciError::ProcessGroupLeak);
    }
    if result.timed_out || result.canceled || result.exit_code != expected_exit {
        return Err(OciError::CleanupVerificationFailed {
            expected_exit,
            actual_exit: result.exit_code,
        });
    }
    Ok(())
}
use crate::{
    thread, CancellationToken, Duration, Instant, OciError, RuntimeControl, RuntimeResult,
    ScalarValue, StepExecutionRequest,
};
