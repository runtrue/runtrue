pub(crate) fn validate_binding(binding: &LeaseBinding, limits: LogLimits) -> Result<(), LogError> {
    validate_identifier("run_id", &binding.run_id, limits)?;
    validate_identifier("job_id", &binding.job_id, limits)?;
    validate_identifier("lease_id", &binding.lease_id, limits)?;
    if binding.fencing_generation == 0 {
        return Err(LogError::InvalidBinding);
    }
    Ok(())
}

pub(crate) fn validate_input(frame: &LogInputFrame, limits: LogLimits) -> Result<(), LogError> {
    validate_binding(
        &LeaseBinding {
            run_id: frame.run_id.clone(),
            job_id: frame.job_id.clone(),
            lease_id: frame.lease_id.clone(),
            fencing_generation: frame.fencing_generation,
        },
        limits,
    )?;
    validate_identifier("step_id", &frame.step_id, limits)
}

pub(crate) fn validate_stream_key(stream: &StreamKey, limits: LogLimits) -> Result<(), LogError> {
    validate_binding(
        &LeaseBinding {
            run_id: stream.run_id.clone(),
            job_id: stream.job_id.clone(),
            lease_id: stream.lease_id.clone(),
            fencing_generation: stream.fencing_generation,
        },
        limits,
    )?;
    validate_identifier("step_id", &stream.step_id, limits)
}

pub(crate) fn validate_step_key(step: &StepKey, limits: LogLimits) -> Result<(), LogError> {
    validate_binding(
        &LeaseBinding {
            run_id: step.run_id.clone(),
            job_id: step.job_id.clone(),
            lease_id: step.lease_id.clone(),
            fencing_generation: step.fencing_generation,
        },
        limits,
    )?;
    validate_identifier("step_id", &step.step_id, limits)
}

pub(crate) fn validate_stored_frame(
    frame: &StoredLogFrame,
    limits: LogLimits,
) -> Result<(), LogError> {
    validate_binding(
        &LeaseBinding {
            run_id: frame.run_id.clone(),
            job_id: frame.job_id.clone(),
            lease_id: frame.lease_id.clone(),
            fencing_generation: frame.fencing_generation,
        },
        limits,
    )?;
    validate_identifier("step_id", &frame.step_id, limits)?;
    if frame.payload.byte_len() > limits.max_run_bytes {
        return Err(LogError::Integrity(
            "stored output exceeds the run byte bound".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    _field: &'static str,
    value: &str,
    limits: LogLimits,
) -> Result<(), LogError> {
    if value.is_empty()
        || value.len() > limits.max_identifier_bytes
        || value.chars().any(char::is_control)
    {
        return Err(LogError::InvalidIdentifier);
    }
    Ok(())
}
use crate::{
    model::{LeaseBinding, LogInputFrame, StepKey, StoredLogFrame, StreamKey},
    LogError, LogLimits,
};
