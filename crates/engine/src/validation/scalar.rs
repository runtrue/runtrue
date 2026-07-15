//! Scalar, binding, command, and environment invariants.

use crate::EngineError;
use runtrue_workflow_ir::{ExecutionCapsule, ScalarValue, StepAction, ValueBinding};

pub(super) fn validate_scalar_invariants(capsule: &ExecutionCapsule) -> Result<(), EngineError> {
    fn scalar(path: String, value: &ScalarValue) -> Result<(), EngineError> {
        let valid = match value {
            ScalarValue::Number(value) => {
                value.is_finite() && value.to_bits() != (-0.0_f64).to_bits()
            }
            ScalarValue::String(value) => !value.contains('\0'),
            ScalarValue::Integer(_) | ScalarValue::Boolean(_) => true,
        };
        if valid {
            Ok(())
        } else {
            Err(EngineError::InvalidScalarValue(path))
        }
    }

    fn binding(path: String, value: &ValueBinding) -> Result<(), EngineError> {
        if let ValueBinding::Literal(value) = value {
            scalar(path, value)?;
        }
        Ok(())
    }

    fn environment_binding(
        path: String,
        _name: &str,
        value: &ValueBinding,
    ) -> Result<(), EngineError> {
        if matches!(
            value,
            ValueBinding::Context(binding)
                if matches!(
                    binding.from.split('.').next().unwrap_or_default(),
                    "event" | "inputs" | "needs" | "steps" | "git"
                )
        ) {
            return Err(EngineError::UnsafeDynamicEnvironment(path));
        }
        binding(path, value)
    }

    for (name, value) in &capsule.context.event_context {
        scalar(format!("context.event_context.{name}"), value)?;
    }
    for (name, value) in &capsule.variables {
        scalar(format!("variables.{name}"), value)?;
    }
    for job in capsule.jobs.iter().chain(
        capsule
            .dynamic_jobs
            .iter()
            .map(|template| &template.template),
    ) {
        for (name, value) in &job.variables {
            scalar(format!("jobs.{}.variables.{name}", job.id), value)?;
        }
        for (name, value) in &job.matrix {
            scalar(format!("jobs.{}.matrix.{name}", job.id), value)?;
        }
        for service in &job.services {
            for (name, value) in &service.environment {
                environment_binding(
                    format!("jobs.{}.services.{}.env.{name}", job.id, service.id),
                    name,
                    value,
                )?;
            }
        }
        for step in job
            .steps
            .iter()
            .chain(job.finalizers.iter().map(|finalizer| &finalizer.step))
        {
            for (name, value) in &step.inputs {
                binding(
                    format!("jobs.{}.steps.{}.inputs.{name}", job.id, step.id),
                    value,
                )?;
            }
            for (name, value) in &step.environment {
                environment_binding(
                    format!("jobs.{}.steps.{}.env.{name}", job.id, step.id),
                    name,
                    value,
                )?;
            }
            match &step.action {
                StepAction::Command { program, args } => {
                    if program.is_empty() || program.contains('\0') {
                        return Err(EngineError::InvalidScalarValue(format!(
                            "jobs.{}.steps.{}.command",
                            job.id, step.id
                        )));
                    }
                    if args.iter().any(ValueBinding::is_untrusted_runtime_context) {
                        return Err(EngineError::UnsafeDynamicArgument(format!(
                            "jobs.{}.steps.{}.args",
                            job.id, step.id
                        )));
                    }
                    for (index, value) in args.iter().enumerate() {
                        binding(
                            format!("jobs.{}.steps.{}.args[{index}]", job.id, step.id),
                            value,
                        )?;
                    }
                }
                StepAction::Script { script, .. } if script.contains('\0') => {
                    return Err(EngineError::InvalidScalarValue(format!(
                        "jobs.{}.steps.{}.script",
                        job.id, step.id
                    )));
                }
                StepAction::Component { .. } | StepAction::Script { .. } => {}
            }
        }
    }
    Ok(())
}
