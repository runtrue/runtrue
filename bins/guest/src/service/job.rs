use crate::GuestAgentError;
use runtrue_workflow_ir::{
    Isolation, NetworkPermission, OperatingSystem, PermissionSet, PlannedJob, Shell, StepAction,
    StepCapabilitySet, ValueBinding,
};

pub(super) fn validate_admitted_job(job: &PlannedJob) -> Result<(), GuestAgentError> {
    if job.runner.isolation != Isolation::Microvm || job.runner.os != OperatingSystem::Linux {
        return Err(GuestAgentError::InvalidConfiguration(
            "admitted job is not a Linux microVM job; isolation downgrade refused".to_owned(),
        ));
    }
    if !job.services.is_empty()
        || job.runner.image.is_some()
        || !job.runner.capabilities.is_empty()
        || job.permissions != PermissionSet::default()
        || !job.outputs.is_empty()
        || job.steps.is_empty()
    {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest services, image labels, host capabilities, data-plane permissions, outputs, and empty jobs are not supported"
                .to_owned(),
        ));
    }
    for step in &job.steps {
        if step.condition.is_some()
            || step.capabilities != StepCapabilitySet::default()
            || step.cache.is_some()
            || !matches!(step.capabilities.network, NetworkPermission::Deny)
            || step
                .inputs
                .values()
                .chain(step.environment.values())
                .any(|value| matches!(value, ValueBinding::Context(_)))
        {
            return Err(GuestAgentError::InvalidConfiguration(
                "admitted step needs an unsupported condition, binding, secret, OIDC, cache, artifact, filesystem, check, or network adapter".to_owned(),
            ));
        }
        match &step.action {
            StepAction::Command { program, args } => {
                if !std::path::Path::new(program).is_absolute()
                    || args
                        .iter()
                        .any(|value| matches!(value, ValueBinding::Context(_)))
                {
                    return Err(GuestAgentError::InvalidConfiguration(
                        "guest commands require an absolute program and literal arguments"
                            .to_owned(),
                    ));
                }
            }
            StepAction::Script {
                shell: Shell::Bash | Shell::Sh,
                ..
            } => {}
            StepAction::Script { .. } | StepAction::Component { .. } => {
                return Err(GuestAgentError::InvalidConfiguration(
                    "admitted step action has no exact guest adapter".to_owned(),
                ));
            }
        }
    }
    Ok(())
}
