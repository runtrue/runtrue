use super::{
    super::{
        absolute, display_path, print_human_run, print_json, read_event, resolve_one_workflow,
        write_atomic_output, CliError, RunArgs, EXIT_EXECUTION, EXIT_OK,
    },
    compile_path,
};
use runtrue_engine::{Engine, ExecutionResult, NativeProcessExecutor, RunState, RuntimeContext};
use runtrue_expression::{Context as ExpressionContext, Expression, Value as ExpressionValue};
use runtrue_replay::ReplayBundle;
use runtrue_runtime_local::{
    LocalArtifactCapture, LocalArtifactConfig, LocalArtifactExecutor, LocalCacheConfig,
    LocalCacheExecutor,
};
use runtrue_workflow_ir::{
    Architecture, ExecutionCapsule, Isolation, OperatingSystem, ScalarValue, StepAction,
    ValueBinding,
};
use serde::Serialize;
use std::{env, path::Path};

pub(crate) fn run(workspace: &Path, args: RunArgs) -> Result<u8, CliError> {
    if !args.allow_native {
        return Err(CliError::NativeAcknowledgementRequired);
    }
    let path = resolve_one_workflow(workspace, args.context.workflow)?;
    let event = read_event(args.context.event.as_deref(), workspace)?;
    let compilation = compile_path(
        workspace,
        &path,
        event,
        args.context.source_commit,
        args.context.base_commit,
        args.job,
    )?;
    let runtime_context = compilation.capsule.context.event_context.clone();
    validate_local_capsule(&compilation.capsule, &runtime_context)?;

    let mut executor = NativeProcessExecutor::new(workspace, args.allow_native);
    executor.set_external_cache_handling(true);
    executor.set_external_artifact_handling(true);
    let executor = LocalCacheExecutor::new(executor, LocalCacheConfig::for_workspace(workspace));
    let executor =
        LocalArtifactExecutor::new(executor, LocalArtifactConfig::for_workspace(workspace));
    let mut engine = Engine::new(executor);
    let result = engine.execute_with_context(&compilation.capsule, &runtime_context)?;
    let artifacts = engine
        .executor_mut()
        .capture_successful_jobs(&compilation.capsule, &result)?;
    let succeeded = result.state == RunState::Succeeded;
    let cache_references = engine.executor().inner().cache_references();
    let mut artifact_references = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<Vec<_>>();
    artifact_references.sort();
    artifact_references.dedup();
    let replay_record = args
        .replay_bundle
        .map(|path| {
            let path = absolute(workspace, path);
            let mut bundle = ReplayBundle::new(
                compilation.capsule.clone(),
                compilation.approval_subject_digest.clone(),
                Some(&result),
            )?;
            bundle.artifact_references.clone_from(&artifact_references);
            bundle.cache_references.clone_from(&cache_references);
            let envelope = bundle.seal()?;
            let bytes = envelope.canonical_bytes()?;
            write_atomic_output(&path, &bytes)?;
            Ok::<_, CliError>((path, envelope.bundle_digest))
        })
        .transpose()?;
    if args.json {
        print_json(&RunReport {
            capsule_digest: compilation.capsule_digest.to_string(),
            approval_subject_digest: compilation.approval_subject_digest.to_string(),
            risk_score: compilation.risk_report.score,
            replay_bundle_digest: replay_record.as_ref().map(|(_, digest)| digest.to_string()),
            replay_bundle_path: replay_record
                .as_ref()
                .map(|(path, _)| display_path(workspace, path)),
            artifacts,
            result,
        })?;
    } else {
        print_human_run(&compilation, &result, &artifacts)?;
        if let Some((path, digest)) = replay_record {
            println!(
                "replay bundle: {digest}  {}",
                display_path(workspace, &path)
            );
        }
    }
    Ok(if succeeded { EXIT_OK } else { EXIT_EXECUTION })
}

pub(crate) fn validate_local_capsule(
    capsule: &ExecutionCapsule,
    runtime_context: &RuntimeContext,
) -> Result<(), CliError> {
    let host_os = match env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::Macos,
        "linux" => OperatingSystem::Linux,
        other => {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "host operating system `{other}` has no local executor"
            )));
        }
    };
    let host_arch = match env::consts::ARCH {
        "aarch64" => Architecture::Arm64,
        "x86_64" => Architecture::Amd64,
        other => {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "host architecture `{other}` has no local executor"
            )));
        }
    };
    for job in &capsule.jobs {
        if job.runner.isolation != Isolation::Native {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` requests {:?} isolation; only explicitly trusted native execution is available",
                job.id, job.runner.isolation
            )));
        }
        if job.runner.os != host_os || job.runner.arch != host_arch {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` targets {:?}/{:?}, but this host is {host_os:?}/{host_arch:?}",
                job.id, job.runner.os, job.runner.arch
            )));
        }
        if !job.services.is_empty() {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` declares service containers",
                job.id
            )));
        }
        if !job.runner.capabilities.is_empty() {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` requests runner capabilities",
                job.id
            )));
        }
        if job.concurrency.is_some() {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` declares a concurrency group",
                job.id
            )));
        }
        if job.environment.is_some() {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "job `{}` targets a protected environment",
                job.id
            )));
        }

        let mut expression_context = ExpressionContext::new();
        for (path, value) in runtime_context {
            expression_context.insert(path.clone(), expression_value(value)?);
        }
        expression_context.insert(
            "git.source_commit",
            ExpressionValue::string(capsule.context.source_commit.clone()),
        );
        if let Some(base_commit) = &capsule.context.base_commit {
            expression_context.insert(
                "git.base_commit",
                ExpressionValue::string(base_commit.clone()),
            );
        }
        for (name, value) in capsule.variables.iter().chain(&job.variables) {
            expression_context.insert(format!("vars.{name}"), expression_value(value)?);
        }
        for (name, value) in &job.matrix {
            expression_context.insert(format!("matrix.{name}"), expression_value(value)?);
        }
        expression_context.insert("success", ExpressionValue::boolean(true));
        expression_context.insert("failure", ExpressionValue::boolean(false));
        expression_context.insert("cancelled", ExpressionValue::boolean(false));
        validate_local_condition(job.condition.as_deref(), &expression_context)?;

        for step in &job.steps {
            if matches!(step.action, StepAction::Component { .. }) {
                return Err(CliError::UnsupportedLocalFeature(format!(
                    "step `{}.{}` uses a component action",
                    job.id, step.id
                )));
            }
            if !step.capabilities.secrets.is_empty() || !step.capabilities.oidc_audiences.is_empty()
            {
                return Err(CliError::UnsupportedLocalFeature(format!(
                    "step `{}.{}` requires a secret or workload identity broker",
                    job.id, step.id
                )));
            }
            validate_local_condition(step.condition.as_deref(), &expression_context)?;
            for binding in step.environment.values().chain(step.inputs.values()) {
                validate_local_binding(binding, &expression_context)?;
            }
            if let StepAction::Command { args, .. } = &step.action {
                for binding in args {
                    validate_local_binding(binding, &expression_context)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_local_condition(
    condition: Option<&str>,
    context: &ExpressionContext,
) -> Result<(), CliError> {
    let Some(condition) = condition else {
        return Ok(());
    };
    let expression = Expression::parse(condition).map_err(|error| {
        CliError::UnsupportedLocalFeature(format!("condition `{condition}` is invalid: {error}"))
    })?;
    for reference in expression.context_references() {
        let root = reference.split('.').next().unwrap_or_default();
        if matches!(root, "inputs" | "needs" | "steps") {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "condition `{condition}` uses unsupported local context `{root}`"
            )));
        }
        if context.get(&reference).is_none() {
            return Err(CliError::UnsupportedLocalFeature(format!(
                "condition `{condition}` references unavailable context `{reference}`"
            )));
        }
    }
    expression.evaluate_bool(context).map_err(|error| {
        CliError::UnsupportedLocalFeature(format!(
            "condition `{condition}` cannot be evaluated before execution: {error}"
        ))
    })?;
    Ok(())
}

fn validate_local_binding(
    binding: &ValueBinding,
    context: &ExpressionContext,
) -> Result<(), CliError> {
    let ValueBinding::Context(binding) = binding else {
        return Ok(());
    };
    let root = binding.from.split('.').next().unwrap_or_default();
    if matches!(root, "inputs" | "needs" | "steps") {
        return Err(CliError::UnsupportedLocalFeature(format!(
            "value binding `{}` uses unsupported local context `{root}`",
            binding.from
        )));
    }
    if context.get(&binding.from).is_none() {
        return Err(CliError::UnsupportedLocalFeature(format!(
            "value binding references unavailable context `{}`",
            binding.from
        )));
    }
    if context
        .get(&binding.from)
        .and_then(ExpressionValue::as_str)
        .is_some_and(|value| value.contains('\0'))
    {
        return Err(CliError::UnsupportedLocalFeature(format!(
            "value binding `{}` resolves to a string containing a NUL byte",
            binding.from
        )));
    }
    Ok(())
}

fn expression_value(value: &ScalarValue) -> Result<ExpressionValue, CliError> {
    match value {
        ScalarValue::String(value) => Ok(ExpressionValue::string(value.clone())),
        ScalarValue::Integer(value) => ExpressionValue::integer(*value).map_err(|error| {
            CliError::UnsupportedLocalFeature(format!("inexact expression context value: {error}"))
        }),
        ScalarValue::Number(value) => ExpressionValue::number(*value).map_err(|error| {
            CliError::UnsupportedLocalFeature(format!("non-finite context value: {error}"))
        }),
        ScalarValue::Boolean(value) => Ok(ExpressionValue::boolean(*value)),
    }
}

#[derive(Debug, Serialize)]
struct RunReport {
    capsule_digest: String,
    approval_subject_digest: String,
    risk_score: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_bundle_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_bundle_path: Option<String>,
    artifacts: Vec<LocalArtifactCapture>,
    result: ExecutionResult,
}
