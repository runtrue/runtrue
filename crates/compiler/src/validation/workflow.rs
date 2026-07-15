pub(crate) fn validate_workflow_shape(
    workflow: &ast::Workflow,
    settings: &CompilerSettings,
) -> Result<(), CompileError> {
    if workflow.jobs.is_empty() {
        return Err(CompileError::semantic(
            "jobs",
            "workflow must contain at least one job",
        ));
    }
    if workflow.jobs.len() > MAX_WORKFLOW_JOBS {
        return Err(CompileError::semantic(
            "jobs",
            format!("workflow exceeds the {MAX_WORKFLOW_JOBS} job limit"),
        ));
    }
    if settings.max_matrix_jobs == 0 || settings.max_matrix_jobs > MAX_WORKFLOW_JOBS {
        return Err(CompileError::semantic(
            "compiler.max_matrix_jobs",
            format!("matrix limit must be between 1 and {MAX_WORKFLOW_JOBS}"),
        ));
    }
    if settings.max_reusable_depth == 0 || settings.max_reusable_depth > 32 {
        return Err(CompileError::semantic(
            "compiler.max_reusable_depth",
            "reusable workflow depth limit must be between 1 and 32",
        ));
    }
    if settings.max_reusable_jobs == 0 || settings.max_reusable_jobs > MAX_WORKFLOW_JOBS {
        return Err(CompileError::semantic(
            "compiler.max_reusable_jobs",
            format!("reusable workflow fan-out limit must be between 1 and {MAX_WORKFLOW_JOBS}"),
        ));
    }
    if let Some(name) = &workflow.name {
        if name.is_empty() || name.chars().count() > 200 {
            return Err(CompileError::semantic(
                "name",
                "workflow name must contain 1 to 200 characters",
            ));
        }
    }
    validate_permissions(&workflow.permissions, "permissions")?;
    validate_variables(&workflow.vars, "vars")?;
    validate_inputs(workflow)?;
    for (name, output) in &workflow.outputs {
        validate_identifier(name, &format!("outputs.{name}"))?;
        parse_workflow_output_path(&output.from, &format!("outputs.{name}.from"))?;
    }

    for (job_id, job) in &workflow.jobs {
        validate_identifier(job_id, &format!("jobs.{job_id}"))?;
        if job.dynamic_matrix.is_some() && !job.matrix.is_empty() {
            return Err(CompileError::semantic(
                format!("jobs.{job_id}.dynamic-matrix"),
                "dynamic-matrix is mutually exclusive with static matrix",
            ));
        }
        if let Some(dynamic) = &job.dynamic_matrix {
            if dynamic.max_jobs == 0 || dynamic.max_jobs > settings.max_matrix_jobs {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.max-jobs"),
                    format!(
                        "dynamic matrix limit must be between 1 and the configured {} job limit",
                        settings.max_matrix_jobs
                    ),
                ));
            }
            let (producer, output) = parse_dynamic_matrix_path(
                &dynamic.from,
                &format!("jobs.{job_id}.dynamic-matrix.from"),
            )?;
            if !job.needs.iter().any(|dependency| dependency == producer) {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    "dynamic matrix producer must be an explicit job dependency",
                ));
            }
            let producer_job = workflow.jobs.get(producer).ok_or_else(|| {
                CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    format!("unknown dynamic matrix producer `{producer}`"),
                )
            })?;
            if !producer_job.matrix.is_empty() || producer_job.dynamic_matrix.is_some() {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    "dynamic matrix producer must be one non-matrix signed job",
                ));
            }
            let projected = producer_job.value_outputs.get(output).ok_or_else(|| {
                CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    "dynamic matrix source is not a declared producer job value output",
                )
            })?;
            let (step_id, step_output) = parse_step_output_path(
                &projected.from,
                &format!("jobs.{producer}.value-outputs.{output}.from"),
            )?;
            let source_step = producer_job
                .steps
                .iter()
                .find(|step| step.id.as_deref() == Some(step_id))
                .map(|step| (step, true))
                .or_else(|| {
                    producer_job
                        .finalizers
                        .iter()
                        .find(|finalizer| finalizer.step.id.as_deref() == Some(step_id))
                        .map(|finalizer| (&finalizer.step, finalizer.required))
                });
            let schema = source_step
                .as_ref()
                .and_then(|(step, _)| step.outputs.get(step_output));
            if !matches!(
                schema.map(|schema| (schema.kind, schema.required)),
                Some((ast::StepOutputType::Json, true))
            ) {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    "dynamic matrix source must be a declared required JSON structured output",
                ));
            }
            if !matches!(
                source_step,
                Some((step, required_execution))
                    if required_execution && step.condition.is_none() && !step.continue_on_error
            ) {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.dynamic-matrix.from"),
                    "dynamic matrix source step must be unconditional and execution-critical so producer success guarantees the output",
                ));
            }
        }
        if job.uses.is_some() {
            validate_reusable_call_shape(job_id, job)?;
        } else {
            if !job.inputs.is_empty() {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.with"),
                    "`with` is valid only for reusable workflow calls",
                ));
            }
            if job.steps.is_empty() {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.steps"),
                    "executable job must contain at least one step",
                ));
            }
        }
        if job.steps.len().saturating_add(job.finalizers.len()) > MAX_STEPS_PER_JOB {
            return Err(CompileError::semantic(
                format!("jobs.{job_id}.steps"),
                format!("job steps plus finalizers exceed the {MAX_STEPS_PER_JOB} limit"),
            ));
        }
        validate_variables(&job.vars, &format!("jobs.{job_id}.vars"))?;
        if let Some(permissions) = &job.permissions {
            validate_permissions(permissions, &format!("jobs.{job_id}.permissions"))?;
        }
    }
    for (job_id, job) in &workflow.jobs {
        for dependency in &job.needs {
            if workflow
                .jobs
                .get(dependency)
                .is_some_and(|dependency| dependency.dynamic_matrix.is_some())
            {
                return Err(CompileError::semantic(
                    format!("jobs.{job_id}.needs"),
                    "this version supports dynamic matrices only for terminal jobs",
                ));
            }
        }
    }
    Ok(())
}
use crate::{
    ast, parse_dynamic_matrix_path, parse_step_output_path, parse_workflow_output_path,
    validate_identifier, validate_inputs, validate_permissions, validate_reusable_call_shape,
    validate_variables, CompileError, CompilerSettings, MAX_STEPS_PER_JOB, MAX_WORKFLOW_JOBS,
};
