pub(crate) fn validate_inputs(workflow: &ast::Workflow) -> Result<(), CompileError> {
    validate_input_definitions(&workflow.inputs, "inputs")?;
    if let Some(manual) = &workflow.triggers.manual {
        validate_input_definitions(&manual.inputs, "on.manual.inputs")?;
    }
    Ok(())
}

pub(crate) fn parse_workflow_output_path<'a>(
    value: &'a str,
    path: &str,
) -> Result<(&'a str, &'a str), CompileError> {
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 4 || segments[0] != "needs" || segments[2] != "outputs" {
        return Err(CompileError::semantic(
            path,
            "workflow output must use `needs.<job-id>.outputs.<output-id>`",
        ));
    }
    validate_identifier(segments[1], path)?;
    validate_identifier(segments[3], path)?;
    Ok((segments[1], segments[3]))
}

pub(crate) fn parse_dynamic_matrix_path<'a>(
    value: &'a str,
    path: &str,
) -> Result<(&'a str, &'a str), CompileError> {
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 4 || segments[0] != "needs" || segments[2] != "outputs" {
        return Err(CompileError::semantic(
            path,
            "dynamic matrix source must use `needs.<job-id>.outputs.<output-id>`",
        ));
    }
    validate_identifier(segments[1], path)?;
    validate_identifier(segments[3], path)?;
    Ok((segments[1], segments[3]))
}

pub(crate) fn parse_step_output_path<'a>(
    value: &'a str,
    path: &str,
) -> Result<(&'a str, &'a str), CompileError> {
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 4 || segments[0] != "steps" || segments[2] != "outputs" {
        return Err(CompileError::semantic(
            path,
            "job value output must use `steps.<step-id>.outputs.<output-id>`",
        ));
    }
    validate_identifier(segments[1], path)?;
    validate_identifier(segments[3], path)?;
    Ok((segments[1], segments[3]))
}

pub(crate) fn validate_input_definitions(
    inputs: &BTreeMap<String, ast::InputDefinition>,
    path: &str,
) -> Result<(), CompileError> {
    for (name, input) in inputs {
        validate_identifier(name, &format!("{path}.{name}"))?;
        if input.kind == ast::InputType::Choice && input.options.is_empty() {
            return Err(CompileError::semantic(
                format!("{path}.{name}.options"),
                "choice input must declare at least one option",
            ));
        }
        if input.options.iter().any(|value| !value.is_finite()) {
            return Err(CompileError::semantic(
                format!("{path}.{name}.options"),
                "numeric input options must be finite",
            ));
        }
        if input.required && input.default.is_none() {
            continue;
        }
        if let Some(default) = &input.default {
            if !default.is_finite() {
                return Err(CompileError::semantic(
                    format!("{path}.{name}.default"),
                    "numeric input defaults must be finite",
                ));
            }
            if !scalar_matches_input(default, input.kind) {
                return Err(CompileError::semantic(
                    format!("{path}.{name}.default"),
                    "default value does not match the declared input type",
                ));
            }
            if input.kind == ast::InputType::Choice && !input.options.contains(default) {
                return Err(CompileError::semantic(
                    format!("{path}.{name}.default"),
                    "choice default must be one of the declared options",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_reusable_call_shape(
    job_id: &str,
    job: &ast::Job,
) -> Result<(), CompileError> {
    let path = format!("jobs.{job_id}");
    if !job.steps.is_empty()
        || job.trust != ast::Trust::default()
        || job.environment.is_some()
        || job.runner != ast::Runner::default()
        || job.permissions.is_some()
        || job.timeout.is_some()
        || job.retries != 0
        || !job.matrix.is_empty()
        || job.dynamic_matrix.is_some()
        || job.concurrency.is_some()
        || !job.vars.is_empty()
        || !job.services.is_empty()
        || !job.finalizers.is_empty()
        || job.finalizer_timeout.is_some()
        || !job.value_outputs.is_empty()
        || !job.outputs.is_empty()
    {
        return Err(CompileError::semantic(
            path,
            "a reusable workflow call may define only name, needs, if, uses, and with",
        ));
    }
    for (name, value) in &job.inputs {
        validate_identifier(name, &format!("jobs.{job_id}.with.{name}"))?;
        if !value.is_finite() {
            return Err(CompileError::semantic(
                format!("jobs.{job_id}.with.{name}"),
                "numeric call inputs must be finite",
            ));
        }
    }
    Ok(())
}

pub(crate) fn scalar_matches_input(value: &ast::Scalar, kind: ast::InputType) -> bool {
    matches!(
        (value, kind),
        (
            ast::Scalar::String(_),
            ast::InputType::String | ast::InputType::Choice
        ) | (
            ast::Scalar::Boolean(_),
            ast::InputType::Boolean | ast::InputType::Choice
        ) | (
            ast::Scalar::Integer(_),
            ast::InputType::Integer | ast::InputType::Number | ast::InputType::Choice
        ) | (
            ast::Scalar::Number(_),
            ast::InputType::Number | ast::InputType::Choice
        )
    )
}
use crate::{ast, validate_identifier, BTreeMap, CompileError};
