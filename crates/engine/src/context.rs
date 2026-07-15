//! Runtime context construction and updates.

pub use crate::model::RuntimeContext;
use crate::{JobResult, StepResult, StepState};
use runtrue_workflow_ir::{ExecutionCapsule, PlannedJob, ScalarValue, TypedOutputValue};
use std::collections::BTreeMap;

pub(crate) fn runtime_context_matches(left: &RuntimeContext, right: &RuntimeContext) -> bool {
    left.len() == right.len()
        && left.iter().all(|(path, left_value)| {
            right
                .get(path)
                .is_some_and(|right_value| scalar_value_matches(left_value, right_value))
        })
}

fn scalar_value_matches(left: &ScalarValue, right: &ScalarValue) -> bool {
    match (left, right) {
        (ScalarValue::String(left), ScalarValue::String(right)) => left == right,
        (ScalarValue::Integer(left), ScalarValue::Integer(right)) => left == right,
        (ScalarValue::Number(left), ScalarValue::Number(right)) => {
            left.to_bits() == right.to_bits()
        }
        (ScalarValue::Boolean(left), ScalarValue::Boolean(right)) => left == right,
        (
            ScalarValue::String(_)
            | ScalarValue::Integer(_)
            | ScalarValue::Number(_)
            | ScalarValue::Boolean(_),
            _,
        ) => false,
    }
}

pub(crate) fn build_job_context(
    capsule: &ExecutionCapsule,
    job: &PlannedJob,
    runtime_context: &RuntimeContext,
    prior_results: &BTreeMap<String, JobResult>,
) -> RuntimeContext {
    let mut context = runtime_context.clone();
    context.insert(
        "git.source_commit".to_owned(),
        ScalarValue::String(capsule.context.source_commit.clone()),
    );
    if let Some(base_commit) = &capsule.context.base_commit {
        context.insert(
            "git.base_commit".to_owned(),
            ScalarValue::String(base_commit.clone()),
        );
    }
    for (name, value) in &capsule.variables {
        context.insert(name.clone(), value.clone());
        context.insert(format!("vars.{name}"), value.clone());
    }
    for (name, value) in &job.variables {
        context.insert(name.clone(), value.clone());
        context.insert(format!("vars.{name}"), value.clone());
    }
    for (name, value) in &job.matrix {
        context.insert(format!("matrix.{name}"), value.clone());
    }
    for dependency in &job.needs {
        if let Some(result) = prior_results.get(dependency) {
            for (name, output) in &result.outputs {
                if let Some(value) = output_context_scalar(&output.value) {
                    context.insert(format!("needs.{dependency}.outputs.{name}"), value);
                }
            }
        }
    }
    context
}

pub(crate) fn update_one_step_context(context: &mut RuntimeContext, result: &StepResult) {
    let outcome = match result.state {
        StepState::Succeeded => "success",
        StepState::Failed => "failure",
        StepState::Canceled => "cancelled",
        StepState::TimedOut => "timed_out",
        StepState::Skipped => "skipped",
        StepState::Created | StepState::Running => "in_progress",
    };
    let conclusion = if result.continued_on_error {
        "success"
    } else {
        outcome
    };
    context.insert(
        format!("steps.{}.outcome", result.id),
        ScalarValue::String(outcome.to_owned()),
    );
    for (name, output) in &result.outputs {
        if let Some(value) = output_context_scalar(&output.value) {
            context.insert(format!("steps.{}.outputs.{name}", result.id), value);
        }
    }
    context.insert(
        format!("steps.{}.conclusion", result.id),
        ScalarValue::String(conclusion.to_owned()),
    );
    if !result.continued_on_error {
        match result.state {
            StepState::Failed | StepState::TimedOut => {
                context.insert("success".to_owned(), ScalarValue::Boolean(false));
                context.insert("failure".to_owned(), ScalarValue::Boolean(true));
            }
            StepState::Canceled => {
                context.insert("success".to_owned(), ScalarValue::Boolean(false));
                context.insert("cancelled".to_owned(), ScalarValue::Boolean(true));
            }
            StepState::Created | StepState::Running | StepState::Succeeded | StepState::Skipped => {
            }
        }
    }
}

fn output_context_scalar(value: &TypedOutputValue) -> Option<ScalarValue> {
    match value {
        TypedOutputValue::String(value) => Some(ScalarValue::String(value.clone())),
        TypedOutputValue::Integer(value) => Some(ScalarValue::Integer(*value)),
        TypedOutputValue::Number(value) => Some(ScalarValue::Number(*value)),
        TypedOutputValue::Boolean(value) => Some(ScalarValue::Boolean(*value)),
        TypedOutputValue::ArtifactReference(value) => {
            Some(ScalarValue::String(value.artifact_id.clone()))
        }
        TypedOutputValue::Json(_) => None,
    }
}
