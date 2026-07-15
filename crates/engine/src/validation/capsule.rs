//! Capsule structure, compatibility, lifecycle, and dynamic-job validation.

use super::{validate_acyclic, validate_scalar_invariants};
use crate::{EngineError, MAX_EXPANDED_JOBS, MAX_FINALIZER_TIMEOUT_MS, MAX_JOB_RETRIES};
use runtrue_expression::Expression;
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    ExecutionCapsule, PlannedStep, StepAction, StepOutputSchema, StepOutputType,
    CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::BTreeSet;

fn unwrap_expression(expression: &str) -> &str {
    expression
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
        .map(str::trim)
        .unwrap_or(expression)
}

pub(crate) fn validate_capsule(capsule: &ExecutionCapsule) -> Result<(), EngineError> {
    if capsule.schema_version != CAPSULE_SCHEMA_VERSION {
        return Err(EngineError::IncompatibleSchemaVersion {
            found: capsule.schema_version,
            expected: CAPSULE_SCHEMA_VERSION,
        });
    }
    if capsule.engine_compatibility_version != ENGINE_COMPATIBILITY_VERSION {
        return Err(EngineError::IncompatibleEngineVersion {
            found: capsule.engine_compatibility_version.clone(),
            expected: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        });
    }
    validate_scalar_invariants(capsule)?;

    let all_jobs = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .collect::<Vec<_>>();
    let maximum_expanded_jobs = capsule.jobs.len().saturating_add(
        capsule
            .dynamic_jobs
            .iter()
            .map(|template| template.source.maximum_jobs)
            .fold(0_usize, usize::saturating_add),
    );
    if maximum_expanded_jobs > MAX_EXPANDED_JOBS {
        return Err(EngineError::DynamicMatrix {
            template_id: "capsule".to_owned(),
            message: format!(
                "static jobs plus signed dynamic maxima exceed the {MAX_EXPANDED_JOBS} job limit"
            ),
        });
    }
    let static_job_ids = capsule
        .jobs
        .iter()
        .map(|job| job.id.as_str())
        .collect::<BTreeSet<_>>();
    let dynamic_job_ids = capsule
        .dynamic_jobs
        .iter()
        .map(|template| template.id.as_str())
        .collect::<BTreeSet<_>>();
    if let Some((job, dependency)) = capsule.jobs.iter().find_map(|job| {
        job.needs
            .iter()
            .find(|dependency| dynamic_job_ids.contains(dependency.as_str()))
            .map(|dependency| (job, dependency))
    }) {
        return Err(EngineError::DynamicMatrix {
            template_id: dependency.clone(),
            message: format!(
                "dynamic job must be terminal and cannot be a dependency of static job `{}`",
                job.id
            ),
        });
    }
    let mut job_ids = BTreeSet::new();
    for job in &all_jobs {
        if job.id.is_empty() {
            return Err(EngineError::EmptyJobId);
        }
        if !job_ids.insert(job.id.clone()) {
            return Err(EngineError::DuplicateJob(job.id.clone()));
        }
    }
    for template in &capsule.dynamic_jobs {
        if template.id != template.template.id {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "template id does not match its signed job id".to_owned(),
            });
        }
        let producer = capsule
            .jobs
            .iter()
            .find(|job| job.id == template.source.producer_job_id)
            .ok_or_else(|| EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "producer is not a static signed job".to_owned(),
            })?;
        if !template.template.matrix.is_empty() {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "template contains pre-expanded matrix values".to_owned(),
            });
        }
        if !template
            .template
            .needs
            .iter()
            .any(|dependency| dependency == &template.source.producer_job_id)
        {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "template does not retain its producer dependency".to_owned(),
            });
        }
        if let Some(dependency) = template
            .template
            .needs
            .iter()
            .find(|dependency| !static_job_ids.contains(dependency.as_str()))
        {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: format!("template has non-static dependency `{dependency}`"),
            });
        }
        let source_step = producer
            .value_outputs
            .get(&template.source.output_name)
            .and_then(|projection| {
                producer
                    .steps
                    .iter()
                    .find(|step| step.id == projection.step_id)
                    .map(|step| (step, true))
                    .or_else(|| {
                        producer
                            .finalizers
                            .iter()
                            .find(|finalizer| finalizer.step.id == projection.step_id)
                            .map(|finalizer| (&finalizer.step, finalizer.required))
                    })
                    .map(|(step, required_execution)| {
                        (
                            step,
                            required_execution,
                            step.outputs.get(&projection.output_name),
                        )
                    })
            });
        if !matches!(
            source_step,
            Some((
                PlannedStep {
                    condition: None,
                    continue_on_error: false,
                    ..
                },
                true,
                Some(StepOutputSchema {
                    kind: StepOutputType::Json,
                    required: true
                })
            ))
        ) {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "producer source is not a guaranteed required JSON output".to_owned(),
            });
        }
        if template.source.maximum_jobs == 0 || template.source.maximum_jobs > 1_024 {
            return Err(EngineError::DynamicMatrix {
                template_id: template.id.clone(),
                message: "maximum_jobs is outside 1..=1024".to_owned(),
            });
        }
    }
    for job in all_jobs {
        validate_condition_syntax(job.condition.as_deref())?;
        let mut dependencies = BTreeSet::new();
        for dependency in &job.needs {
            if !job_ids.contains(dependency) {
                return Err(EngineError::UnknownDependency {
                    job_id: job.id.clone(),
                    dependency: dependency.clone(),
                });
            }
            if !dependencies.insert(dependency) {
                return Err(EngineError::DuplicateDependency {
                    job_id: job.id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
        if job.retries > MAX_JOB_RETRIES {
            return Err(EngineError::TooManyRetries {
                job_id: job.id.clone(),
                retries: job.retries,
            });
        }
        if job.timeout_ms == 0 {
            return Err(EngineError::InvalidTimeout {
                scope: format!("job `{}`", job.id),
            });
        }
        if job.finalizer_timeout_ms == 0 || job.finalizer_timeout_ms > MAX_FINALIZER_TIMEOUT_MS {
            return Err(EngineError::InvalidTimeout {
                scope: format!("job `{}` finalizers", job.id),
            });
        }

        let mut step_ids = BTreeSet::new();
        for step in &job.steps {
            if step.id.is_empty() {
                return Err(EngineError::EmptyStepId {
                    job_id: job.id.clone(),
                });
            }
            if !step_ids.insert(step.id.clone()) {
                return Err(EngineError::DuplicateStep {
                    job_id: job.id.clone(),
                    step_id: step.id.clone(),
                });
            }
            validate_condition_syntax(step.condition.as_deref())?;
            if step.timeout_ms == Some(0) {
                return Err(EngineError::InvalidTimeout {
                    scope: format!("step `{}.{}`", job.id, step.id),
                });
            }
            if let StepAction::Script {
                script,
                script_digest,
                ..
            } = &step.action
            {
                if ContentDigest::sha256(script.as_bytes()) != *script_digest {
                    return Err(EngineError::ScriptDigestMismatch {
                        job_id: job.id.clone(),
                        step_id: step.id.clone(),
                    });
                }
            }
        }
        for finalizer in &job.finalizers {
            let step = &finalizer.step;
            if step.id.is_empty() {
                return Err(EngineError::EmptyStepId {
                    job_id: job.id.clone(),
                });
            }
            if !step_ids.insert(step.id.clone()) {
                return Err(EngineError::DuplicateStep {
                    job_id: job.id.clone(),
                    step_id: step.id.clone(),
                });
            }
            validate_condition_syntax(step.condition.as_deref())?;
            if step.timeout_ms == Some(0) {
                return Err(EngineError::InvalidTimeout {
                    scope: format!("finalizer `{}.{}`", job.id, step.id),
                });
            }
            if let StepAction::Script {
                script,
                script_digest,
                ..
            } = &step.action
            {
                if ContentDigest::sha256(script.as_bytes()) != *script_digest {
                    return Err(EngineError::ScriptDigestMismatch {
                        job_id: job.id.clone(),
                        step_id: step.id.clone(),
                    });
                }
            }
        }
    }
    validate_acyclic(capsule)
}

fn validate_condition_syntax(condition: Option<&str>) -> Result<(), EngineError> {
    let Some(condition) = condition else {
        return Ok(());
    };
    Expression::parse(unwrap_expression(condition))
        .map(|_| ())
        .map_err(|error| EngineError::InvalidCondition {
            expression: condition.to_owned(),
            message: error.to_string(),
        })
}
