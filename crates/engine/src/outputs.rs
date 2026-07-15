//! Structured output decoding, validation, and job projection.

use crate::{EngineError, JobAttemptResult, MAX_STRUCTURED_OUTPUT_BYTES};
use runtrue_model::ContentDigest;
use runtrue_workflow_ir::{
    OutputChannel, OutputProvenance, PlannedJob, StepOutputSchema, StepOutputType,
    TypedOutputRecord, TypedOutputValue,
};
use std::collections::BTreeMap;

pub(crate) fn decode_structured_outputs(
    capsule_digest: &ContentDigest,
    job_id: &str,
    step_id: &str,
    job_attempt: u32,
    schemas: &BTreeMap<String, StepOutputSchema>,
    encoded: Option<&str>,
) -> Result<BTreeMap<String, TypedOutputRecord>, EngineError> {
    let encoded = encoded.unwrap_or("{}");
    if encoded.len() > MAX_STRUCTURED_OUTPUT_BYTES {
        return Err(invalid_structured_output(
            job_id,
            step_id,
            format!("record exceeds the {MAX_STRUCTURED_OUTPUT_BYTES}-byte limit"),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(encoded).map_err(|error| {
        invalid_structured_output(job_id, step_id, format!("invalid JSON object: {error}"))
    })?;
    let canonical_record =
        serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(value.clone()))
            .map_err(|error| invalid_structured_output(job_id, step_id, error.to_string()))?;
    if canonical_record != encoded.as_bytes() {
        return Err(invalid_structured_output(
            job_id,
            step_id,
            "record must use duplicate-free canonical JSON bytes",
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        invalid_structured_output(job_id, step_id, "record must be a JSON object")
    })?;
    if let Some(unknown) = object.keys().find(|name| !schemas.contains_key(*name)) {
        return Err(invalid_structured_output(
            job_id,
            step_id,
            format!("undeclared output `{unknown}`"),
        ));
    }
    let mut outputs = BTreeMap::new();
    for (name, schema) in schemas {
        let Some(value) = object.get(name) else {
            if schema.required {
                return Err(invalid_structured_output(
                    job_id,
                    step_id,
                    format!("required output `{name}` is missing"),
                ));
            }
            continue;
        };
        let value = decode_typed_output(value, schema.kind).map_err(|message| {
            invalid_structured_output(job_id, step_id, format!("output `{name}` {message}"))
        })?;
        let canonical = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
            serde_json::to_value(&value)
                .map_err(|error| invalid_structured_output(job_id, step_id, error.to_string()))?,
        ))
        .map_err(|error| invalid_structured_output(job_id, step_id, error.to_string()))?;
        outputs.insert(
            name.clone(),
            TypedOutputRecord {
                value,
                value_digest: ContentDigest::sha256(canonical),
                provenance: OutputProvenance {
                    capsule_digest: capsule_digest.clone(),
                    job_id: job_id.to_owned(),
                    step_id: step_id.to_owned(),
                    job_attempt,
                    channel: OutputChannel::ExecutorStructured,
                },
            },
        );
    }
    Ok(outputs)
}

fn decode_typed_output(
    value: &serde_json::Value,
    kind: StepOutputType,
) -> Result<TypedOutputValue, String> {
    match kind {
        StepOutputType::String => value
            .as_str()
            .filter(|value| !value.contains('\0'))
            .map(|value| TypedOutputValue::String(value.to_owned()))
            .ok_or_else(|| "must be a NUL-free string".to_owned()),
        StepOutputType::Integer => value
            .as_i64()
            .map(TypedOutputValue::Integer)
            .ok_or_else(|| "must be a signed 64-bit integer".to_owned()),
        StepOutputType::Number => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(|value| TypedOutputValue::Number(if value == 0.0 { 0.0 } else { value }))
            .ok_or_else(|| "must be a finite number".to_owned()),
        StepOutputType::Boolean => value
            .as_bool()
            .map(TypedOutputValue::Boolean)
            .ok_or_else(|| "must be a boolean".to_owned()),
        StepOutputType::Json => Ok(TypedOutputValue::Json(
            runtrue_workflow_ir::canonicalize_value(value.clone()),
        )),
        StepOutputType::ArtifactReference => {
            let reference: runtrue_workflow_ir::ArtifactReference =
                serde_json::from_value(value.clone())
                    .map_err(|_| "must be an artifact_id/manifest_digest object".to_owned())?;
            if reference.artifact_id.is_empty()
                || reference.artifact_id.len() > 256
                || reference
                    .artifact_id
                    .contains(['\0', '\n', '\r', '/', '\\'])
            {
                return Err("contains an invalid immutable artifact id".to_owned());
            }
            Ok(TypedOutputValue::ArtifactReference(reference))
        }
    }
}

fn invalid_structured_output(
    job_id: &str,
    step_id: &str,
    message: impl Into<String>,
) -> EngineError {
    EngineError::InvalidStructuredOutput {
        job_id: job_id.to_owned(),
        step_id: step_id.to_owned(),
        message: message.into(),
    }
}

pub(crate) fn project_job_outputs(
    job: &PlannedJob,
    attempt: &JobAttemptResult,
) -> Result<BTreeMap<String, TypedOutputRecord>, EngineError> {
    let steps = attempt
        .steps
        .iter()
        .chain(attempt.finalizers.iter())
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let mut outputs = BTreeMap::new();
    for (name, projection) in &job.value_outputs {
        let Some(record) = steps
            .get(projection.step_id.as_str())
            .and_then(|step| step.outputs.get(&projection.output_name))
        else {
            continue;
        };
        outputs.insert(name.clone(), record.clone());
    }
    Ok(outputs)
}
