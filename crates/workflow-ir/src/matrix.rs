use crate::{canonicalize_value, CapsuleError, MatrixExpansionError, PlannedJob, ScalarValue};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicMatrixSource {
    pub producer_job_id: String,
    pub output_name: String,
    pub maximum_jobs: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicJobTemplate {
    pub id: String,
    pub source: DynamicMatrixSource,
    pub template: PlannedJob,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpandedJobSet {
    pub version: u32,
    pub parent_capsule_digest: ContentDigest,
    pub producer_job_id: String,
    pub producer_output_name: String,
    pub matrix_input_digest: ContentDigest,
    pub generated_job_ids: Vec<String>,
    pub jobs: Vec<PlannedJob>,
    pub policy_epoch: u64,
}

pub type MatrixValues = BTreeMap<String, ScalarValue>;
pub type MatrixExpansion = (String, MatrixValues);

impl ExpandedJobSet {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapsuleError> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&canonicalize_value(value)).map_err(CapsuleError::Serialize)
    }
    pub fn digest(&self) -> Result<ContentDigest, CapsuleError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

pub fn expand_matrix_values(
    base_id: &str,
    axes: &BTreeMap<String, Vec<ScalarValue>>,
    maximum_jobs: usize,
) -> Result<Vec<MatrixExpansion>, MatrixExpansionError> {
    if maximum_jobs == 0 || maximum_jobs > 1_024 {
        return Err(MatrixExpansionError::InvalidLimit(maximum_jobs));
    }
    if axes.is_empty() {
        return Ok(vec![(base_id.to_owned(), BTreeMap::new())]);
    }
    let mut combinations = vec![BTreeMap::new()];
    for (axis, values) in axes {
        if !valid_matrix_identifier(axis) {
            return Err(MatrixExpansionError::InvalidAxis(axis.clone()));
        }
        if values.is_empty() {
            return Err(MatrixExpansionError::EmptyAxis(axis.clone()));
        }
        let mut values = values
            .iter()
            .cloned()
            .map(|value| {
                validate_matrix_scalar(&value)?;
                let canonical =
                    serde_json::to_vec(&canonicalize_value(serde_json::to_value(&value)?))?;
                Ok((canonical, value))
            })
            .collect::<Result<Vec<_>, MatrixExpansionError>>()?;
        values.sort_by(|left, right| left.0.cmp(&right.0));
        values.dedup_by(|left, right| left.0 == right.0);
        let mut next = Vec::new();
        for combination in &combinations {
            for (_, value) in &values {
                let mut combination = combination.clone();
                combination.insert(axis.clone(), value.clone());
                next.push(combination);
                if next.len() > maximum_jobs {
                    return Err(MatrixExpansionError::LimitExceeded(maximum_jobs));
                }
            }
        }
        combinations = next;
    }
    let width = combinations
        .len()
        .saturating_sub(1)
        .to_string()
        .len()
        .max(1);
    Ok(combinations
        .into_iter()
        .enumerate()
        .map(|(index, values)| (format!("{base_id}[{index:0width$}]"), values))
        .collect())
}

pub fn expand_dynamic_job_set(
    parent_capsule_digest: ContentDigest,
    template: &DynamicJobTemplate,
    input: &Value,
    policy_epoch: u64,
) -> Result<ExpandedJobSet, MatrixExpansionError> {
    if template.id != template.template.id {
        return Err(MatrixExpansionError::TemplateIdentityMismatch);
    }
    if !template.template.matrix.is_empty() {
        return Err(MatrixExpansionError::TemplateMatrixNotEmpty);
    }
    if !template
        .template
        .needs
        .iter()
        .any(|dependency| dependency == &template.source.producer_job_id)
    {
        return Err(MatrixExpansionError::ProducerDependencyMissing);
    }
    let object = input
        .as_object()
        .ok_or(MatrixExpansionError::InputMustBeObject)?;
    let mut axes = BTreeMap::new();
    for (axis, values) in object {
        let values = values
            .as_array()
            .ok_or_else(|| MatrixExpansionError::AxisMustBeArray(axis.clone()))?;
        let values = values
            .iter()
            .map(json_scalar)
            .collect::<Result<Vec<_>, _>>()?;
        axes.insert(axis.clone(), values);
    }
    let canonical_input = serde_json::to_vec(&canonicalize_value(input.clone()))?;
    let matrix_input_digest = ContentDigest::sha256(canonical_input);
    let expanded = expand_matrix_values(&template.id, &axes, template.source.maximum_jobs)?;
    let mut jobs = Vec::with_capacity(expanded.len());
    for (id, matrix) in expanded {
        let mut job = template.template.clone();
        job.id = id;
        job.matrix = matrix;
        jobs.push(job);
    }
    let generated_job_ids = jobs.iter().map(|job| job.id.clone()).collect();
    Ok(ExpandedJobSet {
        version: 1,
        parent_capsule_digest,
        producer_job_id: template.source.producer_job_id.clone(),
        producer_output_name: template.source.output_name.clone(),
        matrix_input_digest,
        generated_job_ids,
        jobs,
        policy_epoch,
    })
}

fn valid_matrix_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_matrix_scalar(value: &ScalarValue) -> Result<(), MatrixExpansionError> {
    match value {
        ScalarValue::Number(value)
            if !value.is_finite() || value.to_bits() == (-0.0_f64).to_bits() =>
        {
            Err(MatrixExpansionError::InvalidScalar)
        }
        ScalarValue::String(value) if value.contains('\0') => {
            Err(MatrixExpansionError::InvalidScalar)
        }
        _ => Ok(()),
    }
}

fn json_scalar(value: &Value) -> Result<ScalarValue, MatrixExpansionError> {
    match value {
        Value::String(value) => Ok(ScalarValue::String(value.clone())),
        Value::Bool(value) => Ok(ScalarValue::Boolean(*value)),
        Value::Number(value) if value.is_i64() => Ok(ScalarValue::Integer(
            value.as_i64().ok_or(MatrixExpansionError::InvalidScalar)?,
        )),
        Value::Number(value) if value.is_u64() => Err(MatrixExpansionError::InvalidScalar),
        Value::Number(value) => Ok(ScalarValue::Number(
            value.as_f64().ok_or(MatrixExpansionError::InvalidScalar)?,
        )),
        _ => Err(MatrixExpansionError::InvalidScalar),
    }
}
