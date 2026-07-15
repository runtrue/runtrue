use crate::ArtifactReference;
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobValueOutput {
    pub step_id: String,
    pub output_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepOutputSchema {
    pub kind: StepOutputType,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepOutputType {
    String,
    Integer,
    Number,
    Boolean,
    Json,
    ArtifactReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum TypedOutputValue {
    String(String),
    Integer(i64),
    Number(f64),
    Boolean(bool),
    Json(Value),
    ArtifactReference(ArtifactReference),
}

impl PartialEq for TypedOutputValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Integer(left), Self::Integer(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left.to_bits() == right.to_bits(),
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Json(left), Self::Json(right)) => left == right,
            (Self::ArtifactReference(left), Self::ArtifactReference(right)) => left == right,
            _ => false,
        }
    }
}
impl Eq for TypedOutputValue {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputChannel {
    ExecutorStructured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputProvenance {
    pub capsule_digest: ContentDigest,
    pub job_id: String,
    pub step_id: String,
    pub job_attempt: u32,
    pub channel: OutputChannel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedOutputRecord {
    pub value: TypedOutputValue,
    pub value_digest: ContentDigest,
    pub provenance: OutputProvenance,
}
