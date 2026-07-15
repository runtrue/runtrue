use crate::{
    CapsuleContext, CapsuleError, DynamicJobTemplate, PermissionSet, PlannedJob, ScalarValue,
};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical schema version for an immutable execution [`ExecutionCapsule`].
pub const CAPSULE_SCHEMA_VERSION: u32 = 1;
pub const ENGINE_COMPATIBILITY_VERSION: &str = "runtrue-engine-v1";

/// The immutable, canonical execution artifact produced by the compiler.
///
/// A Capsule binds the workflow identity, normalized context, permissions,
/// jobs, policy inputs, and expected engine parity. Its canonical bytes and
/// digest are therefore suitable for exact-subject approval and replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCapsule {
    pub schema_version: u32,
    pub engine_compatibility_version: String,
    pub compiler_version: String,
    pub workflow: WorkflowIdentity,
    pub context: CapsuleContext,
    pub variables: BTreeMap<String, ScalarValue>,
    pub permissions: PermissionSet,
    pub jobs: Vec<PlannedJob>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_jobs: Vec<DynamicJobTemplate>,
    pub approval: ApprovalRequirements,
    pub expected_parity: ParityGrade,
}

impl ExecutionCapsule {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapsuleError> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&canonicalize_value(value)).map_err(CapsuleError::Serialize)
    }
    pub fn digest(&self) -> Result<ContentDigest, CapsuleError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowIdentity {
    pub name: String,
    pub digest: ContentDigest,
    pub source_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequirements {
    pub workflow_definition: bool,
    pub privileged_execution: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParityGrade {
    AExact,
    BEnvironmentEquivalent,
    CPlatformSpecific,
    DNonReplayable,
}

#[must_use]
pub fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        value => value,
    }
}
