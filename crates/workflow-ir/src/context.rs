use crate::Trust;
use runtrue_model::ContentDigest;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowFrontendProvenance {
    pub frontend_id: String,
    pub contract_generation: u32,
    pub frontend_generation: u32,
    pub configuration_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub native_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_digest: Option<ContentDigest>,
}

/// Bounded diagnostic artifact emitted while translating a source workflow.
///
/// This is a client-produced compilation artifact, not Provider Evidence as
/// defined by ADR 0015. Its digest is signed through
/// [`WorkflowFrontendProvenance`]; the bytes are retained separately from the
/// execution capsule so retention and access policy can evolve independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowFrontendReportArtifact {
    pub media_type: String,
    pub digest: ContentDigest,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleContext {
    pub source_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    #[serde(default)]
    pub source_trust: SourceTrust,
    pub normalized_event_digest: ContentDigest,
    /// Canonical provider-neutral event bytes retained only for authenticated
    /// SCM capsules so an isolated action can receive the signed event contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_event_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scm: Option<ScmRuntimeContext>,
    pub event_context: BTreeMap<String, ScalarValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_frontend: Option<WorkflowFrontendProvenance>,
    pub policy_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScmRuntimeContext {
    pub provider: String,
    pub api_url: String,
    pub repository: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ScalarValue {
    String(String),
    Integer(i64),
    Number(f64),
    Boolean(bool),
}

impl<'de> Deserialize<'de> for ScalarValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarValueVisitor;
        impl<'de> Visitor<'de> for ScalarValueVisitor {
            type Value = ScalarValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string, signed 64-bit integer, finite number, or boolean")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(ScalarValue::Boolean(value))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(ScalarValue::Integer(value))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i64::try_from(value)
                    .map(ScalarValue::Integer)
                    .map_err(|_| E::custom("integer is outside the supported signed 64-bit range"))
            }
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.is_finite() {
                    Ok(ScalarValue::Number(if value == 0.0 { 0.0 } else { value }))
                } else {
                    Err(E::custom("numeric values must be finite"))
                }
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ScalarValue::String(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(ScalarValue::String(value))
            }
        }
        deserializer.deserialize_any(ScalarValueVisitor)
    }
}

impl fmt::Display for ScalarValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(value) => formatter.write_str(value),
            Self::Integer(value) => write!(formatter, "{value}"),
            Self::Number(value) => write!(formatter, "{value}"),
            Self::Boolean(value) => write!(formatter, "{value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValueBinding {
    Literal(ScalarValue),
    Context(ContextBinding),
}

impl ValueBinding {
    #[must_use]
    pub fn is_untrusted_runtime_context(&self) -> bool {
        matches!(self, Self::Context(binding) if matches!(binding.from.split('.').next().unwrap_or_default(), "event" | "inputs" | "needs" | "steps" | "git"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBinding {
    pub from: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceTrust {
    #[default]
    Untrusted,
    Trusted,
    ProtectedBranch,
}

impl SourceTrust {
    #[must_use]
    pub const fn satisfies(self, required: Trust) -> bool {
        matches!(
            (self, required),
            (_, Trust::UntrustedOk)
                | (Self::Trusted | Self::ProtectedBranch, Trust::TrustedOnly)
                | (Self::ProtectedBranch, Trust::ProtectedBranchOnly)
        )
    }
}
