use crate::{Job, Permissions, StrictMap, Triggers, WorkflowOutputDefinition};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub version: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "on")]
    pub triggers: Triggers,
    /// Typed parameters accepted when this workflow is invoked by another
    /// workflow. Root workflows may leave this empty.
    #[serde(default)]
    pub inputs: StrictMap<InputDefinition>,
    /// Public output aliases for reusable callers. Each alias must resolve to
    /// an artifact output from one of this workflow's jobs.
    #[serde(default)]
    pub outputs: StrictMap<WorkflowOutputDefinition>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub vars: StrictMap<Scalar>,
    pub jobs: StrictMap<Job>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Scalar {
    String(String),
    Integer(i64),
    Number(f64),
    Boolean(bool),
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string, signed 64-bit integer, finite number, or boolean")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(Scalar::Boolean(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Scalar::Integer(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i64::try_from(value)
                    .map(Scalar::Integer)
                    .map_err(|_| E::custom("integer is outside the supported signed 64-bit range"))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.is_finite() {
                    Ok(Scalar::Number(if value == 0.0 { 0.0 } else { value }))
                } else {
                    Err(E::custom("numeric values must be finite"))
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Scalar::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(Scalar::String(value))
            }
        }

        deserializer.deserialize_any(ScalarVisitor)
    }
}

impl Scalar {
    #[must_use]
    pub fn is_finite(&self) -> bool {
        !matches!(self, Self::Number(value) if !value.is_finite())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDefinition {
    #[serde(rename = "type")]
    pub kind: InputType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<Scalar>,
    #[serde(default)]
    pub options: Vec<Scalar>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    String,
    Boolean,
    Integer,
    Number,
    Choice,
}
