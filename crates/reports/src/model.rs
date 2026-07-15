#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportFormat {
    JunitXml,
    Sarif,
    CoverageSummary,
    CustomEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedReport {
    pub format: ReportFormat,
    pub source_digest: ContentDigest,
    pub summary: ReportSummary,
    pub annotations: Vec<Annotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageSummary>,
}

impl NormalizedReport {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReportError> {
        let value = serde_json::to_value(self).map_err(ReportError::Serialize)?;
        serde_json::to_vec(&canonicalize(value)).map_err(ReportError::Serialize)
    }

    pub fn digest(&self) -> Result<ContentDigest, ReportError> {
        Ok(ContentDigest::sha256(self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSummary {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub warnings: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationLevel {
    Notice,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Annotation {
    pub level: AnnotationLevel,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u64>,
}

impl Annotation {
    /// Render the annotation message as escaped text. Raw report strings must
    /// never be inserted directly into an HTML response.
    #[must_use]
    pub fn escaped_message(&self) -> String {
        escape_html(&self.message)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<CoverageCounter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<CoverageCounter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branches: Option<CoverageCounter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statements: Option<CoverageCounter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCounter {
    pub covered: u64,
    pub total: u64,
}

fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}
use crate::{error::ReportError, html::escape_html};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn normalized_digest_is_deterministic() {
        let input = br#"{"lines":{"covered":1,"total":1}}"#;
        let first = ingest(
            ReportFormat::CoverageSummary,
            input,
            ReportLimits::default(),
        )
        .unwrap();
        let second = ingest(
            ReportFormat::CoverageSummary,
            input,
            ReportLimits::default(),
        )
        .unwrap();
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }
}
