//! Domain-neutral source-language boundary for workflow integrations.
//!
//! A frontend can live in a separate repository and deployment artifact. It
//! produces native Runtrue workflow YAML plus integrity-bound diagnostics; it
//! never receives authority to admit or execute the translated Program.

#![forbid(unsafe_code)]

use runtrue_model::ContentDigest;
use std::{error::Error, fmt};

const MAX_FRONTEND_ID_BYTES: usize = 128;
const MAX_REPORT_MEDIA_TYPE_BYTES: usize = 255;
const MAX_REPORT_BYTES: usize = 1024 * 1024;

/// Inputs that affect source translation and therefore its emitted digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkflowFrontendOptions {
    pub default_job_container_image: Option<String>,
}

/// Adapter-specific diagnostic bytes with a generic, integrity-bound envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowFrontendReport {
    pub media_type: String,
    pub digest: ContentDigest,
    pub bytes: Vec<u8>,
}

/// Auditable result of translating a source language to native workflow YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkflowSource {
    pub frontend_id: &'static str,
    pub frontend_generation: u32,
    pub input_digest: ContentDigest,
    pub native_digest: ContentDigest,
    pub native_yaml: String,
    pub generated_lockfile_toml: Option<String>,
    pub report: Option<WorkflowFrontendReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowFrontendValidationError {
    InvalidFrontendIdentity,
    InvalidFrontendGeneration,
    InputDigestMismatch,
    NativeWorkflowEmpty,
    NativeDigestMismatch,
    InvalidReportMediaType,
    ReportTooLarge,
    ReportDigestMismatch,
}

impl fmt::Display for WorkflowFrontendValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrontendIdentity => "frontend identity is invalid",
            Self::InvalidFrontendGeneration => "frontend generation must be greater than zero",
            Self::InputDigestMismatch => "frontend input digest does not match the exact source",
            Self::NativeWorkflowEmpty => "frontend emitted an empty native workflow",
            Self::NativeDigestMismatch => "frontend native digest does not match emitted YAML",
            Self::InvalidReportMediaType => "frontend report media type is invalid",
            Self::ReportTooLarge => "frontend report exceeds the maximum size",
            Self::ReportDigestMismatch => "frontend report digest does not match its bytes",
        })
    }
}

impl Error for WorkflowFrontendValidationError {}

impl PreparedWorkflowSource {
    /// Validate the complete frontend result against the exact source supplied
    /// to the adapter. The trusted planner calls this before consuming any
    /// translated YAML, generated lockfile, or diagnostic bytes.
    pub fn validate_for(&self, source: &str) -> Result<(), WorkflowFrontendValidationError> {
        if self.frontend_id.is_empty()
            || self.frontend_id.len() > MAX_FRONTEND_ID_BYTES
            || !self
                .frontend_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(WorkflowFrontendValidationError::InvalidFrontendIdentity);
        }
        if self.frontend_generation == 0 {
            return Err(WorkflowFrontendValidationError::InvalidFrontendGeneration);
        }
        if self.input_digest != ContentDigest::sha256(source.as_bytes()) {
            return Err(WorkflowFrontendValidationError::InputDigestMismatch);
        }
        if self.native_yaml.trim().is_empty() {
            return Err(WorkflowFrontendValidationError::NativeWorkflowEmpty);
        }
        if self.native_digest != ContentDigest::sha256(self.native_yaml.as_bytes()) {
            return Err(WorkflowFrontendValidationError::NativeDigestMismatch);
        }
        if let Some(report) = &self.report {
            if report.media_type.is_empty()
                || report.media_type.len() > MAX_REPORT_MEDIA_TYPE_BYTES
                || !report.media_type.contains('/')
                || report
                    .media_type
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'*' | b','))
            {
                return Err(WorkflowFrontendValidationError::InvalidReportMediaType);
            }
            if report.bytes.len() > MAX_REPORT_BYTES {
                return Err(WorkflowFrontendValidationError::ReportTooLarge);
            }
            if report.digest != ContentDigest::sha256(&report.bytes) {
                return Err(WorkflowFrontendValidationError::ReportDigestMismatch);
            }
        }
        Ok(())
    }
}

/// A replaceable source adapter injected by the composition root.
pub trait WorkflowSourceFrontend: Send + Sync {
    fn supports(&self, workflow_path: &str) -> bool;

    fn prepare(
        &self,
        source: &str,
        workflow_path: &str,
        options: &WorkflowFrontendOptions,
    ) -> Result<PreparedWorkflowSource, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared(source: &str) -> PreparedWorkflowSource {
        let native_yaml = "version: 1\njobs: {}\n".to_owned();
        let report_bytes = br#"{"status":"compatible"}"#.to_vec();
        PreparedWorkflowSource {
            frontend_id: "runtrue.test",
            frontend_generation: 1,
            input_digest: ContentDigest::sha256(source.as_bytes()),
            native_digest: ContentDigest::sha256(native_yaml.as_bytes()),
            native_yaml,
            generated_lockfile_toml: None,
            report: Some(WorkflowFrontendReport {
                media_type: "application/vnd.runtrue.test+json".to_owned(),
                digest: ContentDigest::sha256(&report_bytes),
                bytes: report_bytes,
            }),
        }
    }

    #[test]
    fn exact_frontend_integrity_envelope_is_accepted() {
        prepared("source").validate_for("source").unwrap();
    }

    #[test]
    fn every_frontend_integrity_field_fails_closed() {
        let source = "source";

        let mut value = prepared(source);
        value.frontend_id = "invalid identity";
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::InvalidFrontendIdentity)
        );

        let mut value = prepared(source);
        value.frontend_generation = 0;
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::InvalidFrontendGeneration)
        );

        let mut value = prepared(source);
        value.input_digest = ContentDigest::sha256(b"different input");
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::InputDigestMismatch)
        );

        let mut value = prepared(source);
        value.native_yaml.push_str("# unbound mutation\n");
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::NativeDigestMismatch)
        );

        let mut value = prepared(source);
        value.report.as_mut().unwrap().media_type = "not a media type".to_owned();
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::InvalidReportMediaType)
        );

        let mut value = prepared(source);
        value.report.as_mut().unwrap().bytes.push(b'!');
        assert_eq!(
            value.validate_for(source),
            Err(WorkflowFrontendValidationError::ReportDigestMismatch)
        );
    }
}
