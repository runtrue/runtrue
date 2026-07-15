//! Domain-neutral source-language boundary for workflow integrations.
//!
//! A frontend can live in a separate repository and deployment artifact. It
//! produces native Runtrue workflow YAML plus integrity-bound diagnostics; it
//! never receives authority to admit or execute the translated Program.

#![forbid(unsafe_code)]

use runtrue_model::ContentDigest;
use std::{collections::BTreeSet, error::Error, fmt};

const MAX_FRONTEND_ID_BYTES: usize = 128;
const MAX_FRONTENDS: usize = 16;
const MAX_DISCOVERY_ROOTS: usize = 64;
const MAX_WORKFLOW_PATH_BYTES: usize = 1024;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowFrontendRegistryError {
    TooManyFrontends,
    TooManyDiscoveryRoots,
    InvalidDiscoveryRoot,
    InvalidWorkflowPath,
    AmbiguousFrontend,
}

impl fmt::Display for WorkflowFrontendRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyFrontends => "workflow frontend registry exceeds its frontend bound",
            Self::TooManyDiscoveryRoots => {
                "workflow frontend registry exceeds its discovery-root bound"
            }
            Self::InvalidDiscoveryRoot => "workflow frontend discovery root is invalid",
            Self::InvalidWorkflowPath => "workflow frontend path is invalid",
            Self::AmbiguousFrontend => "multiple workflow frontends claim the same path",
        })
    }
}

impl Error for WorkflowFrontendRegistryError {}

/// Validated collection of source-language frontends supplied by the binary's
/// composition root. Discovery metadata lives with each adapter so the trusted
/// server and planner do not acquire source-language-specific paths.
pub struct WorkflowFrontendRegistry<'a> {
    frontends: Vec<&'a dyn WorkflowSourceFrontend>,
    discovery_roots: Vec<&'static str>,
}

impl<'a> WorkflowFrontendRegistry<'a> {
    pub fn new(
        frontends: &[&'a dyn WorkflowSourceFrontend],
    ) -> Result<Self, WorkflowFrontendRegistryError> {
        if frontends.len() > MAX_FRONTENDS {
            return Err(WorkflowFrontendRegistryError::TooManyFrontends);
        }
        let mut discovery_roots = BTreeSet::new();
        for frontend in frontends {
            for root in frontend.discovery_roots() {
                if !valid_relative_path(root) {
                    return Err(WorkflowFrontendRegistryError::InvalidDiscoveryRoot);
                }
                discovery_roots.insert(*root);
                if discovery_roots.len() > MAX_DISCOVERY_ROOTS {
                    return Err(WorkflowFrontendRegistryError::TooManyDiscoveryRoots);
                }
            }
        }
        Ok(Self {
            frontends: frontends.to_vec(),
            discovery_roots: discovery_roots.into_iter().collect(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frontends.is_empty()
    }

    #[must_use]
    pub fn discovery_roots(&self) -> &[&'static str] {
        &self.discovery_roots
    }

    pub fn frontend_for(
        &self,
        workflow_path: &str,
    ) -> Result<Option<&'a dyn WorkflowSourceFrontend>, WorkflowFrontendRegistryError> {
        if !valid_relative_path(workflow_path) {
            return Err(WorkflowFrontendRegistryError::InvalidWorkflowPath);
        }
        let mut matches = self
            .frontends
            .iter()
            .copied()
            .filter(|frontend| frontend.supports(workflow_path));
        let selected = matches.next();
        if matches.next().is_some() {
            return Err(WorkflowFrontendRegistryError::AmbiguousFrontend);
        }
        Ok(selected)
    }
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_WORKFLOW_PATH_BYTES
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .chars()
            .any(|character| matches!(character, '\\' | '\0'))
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

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
    /// Repository directories inspected for workflows owned by this adapter.
    /// Every returned path is validated by `WorkflowFrontendRegistry`.
    fn discovery_roots(&self) -> &'static [&'static str];

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

    struct TestFrontend {
        roots: &'static [&'static str],
        suffix: &'static str,
    }

    impl WorkflowSourceFrontend for TestFrontend {
        fn discovery_roots(&self) -> &'static [&'static str] {
            self.roots
        }

        fn supports(&self, workflow_path: &str) -> bool {
            workflow_path.ends_with(self.suffix)
        }

        fn prepare(
            &self,
            _source: &str,
            _workflow_path: &str,
            _options: &WorkflowFrontendOptions,
        ) -> Result<PreparedWorkflowSource, String> {
            Err("not used by registry tests".to_owned())
        }
    }

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

    #[test]
    fn registry_owns_deduplicated_discovery_and_exact_selection() {
        let yaml = TestFrontend {
            roots: &[".foreign/workflows"],
            suffix: ".yaml",
        };
        let yml = TestFrontend {
            roots: &[".foreign/workflows"],
            suffix: ".yml",
        };
        let registry = WorkflowFrontendRegistry::new(&[&yaml, &yml]).unwrap();
        assert_eq!(registry.discovery_roots(), &[".foreign/workflows"]);
        assert!(registry
            .frontend_for(".foreign/workflows/ci.yaml")
            .unwrap()
            .is_some());
        assert!(registry
            .frontend_for(".runtrue/workflows/ci.json")
            .unwrap()
            .is_none());
    }

    #[test]
    fn registry_rejects_unsafe_roots_paths_and_ambiguous_ownership() {
        let unsafe_frontend = TestFrontend {
            roots: &["../workflows"],
            suffix: ".yaml",
        };
        assert!(matches!(
            WorkflowFrontendRegistry::new(&[&unsafe_frontend]),
            Err(WorkflowFrontendRegistryError::InvalidDiscoveryRoot)
        ));

        let first = TestFrontend {
            roots: &["workflows"],
            suffix: ".yaml",
        };
        let second = TestFrontend {
            roots: &["other"],
            suffix: ".yaml",
        };
        let registry = WorkflowFrontendRegistry::new(&[&first, &second]).unwrap();
        assert!(matches!(
            registry.frontend_for("workflows/ci.yaml"),
            Err(WorkflowFrontendRegistryError::AmbiguousFrontend)
        ));
        assert!(matches!(
            registry.frontend_for("workflows/../ci.yaml"),
            Err(WorkflowFrontendRegistryError::InvalidWorkflowPath)
        ));
    }
}
