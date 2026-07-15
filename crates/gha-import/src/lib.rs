//! Strict, fail-closed GitHub Actions compatibility analysis and import.
//!
//! This crate is deliberately a front end. It does not add GitHub semantics to
//! Runtrue's native model: a source construct is converted to native workflow
//! syntax, called out as an emulation, or reported as a blocking incompatibility.

mod analyzer;
mod error;
mod github;
mod native;
mod report;
mod strict_yaml;
mod validation;

use analyzer::Analyzer;
use github::GithubWorkflow;
#[cfg(test)]
use runtrue_workflow_ast as ast;
use runtrue_workflow_frontend::{
    PreparedWorkflowSource, WorkflowFrontendOptions, WorkflowFrontendReport, WorkflowSourceFrontend,
};
use strict_yaml::{validate_expanded_yaml_budget, StrictYamlValue};

pub use error::ImportError;
pub use report::{
    CompatibilityFinding, CompatibilityReport, CompatibilityStatus, ImportResult, StatusCounts,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// Operator-approved, immutable OCI image used for hosted Linux jobs when
    /// this installation has no microVM runner configured.
    pub default_job_container_image: Option<String>,
}

/// GitHub Actions source adapter. The server registers this as Runtrue's first
/// integration; the trusted planner depends only on the neutral frontend API.
#[derive(Debug, Clone, Copy, Default)]
pub struct GithubActionsFrontend;

impl WorkflowSourceFrontend for GithubActionsFrontend {
    fn supports(&self, workflow_path: &str) -> bool {
        workflow_path.starts_with(".github/workflows/")
            || workflow_path.ends_with(".github.yml")
            || workflow_path.ends_with(".github.yaml")
    }

    fn prepare(
        &self,
        source: &str,
        workflow_path: &str,
        options: &WorkflowFrontendOptions,
    ) -> Result<PreparedWorkflowSource, String> {
        let imported = import_github_actions_with_options(
            source,
            workflow_path,
            ImportOptions {
                default_job_container_image: options.default_job_container_image.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        let native_yaml = imported.native_yaml.ok_or_else(|| {
            let blockers = imported
                .report
                .findings
                .iter()
                .filter(|finding| finding.blocking)
                .map(|finding| finding.code.as_str())
                .take(8)
                .collect::<Vec<_>>()
                .join(", ");
            if blockers.is_empty() {
                "compatibility analysis produced no executable workflow".to_owned()
            } else {
                blockers
            }
        })?;
        let report_bytes =
            serde_json::to_vec(&imported.report).map_err(|error| error.to_string())?;
        Ok(PreparedWorkflowSource {
            frontend_id: "runtrue.github-actions",
            frontend_generation: 1,
            input_digest: runtrue_model::ContentDigest::sha256(source.as_bytes()),
            native_digest: runtrue_model::ContentDigest::sha256(native_yaml.as_bytes()),
            native_yaml,
            generated_lockfile_toml: imported.lockfile_toml,
            report: Some(WorkflowFrontendReport {
                media_type: "application/vnd.runtrue.github-actions-compatibility+json".to_owned(),
                digest: runtrue_model::ContentDigest::sha256(&report_bytes),
                bytes: report_bytes,
            }),
        })
    }
}

/// Maximum accepted GitHub Actions workflow source size.
pub const MAX_GITHUB_WORKFLOW_BYTES: usize = 1024 * 1024;

/// Analyze and, when safe and fully representable, import a GitHub Actions
/// workflow into native Runtrue YAML.
pub fn import_github_actions(
    source: &str,
    source_name: impl Into<String>,
) -> Result<ImportResult, ImportError> {
    import_github_actions_with_options(source, source_name, ImportOptions::default())
}

pub fn import_github_actions_with_options(
    source: &str,
    source_name: impl Into<String>,
    options: ImportOptions,
) -> Result<ImportResult, ImportError> {
    if source.len() > MAX_GITHUB_WORKFLOW_BYTES {
        return Err(ImportError::TooLarge);
    }
    validate_expanded_yaml_budget(source)?;
    // This allocation is intentional: unlike `serde_yaml::Value`, the strict
    // visitor rejects duplicate keys recursively before typed decoding.
    let _: StrictYamlValue = serde_yaml::from_str(source)?;
    let workflow: GithubWorkflow = serde_yaml::from_str(source)?;
    Analyzer::new(source_name.into(), options).analyze(workflow)
}

#[cfg(test)]
mod tests;
