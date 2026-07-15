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
