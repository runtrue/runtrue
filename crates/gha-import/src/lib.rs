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
mod repository_action;
mod strict_yaml;
mod validation;

use analyzer::Analyzer;
use github::GithubWorkflow;
#[cfg(test)]
use runtrue_workflow_ast as ast;
use runtrue_workflow_frontend::{
    PreparedWorkflowSource, ResolvedRepositoryAction, WorkflowFrontendOptions,
    WorkflowFrontendReport, WorkflowSourceFrontend,
};
use std::collections::BTreeMap;
use strict_yaml::{validate_expanded_yaml_budget, StrictYamlValue};

pub use error::ImportError;
pub use report::{
    CompatibilityFinding, CompatibilityReport, CompatibilityStatus, ImportResult, StatusCounts,
};
pub use repository_action::{parse_repository_action_metadata, RepositoryActionMetadata};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// Operator-approved, immutable OCI image used for hosted Linux jobs when
    /// this installation has no microVM runner configured.
    pub default_job_container_image: Option<String>,
    /// Trusted, exact repository-action resolutions produced outside this
    /// pure frontend. A missing entry remains a blocking incompatibility.
    pub resolved_repository_actions: BTreeMap<String, ResolvedRepositoryAction>,
}

/// GitHub Actions source adapter. The server registers this as Runtrue's first
/// integration; the trusted planner depends only on the neutral frontend API.
#[derive(Debug, Clone, Copy, Default)]
pub struct GithubActionsFrontend;

impl WorkflowSourceFrontend for GithubActionsFrontend {
    fn discovery_roots(&self) -> &'static [&'static str] {
        &[".github/workflows"]
    }

    fn supports(&self, workflow_path: &str) -> bool {
        let explicitly_native =
            workflow_path.ends_with(".runtrue.yml") || workflow_path.ends_with(".runtrue.yaml");
        !explicitly_native
            && (workflow_path.starts_with(".github/workflows/")
                || workflow_path.ends_with(".github.yml")
                || workflow_path.ends_with(".github.yaml"))
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
                resolved_repository_actions: options.resolved_repository_actions.clone(),
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

/// Return immutable root repository-action references that require trusted
/// preparation. This performs the same bounded, strict YAML decoding as the
/// importer and deliberately ignores mutable, local, Docker, and built-in
/// action references; the normal analyzer reports those independently.
pub fn pinned_repository_action_references(source: &str) -> Result<Vec<String>, ImportError> {
    if source.len() > MAX_GITHUB_WORKFLOW_BYTES {
        return Err(ImportError::TooLarge);
    }
    validate_expanded_yaml_budget(source)?;
    let _: StrictYamlValue = serde_yaml::from_str(source)?;
    let workflow: GithubWorkflow = serde_yaml::from_str(source)?;
    let mut references = std::collections::BTreeSet::new();
    for job in workflow.jobs.values() {
        for step in &job.steps {
            let Some(reference) = step.uses.as_ref().and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            let Some((action, selector)) = reference.rsplit_once('@') else {
                continue;
            };
            let normalized = action.to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "actions/checkout"
                    | "actions/cache"
                    | "actions/cache/restore"
                    | "actions/cache/save"
                    | "actions/upload-artifact"
                    | "actions/download-artifact"
                    | "docker/build-push-action"
                    | "docker/setup-buildx-action"
            ) || !validation::is_full_git_commit(selector)
                || !analyzer::is_canonical_repository_action(action)
            {
                continue;
            }
            references.insert(reference.to_owned());
        }
    }
    Ok(references.into_iter().collect())
}

#[cfg(test)]
mod tests;
