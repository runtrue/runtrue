//! Replaceable source-language frontends for the workflow integration.
//!
//! Frontends end at native Runtrue workflow YAML. They are deliberately kept
//! outside the execution kernel so moving a source-language adapter to another
//! repository does not change Program, Capsule, Seal, or Provider semantics.

use runtrue_gha_import::{import_github_actions_with_options, ImportOptions};
use runtrue_model::ContentDigest;

/// Inputs which affect source translation and therefore its emitted digest.
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

/// Auditable result of translating a workflow source language to native YAML.
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

/// A source adapter that can be injected into the trusted workflow planner.
///
/// Implementations must be deterministic for the same source, path, and
/// options. The planner re-parses and compiles the returned native YAML; an
/// adapter never obtains execution authority by translating source.
pub trait WorkflowSourceFrontend: Send + Sync {
    fn supports(&self, workflow_path: &str) -> bool;

    fn prepare(
        &self,
        source: &str,
        workflow_path: &str,
        options: &WorkflowFrontendOptions,
    ) -> Result<PreparedWorkflowSource, String>;
}

/// The co-located GitHub Actions adapter. This remains Runtrue's first main
/// integration while depending only on the public frontend seam.
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
            input_digest: ContentDigest::sha256(source.as_bytes()),
            native_digest: ContentDigest::sha256(native_yaml.as_bytes()),
            native_yaml,
            generated_lockfile_toml: imported.lockfile_toml,
            report: Some(WorkflowFrontendReport {
                media_type: "application/vnd.runtrue.github-actions-compatibility+json".to_owned(),
                digest: ContentDigest::sha256(&report_bytes),
                bytes: report_bytes,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_frontend_is_deterministic_and_reports_exact_translation_identity() {
        let source = r#"name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
"#;
        let options = WorkflowFrontendOptions {
            default_job_container_image: Some(format!(
                "registry.example/runtrue-ci@sha256:{}",
                "a".repeat(64)
            )),
        };
        let frontend = GithubActionsFrontend;
        let first = frontend
            .prepare(source, ".github/workflows/ci.yml", &options)
            .unwrap();
        let second = frontend
            .prepare(source, ".github/workflows/ci.yml", &options)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.input_digest, ContentDigest::sha256(source.as_bytes()));
        assert_eq!(
            first.native_digest,
            ContentDigest::sha256(first.native_yaml.as_bytes())
        );
        let report = first.report.unwrap();
        assert_eq!(report.digest, ContentDigest::sha256(&report.bytes));
    }

    #[test]
    fn github_frontend_fails_closed_on_blocking_semantics() {
        let source = r#"name: unsafe
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: unknown/remote-action@main
"#;
        let error = GithubActionsFrontend
            .prepare(
                source,
                ".github/workflows/deploy.yml",
                &WorkflowFrontendOptions::default(),
            )
            .unwrap_err();
        assert!(!error.is_empty());
    }
}
