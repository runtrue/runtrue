mod actions;
mod expressions;
mod jobs;
mod security;
mod steps;
mod workflow;

use crate::{
    error::ImportError,
    github::GithubWorkflow,
    native::{
        build_lockfile, GeneratedImageLock, NativeCache, NativeJob, NativeOutput, NativeRun,
        NativeStepCapabilities, NativeWorkflow, PermissionState,
    },
    report::{
        CompatibilityFinding, CompatibilityReport, CompatibilityStatus, ImportResult, StatusCounts,
    },
    ImportOptions,
};
use runtrue_compiler::{CompileContext, Compiler};
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use expressions::{
    has_expression, positive_u64, static_bool, static_runner_labels, static_string,
    static_string_list, yaml_string_map,
};
pub(crate) use security::{
    contains_github_runtime, has_privileged_or_host_feature, has_secret_expression,
    is_empty_scalar, is_github_token_expression, looks_like_secret_name,
};

pub(crate) struct JobEffects {
    pub(crate) permissions: PermissionState,
    pub(crate) outputs: BTreeMap<String, NativeOutput>,
    pub(crate) runner_capabilities: BTreeSet<String>,
    pub(crate) container_action_image: Option<String>,
}

pub(crate) struct ActionMapping {
    pub(crate) run: NativeRun,
    pub(crate) env: BTreeMap<String, runtrue_workflow_ast::Scalar>,
    pub(crate) cache: Option<NativeCache>,
    pub(crate) capabilities: Option<NativeStepCapabilities>,
    pub(crate) mapped: bool,
}

pub(crate) struct Analyzer {
    pub(crate) source_name: String,
    pub(crate) findings: Vec<CompatibilityFinding>,
    pub(crate) required_changes: BTreeSet<String>,
    pub(crate) mapped_jobs: usize,
    pub(crate) mapped_steps: usize,
    pub(crate) lock_images: BTreeSet<GeneratedImageLock>,
    pub(crate) pull_request_target_requested: bool,
    pub(crate) workflow_concurrency: Option<String>,
    pub(crate) default_job_container_image: Option<String>,
}

impl Analyzer {
    pub(crate) fn new(source_name: String, options: ImportOptions) -> Self {
        Self {
            source_name,
            findings: Vec::new(),
            required_changes: BTreeSet::new(),
            mapped_jobs: 0,
            mapped_steps: 0,
            lock_images: BTreeSet::new(),
            pull_request_target_requested: false,
            workflow_concurrency: None,
            default_job_container_image: options.default_job_container_image,
        }
    }

    pub(crate) fn finding(
        &mut self,
        status: CompatibilityStatus,
        code: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
        required_change: Option<String>,
    ) {
        if let Some(change) = &required_change {
            self.required_changes.insert(change.clone());
        }
        self.findings.push(CompatibilityFinding {
            status,
            code: code.into(),
            path: path.into(),
            message: message.into(),
            blocking: status.is_blocking(),
            required_change,
        });
    }

    pub(crate) fn unsupported_extras(&mut self, path: &str, extras: &BTreeMap<String, YamlValue>) {
        for field in extras.keys() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "unknown-field",
                format!("{path}.{field}"),
                format!("GitHub field `{field}` has no importer mapping"),
                Some(format!(
                    "Remove `{path}.{field}` or replace it with a supported native construct."
                )),
            );
        }
    }

    pub(crate) fn analyze(mut self, workflow: GithubWorkflow) -> Result<ImportResult, ImportError> {
        self.unsupported_extras("workflow", &workflow.extra);
        let name = self.convert_display_name(workflow.name, "name");
        let triggers = self.convert_triggers(workflow.triggers);
        if self.pull_request_target_requested {
            let safe =
                workflow.jobs.values().all(|job| {
                    job.uses.is_none()
                        && job.container.is_none()
                        && job.services.is_empty()
                        && !job.steps.is_empty()
                        && job.steps.iter().all(|step| {
                            step.run.is_none()
                                && step.uses.as_ref().and_then(static_string).is_some_and(
                                    |reference| {
                                        reference
                                            .strip_prefix("docker://")
                                            .is_some_and(crate::validation::is_full_sha256_image)
                                    },
                                )
                        })
                });
            if safe {
                self.finding(
                    CompatibilityStatus::Emulated,
                    "trusted-pull-request-target",
                    "on.pull_request_target",
                    "pull_request_target uses the trusted default-branch workflow and only digest-pinned container actions",
                    None,
                );
            } else {
                self.finding(
                    CompatibilityStatus::Unsafe,
                    "pull-request-target-source-execution",
                    "on.pull_request_target",
                    "pull_request_target is allowed only when every job contains digest-pinned container actions and no source-code run steps",
                    Some(
                        "Package the automation as a digest-pinned container action and remove source-code execution from the trusted-target workflow."
                            .to_owned(),
                    ),
                );
            }
        }
        let workflow_permissions = self.convert_permissions(
            workflow.permissions.as_ref(),
            "permissions",
            &PermissionState::default(),
        );
        let vars = self.convert_env(&workflow.env, "env");
        self.workflow_concurrency =
            self.convert_concurrency(workflow.concurrency.as_ref(), "concurrency");

        if workflow.jobs.is_empty() {
            self.finding(
                CompatibilityStatus::Unsupported,
                "empty-workflow",
                "jobs",
                "the workflow contains no jobs",
                Some("Add at least one supported job.".to_owned()),
            );
        }

        let mut jobs = BTreeMap::new();
        let mut maximum_permissions = workflow_permissions.clone();
        for (job_id, job) in workflow.jobs {
            let native = self.convert_job(&job_id, job, &workflow_permissions);
            maximum_permissions.merge_maximum(&native.permission_state);
            jobs.insert(job_id, native.job);
        }

        let native = NativeWorkflow {
            version: 1,
            name,
            triggers,
            permissions: maximum_permissions.native(),
            vars,
            jobs,
        };
        self.finish(native)
    }

    pub(crate) fn finish(mut self, workflow: NativeWorkflow) -> Result<ImportResult, ImportError> {
        self.findings.sort_by(|left, right| {
            (&left.path, &left.code, left.status).cmp(&(&right.path, &right.code, right.status))
        });
        let compatible = !self.findings.iter().any(|finding| finding.blocking);
        let mut status_counts = StatusCounts::default();
        for finding in &self.findings {
            status_counts.add(finding.status);
        }
        let total = status_counts.total();
        let earned_twice = status_counts.supported.saturating_mul(2) + status_counts.emulated;
        let percent = if total == 0 {
            100
        } else {
            u8::try_from(earned_twice.saturating_mul(100) / total.saturating_mul(2)).unwrap_or(100)
        };

        let mut native_yaml = None;
        let mut lockfile_toml = None;
        let mut native_ast_validated = false;
        let mut compiler_validated = false;
        if compatible {
            let yaml = serde_yaml::to_string(&workflow)
                .map_err(|error| ImportError::Serialize(error.to_string()))?;
            runtrue_workflow_ast::parse_yaml(&yaml)
                .map_err(|error| ImportError::GeneratedWorkflow(error.to_string()))?;
            native_ast_validated = true;

            let parsed_lock = build_lockfile(self.lock_images)?.map(|(lock, text)| {
                lockfile_toml = Some(text);
                lock
            });
            let context = CompileContext {
                workflow_path: self.source_name.clone(),
                lockfile: parsed_lock,
                ..CompileContext::default()
            };
            Compiler::default()
                .compile_yaml(&yaml, context)
                .map_err(|error| ImportError::GeneratedWorkflow(error.to_string()))?;
            compiler_validated = true;
            native_yaml = Some(yaml);
        }

        Ok(ImportResult {
            native_yaml,
            lockfile_toml,
            report: CompatibilityReport {
                workflow: self.source_name,
                compatible,
                overall_compatibility_percent: percent,
                mapped_jobs: self.mapped_jobs,
                mapped_steps: self.mapped_steps,
                status_counts,
                schema_validated: native_ast_validated,
                native_ast_validated,
                compiler_validated,
                findings: self.findings,
                required_changes: self.required_changes.into_iter().collect(),
            },
        })
    }
}

pub(crate) struct ConvertedJob {
    pub(crate) job: NativeJob,
    pub(crate) permission_state: PermissionState,
}
