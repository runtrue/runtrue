//! Trusted SCM-to-capsule orchestration.
//!
//! Workflow and lockfile bytes are loaded only from exact Git object IDs. For
//! pull requests the target/base definition is always the executable default;
//! proposed bytes are compiled separately for semantic risk analysis and may
//! replace the base definition only with approval evidence bound to the full
//! compiler approval-subject digest.

use crate::{
    analysis::absent_workflow_digest,
    derive_source_trust,
    limits::normalize_policy_versions,
    locks::{lock_identity, parse_analysis_lock, parse_required_lock},
    provider::hydrate_reusable_sources,
    ProposedAnalysisFailure, ProposedWorkflowAnalysis, ReusableWorkflowSourceProvider,
    TrustedCapsuleResult, TrustedPlannerError, TrustedPlannerLimits, DEFAULT_LOCKFILE_PATH,
};
use runtrue_compiler::{semantic_risk_diff, Compilation, CompileContext, Compiler};
use runtrue_git::{GitBlob, GitError, GitRepository};
use runtrue_lock::LockFile;
use runtrue_model::ContentDigest;
use runtrue_scm::{
    select_trusted_workflow_source, EventEnvelope, EventType, GitRevision,
    TrustedWorkflowSelection, WorkflowDefinitionApprovalEvidence,
    WorkflowDefinitionApprovalVerifier, WorkflowSourceInputs,
};
use runtrue_workflow_frontend::{WorkflowFrontendOptions, WorkflowFrontendRegistry};
use runtrue_workflow_ir::SourceTrust;
use std::collections::BTreeMap;

pub struct TrustedPlanner<'a> {
    repository: &'a GitRepository,
    reusable_source_provider: Option<&'a dyn ReusableWorkflowSourceProvider>,
    compiler: Compiler,
    limits: TrustedPlannerLimits,
    source_tree_digest: Option<ContentDigest>,
    scm_api_url: Option<String>,
    default_job_container_image: Option<String>,
    resolved_repository_actions: BTreeMap<String, String>,
    source_frontends: Option<&'a WorkflowFrontendRegistry<'a>>,
}

impl<'a> TrustedPlanner<'a> {
    #[must_use]
    pub fn new(repository: &'a GitRepository) -> Self {
        Self {
            repository,
            reusable_source_provider: None,
            compiler: Compiler::default(),
            limits: TrustedPlannerLimits::default(),
            source_tree_digest: None,
            scm_api_url: None,
            default_job_container_image: None,
            resolved_repository_actions: BTreeMap::new(),
            source_frontends: None,
        }
    }

    #[must_use]
    pub fn with_compiler(
        repository: &'a GitRepository,
        compiler: Compiler,
        limits: TrustedPlannerLimits,
    ) -> Self {
        Self {
            repository,
            reusable_source_provider: None,
            compiler,
            limits,
            source_tree_digest: None,
            scm_api_url: None,
            default_job_container_image: None,
            resolved_repository_actions: BTreeMap::new(),
            source_frontends: None,
        }
    }

    #[must_use]
    pub fn with_reusable_source_provider(
        mut self,
        provider: &'a dyn ReusableWorkflowSourceProvider,
    ) -> Self {
        self.reusable_source_provider = Some(provider);
        self
    }

    /// Bind compilation to a source manifest that has already been built from
    /// and verified against `event.source.commit` by the authenticated SCM
    /// fetch path.
    #[must_use]
    pub fn with_source_snapshot_digest(mut self, digest: ContentDigest) -> Self {
        self.source_tree_digest = Some(digest);
        self
    }

    /// Bind the isolated action runtime to the operator-configured provider
    /// API endpoint. Payload URLs are never accepted for this purpose.
    #[must_use]
    pub fn with_scm_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.scm_api_url = Some(api_url.into());
        self
    }

    /// Configure an immutable OCI image for imported hosted-Linux jobs when
    /// the installation deliberately operates without a microVM runner.
    #[must_use]
    pub fn with_default_job_container_image(mut self, image: impl Into<String>) -> Self {
        self.default_job_container_image = Some(image.into());
        self
    }

    /// Supply exact repository-action Programs prepared by a trusted external
    /// resolver. Source-language frontends can consume only exact reference
    /// matches and the generated lock binds each mapping.
    #[must_use]
    pub fn with_resolved_repository_actions(mut self, actions: BTreeMap<String, String>) -> Self {
        self.resolved_repository_actions = actions;
        self
    }

    /// Override source-language translation without changing the execution
    /// kernel. This is the seam used when an integration moves to a separate
    /// repository or deployment artifact.
    #[must_use]
    pub fn with_source_frontends(mut self, frontends: &'a WorkflowFrontendRegistry<'a>) -> Self {
        self.source_frontends = Some(frontends);
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn capsule(
        &self,
        event: &EventEnvelope,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        default_branch: &str,
        policy_version_ids: Vec<String>,
        approval: Option<&WorkflowDefinitionApprovalEvidence>,
        verifier: &dyn WorkflowDefinitionApprovalVerifier,
        now_unix_ms: u64,
    ) -> Result<TrustedCapsuleResult, TrustedPlannerError> {
        event
            .verify(self.limits.webhook)
            .map_err(|_| TrustedPlannerError::InvalidEvent)?;
        let source_trust = derive_source_trust(event, default_branch)?;
        let policy_version_ids = normalize_policy_versions(policy_version_ids)?;
        match event.event_type {
            EventType::PullRequest { .. } => self.capsule_pull_request(
                event,
                workflow_path,
                installation_id,
                tenant_id,
                repository_id,
                source_trust,
                policy_version_ids,
                approval,
                verifier,
                now_unix_ms,
            ),
            EventType::Push | EventType::MergeGroup => self.capsule_direct(
                event,
                workflow_path,
                installation_id,
                tenant_id,
                repository_id,
                source_trust,
                policy_version_ids,
                approval,
                verifier,
                now_unix_ms,
            ),
            EventType::IssueComment { .. } | EventType::CheckRun { .. } | EventType::Ping => {
                Err(TrustedPlannerError::NoExecutableRevision)
            }
        }
    }

    /// Capsule a non-code webhook against an exact provider-resolved default
    /// branch revision. The signed normalized event remains unchanged; the
    /// trusted revision is supplied out of band by the authenticated SCM
    /// worker and is bound into the compiled capsule.
    #[allow(clippy::too_many_arguments)]
    pub fn capsule_trusted_default_revision(
        &self,
        event: &EventEnvelope,
        trusted_revision: &GitRevision,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        default_branch: &str,
        policy_version_ids: Vec<String>,
    ) -> Result<TrustedCapsuleResult, TrustedPlannerError> {
        event
            .verify(self.limits.webhook)
            .map_err(|_| TrustedPlannerError::InvalidEvent)?;
        if !matches!(
            event.event_type,
            EventType::IssueComment { .. } | EventType::CheckRun { .. }
        ) || default_branch.is_empty()
            || default_branch.len() > 255
            || trusted_revision.commit.len() != 40
            || !trusted_revision
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || trusted_revision.ref_name.as_deref()
                != Some(format!("refs/heads/{default_branch}").as_str())
            || trusted_revision.repository_full_name.as_deref()
                != Some(event.repository.full_name.as_str())
        {
            return Err(TrustedPlannerError::InvalidEvent);
        }
        let policy_version_ids = normalize_policy_versions(policy_version_ids)?;
        let workflow = self.required_blob(&trusted_revision.commit, workflow_path, "workflow")?;
        let lock_blob = self.optional_blob(&trusted_revision.commit, DEFAULT_LOCKFILE_PATH)?;
        let lock = parse_required_lock(lock_blob.as_ref(), "lockfile")?;
        let execution = self.compile_blob_at_revision(
            &workflow,
            lock,
            event,
            workflow_path,
            installation_id,
            tenant_id,
            repository_id,
            &trusted_revision.commit,
            None,
            SourceTrust::ProtectedBranch,
            policy_version_ids.clone(),
            false,
        )?;
        let inputs = WorkflowSourceInputs {
            workflow_path: workflow_path.to_owned(),
            proposed_workflow_digest: workflow.digest,
            base_workflow_digest: None,
            proposed_lockfile_digest: lock_identity(lock_blob.as_ref()),
            base_lockfile_digest: None,
            proposed_approval_subject_digest: Some(execution.approval_subject_digest.clone()),
            policy_version_ids,
        };
        Ok(TrustedCapsuleResult {
            execution,
            selection: TrustedWorkflowSelection {
                code_revision: trusted_revision.clone(),
                workflow_revision: trusted_revision.clone(),
                analysis_workflow_revision: None,
                definition_changed: false,
                trusted_base_workflow_executed: true,
                workflow_definition_approval_required: false,
                approval_id: None,
            },
            proposed_analysis: ProposedWorkflowAnalysis::NotApplicable,
            source_inputs: inputs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn capsule_pull_request(
        &self,
        event: &EventEnvelope,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        source_trust: SourceTrust,
        policy_version_ids: Vec<String>,
        approval: Option<&WorkflowDefinitionApprovalEvidence>,
        verifier: &dyn WorkflowDefinitionApprovalVerifier,
        now_unix_ms: u64,
    ) -> Result<TrustedCapsuleResult, TrustedPlannerError> {
        let base = event
            .base
            .as_ref()
            .ok_or(TrustedPlannerError::InvalidEvent)?;
        let base_workflow = self.required_blob(&base.commit, workflow_path, "base workflow")?;
        let base_lock_blob = self.optional_blob(&base.commit, DEFAULT_LOCKFILE_PATH)?;
        let base_lock = parse_required_lock(base_lock_blob.as_ref(), "base lockfile")?;
        let base_compilation = self.compile_blob(
            &base_workflow,
            base_lock.clone(),
            event,
            workflow_path,
            installation_id,
            tenant_id,
            repository_id,
            source_trust,
            policy_version_ids.clone(),
            false,
        )?;

        let proposed_workflow = self.optional_blob(&event.source.commit, workflow_path)?;
        let proposed_workflow_digest = proposed_workflow
            .as_ref()
            .map_or_else(absent_workflow_digest, |blob| blob.digest.clone());
        let proposed_lock_blob = self.optional_blob(&event.source.commit, DEFAULT_LOCKFILE_PATH)?;
        let proposed_lock_digest = lock_identity(proposed_lock_blob.as_ref());
        let base_lock_digest = lock_identity(base_lock_blob.as_ref());

        let (proposed_compilation, initial_analysis) = match proposed_workflow.as_ref() {
            None => (
                None,
                ProposedWorkflowAnalysis::Deleted {
                    workflow_digest: proposed_workflow_digest.clone(),
                },
            ),
            Some(workflow) => match parse_analysis_lock(proposed_lock_blob.as_ref()) {
                Ok(lock) => match self.compile_blob(
                    workflow,
                    lock,
                    event,
                    workflow_path,
                    installation_id,
                    tenant_id,
                    repository_id,
                    source_trust,
                    policy_version_ids.clone(),
                    true,
                ) {
                    Ok(compilation) => {
                        let risk =
                            semantic_risk_diff(&base_compilation.capsule, &compilation.capsule);
                        (
                            Some(compilation.clone()),
                            ProposedWorkflowAnalysis::Valid {
                                compilation: Box::new(compilation),
                                semantic_risk: risk,
                            },
                        )
                    }
                    Err(TrustedPlannerError::WorkflowNotUtf8 { .. }) => (
                        None,
                        ProposedWorkflowAnalysis::Invalid {
                            workflow_digest: proposed_workflow_digest.clone(),
                            failure: ProposedAnalysisFailure::WorkflowNotUtf8,
                        },
                    ),
                    Err(
                        TrustedPlannerError::Compile(_)
                        | TrustedPlannerError::WorkflowFrontend(_)
                        | TrustedPlannerError::ReusableSourceProviderRequired
                        | TrustedPlannerError::ReusableSource(_)
                        | TrustedPlannerError::ReusableBundle(_),
                    ) => (
                        None,
                        ProposedWorkflowAnalysis::Invalid {
                            workflow_digest: proposed_workflow_digest.clone(),
                            failure: ProposedAnalysisFailure::WorkflowInvalid,
                        },
                    ),
                    Err(error) => return Err(error),
                },
                Err(()) => (
                    None,
                    ProposedWorkflowAnalysis::Invalid {
                        workflow_digest: proposed_workflow_digest.clone(),
                        failure: ProposedAnalysisFailure::LockfileInvalid,
                    },
                ),
            },
        };

        let inputs = WorkflowSourceInputs {
            workflow_path: workflow_path.to_owned(),
            proposed_workflow_digest,
            base_workflow_digest: Some(base_workflow.digest.clone()),
            proposed_lockfile_digest: proposed_lock_digest,
            base_lockfile_digest: base_lock_digest,
            proposed_approval_subject_digest: proposed_compilation
                .as_ref()
                .map(|compilation| compilation.approval_subject_digest.clone()),
            policy_version_ids,
        };
        let selection = select_trusted_workflow_source(
            event,
            &inputs,
            approval,
            verifier,
            now_unix_ms,
            self.limits.webhook,
        )?;

        let execution = if selection.trusted_base_workflow_executed {
            base_compilation
        } else {
            proposed_compilation.ok_or(TrustedPlannerError::ApprovedDefinitionInvalid)?
        };
        Ok(TrustedCapsuleResult {
            execution,
            selection,
            proposed_analysis: initial_analysis,
            source_inputs: inputs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn capsule_direct(
        &self,
        event: &EventEnvelope,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        source_trust: SourceTrust,
        policy_version_ids: Vec<String>,
        approval: Option<&WorkflowDefinitionApprovalEvidence>,
        verifier: &dyn WorkflowDefinitionApprovalVerifier,
        now_unix_ms: u64,
    ) -> Result<TrustedCapsuleResult, TrustedPlannerError> {
        let workflow = self.required_blob(&event.source.commit, workflow_path, "workflow")?;
        let lock_blob = self.optional_blob(&event.source.commit, DEFAULT_LOCKFILE_PATH)?;
        let lock = parse_required_lock(lock_blob.as_ref(), "lockfile")?;
        let execution = self.compile_blob(
            &workflow,
            lock,
            event,
            workflow_path,
            installation_id,
            tenant_id,
            repository_id,
            source_trust,
            policy_version_ids.clone(),
            false,
        )?;
        let inputs = WorkflowSourceInputs {
            workflow_path: workflow_path.to_owned(),
            proposed_workflow_digest: workflow.digest,
            base_workflow_digest: None,
            proposed_lockfile_digest: lock_identity(lock_blob.as_ref()),
            base_lockfile_digest: None,
            proposed_approval_subject_digest: Some(execution.approval_subject_digest.clone()),
            policy_version_ids,
        };
        let selection = select_trusted_workflow_source(
            event,
            &inputs,
            approval,
            verifier,
            now_unix_ms,
            self.limits.webhook,
        )?;
        Ok(TrustedCapsuleResult {
            execution,
            selection,
            proposed_analysis: ProposedWorkflowAnalysis::NotApplicable,
            source_inputs: inputs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_blob(
        &self,
        workflow: &GitBlob,
        lockfile: Option<LockFile>,
        event: &EventEnvelope,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        source_trust: SourceTrust,
        policy_version_ids: Vec<String>,
        workflow_changed: bool,
    ) -> Result<Compilation, TrustedPlannerError> {
        self.compile_blob_at_revision(
            workflow,
            lockfile,
            event,
            workflow_path,
            installation_id,
            tenant_id,
            repository_id,
            &event.source.commit,
            event.base.as_ref().map(|base| base.commit.as_str()),
            source_trust,
            policy_version_ids,
            workflow_changed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compile_blob_at_revision(
        &self,
        workflow: &GitBlob,
        mut lockfile: Option<LockFile>,
        event: &EventEnvelope,
        workflow_path: &str,
        installation_id: &str,
        tenant_id: &str,
        repository_id: &str,
        source_commit: &str,
        base_commit: Option<&str>,
        source_trust: SourceTrust,
        policy_version_ids: Vec<String>,
        workflow_changed: bool,
    ) -> Result<Compilation, TrustedPlannerError> {
        let source = std::str::from_utf8(&workflow.bytes).map_err(|_| {
            TrustedPlannerError::WorkflowNotUtf8 {
                revision: workflow.commit.clone(),
            }
        })?;
        let frontend = self
            .source_frontends
            .map(|frontends| frontends.frontend_for(workflow_path))
            .transpose()
            .map_err(|error| TrustedPlannerError::WorkflowFrontend(error.to_string()))?
            .flatten();
        let prepared = frontend
            .map(|frontend| {
                frontend.prepare(
                    source,
                    workflow_path,
                    &WorkflowFrontendOptions {
                        default_job_container_image: self.default_job_container_image.clone(),
                        resolved_repository_actions: self.resolved_repository_actions.clone(),
                    },
                )
            })
            .transpose()
            .map_err(TrustedPlannerError::WorkflowFrontend)?;
        if let Some(prepared) = &prepared {
            prepared
                .validate_for(source)
                .map_err(|error| TrustedPlannerError::WorkflowFrontend(error.to_string()))?;
            lockfile = prepared
                .generated_lockfile_toml
                .as_deref()
                .map(|value| LockFile::parse(value.as_bytes()))
                .transpose()
                .map_err(|source| TrustedPlannerError::InvalidLockfile {
                    kind: "generated frontend lockfile",
                    source,
                })?;
        }
        let source = prepared
            .as_ref()
            .map_or(source, |prepared| prepared.native_yaml.as_str());
        let workflow_frontend =
            prepared
                .as_ref()
                .map(|prepared| runtrue_workflow_ir::WorkflowFrontendProvenance {
                    frontend_id: prepared.frontend_id.to_owned(),
                    frontend_generation: prepared.frontend_generation,
                    input_digest: prepared.input_digest.clone(),
                    native_digest: prepared.native_digest.clone(),
                    report_digest: prepared.report.as_ref().map(|report| report.digest.clone()),
                });
        let reusable_workflows =
            hydrate_reusable_sources(self.reusable_source_provider, lockfile.as_ref())?;
        let event_value = serde_json::to_value(event)?;
        let context = CompileContext {
            installation_id: installation_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            repository_id: repository_id.to_owned(),
            workflow_path: workflow_path.to_owned(),
            source_commit: source_commit.to_owned(),
            base_commit: base_commit.map(str::to_owned),
            source_trust,
            event: event_value,
            normalized_event_digest: Some(event.normalized_digest.clone()),
            scm_api_url: self.scm_api_url.clone(),
            reusable_workflows,
            lockfile,
            workflow_frontend,
            policy_version_ids,
            workflow_changed,
            ..CompileContext::default()
        };
        Ok(match &self.source_tree_digest {
            Some(digest) => {
                self.compiler
                    .compile_yaml_with_source_snapshot(source, context, digest.clone())?
            }
            None => self.compiler.compile_yaml(source, context)?,
        })
    }

    fn required_blob(
        &self,
        commit: &str,
        path: &str,
        kind: &'static str,
    ) -> Result<GitBlob, TrustedPlannerError> {
        self.repository.read_blob(commit, path).map_err(|error| {
            if matches!(error, GitError::PathNotFound) {
                TrustedPlannerError::RequiredPathMissing { kind }
            } else {
                TrustedPlannerError::Git(error)
            }
        })
    }

    fn optional_blob(
        &self,
        commit: &str,
        path: &str,
    ) -> Result<Option<GitBlob>, TrustedPlannerError> {
        match self.repository.read_blob(commit, path) {
            Ok(blob) => Ok(Some(blob)),
            Err(GitError::PathNotFound) => Ok(None),
            Err(error) => Err(TrustedPlannerError::Git(error)),
        }
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
