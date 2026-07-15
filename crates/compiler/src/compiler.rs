pub struct Compiler {
    pub(crate) settings: CompilerSettings,
}

fn is_brokered_scm_automation_job(job: &ir::PlannedJob) -> bool {
    let permissions = &job.permissions;
    let provider_token = |secret: &runtrue_model::SecretReference| {
        secret.name == "runtrue-scm-provider-token"
            && secret.purpose.as_deref() == Some("provider-api")
    };
    let status_automation = permissions.scm.statuses == ir::Access::Write
        && permissions.scm.contents != ir::Access::Write
        && permissions.scm.issues == ir::Access::Deny
        && permissions.scm.pull_requests == ir::Access::Deny
        && permissions.scm.checks == ir::Access::Deny;
    let repository_automation = permissions.scm.contents == ir::Access::Write
        && permissions.scm.issues == ir::Access::Write
        && permissions.scm.pull_requests == ir::Access::Write
        && permissions.scm.checks == ir::Access::Read
        && permissions.scm.statuses == ir::Access::Deny;
    (status_automation || repository_automation)
        && !permissions.secrets.is_empty()
        && permissions.secrets.iter().all(provider_token)
        && job.steps.iter().all(|step| {
            step.capabilities.secrets.is_empty()
                || step.capabilities.secrets.iter().all(provider_token)
        })
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new(CompilerSettings::default())
    }
}

impl Compiler {
    #[must_use]
    pub const fn new(settings: CompilerSettings) -> Self {
        Self { settings }
    }

    pub fn compile_yaml(
        &self,
        source: &str,
        context: CompileContext,
    ) -> Result<Compilation, CompileError> {
        let workflow = ast::parse_yaml(source)?;
        self.compile(&workflow, context)
    }

    /// Compile a remote capsule bound to an already verified deterministic source
    /// snapshot. The digest becomes part of both the signed capsule and approval
    /// subject; callers cannot attach it after compilation.
    pub fn compile_yaml_with_source_snapshot(
        &self,
        source: &str,
        context: CompileContext,
        source_tree_digest: ContentDigest,
    ) -> Result<Compilation, CompileError> {
        let workflow = ast::parse_yaml(source)?;
        self.compile_with_source_snapshot(&workflow, context, source_tree_digest)
    }

    pub fn compile(
        &self,
        workflow: &ast::Workflow,
        context: CompileContext,
    ) -> Result<Compilation, CompileError> {
        self.compile_inner(workflow, context, None)
    }

    pub fn compile_with_source_snapshot(
        &self,
        workflow: &ast::Workflow,
        context: CompileContext,
        source_tree_digest: ContentDigest,
    ) -> Result<Compilation, CompileError> {
        self.compile_inner(workflow, context, Some(source_tree_digest))
    }

    fn compile_inner(
        &self,
        workflow: &ast::Workflow,
        mut context: CompileContext,
        source_tree_digest: Option<ContentDigest>,
    ) -> Result<Compilation, CompileError> {
        let expanded = expand_reusable_workflows(workflow, &context, &self.settings)?;
        let workflow = &expanded.workflow;
        validate_workflow_shape(workflow, &self.settings)?;
        validate_dag(workflow)?;

        context.policy_version_ids.sort();
        context.policy_version_ids.dedup();

        let global_permissions = convert_permissions(&workflow.permissions)?;
        let global_variables = convert_variables(&workflow.vars, "vars")?;
        let expansions = expand_all_matrices(workflow, self.settings.max_matrix_jobs)?;

        let mut planned_jobs = Vec::new();
        let mut dynamic_jobs = Vec::new();
        let mut inherent_risks = Vec::new();
        for (base_id, job) in &workflow.jobs {
            let mut expanded_needs = job
                .needs
                .iter()
                .flat_map(|needed| expansions[needed].iter().map(|item| item.id.clone()))
                .collect::<Vec<_>>();
            expanded_needs.sort();

            if let Some(dynamic) = &job.dynamic_matrix {
                let expanded = MatrixExpansion {
                    id: base_id.clone(),
                    values: BTreeMap::new(),
                };
                let template = self.compile_job(
                    base_id,
                    job,
                    &expanded,
                    &expanded_needs,
                    &global_permissions,
                    &global_variables,
                    &mut inherent_risks,
                )?;
                let (producer_job_id, output_name) = parse_dynamic_matrix_path(
                    &dynamic.from,
                    &format!("jobs.{base_id}.dynamic-matrix.from"),
                )?;
                dynamic_jobs.push(ir::DynamicJobTemplate {
                    id: base_id.clone(),
                    source: ir::DynamicMatrixSource {
                        producer_job_id: producer_job_id.to_owned(),
                        output_name: output_name.to_owned(),
                        maximum_jobs: dynamic.max_jobs,
                    },
                    template,
                });
            } else {
                for expanded in &expansions[base_id] {
                    planned_jobs.push(self.compile_job(
                        base_id,
                        job,
                        expanded,
                        &expanded_needs,
                        &global_permissions,
                        &global_variables,
                        &mut inherent_risks,
                    )?);
                }
            }
        }
        let maximum_expanded_jobs = planned_jobs.len().saturating_add(
            dynamic_jobs
                .iter()
                .map(|template| template.source.maximum_jobs)
                .sum::<usize>(),
        );
        if maximum_expanded_jobs > MAX_WORKFLOW_JOBS {
            return Err(CompileError::semantic(
                "jobs",
                format!(
                    "static jobs plus bounded dynamic expansion exceed the {MAX_WORKFLOW_JOBS} job limit"
                ),
            ));
        }
        planned_jobs.sort_by(|left, right| left.id.cmp(&right.id));
        dynamic_jobs.sort_by(|left, right| left.id.cmp(&right.id));

        let workflow_name = workflow
            .name
            .clone()
            .unwrap_or_else(|| "workflow".to_owned());
        let triggers = normalize_triggers(&workflow.triggers);
        let full_expected_parity = expected_parity(
            planned_jobs
                .iter()
                .chain(dynamic_jobs.iter().map(|template| &template.template)),
        );
        let semantic = SemanticWorkflow {
            version: workflow.version,
            name: workflow_name.clone(),
            triggers: &triggers,
            inputs: &workflow.inputs,
            outputs: &workflow.outputs,
            variables: &global_variables,
            permissions: &global_permissions,
            jobs: &planned_jobs,
            dynamic_jobs: &dynamic_jobs,
            reusable_workflows: &expanded.identities,
            expected_parity: full_expected_parity,
        };
        let semantic_value = serde_json::to_value(semantic)?;
        let semantic_bytes = serde_json::to_vec(&ir::canonicalize_value(semantic_value))?;
        let workflow_digest = ContentDigest::sha256(semantic_bytes);
        let lockfile_digest = resolve_external_references(
            &mut planned_jobs,
            &mut dynamic_jobs,
            context.lockfile.as_ref(),
            &expanded.references,
        )?;

        if let Some(selected_job) = &context.selected_job {
            planned_jobs =
                select_job_closure(planned_jobs, selected_job, &expanded.selection_aliases)?;
            let selected_bases = planned_jobs
                .iter()
                .map(|job| job.base_id.as_str())
                .collect::<BTreeSet<_>>();
            inherent_risks.retain(|finding| {
                selected_bases
                    .iter()
                    .any(|base| finding.path.starts_with(&format!("jobs.{base}.")))
            });
        }
        inherent_risks.sort();
        inherent_risks.dedup();

        let expected_parity = expected_parity(
            planned_jobs
                .iter()
                .chain(dynamic_jobs.iter().map(|template| &template.template)),
        );
        let brokered_scm_automation = !context.workflow_changed
            && context.normalized_event_digest.is_some()
            && context.scm_api_url.is_some()
            && !inherent_risks.is_empty()
            && inherent_risks.iter().all(|finding| {
                matches!(
                    finding.code.as_str(),
                    "scm-contents-write"
                        | "scm-issues-write"
                        | "scm-pull-requests-write"
                        | "scm-statuses-write"
                        | "secret-access"
                        | "step-secret-access"
                )
            })
            && planned_jobs
                .iter()
                .chain(dynamic_jobs.iter().map(|template| &template.template))
                .all(is_brokered_scm_automation_job);
        let privileged = !inherent_risks.is_empty() && !brokered_scm_automation;
        let mut approval_reasons = inherent_risks
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<Vec<_>>();
        approval_reasons.sort();
        approval_reasons.dedup();
        let approval = ir::ApprovalRequirements {
            workflow_definition: context.workflow_changed,
            privileged_execution: privileged,
            reasons: approval_reasons,
        };

        let event_value = ir::canonicalize_value(context.event.clone());
        let event_bytes = serde_json::to_vec(&event_value)?;
        let event_digest = context
            .normalized_event_digest
            .clone()
            .unwrap_or_else(|| ContentDigest::sha256(&event_bytes));
        let authenticated_event = context.normalized_event_digest.is_some();
        let normalized_event_json = authenticated_event
            .then(|| String::from_utf8(event_bytes.clone()))
            .transpose()
            .map_err(|_| CompileError::semantic("event", "canonical event JSON is not UTF-8"))?;
        let scm = match (authenticated_event, context.scm_api_url.as_ref()) {
            (true, Some(api_url)) => {
                let repository = context
                    .event
                    .pointer("/repository/full_name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        CompileError::semantic(
                            "event.repository.full_name",
                            "authenticated SCM event is missing its repository identity",
                        )
                    })?;
                let provider = context
                    .event
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        CompileError::semantic(
                            "event.provider",
                            "authenticated SCM event is missing its provider identity",
                        )
                    })?;
                Some(ir::ScmRuntimeContext {
                    provider: provider.to_owned(),
                    api_url: api_url.clone(),
                    repository: repository.to_owned(),
                })
            }
            (true, None) => None,
            (false, Some(_)) => {
                return Err(CompileError::semantic(
                    "scm-api-url",
                    "SCM runtime context requires an authenticated normalized event",
                ))
            }
            (false, None) => None,
        };
        let event_context = project_event_context(&context.event, &planned_jobs)?;
        let capsule = ir::ExecutionCapsule {
            schema_version: ir::CAPSULE_SCHEMA_VERSION,
            engine_compatibility_version: ir::ENGINE_COMPATIBILITY_VERSION.to_owned(),
            compiler_version: env!("CARGO_PKG_VERSION").to_owned(),
            workflow: ir::WorkflowIdentity {
                name: workflow_name,
                digest: workflow_digest,
                source_path: context.workflow_path.clone(),
            },
            context: ir::CapsuleContext {
                source_commit: context.source_commit.clone(),
                source_tree_digest,
                base_commit: context.base_commit.clone(),
                source_trust: context.source_trust,
                normalized_event_digest: event_digest,
                normalized_event_json,
                scm,
                event_context,
                lockfile_digest,
                workflow_frontend: context.workflow_frontend.clone(),
                policy_version_ids: context.policy_version_ids.clone(),
            },
            variables: global_variables,
            permissions: global_permissions,
            jobs: planned_jobs,
            dynamic_jobs,
            approval,
            expected_parity,
        };

        let capsule_digest = capsule.digest()?;
        let approval_subject = approval_subject(
            &capsule,
            &capsule_digest,
            &context,
            &expanded.reusable_digests,
        )?;
        let approval_subject_digest = approval_subject.digest()?;
        let risk_report = RiskReport::from_findings(inherent_risks);

        Ok(Compilation {
            capsule,
            triggers,
            capsule_digest,
            approval_subject,
            approval_subject_digest,
            risk_report,
        })
    }
}
use super::{
    approval_subject, ast, convert_permissions, convert_variables, expand_all_matrices,
    expand_reusable_workflows, expected_parity, ir, normalize_triggers, parse_dynamic_matrix_path,
    project_event_context, resolve_external_references, select_job_closure, validate_dag,
    validate_workflow_shape, BTreeMap, BTreeSet, Compilation, CompileContext, CompileError,
    CompilerSettings, ContentDigest, MatrixExpansion, RiskReport, SemanticWorkflow,
    MAX_WORKFLOW_JOBS,
};
