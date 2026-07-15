pub(crate) fn expand_reusable_workflows(
    workflow: &ast::Workflow,
    context: &CompileContext,
    settings: &CompilerSettings,
) -> Result<ExpandedReusableWorkflows, CompileError> {
    validate_workflow_shape(workflow, settings)?;
    validate_dag(workflow)?;

    let mut state = ReusableExpansionState {
        context,
        settings,
        stack: Vec::new(),
        identities: BTreeMap::new(),
    };
    let fragment = state.expand_definition(workflow, None, &BTreeMap::new(), false, 0, None)?;
    let references = state.identities.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(unused) = context
        .reusable_workflows
        .entries
        .keys()
        .find(|reference| !references.contains(*reference))
    {
        return Err(CompileError::semantic(
            "reusable_workflows",
            format!("source bundle contains unused workflow `{unused}`"),
        ));
    }

    let mut expanded_workflow = workflow.clone();
    expanded_workflow.jobs = fragment.jobs.into();
    expanded_workflow.outputs = fragment
        .public_outputs
        .iter()
        .map(|(name, target)| {
            (
                name.clone(),
                ast::WorkflowOutputDefinition {
                    from: target.context_path(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into();
    let identities = state.identities.into_values().collect::<Vec<_>>();
    let mut reusable_digests = identities
        .iter()
        .map(|identity| identity.digest.to_string())
        .collect::<Vec<_>>();
    reusable_digests.sort();
    reusable_digests.dedup();

    Ok(ExpandedReusableWorkflows {
        workflow: expanded_workflow,
        identities,
        references,
        selection_aliases: fragment.selection_aliases,
        reusable_digests,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReusableOutputTarget {
    pub(crate) job: String,
    pub(crate) output: String,
}

impl ReusableOutputTarget {
    pub(crate) fn context_path(&self) -> String {
        format!("needs.{}.outputs.{}", self.job, self.output)
    }
}

#[derive(Debug)]
pub(crate) struct ReusableFragment {
    pub(crate) jobs: BTreeMap<String, ast::Job>,
    pub(crate) entry_jobs: Vec<String>,
    pub(crate) terminal_jobs: Vec<String>,
    pub(crate) public_outputs: BTreeMap<String, ReusableOutputTarget>,
    pub(crate) selection_aliases: BTreeMap<String, Vec<String>>,
    pub(crate) call_boundary: bool,
}

pub(crate) struct ReusableExpansionState<'a> {
    context: &'a CompileContext,
    settings: &'a CompilerSettings,
    stack: Vec<String>,
    identities: BTreeMap<String, ReusableWorkflowIdentity>,
}

impl ReusableExpansionState<'_> {
    #[allow(clippy::too_many_arguments)]
    fn expand_definition(
        &mut self,
        workflow: &ast::Workflow,
        namespace: Option<&str>,
        provided_inputs: &BTreeMap<String, ast::Scalar>,
        reusable: bool,
        depth: usize,
        inherited_permissions: Option<&ast::Permissions>,
    ) -> Result<ReusableFragment, CompileError> {
        validate_workflow_shape(workflow, self.settings)?;
        validate_dag(workflow)?;
        if reusable && has_triggers(&workflow.triggers) {
            return Err(CompileError::semantic(
                "on",
                "a reusable workflow source cannot declare event triggers",
            ));
        }
        let inputs = if reusable {
            bind_reusable_inputs(&workflow.inputs, provided_inputs)?
        } else {
            BTreeMap::new()
        };
        let input_bindings = reusable.then_some(&inputs);
        let effective_permissions = inherited_permissions
            .map(|maximum| intersect_ast_permissions(maximum, &workflow.permissions))
            .transpose()?
            .unwrap_or_else(|| workflow.permissions.clone());

        let mut pieces = BTreeMap::new();
        for (job_id, job) in &workflow.jobs {
            let qualified_id = qualify_job_id(namespace, job_id)?;
            let piece = if let Some(reference) = &job.uses {
                let mut child = self.expand_call(
                    reference,
                    &qualified_id,
                    &job.inputs,
                    depth.saturating_add(1),
                    &effective_permissions,
                )?;
                child.call_boundary = true;
                if child.jobs.len() > self.settings.max_reusable_jobs {
                    return Err(CompileError::semantic(
                        format!("jobs.{job_id}.uses"),
                        format!(
                            "reusable workflow expands beyond the configured {} job fan-out limit",
                            self.settings.max_reusable_jobs
                        ),
                    ));
                }
                child
                    .selection_aliases
                    .insert(qualified_id.clone(), child.terminal_jobs.clone());
                child
            } else {
                let mut outputs = BTreeMap::new();
                for output in job.outputs.keys() {
                    outputs.insert(
                        output.clone(),
                        ReusableOutputTarget {
                            job: qualified_id.clone(),
                            output: output.clone(),
                        },
                    );
                }
                ReusableFragment {
                    jobs: BTreeMap::from([(qualified_id.clone(), job.clone())]),
                    entry_jobs: vec![qualified_id.clone()],
                    terminal_jobs: vec![qualified_id],
                    public_outputs: outputs,
                    selection_aliases: BTreeMap::new(),
                    call_boundary: false,
                }
            };
            pieces.insert(job_id.clone(), piece);
        }

        let mappings = context_mappings(&pieces);
        for (job_id, original) in &workflow.jobs {
            let dependencies = original
                .needs
                .iter()
                .flat_map(|dependency| pieces[dependency].terminal_jobs.iter().cloned())
                .collect::<Vec<_>>();
            let piece = pieces.get_mut(job_id).expect("piece created for every job");
            if original.uses.is_some() {
                let call_condition = original
                    .condition
                    .as_deref()
                    .map(|condition| {
                        rewrite_condition(
                            condition,
                            input_bindings,
                            &mappings,
                            &format!("jobs.{job_id}.if"),
                        )
                    })
                    .transpose()?;
                for entry in &piece.entry_jobs {
                    let job = piece.jobs.get_mut(entry).expect("entry job is present");
                    job.needs.extend(dependencies.iter().cloned());
                    job.needs.sort();
                    job.needs.dedup();
                }
                if let Some(call_condition) = call_condition {
                    for job in piece.jobs.values_mut() {
                        job.condition = Some(combine_conditions(
                            &call_condition,
                            job.condition.as_deref(),
                        )?);
                    }
                }
            } else {
                let qualified_id = qualify_job_id(namespace, job_id)?;
                let job = piece
                    .jobs
                    .get_mut(&qualified_id)
                    .expect("executable job is present");
                job.needs = dependencies;
                rewrite_executable_job(job, input_bindings, &mappings, &format!("jobs.{job_id}"))?;
                if reusable {
                    let requested = job.permissions.as_ref().unwrap_or(&effective_permissions);
                    job.permissions = Some(intersect_ast_permissions(
                        &effective_permissions,
                        requested,
                    )?);
                    let mut variables = workflow
                        .vars
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect::<BTreeMap<_, _>>();
                    variables.extend(
                        job.vars
                            .iter()
                            .map(|(name, value)| (name.clone(), value.clone())),
                    );
                    job.vars = variables.into();
                }
            }
        }

        let depended_on = workflow
            .jobs
            .values()
            .flat_map(|job| job.needs.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut entry_jobs = workflow
            .jobs
            .iter()
            .filter(|(_, job)| job.needs.is_empty())
            .flat_map(|(id, _)| pieces[id].entry_jobs.iter().cloned())
            .collect::<Vec<_>>();
        let mut terminal_jobs = workflow
            .jobs
            .keys()
            .filter(|id| !depended_on.contains(*id))
            .flat_map(|id| pieces[id].terminal_jobs.iter().cloned())
            .collect::<Vec<_>>();
        entry_jobs.sort();
        entry_jobs.dedup();
        terminal_jobs.sort();
        terminal_jobs.dedup();

        let mut public_outputs = BTreeMap::new();
        for (name, definition) in &workflow.outputs {
            let (job, output) =
                parse_workflow_output_path(&definition.from, &format!("outputs.{name}.from"))?;
            let target = pieces
                .get(job)
                .and_then(|piece| piece.public_outputs.get(output))
                .ok_or_else(|| {
                    CompileError::semantic(
                        format!("outputs.{name}.from"),
                        format!("unknown or unexposed workflow output `{}`", definition.from),
                    )
                })?;
            public_outputs.insert(name.clone(), target.clone());
        }

        let mut jobs = BTreeMap::new();
        let mut selection_aliases = BTreeMap::new();
        for (_, piece) in pieces {
            for (id, job) in piece.jobs {
                if jobs.insert(id.clone(), job).is_some() {
                    return Err(CompileError::semantic(
                        "jobs",
                        format!("reusable workflow namespace collision for job `{id}`"),
                    ));
                }
            }
            for (alias, targets) in piece.selection_aliases {
                if selection_aliases.insert(alias.clone(), targets).is_some() {
                    return Err(CompileError::semantic(
                        "jobs",
                        format!("reusable workflow namespace collision for call `{alias}`"),
                    ));
                }
            }
        }
        if jobs.len() > MAX_WORKFLOW_JOBS {
            return Err(CompileError::semantic(
                "jobs",
                format!("expanded workflow exceeds the {MAX_WORKFLOW_JOBS} job limit"),
            ));
        }

        Ok(ReusableFragment {
            jobs,
            entry_jobs,
            terminal_jobs,
            public_outputs,
            selection_aliases,
            call_boundary: false,
        })
    }

    fn expand_call(
        &mut self,
        reference: &str,
        namespace: &str,
        inputs: &BTreeMap<String, ast::Scalar>,
        depth: usize,
        inherited_permissions: &ast::Permissions,
    ) -> Result<ReusableFragment, CompileError> {
        if depth > self.settings.max_reusable_depth {
            return Err(CompileError::semantic(
                format!("jobs.{namespace}.uses"),
                format!(
                    "reusable workflow nesting exceeds the configured depth limit of {}",
                    self.settings.max_reusable_depth
                ),
            ));
        }
        if self.stack.iter().any(|active| active == reference) {
            let mut cycle = self.stack.clone();
            cycle.push(reference.to_owned());
            return Err(CompileError::semantic(
                format!("jobs.{namespace}.uses"),
                format!("reusable workflow call cycle: {}", cycle.join(" -> ")),
            ));
        }
        let lockfile = self.context.lockfile.as_ref().ok_or_else(|| {
            CompileError::semantic(
                ".runtrue.lock",
                "a validated lockfile is required for every reusable workflow reference",
            )
        })?;
        let locked = lockfile
            .workflows()
            .iter()
            .find(|entry| entry.source() == reference)
            .ok_or_else(|| {
                CompileError::semantic(
                    format!("jobs.{namespace}.uses"),
                    format!("missing reusable workflow lock entry for `{reference}`"),
                )
            })?;
        let bundled = self
            .context
            .reusable_workflows
            .entries
            .get(reference)
            .ok_or_else(|| {
                CompileError::semantic(
                    format!("jobs.{namespace}.uses"),
                    format!("missing authenticated source bytes for `{reference}`"),
                )
            })?;
        if bundled.commit != locked.commit() {
            return Err(CompileError::semantic(
                format!("jobs.{namespace}.uses"),
                format!("source commit for `{reference}` does not match `.runtrue.lock`"),
            ));
        }
        let actual_digest = ContentDigest::sha256(bundled.source.as_ref());
        if &actual_digest != locked.digest() {
            return Err(CompileError::semantic(
                format!("jobs.{namespace}.uses"),
                format!("source digest for `{reference}` does not match `.runtrue.lock`"),
            ));
        }
        let source = std::str::from_utf8(bundled.source.as_ref()).map_err(|_| {
            CompileError::semantic(
                format!("jobs.{namespace}.uses"),
                format!("reusable workflow `{reference}` is not UTF-8"),
            )
        })?;
        let workflow = ast::parse_yaml(source)?;
        self.identities.insert(
            reference.to_owned(),
            ReusableWorkflowIdentity {
                source: reference.to_owned(),
                commit: locked.commit().to_owned(),
                digest: locked.digest().clone(),
            },
        );
        self.stack.push(reference.to_owned());
        let result = self.expand_definition(
            &workflow,
            Some(namespace),
            inputs,
            true,
            depth,
            Some(inherited_permissions),
        );
        self.stack.pop();
        result
    }
}

pub(crate) fn qualify_job_id(
    namespace: Option<&str>,
    job_id: &str,
) -> Result<String, CompileError> {
    let qualified =
        namespace.map_or_else(|| job_id.to_owned(), |prefix| format!("{prefix}__{job_id}"));
    validate_identifier(&qualified, "jobs")?;
    Ok(qualified)
}

pub(crate) fn has_triggers(triggers: &ast::Triggers) -> bool {
    triggers.push.is_some()
        || triggers.pull_request.is_some()
        || triggers.merge_queue.is_some()
        || !triggers.schedule.is_empty()
        || triggers.manual.is_some()
        || triggers.api.is_some()
}
use crate::{
    ast, bind_reusable_inputs, combine_conditions, context_mappings, intersect_ast_permissions,
    parse_workflow_output_path, rewrite_condition, rewrite_executable_job, validate_dag,
    validate_identifier, validate_workflow_shape, BTreeMap, BTreeSet, CompileContext, CompileError,
    CompilerSettings, ContentDigest, ExpandedReusableWorkflows, ReusableWorkflowIdentity,
    MAX_WORKFLOW_JOBS,
};
