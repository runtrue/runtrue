pub(crate) fn resolve_external_references(
    jobs: &mut [ir::PlannedJob],
    dynamic_jobs: &mut [ir::DynamicJobTemplate],
    lockfile: Option<&LockFile>,
    reusable_workflows: &BTreeSet<String>,
) -> Result<Option<ContentDigest>, CompileError> {
    let mut requirements = LockRequirements::default();
    for reference in reusable_workflows {
        requirements.require_workflow(reference.clone());
    }
    for job in jobs
        .iter()
        .chain(dynamic_jobs.iter().map(|template| &template.template))
    {
        let platform = format!(
            "{}/{}",
            match job.runner.os {
                ir::OperatingSystem::Linux => "linux",
                ir::OperatingSystem::Windows => "windows",
                ir::OperatingSystem::Macos => "macos",
            },
            match job.runner.arch {
                ir::Architecture::Amd64 => "amd64",
                ir::Architecture::Arm64 => "arm64",
            }
        );
        if let Some(image) = &job.runner.image {
            requirements.require_image(image.clone(), platform.clone());
        }
        for service in &job.services {
            requirements.require_image(service.image.clone(), platform.clone());
        }
        for step in job_steps(job) {
            if let ir::StepAction::Component { reference } = &step.action {
                requirements.require_component(reference.clone());
            }
        }
    }

    let Some(lockfile) = lockfile else {
        if requirements.is_empty() {
            return Ok(None);
        }
        return Err(CompileError::semantic(
            ".runtrue.lock",
            "a validated lockfile is required for every component, job/service image, or reusable workflow reference",
        ));
    };
    let resolved = lockfile.resolve(&requirements)?;
    for job in jobs.iter_mut().chain(
        dynamic_jobs
            .iter_mut()
            .map(|template| &mut template.template),
    ) {
        let platform = format!(
            "{}/{}",
            match job.runner.os {
                ir::OperatingSystem::Linux => "linux",
                ir::OperatingSystem::Windows => "windows",
                ir::OperatingSystem::Macos => "macos",
            },
            match job.runner.arch {
                ir::Architecture::Amd64 => "amd64",
                ir::Architecture::Arm64 => "arm64",
            }
        );
        if let Some(image) = &mut job.runner.image {
            let resolved_image = resolved
                .image(image, &platform)
                .expect("all OCI job image requirements were resolved");
            resolved_image.clone_into(image);
        }
        for service in &mut job.services {
            let resolved_image = resolved
                .image(&service.image, &platform)
                .expect("all image requirements were resolved");
            resolved_image.clone_into(&mut service.image);
        }
        for step in job_steps_mut(job) {
            if let ir::StepAction::Component { reference } = &mut step.action {
                let resolved_reference = resolved
                    .component(reference)
                    .expect("all component requirements were resolved");
                resolved_reference.clone_into(reference);
            }
        }
    }
    Ok(Some(resolved.digest().clone()))
}

pub(crate) fn approval_subject(
    capsule: &ir::ExecutionCapsule,
    capsule_digest: &ContentDigest,
    context: &CompileContext,
    reusable_workflow_digests: &[String],
) -> Result<ApprovalSubject, CompileError> {
    let mut actions = Vec::new();
    let mut images = Vec::new();
    let mut secrets = Vec::new();
    let mut runners = Vec::new();
    let mut environments = Vec::new();
    for job in capsule_jobs(capsule) {
        if let Some(image) = &job.runner.image {
            images.push(reference_digest(image));
        }
        images.extend(
            job.services
                .iter()
                .map(|service| reference_digest(&service.image)),
        );
        for step in job_steps(job) {
            if let ir::StepAction::Component { reference } = &step.action {
                actions.push(reference_digest(reference));
            }
            secrets.extend(
                step.capabilities
                    .secrets
                    .iter()
                    .map(|secret| secret.metadata_id.clone()),
            );
        }
        secrets.extend(
            job.permissions
                .secrets
                .iter()
                .map(|secret| secret.metadata_id.clone()),
        );
        let mut capabilities = job.runner.capabilities.clone();
        capabilities.sort();
        runners.push(RunnerApprovalProfile {
            os: job.runner.os,
            arch: job.runner.arch,
            isolation_floor: job.runner.isolation,
            cpu: job.runner.cpu,
            memory_bytes: job.runner.memory_bytes,
            storage_bytes: job.runner.storage_bytes,
            region: job.runner.region.clone(),
            capabilities,
        });
        if let Some(environment) = &job.environment {
            environments.push(format!(
                "local:{}",
                ContentDigest::sha256(environment).as_str()
            ));
        }
    }
    actions.sort();
    actions.dedup();
    images.sort();
    images.dedup();
    secrets.sort();
    secrets.dedup();
    runners.sort();
    runners.dedup();
    environments.sort();
    environments.dedup();

    let permission_snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| {
            (
                &job.id,
                &job.permissions,
                job_steps(job)
                    .map(|step| (&step.id, &step.capabilities))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let variable_snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| (&job.id, &job.variables, &job.matrix))
        .collect::<Vec<_>>();
    let network_snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| {
            (
                &job.id,
                &job.permissions.network,
                job_steps(job)
                    .map(|step| (&step.id, &step.capabilities.network))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let cache_snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| {
            (
                &job.id,
                job.permissions.cache_read,
                job.permissions.cache_write,
                job_steps(job)
                    .map(|step| {
                        (
                            &step.id,
                            step.capabilities.cache_read,
                            step.capabilities.cache_write,
                            &step.cache,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let artifact_snapshot = capsule
        .jobs
        .iter()
        .chain(
            capsule
                .dynamic_jobs
                .iter()
                .map(|template| &template.template),
        )
        .map(|job| {
            (
                &job.id,
                job.permissions.artifacts,
                &job.outputs,
                job_steps(job)
                    .map(|step| (&step.id, step.capabilities.artifacts))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();

    Ok(ApprovalSubject {
        subject_version: "phase0-local-v1".to_owned(),
        authorization_ready: false,
        installation_id: context.installation_id.clone(),
        tenant_id: context.tenant_id.clone(),
        repository_id: context.repository_id.clone(),
        source_commit: capsule.context.source_commit.clone(),
        source_tree_digest: capsule.context.source_tree_digest.clone(),
        base_commit: capsule.context.base_commit.clone(),
        source_trust: capsule.context.source_trust,
        normalized_event_digest: capsule.context.normalized_event_digest.clone(),
        canonical_workflow_digest: capsule.workflow.digest.clone(),
        execution_capsule_digest: capsule_digest.clone(),
        lockfile_digest: capsule.context.lockfile_digest.clone(),
        resolved_action_digests: actions,
        resolved_image_digests: images,
        reusable_workflow_digests: reusable_workflow_digests.to_vec(),
        workflow_frontend: capsule.context.workflow_frontend.clone(),
        permission_set_digest: digest_json(&(&capsule.permissions, permission_snapshot))?,
        secret_metadata_ids: secrets,
        variable_snapshot_digest: digest_json(&(&capsule.variables, variable_snapshot))?,
        network_policy_digest: digest_json(&network_snapshot)?,
        cache_policy_digest: digest_json(&cache_snapshot)?,
        artifact_policy_digest: digest_json(&artifact_snapshot)?,
        runner_profiles: runners,
        environment_ids: environments,
        deployment_target_digest: None,
        policy_version_ids: capsule.context.policy_version_ids.clone(),
        engine_compatibility_version: capsule.engine_compatibility_version.clone(),
        expiration_boundary: context.expiration_boundary.clone(),
    })
}

pub(crate) fn reference_digest(reference: &str) -> String {
    reference
        .rsplit_once('@')
        .map_or_else(|| reference.to_owned(), |(_, digest)| digest.to_owned())
}

pub(crate) fn digest_json(value: &impl Serialize) -> Result<ContentDigest, CompileError> {
    Ok(ContentDigest::sha256(canonical_bytes(value)?))
}

pub(crate) fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, CompileError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&ir::canonicalize_value(value))?)
}

pub(crate) fn expected_parity<'a>(
    jobs: impl IntoIterator<Item = &'a ir::PlannedJob>,
) -> ir::ParityGrade {
    let mut parity = ir::ParityGrade::AExact;
    for job in jobs {
        if job.environment.is_some() {
            return ir::ParityGrade::DNonReplayable;
        }
        if job.runner.isolation == ir::Isolation::Native {
            parity = ir::ParityGrade::CPlatformSpecific;
        } else if job.runner.isolation == ir::Isolation::Microvm
            && parity == ir::ParityGrade::AExact
        {
            parity = ir::ParityGrade::BEnvironmentEquivalent;
        }
    }
    parity
}

pub(crate) fn capsule_jobs(
    capsule: &ir::ExecutionCapsule,
) -> impl Iterator<Item = &ir::PlannedJob> {
    capsule.jobs.iter().chain(
        capsule
            .dynamic_jobs
            .iter()
            .map(|template| &template.template),
    )
}

pub(crate) fn job_steps(job: &ir::PlannedJob) -> impl Iterator<Item = &ir::PlannedStep> {
    job.steps
        .iter()
        .chain(job.finalizers.iter().map(|finalizer| &finalizer.step))
}

pub(crate) fn job_steps_mut(
    job: &mut ir::PlannedJob,
) -> impl Iterator<Item = &mut ir::PlannedStep> {
    job.steps.iter_mut().chain(
        job.finalizers
            .iter_mut()
            .map(|finalizer| &mut finalizer.step),
    )
}

impl Compiler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compile_job(
        &self,
        base_id: &str,
        job: &ast::Job,
        expanded: &MatrixExpansion,
        needs: &[String],
        global_permissions: &ir::PermissionSet,
        global_variables: &BTreeMap<String, ir::ScalarValue>,
        risks: &mut Vec<RiskFinding>,
    ) -> Result<ir::PlannedJob, CompileError> {
        let path = format!("jobs.{base_id}");
        let condition = job
            .condition
            .as_deref()
            .map(|condition| normalize_expression(condition, &format!("{path}.if")))
            .transpose()?;
        if job.retries > 10 {
            return Err(CompileError::semantic(
                format!("{path}.retries"),
                "retries cannot exceed 10",
            ));
        }
        if job.runner.os != ast::OperatingSystem::Linux {
            return Err(CompileError::semantic(
                format!("{path}.runner.os"),
                "the current compiler supports Linux runners only",
            ));
        }
        if job.runner.isolation == ast::Isolation::Native && job.trust == ast::Trust::UntrustedOk {
            return Err(CompileError::semantic(
                format!("{path}.runner.isolation"),
                "native execution requires trust: trusted-only or protected-branch-only",
            ));
        }
        match (job.runner.isolation, job.runner.image.as_deref()) {
            (ast::Isolation::Oci, Some(image)) => {
                validate_external_reference(image, &format!("{path}.runner.image"))?;
            }
            (ast::Isolation::Oci, None) => {
                return Err(CompileError::semantic(
                    format!("{path}.runner.image"),
                    "OCI isolation requires an explicit runner image",
                ));
            }
            (_, Some(_)) => {
                return Err(CompileError::semantic(
                    format!("{path}.runner.image"),
                    "runner image is valid only with isolation: oci",
                ));
            }
            (_, None) => {}
        }

        let requested_permissions = match &job.permissions {
            Some(permissions) => convert_permissions(permissions)?,
            None => global_permissions.clone(),
        };
        let permissions = intersect_permissions(global_permissions, &requested_permissions);
        collect_permission_risks(&permissions, &path, risks);

        if job.runner.isolation == ast::Isolation::Native {
            risks.push(RiskFinding::high(
                "native-execution",
                format!("{path}.runner.isolation"),
                "job requests trusted native host execution",
            ));
        }
        if job.environment.is_some() {
            risks.push(RiskFinding::high(
                "protected-environment",
                format!("{path}.environment"),
                "job targets an environment and requires a privileged-execution decision",
            ));
        }

        let timeout_ms = match &job.timeout {
            Some(timeout) => parse_duration(timeout, &format!("{path}.timeout"))?,
            None => DEFAULT_JOB_TIMEOUT_MS,
        };
        let memory_bytes = ByteSize::parse(&job.runner.memory)
            .map_err(|error| CompileError::model(format!("{path}.runner.memory"), error))?
            .0;
        if memory_bytes == 0 {
            return Err(CompileError::semantic(
                format!("{path}.runner.memory"),
                "runner memory must be greater than zero",
            ));
        }
        let storage_bytes = job
            .runner
            .storage
            .as_deref()
            .map(ByteSize::parse)
            .transpose()
            .map_err(|error| CompileError::model(format!("{path}.runner.storage"), error))?
            .map(|size| size.0);
        if storage_bytes == Some(0) {
            return Err(CompileError::semantic(
                format!("{path}.runner.storage"),
                "runner storage must be greater than zero",
            ));
        }
        if job.runner.cpu == 0 {
            return Err(CompileError::semantic(
                format!("{path}.runner.cpu"),
                "runner CPU count must be positive",
            ));
        }

        let mut capabilities = job.runner.capabilities.clone();
        capabilities.sort();
        capabilities.dedup();
        if !capabilities.is_empty() {
            risks.push(RiskFinding::high(
                "runner-capability-request",
                format!("{path}.runner.capabilities"),
                "job requests specialized or privileged runner capabilities",
            ));
        }

        let mut variables = global_variables.clone();
        variables.extend(convert_variables(&job.vars, &format!("{path}.vars"))?);

        let services = job
            .services
            .iter()
            .map(|(id, service)| compile_service(id, service, &path))
            .collect::<Result<Vec<_>, _>>()?;

        let mut seen_steps = BTreeSet::new();
        let mut steps = Vec::with_capacity(job.steps.len());
        for (index, step) in job.steps.iter().enumerate() {
            let step_id = step
                .id
                .clone()
                .unwrap_or_else(|| format!("step_{}", index + 1));
            validate_identifier(&step_id, &format!("{path}.steps[{index}].id"))?;
            if !seen_steps.insert(step_id.clone()) {
                return Err(CompileError::semantic(
                    format!("{path}.steps[{index}].id"),
                    format!("duplicate step id `{step_id}`"),
                ));
            }
            steps.push(self.compile_step(step, &step_id, index, &path, &permissions, risks)?);
        }

        let finalizer_timeout_ms = match &job.finalizer_timeout {
            Some(timeout) => parse_duration(timeout, &format!("{path}.finalizer-timeout"))?,
            None => DEFAULT_FINALIZER_TIMEOUT_MS,
        };
        if finalizer_timeout_ms == 0 || finalizer_timeout_ms > MAX_FINALIZER_TIMEOUT_MS {
            return Err(CompileError::semantic(
                format!("{path}.finalizer-timeout"),
                format!("finalizer timeout must be between 1ms and {MAX_FINALIZER_TIMEOUT_MS}ms"),
            ));
        }
        let mut finalizers = Vec::with_capacity(job.finalizers.len());
        for (index, finalizer) in job.finalizers.iter().enumerate() {
            let step_id = finalizer
                .step
                .id
                .clone()
                .unwrap_or_else(|| format!("finalizer_{}", index + 1));
            validate_identifier(&step_id, &format!("{path}.finalizers[{index}].id"))?;
            if !seen_steps.insert(step_id.clone()) {
                return Err(CompileError::semantic(
                    format!("{path}.finalizers[{index}].id"),
                    format!("duplicate normal/finalizer step id `{step_id}`"),
                ));
            }
            let step = self.compile_step(
                &finalizer.step,
                &step_id,
                index,
                &format!("{path}.finalizers"),
                &permissions,
                risks,
            )?;
            finalizers.push(ir::PlannedFinalizer {
                step,
                required: finalizer.required,
                run_on_cancel: finalizer.run_on_cancel,
            });
        }

        let value_outputs = job
            .value_outputs
            .iter()
            .map(|(name, output)| {
                validate_identifier(name, &format!("{path}.value-outputs.{name}"))?;
                let (step_id, output_name) = parse_step_output_path(
                    &output.from,
                    &format!("{path}.value-outputs.{name}.from"),
                )?;
                let schema_exists = steps
                    .iter()
                    .chain(finalizers.iter().map(|finalizer| &finalizer.step))
                    .find(|step| step.id == step_id)
                    .is_some_and(|step| step.outputs.contains_key(output_name));
                if !schema_exists {
                    return Err(CompileError::semantic(
                        format!("{path}.value-outputs.{name}.from"),
                        "job value output must reference a declared step output",
                    ));
                }
                Ok((
                    name.clone(),
                    ir::JobValueOutput {
                        step_id: step_id.to_owned(),
                        output_name: output_name.to_owned(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CompileError>>()?;

        let outputs = job
            .outputs
            .iter()
            .map(|(id, output)| compile_output(id, output, &path))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(ir::PlannedJob {
            id: expanded.id.clone(),
            base_id: base_id.to_owned(),
            name: job.name.clone().unwrap_or_else(|| base_id.to_owned()),
            needs: needs.to_vec(),
            matrix: expanded.values.clone(),
            condition,
            trust: convert_trust(job.trust),
            environment: job.environment.clone(),
            runner: ir::RunnerRequirements {
                os: convert_os(job.runner.os),
                arch: convert_arch(job.runner.arch),
                isolation: convert_isolation(job.runner.isolation),
                image: job.runner.image.clone(),
                cpu: job.runner.cpu,
                memory_bytes,
                storage_bytes,
                region: job.runner.region.clone(),
                capabilities,
            },
            permissions,
            timeout_ms,
            retries: job.retries,
            concurrency: job.concurrency.clone(),
            variables,
            services,
            steps,
            finalizers,
            finalizer_timeout_ms,
            value_outputs,
            outputs,
        })
    }
}
use super::{
    ast, collect_permission_risks, compile_output, compile_service, convert_arch,
    convert_isolation, convert_os, convert_permissions, convert_trust, convert_variables,
    intersect_permissions, ir, normalize_expression, parse_duration, parse_step_output_path,
    validate_external_reference, validate_identifier, ApprovalSubject, BTreeMap, BTreeSet,
    ByteSize, CompileContext, CompileError, Compiler, ContentDigest, LockFile, LockRequirements,
    MatrixExpansion, RiskFinding, RunnerApprovalProfile, Serialize, DEFAULT_FINALIZER_TIMEOUT_MS,
    DEFAULT_JOB_TIMEOUT_MS, MAX_FINALIZER_TIMEOUT_MS,
};
