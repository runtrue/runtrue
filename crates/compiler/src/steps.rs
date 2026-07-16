pub(crate) fn compile_run(
    run: &ast::Run,
    path: &str,
    allow_unsafe_interpolation: bool,
    risks: &mut Vec<RiskFinding>,
) -> Result<(ir::StepAction, Option<String>), CompileError> {
    match run {
        ast::Run::Command(command) => {
            if command.command.is_empty() || command.command[0].is_empty() {
                return Err(CompileError::semantic(
                    format!("{path}.run.command"),
                    "command must contain a non-empty program",
                ));
            }
            if command
                .command
                .iter()
                .any(|argument| argument.contains('\0'))
            {
                return Err(CompileError::semantic(
                    format!("{path}.run.command"),
                    "command values cannot contain NUL bytes",
                ));
            }
            let mut args = command.command[1..]
                .iter()
                .cloned()
                .map(|value| ir::ValueBinding::Literal(ir::ScalarValue::String(value)))
                .collect::<Vec<_>>();
            for (index, binding) in command.args.iter().enumerate() {
                args.push(convert_binding(
                    binding,
                    &format!("{path}.run.args[{index}]"),
                )?);
            }
            if args
                .iter()
                .any(ir::ValueBinding::is_untrusted_runtime_context)
            {
                return Err(CompileError::semantic(
                    format!("{path}.run.args"),
                    "untrusted runtime values cannot be passed to process arguments; use a reviewed workflow literal, vars value, or static matrix value",
                ));
            }
            let working_directory = command
                .working_directory
                .as_deref()
                .map(normalize_relative_path)
                .transpose()
                .map_err(|error| {
                    CompileError::model(format!("{path}.run.working-directory"), error)
                })?;
            Ok((
                ir::StepAction::Command {
                    program: command.command[0].clone(),
                    args,
                },
                working_directory,
            ))
        }
        ast::Run::Container(container) => {
            if container
                .container
                .entrypoint
                .as_ref()
                .is_some_and(|entrypoint| entrypoint.is_empty() || entrypoint.contains('\0'))
            {
                return Err(CompileError::semantic(
                    format!("{path}.run.container.entrypoint"),
                    "container entrypoint must be non-empty and contain no NUL byte",
                ));
            }
            let args = container
                .container
                .args
                .as_ref()
                .map(|args| {
                    args.iter()
                        .enumerate()
                        .map(|(index, binding)| {
                            convert_binding(binding, &format!("{path}.run.container.args[{index}]"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            if args.as_ref().is_some_and(Vec::is_empty) {
                return Err(CompileError::semantic(
                    format!("{path}.run.container.args"),
                    "container args must be omitted or non-empty",
                ));
            }
            if args.as_ref().is_some_and(|args| {
                args.iter()
                    .any(ir::ValueBinding::is_untrusted_runtime_context)
            }) {
                return Err(CompileError::semantic(
                    format!("{path}.run.container.args"),
                    "untrusted runtime values cannot be passed to container arguments",
                ));
            }
            Ok((
                ir::StepAction::Container {
                    entrypoint: container.container.entrypoint.clone(),
                    args,
                },
                None,
            ))
        }
        ast::Run::Script(script) => {
            if script.script.contains('\0') {
                return Err(CompileError::semantic(
                    format!("{path}.run.script"),
                    "script source cannot contain NUL bytes",
                ));
            }
            if matches!(script.shell, ast::Shell::Pwsh | ast::Shell::Cmd) {
                return Err(CompileError::semantic(
                    format!("{path}.run.shell"),
                    "the current compiler supports bash and sh scripts only",
                ));
            }
            let contains_interpolation = script.script.contains("${{");
            if contains_interpolation
                && !(script.unsafe_interpolation && allow_unsafe_interpolation)
            {
                return Err(CompileError::semantic(
                    format!("{path}.run.script"),
                    "expression interpolation in shell source is denied; pass values through env or args",
                ));
            }
            if script.unsafe_interpolation {
                if !allow_unsafe_interpolation {
                    return Err(CompileError::semantic(
                        format!("{path}.run.unsafe-interpolation"),
                        "unsafe interpolation requires an explicit compiler policy exception",
                    ));
                }
                risks.push(RiskFinding::high(
                    "unsafe-shell-interpolation",
                    format!("{path}.run.script"),
                    "shell source permits unsafe expression interpolation",
                ));
            }
            let working_directory = script
                .working_directory
                .as_deref()
                .map(normalize_relative_path)
                .transpose()
                .map_err(|error| {
                    CompileError::model(format!("{path}.run.working-directory"), error)
                })?;
            Ok((
                ir::StepAction::Script {
                    shell: convert_shell(script.shell),
                    script: script.script.clone(),
                    script_digest: ContentDigest::sha256(script.script.as_bytes()),
                },
                working_directory,
            ))
        }
    }
}

pub(crate) fn compile_service(
    id: &str,
    service: &ast::Service,
    job_path: &str,
) -> Result<ir::PlannedService, CompileError> {
    validate_identifier(id, &format!("{job_path}.services.{id}"))?;
    validate_external_reference(&service.image, &format!("{job_path}.services.{id}.image"))?;
    if service.ports.contains(&0) {
        return Err(CompileError::semantic(
            format!("{job_path}.services.{id}.ports"),
            "service ports must be between 1 and 65535",
        ));
    }
    let environment = service
        .env
        .iter()
        .map(|(name, binding)| {
            validate_environment_name(name, &format!("{job_path}.services.{id}.env.{name}"))?;
            Ok((
                name.clone(),
                convert_environment_binding(
                    name,
                    binding,
                    &format!("{job_path}.services.{id}.env.{name}"),
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CompileError>>()?;
    let healthcheck = service
        .healthcheck
        .as_ref()
        .map(|healthcheck| {
            if healthcheck.command.is_empty() || healthcheck.command[0].is_empty() {
                return Err(CompileError::semantic(
                    format!("{job_path}.services.{id}.healthcheck.command"),
                    "healthcheck command must contain a non-empty program",
                ));
            }
            if !(1..=100).contains(&healthcheck.retries) {
                return Err(CompileError::semantic(
                    format!("{job_path}.services.{id}.healthcheck.retries"),
                    "healthcheck retries must be between 1 and 100",
                ));
            }
            Ok(ir::Healthcheck {
                command: healthcheck.command.clone(),
                interval_ms: parse_duration(
                    &healthcheck.interval,
                    &format!("{job_path}.services.{id}.healthcheck.interval"),
                )?,
                timeout_ms: parse_duration(
                    &healthcheck.timeout,
                    &format!("{job_path}.services.{id}.healthcheck.timeout"),
                )?,
                retries: healthcheck.retries,
            })
        })
        .transpose()?;
    let mut ports = service.ports.clone();
    ports.sort_unstable();
    ports.dedup();
    Ok(ir::PlannedService {
        id: id.to_owned(),
        image: service.image.clone(),
        ports,
        environment,
        healthcheck,
    })
}

pub(crate) fn compile_output(
    id: &str,
    output: &ast::OutputDefinition,
    job_path: &str,
) -> Result<(String, ir::ArtifactOutput), CompileError> {
    validate_identifier(id, &format!("{job_path}.outputs.{id}"))?;
    let path = normalize_relative_path(&output.path)
        .map_err(|error| CompileError::model(format!("{job_path}.outputs.{id}.path"), error))?;
    let retention_ms = parse_retention(
        &output.retention,
        &format!("{job_path}.outputs.{id}.retention"),
    )?;
    Ok((
        id.to_owned(),
        ir::ArtifactOutput {
            path,
            retention_ms,
            classification: convert_classification(output.classification),
        },
    ))
}

pub(crate) fn compile_cache(
    cache: &ast::CacheDeclaration,
    path: &str,
) -> Result<ir::CacheDeclaration, CompileError> {
    let mut inputs = cache
        .inputs
        .iter()
        .map(|value| normalize_pattern(value, &format!("{path}.cache.inputs")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut outputs = cache
        .outputs
        .iter()
        .map(|value| normalize_pattern(value, &format!("{path}.cache.outputs")))
        .collect::<Result<Vec<_>, _>>()?;
    inputs.sort();
    inputs.dedup();
    outputs.sort();
    outputs.dedup();
    if inputs.is_empty() && outputs.is_empty() {
        return Err(CompileError::semantic(
            format!("{path}.cache"),
            "cache declaration must include inputs or outputs",
        ));
    }
    let max_size_bytes = cache
        .max_size
        .as_deref()
        .map(ByteSize::parse)
        .transpose()
        .map_err(|error| CompileError::model(format!("{path}.cache.max-size"), error))?
        .map(|size| size.0);
    if max_size_bytes == Some(0) {
        return Err(CompileError::semantic(
            format!("{path}.cache.max-size"),
            "cache max-size must be greater than zero",
        ));
    }
    Ok(ir::CacheDeclaration {
        inputs,
        outputs,
        mode: match cache.mode {
            ast::CacheMode::ReadOnly => ir::CacheMode::ReadOnly,
            ast::CacheMode::ReadWrite => ir::CacheMode::ReadWrite,
            ast::CacheMode::WriteOnly => ir::CacheMode::WriteOnly,
        },
        max_size_bytes,
    })
}

pub(crate) fn compile_step_capabilities(
    capabilities: &ast::StepCapabilities,
    job_permissions: &ir::PermissionSet,
    path: &str,
) -> Result<ir::StepCapabilitySet, CompileError> {
    let mut fs_read = capabilities
        .fs
        .as_ref()
        .map(|fs| {
            fs.read
                .iter()
                .map(|value| normalize_pattern(value, &format!("{path}.capabilities.fs.read")))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let mut fs_write = capabilities
        .fs
        .as_ref()
        .map(|fs| {
            fs.write
                .iter()
                .map(|value| normalize_pattern(value, &format!("{path}.capabilities.fs.write")))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    fs_read.sort();
    fs_read.dedup();
    fs_write.sort();
    fs_write.dedup();

    let requested_network = capabilities
        .network
        .as_ref()
        .map(convert_network_policy)
        .transpose()?
        .unwrap_or(ir::NetworkPermission::Deny);
    let network = intersect_network(&job_permissions.network, &requested_network);

    let allowed_secrets = job_permissions.secrets.iter().collect::<BTreeSet<_>>();
    for request in &capabilities.secrets {
        let requested = secret_reference(request);
        if !allowed_secrets.contains(&requested) {
            return Err(CompileError::semantic(
                format!("{path}.capabilities.secrets"),
                format!(
                    "step requests secret `{}` with an ungranted purpose",
                    request.name,
                ),
            ));
        }
    }
    let mut secrets = capabilities
        .secrets
        .iter()
        .map(secret_reference)
        .collect::<Vec<_>>();
    secrets.sort();
    secrets.dedup();

    let cache = capabilities.cache.as_ref().map(convert_cache_permissions);
    let (cache_read, cache_write) = cache
        .map(|(read, write)| {
            (
                min_cache_read(job_permissions.cache_read, read),
                min_cache_write(job_permissions.cache_write, write),
            )
        })
        .unwrap_or((ir::CacheRead::Deny, ir::CacheWrite::Deny));

    let requested_audiences = capabilities
        .oidc
        .as_ref()
        .map(|oidc| oidc.audiences.iter().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let allowed_audiences = job_permissions
        .oidc_audiences
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !requested_audiences.is_subset(&allowed_audiences) {
        return Err(CompileError::semantic(
            format!("{path}.capabilities.oidc"),
            "step requests an OIDC audience outside the job permission set",
        ));
    }

    let signing_path = format!("{path}.capabilities.signing");
    validate_signing_requests(&capabilities.signing, &signing_path)?;
    let allowed_signing = job_permissions.signing.iter().collect::<BTreeSet<_>>();
    let mut signing = capabilities
        .signing
        .iter()
        .map(signing_capability)
        .collect::<Vec<_>>();
    if signing
        .iter()
        .any(|capability| !allowed_signing.contains(capability))
    {
        return Err(CompileError::semantic(
            signing_path,
            "step requests a signing purpose, operation, or key policy outside the job permission set",
        ));
    }
    signing.sort();

    Ok(ir::StepCapabilitySet {
        fs_read,
        fs_write,
        network,
        secrets,
        checks: min_access(job_permissions.checks, convert_access(capabilities.checks)),
        artifacts: min_access(
            job_permissions.artifacts,
            convert_access(capabilities.artifacts),
        ),
        cache_read,
        cache_write,
        oidc_audiences: requested_audiences.into_iter().collect(),
        signing,
    })
}

impl Compiler {
    pub(crate) fn compile_step(
        &self,
        step: &ast::Step,
        step_id: &str,
        index: usize,
        job_path: &str,
        job_permissions: &ir::PermissionSet,
        risks: &mut Vec<RiskFinding>,
    ) -> Result<ir::PlannedStep, CompileError> {
        let path = format!("{job_path}.steps[{index}]");
        if step.uses.is_some() == step.run.is_some() {
            return Err(CompileError::semantic(
                path,
                "a step must define exactly one of `uses` or `run`",
            ));
        }
        if step.run.is_some() && !step.inputs.is_empty() {
            return Err(CompileError::semantic(
                format!("{path}.with"),
                "`with` inputs are valid only for component steps; use env or run.args for commands",
            ));
        }
        let condition = step
            .condition
            .as_deref()
            .map(|condition| normalize_expression(condition, &format!("{path}.if")))
            .transpose()?;

        for name in step.env.keys() {
            validate_environment_name(name, &format!("{path}.env.{name}"))?;
        }
        let environment = step
            .env
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.clone(),
                    convert_environment_binding(name, value, &format!("{path}.env.{name}"))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CompileError>>()?;
        let inputs = step
            .inputs
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.clone(),
                    convert_binding(value, &format!("{path}.with.{name}"))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CompileError>>()?;

        let (action, working_directory) = if let Some(reference) = &step.uses {
            validate_external_reference(reference, &format!("{path}.uses"))?;
            (
                ir::StepAction::Component {
                    reference: reference.clone(),
                },
                None,
            )
        } else {
            compile_run(
                step.run.as_ref().expect("validated run"),
                &path,
                self.settings.allow_unsafe_interpolation,
                risks,
            )?
        };

        let timeout_ms = step
            .timeout
            .as_deref()
            .map(|timeout| parse_duration(timeout, &format!("{path}.timeout")))
            .transpose()?;
        let capabilities = compile_step_capabilities(&step.capabilities, job_permissions, &path)?;
        collect_step_risks(&capabilities, &path, risks);
        let cache = step
            .cache
            .as_ref()
            .map(|cache| compile_cache(cache, &path))
            .transpose()?;
        let outputs = step
            .outputs
            .iter()
            .map(|(name, output)| {
                validate_identifier(name, &format!("{path}.outputs.{name}"))?;
                Ok((
                    name.clone(),
                    ir::StepOutputSchema {
                        kind: convert_step_output_type(output.kind),
                        required: output.required,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CompileError>>()?;

        Ok(ir::PlannedStep {
            id: step_id.to_owned(),
            name: step.name.clone().unwrap_or_else(|| step_id.to_owned()),
            condition,
            action,
            inputs,
            environment,
            capabilities,
            cache,
            timeout_ms,
            continue_on_error: step.continue_on_error,
            outputs,
            working_directory,
        })
    }
}
use super::{
    ast, collect_step_risks, convert_access, convert_binding, convert_cache_permissions,
    convert_classification, convert_environment_binding, convert_network_policy, convert_shell,
    convert_step_output_type, intersect_network, ir, min_access, min_cache_read, min_cache_write,
    normalize_expression, normalize_pattern, normalize_relative_path, parse_duration,
    parse_retention, secret_reference, signing_capability, validate_environment_name,
    validate_external_reference, validate_identifier, validate_signing_requests, BTreeMap,
    BTreeSet, ByteSize, CompileError, Compiler, ContentDigest, RiskFinding,
};
