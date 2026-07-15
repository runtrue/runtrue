pub(crate) fn rewrite_executable_job(
    job: &mut ast::Job,
    inputs: Option<&BTreeMap<String, ast::Scalar>>,
    mappings: &ReusableContextMappings,
    path: &str,
) -> Result<(), CompileError> {
    job.condition = job
        .condition
        .as_deref()
        .map(|condition| rewrite_condition(condition, inputs, mappings, &format!("{path}.if")))
        .transpose()?;

    let mut services = BTreeMap::new();
    for (name, service) in &job.services {
        let mut service = service.clone();
        service.env = rewrite_binding_map(
            &service.env,
            inputs,
            mappings,
            &format!("{path}.services.{name}.env"),
        )?;
        services.insert(name.clone(), service);
    }
    job.services = services.into();

    for (index, step) in job.steps.iter_mut().enumerate() {
        let step_path = format!("{path}.steps[{index}]");
        step.condition = step
            .condition
            .as_deref()
            .map(|condition| {
                rewrite_condition(condition, inputs, mappings, &format!("{step_path}.if"))
            })
            .transpose()?;
        step.inputs =
            rewrite_binding_map(&step.inputs, inputs, mappings, &format!("{step_path}.with"))?;
        step.env = rewrite_binding_map(&step.env, inputs, mappings, &format!("{step_path}.env"))?;
        if let Some(ast::Run::Command(command)) = &mut step.run {
            for (argument_index, argument) in command.args.iter_mut().enumerate() {
                rewrite_binding(
                    argument,
                    inputs,
                    mappings,
                    &format!("{step_path}.run.args[{argument_index}]"),
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn rewrite_binding_map(
    values: &BTreeMap<String, ast::ValueBinding>,
    inputs: Option<&BTreeMap<String, ast::Scalar>>,
    mappings: &ReusableContextMappings,
    path: &str,
) -> Result<ast::StrictMap<ast::ValueBinding>, CompileError> {
    values
        .iter()
        .map(|(name, value)| {
            let mut value = value.clone();
            rewrite_binding(&mut value, inputs, mappings, &format!("{path}.{name}"))?;
            Ok((name.clone(), value))
        })
        .collect::<Result<BTreeMap<_, _>, CompileError>>()
        .map(Into::into)
}

pub(crate) fn rewrite_binding(
    value: &mut ast::ValueBinding,
    inputs: Option<&BTreeMap<String, ast::Scalar>>,
    mappings: &ReusableContextMappings,
    path: &str,
) -> Result<(), CompileError> {
    let ast::ValueBinding::From(binding) = value else {
        return Ok(());
    };
    if let Some(name) = binding.from.strip_prefix("inputs.") {
        let Some(inputs) = inputs else {
            return Ok(());
        };
        if name.is_empty() || name.contains('.') {
            return Err(CompileError::semantic(
                path,
                "reusable input path must name one input",
            ));
        }
        let bound = inputs.get(name).ok_or_else(|| {
            CompileError::semantic(path, format!("unbound reusable workflow input `{name}`"))
        })?;
        *value = ast::ValueBinding::Scalar(bound.clone());
    } else {
        binding.from = rewrite_context_reference(&binding.from, mappings, path)?;
    }
    Ok(())
}

pub(crate) fn rewrite_condition(
    source: &str,
    inputs: Option<&BTreeMap<String, ast::Scalar>>,
    mappings: &ReusableContextMappings,
    path: &str,
) -> Result<String, CompileError> {
    let canonical = Expression::parse(source)
        .map_err(|error| {
            CompileError::semantic(path, format!("invalid typed expression: {error}"))
        })?
        .canonical_source();
    let mut rewritten = String::with_capacity(canonical.len());
    let characters = canonical.char_indices().collect::<Vec<_>>();
    let mut position = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while position < characters.len() {
        let (byte_index, character) = characters[position];
        if in_string {
            rewritten.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            position += 1;
            continue;
        }
        if character == '"' {
            in_string = true;
            rewritten.push(character);
            position += 1;
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let start = byte_index;
            position += 1;
            while position < characters.len()
                && (characters[position].1.is_ascii_alphanumeric()
                    || matches!(characters[position].1, '_' | '-' | '.'))
            {
                position += 1;
            }
            let end = characters
                .get(position)
                .map_or(canonical.len(), |(index, _)| *index);
            let token = &canonical[start..end];
            if let Some(name) = token.strip_prefix("inputs.") {
                let Some(inputs) = inputs else {
                    rewritten.push_str(token);
                    continue;
                };
                if name.is_empty() || name.contains('.') {
                    return Err(CompileError::semantic(
                        path,
                        "reusable input expression must name one input",
                    ));
                }
                let value = inputs.get(name).ok_or_else(|| {
                    CompileError::semantic(
                        path,
                        format!("unbound reusable workflow input `{name}`"),
                    )
                })?;
                rewritten.push_str(&scalar_expression_literal(value)?);
            } else {
                rewritten.push_str(&rewrite_context_reference(token, mappings, path)?);
            }
        } else {
            rewritten.push(character);
            position += 1;
        }
    }
    Expression::parse(&rewritten)
        .map(|expression| expression.canonical_source())
        .map_err(|error| {
            CompileError::semantic(path, format!("rewritten expression is invalid: {error}"))
        })
}

pub(crate) fn scalar_expression_literal(value: &ast::Scalar) -> Result<String, CompileError> {
    match value {
        ast::Scalar::String(value) => serde_json::to_string(value).map_err(CompileError::from),
        ast::Scalar::Integer(value) => Ok(value.to_string()),
        ast::Scalar::Number(value) => serde_json::to_string(value).map_err(CompileError::from),
        ast::Scalar::Boolean(value) => Ok(value.to_string()),
    }
}

pub(crate) fn rewrite_context_reference(
    reference: &str,
    mappings: &ReusableContextMappings,
    path: &str,
) -> Result<String, CompileError> {
    let Some(rest) = reference.strip_prefix("needs.") else {
        return Ok(reference.to_owned());
    };
    let segments = rest.split('.').collect::<Vec<_>>();
    if segments.len() == 3 && segments[1] == "outputs" {
        return mappings
            .outputs
            .get(&(segments[0].to_owned(), segments[2].to_owned()))
            .map(ReusableOutputTarget::context_path)
            .ok_or_else(|| {
                CompileError::semantic(
                    path,
                    format!("unknown or unexposed dependency output `{reference}`"),
                )
            });
    }
    let Some(target) = mappings
        .jobs
        .get(segments.first().copied().unwrap_or_default())
    else {
        return Err(CompileError::semantic(
            path,
            format!("unknown dependency context `{reference}`"),
        ));
    };
    let target = target.as_ref().ok_or_else(|| {
        CompileError::semantic(
            path,
            format!("reusable call context `{reference}` must use a declared workflow output"),
        )
    })?;
    Ok(format!("needs.{target}.{}", segments[1..].join(".")))
}

pub(crate) fn combine_conditions(
    parent: &str,
    child: Option<&str>,
) -> Result<String, CompileError> {
    let combined = child.map_or_else(
        || parent.to_owned(),
        |child| format!("({parent}) && ({child})"),
    );
    Expression::parse(&combined)
        .map(|expression| expression.canonical_source())
        .map_err(|error| {
            CompileError::semantic("if", format!("invalid combined condition: {error}"))
        })
}

pub(crate) fn intersect_ast_permissions(
    maximum: &ast::Permissions,
    requested: &ast::Permissions,
) -> Result<ast::Permissions, CompileError> {
    let permissions = intersect_permissions(
        &convert_permissions(maximum)?,
        &convert_permissions(requested)?,
    );
    Ok(ast::Permissions {
        repository: ast_access(permissions.repository),
        scm: ast::ScmPermissions {
            contents: ast_access(permissions.scm.contents),
            issues: ast_access(permissions.scm.issues),
            pull_requests: ast_access(permissions.scm.pull_requests),
            checks: ast_access(permissions.scm.checks),
            statuses: ast_access(permissions.scm.statuses),
        },
        checks: ast_access(permissions.checks),
        artifacts: ast_access(permissions.artifacts),
        registry: ast_access(permissions.registry),
        network: match permissions.network {
            ir::NetworkPermission::Deny => ast::NetworkPermission::Keyword("deny".to_owned()),
            ir::NetworkPermission::Allow {
                dns,
                deny_private_ranges,
                destinations,
                listen,
            } => ast::NetworkPermission::Policy(ast::NetworkPolicy {
                dns: match dns {
                    ir::DnsPolicy::Deny => ast::DnsPolicy::Deny,
                    ir::DnsPolicy::Restricted => ast::DnsPolicy::Restricted,
                    ir::DnsPolicy::Allow => ast::DnsPolicy::Allow,
                },
                deny_private_ranges,
                allow: destinations
                    .into_iter()
                    .map(|destination| ast::NetworkDestination {
                        host: destination.host,
                        port: destination.port,
                        protocol: match destination.protocol {
                            ir::NetworkProtocol::Tcp => ast::NetworkProtocol::Tcp,
                            ir::NetworkProtocol::Udp => ast::NetworkProtocol::Udp,
                        },
                    })
                    .collect(),
                listen,
            }),
        },
        oidc: if permissions.oidc_audiences.is_empty() {
            ast::OidcPermission::Keyword("deny".to_owned())
        } else {
            ast::OidcPermission::Allow(ast::OidcAllow {
                audiences: permissions.oidc_audiences,
            })
        },
        cache: ast::CachePermissions {
            read: match permissions.cache_read {
                ir::CacheRead::Deny => ast::CacheRead::Deny,
                ir::CacheRead::Public => ast::CacheRead::Public,
                ir::CacheRead::Verified => ast::CacheRead::Verified,
                ir::CacheRead::Branch => ast::CacheRead::Branch,
                ir::CacheRead::Run => ast::CacheRead::Run,
            },
            write: match permissions.cache_write {
                ir::CacheWrite::Deny => ast::CacheWrite::Deny,
                ir::CacheWrite::Quarantine => ast::CacheWrite::Quarantine,
                ir::CacheWrite::Branch => ast::CacheWrite::Branch,
                ir::CacheWrite::Verified => ast::CacheWrite::Verified,
            },
        },
        secrets: permissions
            .secrets
            .into_iter()
            .map(|secret| ast::SecretRequest {
                name: secret.name,
                purpose: secret.purpose,
            })
            .collect(),
        signing: permissions
            .signing
            .into_iter()
            .map(|capability| ast::SigningRequest {
                purpose: capability.purpose,
                operation: match capability.operation {
                    ir::SigningOperation::SignDigest => ast::SigningOperation::SignDigest,
                    ir::SigningOperation::SignAttestation => ast::SigningOperation::SignAttestation,
                },
                key_policy: capability.key_policy,
            })
            .collect(),
    })
}

pub(crate) const fn ast_access(access: ir::Access) -> ast::Access {
    match access {
        ir::Access::Deny => ast::Access::Deny,
        ir::Access::Read => ast::Access::Read,
        ir::Access::Write => ast::Access::Write,
    }
}

pub(crate) fn select_job_closure(
    jobs: Vec<ir::PlannedJob>,
    selected: &str,
    aliases: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<ir::PlannedJob>, CompileError> {
    let by_id = jobs
        .iter()
        .map(|job| (job.id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    let mut retained = jobs
        .iter()
        .filter(|job| job.id == selected || job.base_id == selected)
        .map(|job| job.id.clone())
        .collect::<BTreeSet<_>>();
    if let Some(alias_targets) = aliases.get(selected) {
        for target in alias_targets {
            retained.extend(
                jobs.iter()
                    .filter(|job| job.id == *target || job.base_id == *target)
                    .map(|job| job.id.clone()),
            );
        }
    }
    if retained.is_empty() {
        return Err(CompileError::semantic(
            "selected_job",
            format!("workflow has no job named `{selected}`"),
        ));
    }
    let mut pending = retained.iter().cloned().collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        for dependency in &by_id[id.as_str()].needs {
            if retained.insert(dependency.clone()) {
                pending.push(dependency.clone());
            }
        }
    }
    Ok(jobs
        .into_iter()
        .filter(|job| retained.contains(&job.id))
        .collect())
}

pub(crate) fn project_event_context(
    event: &Value,
    jobs: &[ir::PlannedJob],
) -> Result<BTreeMap<String, ir::ScalarValue>, CompileError> {
    let mut references = BTreeSet::new();
    for job in jobs {
        collect_expression_event_references(job.condition.as_deref(), &mut references)?;
        for service in &job.services {
            for binding in service.environment.values() {
                collect_binding_event_reference(binding, &mut references);
            }
        }
        for step in &job.steps {
            collect_expression_event_references(step.condition.as_deref(), &mut references)?;
            for binding in step.environment.values().chain(step.inputs.values()) {
                collect_binding_event_reference(binding, &mut references);
            }
            if let ir::StepAction::Command { args, .. } = &step.action {
                for binding in args {
                    collect_binding_event_reference(binding, &mut references);
                }
            }
        }
    }

    references
        .into_iter()
        .map(|path| {
            let value = lookup_event_value(event, &path).ok_or_else(|| {
                CompileError::semantic(
                    "event",
                    format!("workflow references unavailable event value `{path}`"),
                )
            })?;
            Ok((path.clone(), event_scalar(value, &path)?))
        })
        .collect()
}

pub(crate) fn collect_expression_event_references(
    condition: Option<&str>,
    references: &mut BTreeSet<String>,
) -> Result<(), CompileError> {
    let Some(condition) = condition else {
        return Ok(());
    };
    let expression = Expression::parse(condition).map_err(|error| {
        CompileError::semantic("condition", format!("invalid typed expression: {error}"))
    })?;
    references.extend(
        expression
            .context_references()
            .into_iter()
            .filter(|path| path == "event" || path.starts_with("event.")),
    );
    Ok(())
}

pub(crate) fn collect_binding_event_reference(
    binding: &ir::ValueBinding,
    references: &mut BTreeSet<String>,
) {
    if let ir::ValueBinding::Context(binding) = binding {
        if binding.from.starts_with("event.") {
            references.insert(binding.from.clone());
        }
    }
}

pub(crate) fn lookup_event_value<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = event;
    let path = path.strip_prefix("event.")?;
    for segment in path.split('.') {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

pub(crate) fn event_scalar(value: &Value, path: &str) -> Result<ir::ScalarValue, CompileError> {
    match value {
        Value::String(value) => Ok(ir::ScalarValue::String(value.clone())),
        Value::Bool(value) => Ok(ir::ScalarValue::Boolean(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(ir::ScalarValue::Integer(value))
            } else if value.as_u64().is_some() {
                Err(CompileError::semantic(
                    path,
                    "event integer is outside the supported signed 64-bit range",
                ))
            } else {
                value
                    .as_f64()
                    .map(|value| ir::ScalarValue::Number(if value == 0.0 { 0.0 } else { value }))
                    .ok_or_else(|| CompileError::semantic(path, "event number is not finite"))
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => Err(CompileError::semantic(
            path,
            "event bindings and conditions require a scalar value",
        )),
    }
}
use crate::{
    ast, convert_permissions, intersect_permissions, ir, BTreeMap, BTreeSet, CompileError,
    Expression, ReusableContextMappings, ReusableOutputTarget, Value,
};
