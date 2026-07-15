pub(crate) fn validate_variables(
    variables: &BTreeMap<String, ast::Scalar>,
    path: &str,
) -> Result<(), CompileError> {
    for (name, value) in variables {
        validate_environment_name(name, &format!("{path}.{name}"))?;
        if !value.is_finite() {
            return Err(CompileError::semantic(
                format!("{path}.{name}"),
                "numeric values must be finite",
            ));
        }
    }
    Ok(())
}

pub(crate) fn convert_variables(
    variables: &BTreeMap<String, ast::Scalar>,
    path: &str,
) -> Result<BTreeMap<String, ir::ScalarValue>, CompileError> {
    variables
        .iter()
        .map(|(name, value)| {
            Ok((
                name.clone(),
                convert_scalar(value, &format!("{path}.{name}"))?,
            ))
        })
        .collect()
}

pub(crate) fn convert_scalar(
    value: &ast::Scalar,
    path: &str,
) -> Result<ir::ScalarValue, CompileError> {
    match value {
        ast::Scalar::String(value) if value.contains('\0') => Err(CompileError::semantic(
            path,
            "string values cannot contain NUL bytes",
        )),
        ast::Scalar::String(value) => Ok(ir::ScalarValue::String(value.clone())),
        ast::Scalar::Integer(value) => Ok(ir::ScalarValue::Integer(*value)),
        ast::Scalar::Number(value) if value.is_finite() => {
            Ok(ir::ScalarValue::Number(if *value == 0.0 {
                0.0
            } else {
                *value
            }))
        }
        ast::Scalar::Number(_) => Err(CompileError::semantic(
            path,
            "numeric values must be finite",
        )),
        ast::Scalar::Boolean(value) => Ok(ir::ScalarValue::Boolean(*value)),
    }
}

pub(crate) fn convert_binding(
    value: &ast::ValueBinding,
    path: &str,
) -> Result<ir::ValueBinding, CompileError> {
    match value {
        ast::ValueBinding::Scalar(value) => {
            Ok(ir::ValueBinding::Literal(convert_scalar(value, path)?))
        }
        ast::ValueBinding::Literal(value) => Ok(ir::ValueBinding::Literal(convert_scalar(
            &value.literal,
            path,
        )?)),
        ast::ValueBinding::From(value) => {
            validate_context_path(&value.from, path)?;
            Ok(ir::ValueBinding::Context(ir::ContextBinding {
                from: value.from.clone(),
            }))
        }
    }
}

pub(crate) fn convert_environment_binding(
    _name: &str,
    value: &ast::ValueBinding,
    path: &str,
) -> Result<ir::ValueBinding, CompileError> {
    if matches!(
        value,
        ast::ValueBinding::From(binding) if is_untrusted_context_path(&binding.from)
    ) {
        return Err(CompileError::semantic(
            path,
            "untrusted context values cannot be injected through the process environment; use a typed condition, reviewed workflow vars value, or static matrix value",
        ));
    }
    convert_binding(value, path)
}

pub(crate) fn is_untrusted_context_path(path: &str) -> bool {
    matches!(
        path.split('.').next().unwrap_or_default(),
        "event" | "inputs" | "needs" | "steps" | "git"
    )
}

pub(crate) fn validate_context_path(value: &str, path: &str) -> Result<(), CompileError> {
    let expression =
        Regex::new(r"^(event|matrix|vars|inputs|needs|steps|git)(\.[A-Za-z_][A-Za-z0-9_-]*)+$")
            .expect("static regex");
    if expression.is_match(value) {
        Ok(())
    } else {
        Err(CompileError::semantic(
            path,
            format!("invalid context binding `{value}`"),
        ))
    }
}

pub(crate) fn normalize_pattern(value: &str, path: &str) -> Result<String, CompileError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|segment| segment == "..")
        || value.contains('\0')
    {
        return Err(CompileError::semantic(
            path,
            format!("unsafe repository-relative path pattern `{value}`"),
        ));
    }
    let normalized = value
        .strip_prefix("./")
        .unwrap_or(value)
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        return Err(CompileError::semantic(path, "path pattern cannot be empty"));
    }
    Ok(normalized)
}

pub(crate) fn parse_duration(value: &str, path: &str) -> Result<u64, CompileError> {
    DurationMillis::parse(value)
        .map(|duration| duration.0)
        .map_err(|error| CompileError::model(path, error))
}

pub(crate) fn parse_retention(value: &str, path: &str) -> Result<u64, CompileError> {
    if let Some(days) = value.strip_suffix('d') {
        let days = days
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| CompileError::semantic(path, "retention must be a positive duration"))?;
        days.checked_mul(86_400_000)
            .ok_or_else(|| CompileError::semantic(path, "retention duration overflows"))
    } else {
        parse_duration(value, path)
    }
}

pub(crate) const fn convert_access(value: ast::Access) -> ir::Access {
    match value {
        ast::Access::Deny => ir::Access::Deny,
        ast::Access::Read => ir::Access::Read,
        ast::Access::Write => ir::Access::Write,
    }
}

pub(crate) const fn min_access(left: ir::Access, right: ir::Access) -> ir::Access {
    if (left as u8) < (right as u8) {
        left
    } else {
        right
    }
}

pub(crate) const fn min_dns(left: ir::DnsPolicy, right: ir::DnsPolicy) -> ir::DnsPolicy {
    let left_rank = match left {
        ir::DnsPolicy::Deny => 0,
        ir::DnsPolicy::Restricted => 1,
        ir::DnsPolicy::Allow => 2,
    };
    let right_rank = match right {
        ir::DnsPolicy::Deny => 0,
        ir::DnsPolicy::Restricted => 1,
        ir::DnsPolicy::Allow => 2,
    };
    if left_rank < right_rank {
        left
    } else {
        right
    }
}

pub(crate) fn convert_cache_permissions(
    value: &ast::CachePermissions,
) -> (ir::CacheRead, ir::CacheWrite) {
    (
        match value.read {
            ast::CacheRead::Deny => ir::CacheRead::Deny,
            ast::CacheRead::Public => ir::CacheRead::Public,
            ast::CacheRead::Verified => ir::CacheRead::Verified,
            ast::CacheRead::Branch => ir::CacheRead::Branch,
            ast::CacheRead::Run => ir::CacheRead::Run,
        },
        match value.write {
            ast::CacheWrite::Deny => ir::CacheWrite::Deny,
            ast::CacheWrite::Quarantine => ir::CacheWrite::Quarantine,
            ast::CacheWrite::Branch => ir::CacheWrite::Branch,
            ast::CacheWrite::Verified => ir::CacheWrite::Verified,
        },
    )
}

pub(crate) const fn cache_read_rank(value: ir::CacheRead) -> u8 {
    match value {
        ir::CacheRead::Deny => 0,
        ir::CacheRead::Public => 1,
        ir::CacheRead::Verified => 2,
        ir::CacheRead::Branch => 3,
        ir::CacheRead::Run => 4,
    }
}

pub(crate) const fn min_cache_read(left: ir::CacheRead, right: ir::CacheRead) -> ir::CacheRead {
    if cache_read_rank(left) == cache_read_rank(right) {
        left
    } else {
        ir::CacheRead::Deny
    }
}

pub(crate) const fn cache_write_rank(value: ir::CacheWrite) -> u8 {
    match value {
        ir::CacheWrite::Deny => 0,
        ir::CacheWrite::Quarantine => 1,
        ir::CacheWrite::Branch => 2,
        ir::CacheWrite::Verified => 3,
    }
}

pub(crate) const fn min_cache_write(left: ir::CacheWrite, right: ir::CacheWrite) -> ir::CacheWrite {
    if cache_write_rank(left) == cache_write_rank(right) {
        left
    } else {
        ir::CacheWrite::Deny
    }
}

pub(crate) const fn convert_trust(value: ast::Trust) -> ir::Trust {
    match value {
        ast::Trust::UntrustedOk => ir::Trust::UntrustedOk,
        ast::Trust::TrustedOnly => ir::Trust::TrustedOnly,
        ast::Trust::ProtectedBranchOnly => ir::Trust::ProtectedBranchOnly,
    }
}

pub(crate) const fn convert_os(value: ast::OperatingSystem) -> ir::OperatingSystem {
    match value {
        ast::OperatingSystem::Linux => ir::OperatingSystem::Linux,
        ast::OperatingSystem::Windows => ir::OperatingSystem::Windows,
        ast::OperatingSystem::Macos => ir::OperatingSystem::Macos,
    }
}

pub(crate) const fn convert_arch(value: ast::Architecture) -> ir::Architecture {
    match value {
        ast::Architecture::Amd64 => ir::Architecture::Amd64,
        ast::Architecture::Arm64 => ir::Architecture::Arm64,
    }
}

pub(crate) const fn convert_isolation(value: ast::Isolation) -> ir::Isolation {
    match value {
        ast::Isolation::Wasm => ir::Isolation::Wasm,
        ast::Isolation::Oci => ir::Isolation::Oci,
        ast::Isolation::Microvm => ir::Isolation::Microvm,
        ast::Isolation::Native => ir::Isolation::Native,
    }
}

pub(crate) const fn convert_shell(value: ast::Shell) -> ir::Shell {
    match value {
        ast::Shell::Bash => ir::Shell::Bash,
        ast::Shell::Sh => ir::Shell::Sh,
        ast::Shell::Pwsh => ir::Shell::Pwsh,
        ast::Shell::Cmd => ir::Shell::Cmd,
    }
}

pub(crate) const fn convert_classification(
    value: ast::ArtifactClassification,
) -> ir::ArtifactClassification {
    match value {
        ast::ArtifactClassification::UntrustedBuild => ir::ArtifactClassification::UntrustedBuild,
        ast::ArtifactClassification::Quarantined => ir::ArtifactClassification::Quarantined,
        ast::ArtifactClassification::VerifiedTestOutput => {
            ir::ArtifactClassification::VerifiedTestOutput
        }
        ast::ArtifactClassification::ReleaseCandidate => {
            ir::ArtifactClassification::ReleaseCandidate
        }
        ast::ArtifactClassification::PromotedRelease => ir::ArtifactClassification::PromotedRelease,
        ast::ArtifactClassification::Sensitive => ir::ArtifactClassification::Sensitive,
        ast::ArtifactClassification::Public => ir::ArtifactClassification::Public,
    }
}

pub(crate) const fn convert_step_output_type(value: ast::StepOutputType) -> ir::StepOutputType {
    match value {
        ast::StepOutputType::String => ir::StepOutputType::String,
        ast::StepOutputType::Integer => ir::StepOutputType::Integer,
        ast::StepOutputType::Number => ir::StepOutputType::Number,
        ast::StepOutputType::Boolean => ir::StepOutputType::Boolean,
        ast::StepOutputType::Json => ir::StepOutputType::Json,
        ast::StepOutputType::ArtifactReference => ir::StepOutputType::ArtifactReference,
    }
}
use super::{ast, ir, validate_environment_name, BTreeMap, CompileError, DurationMillis, Regex};
