pub(crate) fn validate_exact_image_reference(reference: &str) -> Result<ContentDigest, OciError> {
    validate_bounded_text("image reference", reference, 4096, false)?;
    if reference.contains("//") || reference.contains(',') {
        return Err(OciError::InvalidImageReference(
            "transport prefixes and comma-separated references are forbidden".to_owned(),
        ));
    }
    let mut parts = reference.split('@');
    let repository = parts.next().unwrap_or_default();
    let digest = parts.next().unwrap_or_default();
    if repository.is_empty() || digest.is_empty() || parts.next().is_some() {
        return Err(OciError::InvalidImageReference(
            "image must be exactly repository@sha256:<64 lowercase hex>".to_owned(),
        ));
    }
    let final_component = repository.rsplit('/').next().unwrap_or_default();
    if final_component.is_empty() || final_component.contains(':') {
        return Err(OciError::InvalidImageReference(
            "tags are forbidden at execution; use a digest-only reference".to_owned(),
        ));
    }
    ContentDigest::parse(digest.to_owned()).map_err(|_| {
        OciError::InvalidImageReference(
            "image digest must be a complete lowercase SHA-256 pin".to_owned(),
        )
    })
}

pub(crate) fn validate_locked_image(image: &LockedImage) -> Result<(), OciError> {
    let digest = validate_exact_image_reference(&image.reference)?;
    if digest != image.digest {
        return Err(OciError::InvalidImageReference(
            "stored image digest does not match its reference".to_owned(),
        ));
    }
    validate_bounded_text("signature identity", &image.signature_identity, 1024, false)
}

pub(crate) fn validate_bounded_text(
    kind: &'static str,
    value: &str,
    max_bytes: usize,
    allow_whitespace: bool,
) -> Result<(), OciError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || (!allow_whitespace && value.chars().any(char::is_whitespace))
    {
        return Err(OciError::InvalidRequest(format!(
            "{kind} is empty, oversized, or contains forbidden characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_container_path(path: &str) -> Result<(), OciError> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.len() > 4096
        || path.contains(',')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(OciError::ForbiddenMount(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn mount_argument(
    source: &Path,
    destination: &str,
    read_only: bool,
) -> Result<String, OciError> {
    validate_container_path(destination)?;
    let source = utf8_path(source, "mount source")?;
    if source.contains(',') {
        return Err(OciError::ForbiddenMount(source.to_owned()));
    }
    Ok(format!(
        "--mount=type=bind,src={source},dst={destination},{},bind-propagation=private,nosuid,nodev",
        if read_only { "ro" } else { "rw" }
    ))
}

pub(crate) fn validate_working_directory(path: Option<&str>) -> Result<(), OciError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || path.contains('\\')
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(OciError::UnsafeWorkingDirectory(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_command(
    program: &str,
    arguments: &[String],
    limits: OciLimits,
) -> Result<(), OciError> {
    if program.is_empty() || program.contains('\0') || program.len() > limits.max_argument_bytes {
        return Err(OciError::InvalidCommand(
            "program is empty, contains NUL, or exceeds its bound".to_owned(),
        ));
    }
    if arguments.len() > limits.max_arguments {
        return Err(OciError::LimitExceeded {
            kind: "command argument count",
            limit: limits.max_arguments,
            actual: arguments.len(),
        });
    }
    let mut bytes = program.len();
    for argument in arguments {
        if argument.contains('\0') {
            return Err(OciError::InvalidCommand(
                "command argument contains a NUL byte".to_owned(),
            ));
        }
        bytes = bytes
            .checked_add(argument.len())
            .ok_or(OciError::LimitExceeded {
                kind: "command argument bytes",
                limit: limits.max_argument_bytes,
                actual: usize::MAX,
            })?;
    }
    if bytes > limits.max_argument_bytes {
        return Err(OciError::LimitExceeded {
            kind: "command argument bytes",
            limit: limits.max_argument_bytes,
            actual: bytes,
        });
    }
    Ok(())
}

pub(crate) fn validate_argument_bounds(
    arguments: &[String],
    limits: OciLimits,
) -> Result<(), OciError> {
    if arguments.len() > limits.max_arguments.saturating_add(128) {
        return Err(OciError::LimitExceeded {
            kind: "runtime argument count",
            limit: limits.max_arguments.saturating_add(128),
            actual: arguments.len(),
        });
    }
    let total = arguments.iter().try_fold(0_usize, |total, argument| {
        if argument.contains('\0') {
            return Err(OciError::InvalidCommand(
                "runtime argument contains NUL".to_owned(),
            ));
        }
        total
            .checked_add(argument.len())
            .ok_or(OciError::LimitExceeded {
                kind: "runtime argument bytes",
                limit: limits.max_argument_bytes.saturating_add(64 * 1024),
                actual: usize::MAX,
            })
    })?;
    let limit = limits.max_argument_bytes.saturating_add(64 * 1024);
    if total > limit {
        return Err(OciError::LimitExceeded {
            kind: "runtime argument bytes",
            limit,
            actual: total,
        });
    }
    Ok(())
}

pub(crate) fn ensure_secure_runtime_arguments(
    arguments: &[String],
    exact_image: &str,
    network: Option<&str>,
    program: &str,
) -> Result<(), OciError> {
    for required in [
        "--pull=never",
        "--userns=keep-id",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--pid=private",
        "--ipc=private",
        "--ulimit=core=0:0",
    ] {
        if !arguments.iter().any(|argument| argument == required) {
            return Err(OciError::InvalidConfiguration(format!(
                "required runtime control `{required}` is absent"
            )));
        }
    }
    if arguments
        .iter()
        .filter(|argument| argument.starts_with("--user="))
        .count()
        != 1
    {
        return Err(OciError::InvalidConfiguration(
            "runtime must explicitly use the rootless runner uid and gid".to_owned(),
        ));
    }
    let expected_network = network.map_or_else(
        || "--network=none".to_owned(),
        |network| format!("--network={network}"),
    );
    let expected_entrypoint = format!("--entrypoint={program}");
    if !arguments
        .iter()
        .any(|argument| argument.starts_with("--security-opt=seccomp="))
        || arguments
            .iter()
            .filter(|argument| argument.starts_with("--network="))
            .count()
            != 1
        || !arguments
            .iter()
            .any(|argument| argument == &expected_network)
        || arguments
            .iter()
            .filter(|argument| argument.starts_with("--entrypoint="))
            .count()
            != 1
        || !arguments
            .iter()
            .any(|argument| argument == &expected_entrypoint)
        || arguments.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "--privileged" | "--network=host" | "--pid=host" | "--ipc=host"
            ) || argument.starts_with("--cap-add")
                || argument == "-p"
                || argument.starts_with("--publish")
                || argument.contains("unconfined")
                || FORBIDDEN_SOCKET_NAMES
                    .iter()
                    .any(|socket| argument.contains(socket))
        })
        || arguments
            .iter()
            .filter(|argument| argument.as_str() == exact_image)
            .count()
            != 1
    {
        return Err(OciError::InvalidConfiguration(
            "runtime arguments weaken isolation or expose a host socket".to_owned(),
        ));
    }
    validate_exact_image_reference(exact_image)?;
    Ok(())
}

pub(crate) fn ensure_secure_service_arguments(
    arguments: &[String],
    exact_image: &str,
    network: &str,
    service_id: &str,
) -> Result<(), OciError> {
    for required in [
        "--detach",
        "--pull=never",
        "--userns=keep-id",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--pid=private",
        "--ipc=private",
        "--ulimit=core=0:0",
    ] {
        if !arguments.iter().any(|argument| argument == required) {
            return Err(OciError::InvalidConfiguration(format!(
                "required service runtime control `{required}` is absent"
            )));
        }
    }
    if arguments
        .iter()
        .filter(|argument| argument.starts_with("--user="))
        .count()
        != 1
    {
        return Err(OciError::InvalidConfiguration(
            "service runtime must explicitly use the rootless runner uid and gid".to_owned(),
        ));
    }
    let network_argument = format!("--network={network}");
    let alias_argument = format!("--network-alias={service_id}");
    let weakens_isolation = arguments.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--privileged"
                | "--network=host"
                | "--network=none"
                | "--pid=host"
                | "--ipc=host"
                | "-p"
                | "-v"
        ) || argument.starts_with("--cap-add")
            || argument.starts_with("--publish")
            || argument.starts_with("--volume")
            || argument.starts_with("--mount")
            || argument.starts_with("--device")
            || argument.contains("unconfined")
            || FORBIDDEN_SOCKET_NAMES
                .iter()
                .any(|socket| argument.contains(socket))
    });
    if weakens_isolation
        || !arguments
            .iter()
            .any(|argument| argument == &network_argument)
        || arguments
            .iter()
            .filter(|argument| argument.starts_with("--network="))
            .count()
            != 1
        || !arguments.iter().any(|argument| argument == &alias_argument)
        || !arguments
            .iter()
            .any(|argument| argument.starts_with("--security-opt=seccomp="))
        || arguments
            .iter()
            .filter(|argument| argument.as_str() == exact_image)
            .count()
            != 1
    {
        return Err(OciError::InvalidConfiguration(
            "service runtime arguments weaken isolation, publish a port, or expose a host resource"
                .to_owned(),
        ));
    }
    validate_exact_image_reference(exact_image)?;
    Ok(())
}

pub(crate) fn ensure_secure_network_create_arguments(
    arguments: &[String],
    network: &str,
) -> Result<(), OciError> {
    let required = [
        "network",
        "create",
        "--driver=bridge",
        "--internal",
        network,
    ];
    if required
        .iter()
        .any(|required| !arguments.iter().any(|argument| argument == required))
        || arguments.iter().any(|argument| {
            argument.starts_with("--subnet")
                || argument.starts_with("--gateway")
                || argument.starts_with("--route")
                || argument.starts_with("--interface-name")
        })
        || arguments
            .iter()
            .filter(|argument| argument.as_str() == network)
            .count()
            != 1
    {
        return Err(OciError::InvalidConfiguration(
            "private service network arguments are not internally isolated".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_runtime_identifier(kind: &'static str, value: &str) -> Result<(), OciError> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(OciError::InvalidConfiguration(format!(
            "unsafe {kind} identifier `{value}`"
        )));
    }
    Ok(())
}

pub(crate) fn validate_service_dns_name(value: &str) -> Result<(), OciError> {
    validate_runtime_identifier("service DNS", value)?;
    if value.ends_with('-') {
        return Err(OciError::InvalidConfiguration(format!(
            "service DNS identifier `{value}` ends with a hyphen"
        )));
    }
    Ok(())
}

pub(crate) fn validate_healthcheck(
    job_id: &str,
    service_id: &str,
    healthcheck: &Healthcheck,
    limits: OciLimits,
) -> Result<(), OciError> {
    if healthcheck.command.is_empty() {
        return Err(OciError::InvalidConfiguration(format!(
            "service `{job_id}.{service_id}` healthcheck is empty"
        )));
    }
    validate_command(&healthcheck.command[0], &healthcheck.command[1..], limits)?;
    if healthcheck.interval_ms == 0
        || healthcheck.timeout_ms == 0
        || healthcheck.retries == 0
        || healthcheck.retries > limits.max_service_health_retries
    {
        return Err(OciError::InvalidConfiguration(format!(
            "service `{job_id}.{service_id}` healthcheck bounds are invalid"
        )));
    }
    let retries = u128::from(healthcheck.retries);
    let total_ms = u128::from(healthcheck.timeout_ms)
        .checked_mul(retries)
        .and_then(|value| {
            u128::from(healthcheck.interval_ms)
                .checked_mul(retries.saturating_sub(1))
                .and_then(|intervals| value.checked_add(intervals))
        })
        .ok_or_else(|| {
            OciError::InvalidConfiguration(format!(
                "service `{job_id}.{service_id}` healthcheck duration overflows"
            ))
        })?;
    if total_ms > limits.max_service_startup_timeout.as_millis() {
        return Err(OciError::InvalidConfiguration(format!(
            "service `{job_id}.{service_id}` healthcheck exceeds the startup timeout"
        )));
    }
    Ok(())
}
use crate::{
    utf8_path, Component, ContentDigest, Healthcheck, LockedImage, OciError, OciLimits, Path,
    FORBIDDEN_SOCKET_NAMES,
};
