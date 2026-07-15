#[derive(Clone, Copy)]
pub(crate) enum EnvironmentScope {
    Runtime,
    Container,
}

pub(crate) fn validate_environment(
    environment: &BTreeMap<String, String>,
    limits: OciLimits,
    scope: EnvironmentScope,
) -> Result<(), OciError> {
    if environment.len() > limits.max_environment_variables {
        return Err(OciError::LimitExceeded {
            kind: "environment variable count",
            limit: limits.max_environment_variables,
            actual: environment.len(),
        });
    }
    let mut total = 0_usize;
    for (name, value) in environment {
        if name.is_empty()
            || name.len() > limits.max_environment_name_bytes
            || !name.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            })
        {
            return Err(OciError::InvalidEnvironmentName(name.clone()));
        }
        if FORBIDDEN_SOCKET_ENV.contains(&name.as_str()) {
            return Err(OciError::ForbiddenSocketExposure(format!(
                "environment variable `{name}`"
            )));
        }
        if value.len() > limits.max_environment_value_bytes
            || value.contains('\0')
            || value.contains('\n')
            || value.contains('\r')
        {
            return Err(OciError::InvalidEnvironmentValue(name.clone()));
        }
        if matches!(scope, EnvironmentScope::Runtime)
            && !matches!(
                name.as_str(),
                "HOME" | "PATH" | "XDG_RUNTIME_DIR" | "TMPDIR" | "LANG" | "LC_ALL"
            )
        {
            return Err(OciError::InvalidConfiguration(format!(
                "runtime environment variable `{name}` is not allowlisted"
            )));
        }
        total = total
            .checked_add(name.len().saturating_add(value.len()).saturating_add(2))
            .ok_or(OciError::LimitExceeded {
                kind: "environment bytes",
                limit: limits.max_environment_bytes,
                actual: usize::MAX,
            })?;
    }
    if total > limits.max_environment_bytes {
        return Err(OciError::LimitExceeded {
            kind: "environment bytes",
            limit: limits.max_environment_bytes,
            actual: total,
        });
    }
    Ok(())
}
use crate::{BTreeMap, OciError, OciLimits, FORBIDDEN_SOCKET_ENV};
