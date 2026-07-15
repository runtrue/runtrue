use crate::NetworkError;
use runtrue_workflow_ir::{NetworkDestination, NetworkPermission};

const MAX_IDENTIFIER_BYTES: usize = 1024;

pub(crate) fn validate_policy(policy: &NetworkPermission) -> Result<(), NetworkError> {
    let NetworkPermission::Allow {
        destinations,
        listen,
        ..
    } = policy
    else {
        return Ok(());
    };
    let mut previous_destination: Option<&NetworkDestination> = None;
    for destination in destinations {
        validate_host(&destination.host)?;
        if destination.port == 0 {
            return Err(NetworkError::InvalidPort);
        }
        if previous_destination.is_some_and(|previous| previous >= destination) {
            return Err(NetworkError::NonCanonicalPolicy);
        }
        previous_destination = Some(destination);
    }
    if listen.contains(&0) || listen.windows(2).any(|window| window[0] >= window[1]) {
        return Err(NetworkError::NonCanonicalPolicy);
    }
    Ok(())
}

pub(crate) fn validate_host(host: &str) -> Result<(), NetworkError> {
    if host.is_empty()
        || host.len() > 253
        || host.bytes().any(|byte| byte.is_ascii_control())
        || host != host.to_ascii_lowercase()
    {
        return Err(NetworkError::InvalidHost);
    }
    let value = host.strip_prefix("*.").unwrap_or(host);
    if host == "*"
        || host.matches('*').count() > usize::from(host.starts_with("*."))
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(NetworkError::InvalidHost);
    }
    Ok(())
}

pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.strip_suffix(suffix)
            .is_some_and(|prefix| !prefix.is_empty() && prefix.ends_with('.'))
    } else {
        pattern == host
    }
}

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), NetworkError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(NetworkError::InvalidIdentifier(kind));
    }
    Ok(())
}
