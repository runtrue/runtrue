use crate::AuthError;
use std::collections::BTreeSet;

const MAX_IDENTIFIER_BYTES: usize = 512;
pub(crate) const MAX_SCOPES: usize = 256;

pub(crate) fn require_recent(
    observed: Option<u64>,
    now_unix_ms: u64,
    maximum_age_ms: u64,
    error: AuthError,
) -> Result<(), AuthError> {
    if maximum_age_ms == 0 {
        return Err(error);
    }
    let Some(observed) = observed else {
        return Err(error);
    };
    if observed > now_unix_ms || now_unix_ms - observed > maximum_age_ms {
        return Err(error);
    }
    Ok(())
}

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AuthError::InvalidIdentifier(kind));
    }
    Ok(())
}

pub(crate) fn validate_scopes(scopes: &BTreeSet<String>) -> Result<(), AuthError> {
    if scopes.is_empty() || scopes.len() > MAX_SCOPES {
        return Err(AuthError::InvalidScopes);
    }
    for scope in scopes {
        validate_identifier("token scope", scope)?;
    }
    Ok(())
}
