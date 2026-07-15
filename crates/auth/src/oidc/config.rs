use crate::AuthError;

pub const MAX_OIDC_TRANSACTION_TTL_MS: u64 = 10 * 60 * 1000;
pub const MAX_OIDC_BINDING_BYTES: usize = 2048;

pub(crate) fn validate_oidc_bindings(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), AuthError> {
    for (name, value) in [
        ("OIDC issuer", issuer),
        ("OIDC client id", client_id),
        ("OIDC redirect URI", redirect_uri),
    ] {
        if value.is_empty()
            || value.len() > MAX_OIDC_BINDING_BYTES
            || value.bytes().any(|byte| byte.is_ascii_control())
            || value.chars().any(char::is_whitespace)
        {
            return Err(AuthError::InvalidIdentifier(name));
        }
    }
    if !valid_https_uri_shape(issuer, false) || !valid_https_uri_shape(redirect_uri, true) {
        return Err(AuthError::InsecureOidcBinding);
    }
    Ok(())
}

/// Reject obviously malformed or ambiguous URI forms without pretending to be
/// the configured adapter's standards-compliant URL parser.
fn valid_https_uri_shape(value: &str, allow_query: bool) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('\\')
        || rest.contains('@')
        || rest.contains('#')
        || (!allow_query && rest.contains('?'))
    {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.starts_with('.')
        || authority.ends_with('.')
        || authority.ends_with(':')
    {
        return false;
    }
    if let Some(port) = authority
        .rsplit_once(':')
        .and_then(|(host, port)| (!host.contains(':') && !port.is_empty()).then_some(port))
    {
        if !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    true
}
