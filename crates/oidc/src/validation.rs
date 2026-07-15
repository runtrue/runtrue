use crate::{JwtClaims, OidcError, OidcGrant, MAX_IDENTIFIER_BYTES, MAX_TOKEN_TTL_SECONDS};

pub(crate) fn validate_claims(
    claims: &JwtClaims,
    issuer: &str,
    grant: &OidcGrant,
    audience: &str,
    now: u64,
) -> Result<(), OidcError> {
    if claims.issuer != issuer
        || claims.audience != audience
        || !grant.allowed_audiences.contains(audience)
    {
        return Err(OidcError::ClaimMismatch);
    }
    if claims.issued_unix_seconds > now
        || claims.not_before_unix_seconds > now
        || claims.expires_unix_seconds <= now
        || claims.expires_unix_seconds > grant.expires_unix_seconds
        || claims.not_before_unix_seconds != claims.issued_unix_seconds
    {
        return Err(OidcError::TokenExpiredOrNotYetValid);
    }
    if claims
        .expires_unix_seconds
        .checked_sub(claims.issued_unix_seconds)
        .filter(|ttl| *ttl != 0 && *ttl <= MAX_TOKEN_TTL_SECONDS)
        .is_none()
    {
        return Err(OidcError::InvalidTokenLifetime);
    }
    let expected = JwtClaims::from_grant(
        issuer,
        grant,
        audience.to_owned(),
        claims.issued_unix_seconds,
        claims.expires_unix_seconds,
        claims.jti.clone(),
    );
    if &expected != claims {
        return Err(OidcError::ClaimMismatch);
    }
    validate_identifier("JWT id", &claims.jti)?;
    Ok(())
}

pub(crate) fn validate_issuer(issuer: &str) -> Result<(), OidcError> {
    validate_identifier("OIDC issuer", issuer)?;
    let (secure, remainder) = if let Some(remainder) = issuer.strip_prefix("https://") {
        (true, remainder)
    } else if let Some(remainder) = issuer.strip_prefix("http://") {
        (false, remainder)
    } else {
        return Err(OidcError::InvalidIssuer);
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
        || (!secure && !is_loopback_authority(authority))
        || issuer.ends_with('/')
        || issuer.contains('#')
        || issuer.contains('?')
    {
        return Err(OidcError::InvalidIssuer);
    }
    Ok(())
}

fn is_loopback_authority(authority: &str) -> bool {
    ["localhost", "127.0.0.1", "[::1]"].iter().any(|host| {
        authority == *host
            || authority
                .strip_prefix(*host)
                .and_then(|suffix| suffix.strip_prefix(':'))
                .is_some_and(valid_port)
    })
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|value| value != 0)
}

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> Result<(), OidcError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(OidcError::InvalidIdentifier(kind));
    }
    Ok(())
}
