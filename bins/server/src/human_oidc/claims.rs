use crate::human_oidc::{
    HumanOidcError, VerifiedHumanIdentity, ID_TOKEN_CLOCK_SKEW_SECONDS,
    MAX_ID_TOKEN_LIFETIME_SECONDS,
};
use runtrue_control_plane::TenantOidcProviderConfiguration;
use runtrue_model::ContentDigest;
use serde_json::Value;
use zeroize::Zeroize as _;

pub(super) fn validate_claims(
    claims: Value,
    provider: &TenantOidcProviderConfiguration,
    now_unix_seconds: u64,
) -> Result<VerifiedHumanIdentity, HumanOidcError> {
    let object = claims
        .as_object()
        .ok_or(HumanOidcError::InvalidIdTokenClaims)?;
    let issuer = required_claim_text(object.get("iss"), 2048)?;
    let subject = required_claim_text(object.get("sub"), 2048)?;
    let nonce = required_claim_text(object.get("nonce"), 1024)?;
    let issued_at = required_claim_u64(object.get("iat"))?;
    let expires_at = required_claim_u64(object.get("exp"))?;
    let not_before = object
        .get("nbf")
        .map(|value| required_claim_u64(Some(value)))
        .transpose()?;
    if issuer != provider.issuer
        || issued_at > now_unix_seconds.saturating_add(ID_TOKEN_CLOCK_SKEW_SECONDS)
        || expires_at <= now_unix_seconds
        || expires_at
            .checked_sub(issued_at)
            .filter(|lifetime| *lifetime != 0 && *lifetime <= MAX_ID_TOKEN_LIFETIME_SECONDS)
            .is_none()
        || not_before.is_some_and(|value| {
            value > now_unix_seconds.saturating_add(ID_TOKEN_CLOCK_SKEW_SECONDS)
        })
        || !audience_matches(object, &provider.client_id)?
    {
        return Err(HumanOidcError::InvalidIdTokenClaims);
    }
    let claims_bytes = serde_json::to_vec(&claims).map_err(|_| HumanOidcError::InvalidIdToken)?;
    let mut digest_material = Vec::with_capacity(claims_bytes.len() + 32);
    digest_material.extend_from_slice(b"runtrue.human-oidc-claims.v1\0");
    digest_material.extend_from_slice(&claims_bytes);
    let claims_digest = ContentDigest::sha256(&digest_material);
    digest_material.zeroize();
    Ok(VerifiedHumanIdentity {
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
        nonce: nonce.to_owned(),
        display_name: optional_claim_text(object.get("name"), 1024)?.map(str::to_owned),
        email: optional_claim_text(object.get("email"), 320)?.map(str::to_owned),
        claims_digest,
        mfa_authenticated: mfa_claim_satisfied(&provider.mfa_claim, object)?,
    })
}

fn audience_matches(
    claims: &serde_json::Map<String, Value>,
    client_id: &str,
) -> Result<bool, HumanOidcError> {
    let audience = claims
        .get("aud")
        .ok_or(HumanOidcError::InvalidIdTokenClaims)?;
    match audience {
        Value::String(value) => Ok(value == client_id),
        Value::Array(values) if !values.is_empty() && values.len() <= 8 => {
            let exact = values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or(HumanOidcError::InvalidIdTokenClaims)?;
            if !exact.contains(&client_id) {
                return Ok(false);
            }
            Ok(exact.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => Err(HumanOidcError::InvalidIdTokenClaims),
    }
}

fn mfa_claim_satisfied(
    configuration: &Value,
    claims: &serde_json::Map<String, Value>,
) -> Result<bool, HumanOidcError> {
    if configuration.is_null() {
        return Ok(false);
    }
    let configuration = configuration
        .as_object()
        .ok_or(HumanOidcError::InvalidMfaClaimConfiguration)?;
    if configuration.len() != 2 {
        return Err(HumanOidcError::InvalidMfaClaimConfiguration);
    }
    let claim = required_claim_text(configuration.get("claim"), 128)?;
    let expected = required_claim_text(configuration.get("value"), 256)?;
    match claims.get(claim) {
        Some(Value::String(actual)) => Ok(actual == expected),
        Some(Value::Array(values)) if values.len() <= 32 => Ok(values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or(HumanOidcError::InvalidIdTokenClaims)?
            .contains(&expected)),
        Some(_) => Err(HumanOidcError::InvalidIdTokenClaims),
        None => Ok(false),
    }
}

fn required_claim_text(value: Option<&Value>, maximum: usize) -> Result<&str, HumanOidcError> {
    optional_claim_text(value, maximum)?.ok_or(HumanOidcError::InvalidIdTokenClaims)
}

fn optional_claim_text(
    value: Option<&Value>,
    maximum: usize,
) -> Result<Option<&str>, HumanOidcError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(HumanOidcError::InvalidIdTokenClaims)?;
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(HumanOidcError::InvalidIdTokenClaims);
    }
    Ok(Some(value))
}

fn required_claim_u64(value: Option<&Value>) -> Result<u64, HumanOidcError> {
    value
        .and_then(Value::as_u64)
        .ok_or(HumanOidcError::InvalidIdTokenClaims)
}
