use base64ct::{Base64UrlUnpadded, Encoding as _};
use runtrue_model::ContentDigest;

use crate::{
    token::JwtHeader,
    validation::{validate_claims, validate_identifier, validate_issuer},
    JwkSet, JwtClaims, OidcError, OidcGrant, OidcVerifyingKey, JWT_ALGORITHM, JWT_TYPE,
    MAX_TOKEN_BYTES,
};

pub fn verify_token(
    token: &str,
    key: &OidcVerifyingKey,
    expected_issuer: &str,
    expected_grant: &OidcGrant,
    expected_audience: &str,
    now_unix_seconds: u64,
) -> Result<JwtClaims, OidcError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(OidcError::TokenTooLarge);
    }
    validate_issuer(expected_issuer)?;
    expected_grant.validate()?;
    validate_identifier("OIDC audience", expected_audience)?;
    let mut parts = token.split('.');
    let header_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    let claims_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    let signature_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    if parts.next().is_some()
        || header_encoded.is_empty()
        || claims_encoded.is_empty()
        || signature_encoded.is_empty()
    {
        return Err(OidcError::MalformedToken);
    }
    let header_bytes = Base64UrlUnpadded::decode_vec(header_encoded)?;
    let claims_bytes = Base64UrlUnpadded::decode_vec(claims_encoded)?;
    let signature_bytes = Base64UrlUnpadded::decode_vec(signature_encoded)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)?;
    if header.algorithm != JWT_ALGORITHM
        || header.token_type != JWT_TYPE
        || header.key_id != key.key_id().to_string()
    {
        return Err(OidcError::InvalidHeader);
    }
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| OidcError::InvalidSignatureLength(bytes.len()))?;
    let signing_input = format!("{header_encoded}.{claims_encoded}");
    key.verify(signing_input.as_bytes(), &signature_bytes)
        .map_err(OidcError::InvalidSignature)?;
    let claims: JwtClaims = serde_json::from_slice(&claims_bytes)?;
    validate_claims(
        &claims,
        expected_issuer,
        expected_grant,
        expected_audience,
        now_unix_seconds,
    )?;
    Ok(claims)
}

pub(crate) fn token_key_id(token: &str) -> Result<ContentDigest, OidcError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(OidcError::TokenTooLarge);
    }
    let mut parts = token.split('.');
    let header_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    let claims_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    let signature_encoded = parts.next().ok_or(OidcError::MalformedToken)?;
    if parts.next().is_some()
        || header_encoded.is_empty()
        || claims_encoded.is_empty()
        || signature_encoded.is_empty()
    {
        return Err(OidcError::MalformedToken);
    }
    let header_bytes = Base64UrlUnpadded::decode_vec(header_encoded)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)?;
    if header.algorithm != JWT_ALGORITHM || header.token_type != JWT_TYPE {
        return Err(OidcError::InvalidHeader);
    }
    ContentDigest::parse(header.key_id).map_err(|_| OidcError::InvalidHeader)
}

/// Verify a token by selecting its exact signing key from a strictly validated
/// JWKS document.
pub fn verify_token_with_jwks(
    token: &str,
    jwks: &JwkSet,
    expected_issuer: &str,
    expected_grant: &OidcGrant,
    expected_audience: &str,
    now_unix_seconds: u64,
) -> Result<JwtClaims, OidcError> {
    let key_id = token_key_id(token)?;
    let key = jwks.verifying_key(&key_id)?;
    verify_token(
        token,
        &key,
        expected_issuer,
        expected_grant,
        expected_audience,
        now_unix_seconds,
    )
}
