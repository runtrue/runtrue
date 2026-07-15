use crate::human_oidc::{
    claims::validate_claims, network::decode_bounded, HumanOidcError, VerifiedHumanIdentity,
    MAX_HUMAN_JWKS_KEYS, MAX_ID_TOKEN_BYTES,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use runtrue_control_plane::TenantOidcProviderConfiguration;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdTokenHeader {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HumanJwks {
    keys: Vec<HumanJwk>,
}

#[derive(Debug, Deserialize)]
struct HumanJwk {
    kty: String,
    kid: String,
    crv: String,
    alg: String,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    x: String,
}

pub(super) fn verify_id_token(
    token: &str,
    jwks_bytes: &[u8],
    provider: &TenantOidcProviderConfiguration,
    now_unix_seconds: u64,
) -> Result<VerifiedHumanIdentity, HumanOidcError> {
    let mut parts = token.split('.');
    let header_encoded = parts.next().ok_or(HumanOidcError::InvalidIdToken)?;
    let claims_encoded = parts.next().ok_or(HumanOidcError::InvalidIdToken)?;
    let signature_encoded = parts.next().ok_or(HumanOidcError::InvalidIdToken)?;
    if parts.next().is_some()
        || header_encoded.is_empty()
        || claims_encoded.is_empty()
        || signature_encoded.is_empty()
    {
        return Err(HumanOidcError::InvalidIdToken);
    }
    let header_bytes = decode_bounded(header_encoded, 4096)?;
    let claims_bytes = decode_bounded(claims_encoded, MAX_ID_TOKEN_BYTES)?;
    let signature_bytes = decode_bounded(signature_encoded, 128)?;
    let header: IdTokenHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| HumanOidcError::InvalidIdToken)?;
    if header.alg != "EdDSA"
        || header.kid.is_empty()
        || header.kid.len() > 512
        || header.typ.as_deref().is_some_and(|value| value != "JWT")
    {
        return Err(HumanOidcError::UnsupportedIdTokenAlgorithm);
    }

    let jwks: HumanJwks =
        serde_json::from_slice(jwks_bytes).map_err(|_| HumanOidcError::InvalidJwks)?;
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_HUMAN_JWKS_KEYS {
        return Err(HumanOidcError::InvalidJwks);
    }
    let mut key_ids = BTreeSet::new();
    let mut selected = None;
    for key in &jwks.keys {
        if key.kid.is_empty()
            || key.kid.len() > 512
            || !key_ids.insert(key.kid.as_str())
            || key.kty != "OKP"
            || key.crv != "Ed25519"
            || key.alg != "EdDSA"
            || key.usage.as_deref().is_some_and(|usage| usage != "sig")
        {
            return Err(HumanOidcError::InvalidJwks);
        }
        if key.kid == header.kid {
            selected = Some(key);
        }
    }
    let key = selected.ok_or(HumanOidcError::UnknownSigningKey)?;
    let public_key: [u8; 32] = Base64UrlUnpadded::decode_vec(&key.x)
        .map_err(|_| HumanOidcError::InvalidJwks)?
        .try_into()
        .map_err(|_| HumanOidcError::InvalidJwks)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| HumanOidcError::InvalidIdToken)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| HumanOidcError::InvalidJwks)?;
    verifying_key
        .verify(
            format!("{header_encoded}.{claims_encoded}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| HumanOidcError::InvalidIdTokenSignature)?;

    let claims: Value =
        serde_json::from_slice(&claims_bytes).map_err(|_| HumanOidcError::InvalidIdToken)?;
    validate_claims(claims, provider, now_unix_seconds)
}
