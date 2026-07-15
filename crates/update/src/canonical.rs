pub fn decode_root(bytes: &[u8]) -> Result<SignedEnvelope<RootMetadata>, UpdateError> {
    let root: SignedEnvelope<RootMetadata> = decode_canonical(bytes, MAX_METADATA_BYTES)?;
    root.signed.validate_structure()?;
    Ok(root)
}

pub fn root_envelope_digest(
    root: &SignedEnvelope<RootMetadata>,
) -> Result<ContentDigest, UpdateError> {
    Ok(ContentDigest::sha256(canonical_bytes(root)?))
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, UpdateError> {
    let value = serde_json::to_value(value).map_err(UpdateError::Serialize)?;
    let value = canonicalize_value(value);
    let bytes = serde_json::to_vec(&value).map_err(UpdateError::Serialize)?;
    if bytes.len() > MAX_TRUST_STATE_BYTES {
        return Err(UpdateError::MetadataTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, UpdateError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(UpdateError::MetadataTooLarge);
    }
    let value = strict_json::decode(bytes)?;
    let decoded = serde_json::from_value(value).map_err(UpdateError::Deserialize)?;
    let canonical = canonical_bytes(&decoded)?;
    if canonical != bytes {
        return Err(UpdateError::NonCanonicalMetadata);
    }
    Ok(decoded)
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

pub(crate) fn signature_message<T: Serialize>(
    role: RoleType,
    signed: &T,
) -> Result<Vec<u8>, UpdateError> {
    let canonical = canonical_bytes(signed)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len() + 16);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(role.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(message)
}
use crate::{
    strict_json, RoleType, RootMetadata, SignedEnvelope, UpdateError, MAX_METADATA_BYTES,
    MAX_TRUST_STATE_BYTES, SIGNATURE_DOMAIN,
};
use runtrue_model::ContentDigest;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
