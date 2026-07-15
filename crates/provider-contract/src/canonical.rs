use crate::ProviderContractError;
use runtrue_model::ContentDigest;
use serde::Serialize;
use serde_json::{Map, Value};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 512;
pub(crate) const MAX_SHORT_TEXT_BYTES: usize = 4 * 1024;
pub(crate) const MAX_COLLECTION_ITEMS: usize = 16_384;

pub(crate) fn canonical_bytes<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, ProviderContractError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonicalize(value))?)
}

pub(crate) fn canonical_digest<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, ProviderContractError> {
    let canonical = canonical_bytes(value)?;
    let mut material = Vec::with_capacity(domain.len() + canonical.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(&canonical);
    Ok(ContentDigest::sha256(material))
}

pub(crate) fn validate_identifier(
    kind: &'static str,
    value: &str,
) -> Result<(), ProviderContractError> {
    validate_text(kind, value, MAX_IDENTIFIER_BYTES)
}

pub(crate) fn validate_text(
    kind: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProviderContractError> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderContractError::InvalidText(kind));
    }
    Ok(())
}

pub(crate) fn validate_profile_name(value: &str) -> Result<(), ProviderContractError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
    {
        return Err(ProviderContractError::InvalidText("feature profile name"));
    }
    Ok(())
}

pub(crate) fn validate_collection_size(length: usize) -> Result<(), ProviderContractError> {
    if length > MAX_COLLECTION_ITEMS {
        return Err(ProviderContractError::CollectionLimit);
    }
    Ok(())
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        value => value,
    }
}
