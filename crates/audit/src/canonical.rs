use crate::AuditError;
use runtrue_model::ContentDigest;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn domain_digest(domain: &[u8], bytes: &[u8]) -> ContentDigest {
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    ContentDigest::sha256(input)
}

pub(crate) fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, AuditError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonicalize(value))?)
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value,
    }
}
