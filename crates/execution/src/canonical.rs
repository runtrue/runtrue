use crate::ExecutionModelError;
use runtrue_model::ContentDigest;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ExecutionModelError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonicalize(value))?)
}

pub(crate) fn canonical_digest<T: Serialize>(
    value: &T,
) -> Result<ContentDigest, ExecutionModelError> {
    Ok(ContentDigest::sha256(canonical_bytes(value)?))
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(values.into_iter().collect())
        }
        scalar => scalar,
    }
}
