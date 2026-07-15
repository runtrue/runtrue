use crate::SigningError;
use serde::Serialize;
use std::collections::BTreeMap;

pub(crate) const SIGNING_DOMAIN: &[u8] = b"runtrue.signing-operation.v1\0";

pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SigningError> {
    fn canonicalize(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(canonicalize).collect())
            }
            serde_json::Value::Object(values) => {
                let values = values
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect::<BTreeMap<_, _>>();
                serde_json::Value::Object(values.into_iter().collect())
            }
            other => other,
        }
    }

    let value = serde_json::to_value(value).map_err(|_| SigningError::Serialize)?;
    serde_json::to_vec(&canonicalize(value)).map_err(|_| SigningError::Serialize)
}
