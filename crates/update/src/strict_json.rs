use crate::{UpdateError, MAX_METADATA_BYTES, MAX_STRING_BYTES};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, fmt};

const DUPLICATE_MARKER: &str = "runtrue-duplicate-json-key";
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 200_000;

pub(crate) fn decode(bytes: &[u8]) -> Result<Value, UpdateError> {
    let decoded = serde_json::from_slice::<UniqueValue>(bytes).map_err(|error| {
        if error.to_string().contains(DUPLICATE_MARKER) {
            UpdateError::DuplicateJsonKey
        } else {
            UpdateError::Deserialize(error)
        }
    })?;
    let value = decoded.0;
    let mut nodes = 0_usize;
    let mut string_bytes = 0_usize;
    validate_bounds(&value, 0, &mut nodes, &mut string_bytes)?;
    Ok(value)
}

fn validate_bounds(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    string_bytes: &mut usize,
) -> Result<(), UpdateError> {
    if depth > MAX_JSON_DEPTH {
        return Err(UpdateError::JsonBoundsExceeded);
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or(UpdateError::JsonBoundsExceeded)?;
    if *nodes > MAX_JSON_NODES {
        return Err(UpdateError::JsonBoundsExceeded);
    }
    match value {
        Value::String(value) => add_string(value, string_bytes)?,
        Value::Array(values) => {
            for value in values {
                validate_bounds(value, depth + 1, nodes, string_bytes)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                add_string(key, string_bytes)?;
                validate_bounds(value, depth + 1, nodes, string_bytes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn add_string(value: &str, total: &mut usize) -> Result<(), UpdateError> {
    if value.len() > MAX_STRING_BYTES * 4 {
        return Err(UpdateError::JsonBoundsExceeded);
    }
    *total = total
        .checked_add(value.len())
        .ok_or(UpdateError::JsonBoundsExceeded)?;
    if *total > MAX_METADATA_BYTES {
        return Err(UpdateError::JsonBoundsExceeded);
    }
    Ok(())
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(DUPLICATE_MARKER));
            }
            let value = object.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}
