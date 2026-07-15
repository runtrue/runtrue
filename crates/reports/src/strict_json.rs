#[derive(Debug, Clone, PartialEq)]
pub(crate) enum StrictJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

struct StrictJsonSeed<'a> {
    limits: ReportLimits,
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = StrictJson;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        *self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| D::Error::custom("report complexity limit exceeded"))?;
        if *self.nodes > self.limits.max_events || self.depth > self.limits.max_depth {
            return Err(D::Error::custom("report complexity limit exceeded"));
        }

        deserializer.deserialize_any(StrictJsonVisitor {
            limits: self.limits,
            depth: self.depth,
            nodes: self.nodes,
        })
    }
}

struct StrictJsonVisitor<'a> {
    limits: ReportLimits,
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value with unique object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictJson::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.limits.max_string_bytes || value.contains('\0') {
            return Err(E::custom("report string limit exceeded"));
        }
        Ok(StrictJson::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= self.limits.max_depth {
            return Err(A::Error::custom("report depth limit exceeded"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            limits: self.limits,
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            if values.len() >= self.limits.max_events {
                return Err(A::Error::custom("report complexity limit exceeded"));
            }
            values.push(value);
        }
        Ok(StrictJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= self.limits.max_depth {
            return Err(A::Error::custom("report depth limit exceeded"));
        }
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.limits.max_string_bytes || key.contains('\0') {
                return Err(A::Error::custom("report string limit exceeded"));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "RUNTRUE_DUPLICATE_JSON_KEY:{key}"
                )));
            }
            let value = map.next_value_seed(StrictJsonSeed {
                limits: self.limits,
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(StrictJson::Object(values))
    }
}

pub(crate) fn parse_strict_json(
    input: &[u8],
    limits: ReportLimits,
) -> Result<StrictJson, ReportError> {
    let mut nodes = 0;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let result = StrictJsonSeed {
        limits,
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut deserializer);
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            let message = error.to_string();
            if let Some(rest) = message.split("RUNTRUE_DUPLICATE_JSON_KEY:").nth(1) {
                let key = rest.split(" at line ").next().unwrap_or(rest).to_owned();
                return Err(ReportError::DuplicateKey(key));
            }
            if message.contains("limit exceeded") || message.contains("recursion limit") {
                return Err(ReportError::ComplexityLimit);
            }
            return Err(ReportError::Malformed("invalid JSON".to_owned()));
        }
    };
    deserializer
        .end()
        .map_err(|_| ReportError::Malformed("trailing JSON data".to_owned()))?;
    Ok(value)
}

impl StrictJson {
    pub(crate) fn object(&self, context: &str) -> Result<&BTreeMap<String, Self>, ReportError> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err(ReportError::Malformed(format!(
                "{context} must be an object"
            ))),
        }
    }

    pub(crate) fn array(&self, context: &str) -> Result<&[Self], ReportError> {
        match self {
            Self::Array(value) => Ok(value),
            _ => Err(ReportError::Malformed(format!(
                "{context} must be an array"
            ))),
        }
    }

    pub(crate) fn string(&self, context: &str) -> Result<&str, ReportError> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(ReportError::Malformed(format!(
                "{context} must be a string"
            ))),
        }
    }

    pub(crate) fn u64(&self, context: &str) -> Result<u64, ReportError> {
        match self {
            Self::Number(value) => value.as_u64().ok_or_else(|| {
                ReportError::Malformed(format!("{context} must be an unsigned integer"))
            }),
            _ => Err(ReportError::Malformed(format!(
                "{context} must be an unsigned integer"
            ))),
        }
    }
}

pub(crate) fn required<'a>(
    object: &'a BTreeMap<String, StrictJson>,
    key: &str,
    context: &str,
) -> Result<&'a StrictJson, ReportError> {
    object
        .get(key)
        .ok_or_else(|| ReportError::Malformed(format!("{context}.{key} is required")))
}

pub(crate) fn reject_unknown(
    object: &BTreeMap<String, StrictJson>,
    allowed: &[&str],
    context: &str,
) -> Result<(), ReportError> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ReportError::Malformed(format!(
            "{context} contains unknown field `{key}`"
        )));
    }
    Ok(())
}

pub(crate) fn safe_path(value: &str) -> Result<String, ReportError> {
    if value.contains(['%', ':', '?', '#']) {
        return Err(ReportError::UnsafePath);
    }
    normalize_relative_path(value).map_err(|_| ReportError::UnsafePath)
}

pub(crate) fn optional_coordinate(
    object: &BTreeMap<String, StrictJson>,
    key: &str,
    context: &str,
) -> Result<Option<u64>, ReportError> {
    object
        .get(key)
        .map(|value| {
            let coordinate = value.u64(&format!("{context}.{key}"))?;
            if coordinate == 0 {
                return Err(ReportError::Malformed(format!(
                    "{context}.{key} must be positive"
                )));
            }
            Ok(coordinate)
        })
        .transpose()
}

pub(crate) fn validate_region(
    start_line: Option<u64>,
    start_column: Option<u64>,
    end_line: Option<u64>,
    end_column: Option<u64>,
    context: &str,
) -> Result<(), ReportError> {
    if (start_column.is_some() || end_line.is_some() || end_column.is_some())
        && start_line.is_none()
    {
        return Err(ReportError::Malformed(format!(
            "{context} coordinates require start_line"
        )));
    }
    if end_column.is_some() && end_line.is_none() {
        return Err(ReportError::Malformed(format!(
            "{context}.end_column requires end_line"
        )));
    }
    if let (Some(start), Some(end)) = (start_line, end_line) {
        if end < start {
            return Err(ReportError::Malformed(format!(
                "{context} region ends before it starts"
            )));
        }
        if end == start {
            if let (Some(start_column), Some(end_column)) = (start_column, end_column) {
                if end_column < start_column {
                    return Err(ReportError::Malformed(format!(
                        "{context} region ends before it starts"
                    )));
                }
            }
        }
    }
    Ok(())
}
use crate::{limits::ReportLimits, ReportError};
use runtrue_model::normalize_relative_path;
use serde::{
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use std::{collections::BTreeMap, fmt};

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn every_json_format_rejects_duplicate_keys() {
        let duplicate = br#"{"lines":{"covered":1,"covered":2,"total":2}}"#;
        assert!(matches!(
            ingest(
                ReportFormat::CoverageSummary,
                duplicate,
                ReportLimits::default()
            ),
            Err(ReportError::DuplicateKey(key)) if key == "covered"
        ));
    }
}
