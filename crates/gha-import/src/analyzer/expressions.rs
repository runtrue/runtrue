use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;

pub(crate) fn yaml_string_map(value: &YamlValue) -> Option<BTreeMap<String, &YamlValue>> {
    let mapping = value.as_mapping()?;
    let mut result = BTreeMap::new();
    for (key, value) in mapping {
        result.insert(key.as_str()?.to_owned(), value);
    }
    Some(result)
}

pub(crate) fn static_string(value: &YamlValue) -> Option<String> {
    let value = match value {
        YamlValue::String(value) => value.clone(),
        YamlValue::Bool(value) => value.to_string(),
        YamlValue::Number(value) => value.to_string(),
        _ => return None,
    };
    (!has_expression(&value) && !value.contains('\0')).then_some(value)
}

pub(crate) fn static_string_list(value: &YamlValue) -> Option<Vec<String>> {
    if let Some(value) = static_string(value) {
        return Some(vec![value]);
    }
    value
        .as_sequence()?
        .iter()
        .map(static_string)
        .collect::<Option<Vec<_>>>()
}

pub(crate) fn static_runner_labels(value: &YamlValue) -> Option<Vec<String>> {
    static_string_list(value).filter(|labels| !labels.is_empty())
}

pub(crate) fn static_bool(value: &YamlValue) -> Option<bool> {
    value.as_bool().or_else(|| match value.as_str() {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    })
}

pub(crate) fn positive_u64(value: &YamlValue) -> Option<u64> {
    let value = value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))?;
    (value > 0).then_some(value)
}

pub(crate) fn has_expression(value: &str) -> bool {
    value.contains("${{") || value.contains("}}")
}
