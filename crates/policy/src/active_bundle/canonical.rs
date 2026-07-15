use super::{model::MAX_CANONICAL_POLICY_BYTES, ActivePolicyError};
use cedar_policy::PolicySet;
use runtrue_model::ContentDigest;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, str::FromStr as _};
pub(super) fn canonical_policy_json(source: &str) -> Result<String, ActivePolicyError> {
    let policies = PolicySet::from_str(source).map_err(|_| ActivePolicyError::CanonicalPolicy)?;
    let value = policies
        .to_json()
        .map_err(|_| ActivePolicyError::CanonicalPolicy)?;
    let bytes = canonical_bytes(&value)?;
    if bytes.len() > MAX_CANONICAL_POLICY_BYTES {
        return Err(ActivePolicyError::InvalidPolicySource);
    }
    String::from_utf8(bytes).map_err(|_| ActivePolicyError::CanonicalPolicy)
}

pub(super) fn cedar_source_from_canonical_json(json: &str) -> Result<String, ActivePolicyError> {
    let policies =
        PolicySet::from_json_str(json).map_err(|_| ActivePolicyError::CanonicalPolicy)?;
    if policies.templates().next().is_some() {
        return Err(ActivePolicyError::CanonicalPolicy);
    }
    let mut sources = policies
        .policies()
        .map(|policy| (policy.id().to_string(), policy.to_string()))
        .collect::<Vec<_>>();
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(sources
        .into_iter()
        .map(|(_, source)| source)
        .collect::<Vec<_>>()
        .join("\n"))
}
pub(super) fn canonical_bytes(
    value: &(impl Serialize + ?Sized),
) -> Result<Vec<u8>, ActivePolicyError> {
    let value = serde_json::to_value(value).map_err(|_| ActivePolicyError::CanonicalPolicy)?;
    serde_json::to_vec(&canonicalize(value)).map_err(|_| ActivePolicyError::CanonicalPolicy)
}

pub(super) fn canonicalize(value: Value) -> Value {
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

pub(super) fn domain_digest(domain: &[u8], bytes: &[u8]) -> ContentDigest {
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    ContentDigest::sha256(input)
}
