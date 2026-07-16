//! Resolution of signed value bindings into inert executor inputs.

use crate::{EngineError, RuntimeContext};
use runtrue_workflow_ir::ValueBinding;
use std::collections::BTreeMap;

pub(crate) fn resolve_bindings(
    bindings: &BTreeMap<String, ValueBinding>,
    context: &RuntimeContext,
) -> Result<BTreeMap<String, String>, EngineError> {
    bindings
        .iter()
        .map(|(name, binding)| resolve_binding(binding, context).map(|value| (name.clone(), value)))
        .collect()
}

pub(crate) fn resolve_binding(
    binding: &ValueBinding,
    context: &RuntimeContext,
) -> Result<String, EngineError> {
    match binding {
        ValueBinding::Literal(value) => Ok(value.to_string()),
        ValueBinding::Context(binding) => context
            .get(&binding.from)
            .map(ToString::to_string)
            .ok_or_else(|| EngineError::MissingContextValue {
                path: binding.from.clone(),
            }),
    }
}

pub(crate) fn validate_environment(name: &str, value: &str) -> Result<(), EngineError> {
    if !is_valid_environment_name(name) {
        return Err(EngineError::InvalidEnvironmentName(name.to_owned()));
    }
    if value.contains('\0') {
        return Err(EngineError::InvalidEnvironmentValue(name.to_owned()));
    }
    Ok(())
}

pub(crate) fn is_valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
