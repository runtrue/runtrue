use crate::ExecutionModelError;
use runtrue_model::normalize_relative_path;
use std::collections::BTreeSet;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 512;
pub(crate) const MAX_TEXT_BYTES: usize = 8 * 1024;
pub(crate) const MAX_COLLECTION_ENTRIES: usize = 1024;
pub(crate) const MAX_ARGUMENTS: usize = 4096;

pub(crate) fn schema(
    field: &'static str,
    actual: u32,
    expected: u32,
) -> Result<(), ExecutionModelError> {
    if actual != expected {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "unsupported schema version",
        });
    }
    Ok(())
}

pub(crate) fn identifier(field: &'static str, value: &str) -> Result<(), ExecutionModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value == "*"
    {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "must be non-empty, bounded, control-free, and exact",
        });
    }
    Ok(())
}

pub(crate) fn text(field: &'static str, value: &str) -> Result<(), ExecutionModelError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "must be non-empty, bounded, and control-free",
        });
    }
    Ok(())
}

pub(crate) fn argument(field: &'static str, value: &str) -> Result<(), ExecutionModelError> {
    if value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "must be bounded UTF-8 without a NUL byte",
        });
    }
    Ok(())
}

pub(crate) fn identifiers(
    field: &'static str,
    values: &BTreeSet<String>,
    require_nonempty: bool,
) -> Result<(), ExecutionModelError> {
    bounded(field, values.len(), MAX_COLLECTION_ENTRIES)?;
    if require_nonempty && values.is_empty() {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "must contain at least one exact member",
        });
    }
    for value in values {
        identifier(field, value)?;
    }
    Ok(())
}

pub(crate) fn bounded(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ExecutionModelError> {
    if actual > maximum {
        return Err(ExecutionModelError::TooManyEntries { field, maximum });
    }
    Ok(())
}

pub(crate) fn relative_path(field: &'static str, value: &str) -> Result<(), ExecutionModelError> {
    let normalized =
        normalize_relative_path(value).map_err(|_| ExecutionModelError::InvalidField {
            field,
            reason: "must be a normalized relative path",
        })?;
    if normalized != value {
        return Err(ExecutionModelError::InvalidField {
            field,
            reason: "must already be normalized",
        });
    }
    Ok(())
}
