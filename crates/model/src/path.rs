use crate::ModelError;
use std::path::Component;

/// Normalize a repository-relative path without touching the filesystem.
///
/// Symlink-safe resolution is still the executor's responsibility. This helper
/// rejects absolute paths and lexical traversal before a capsule can be produced.
pub fn normalize_relative_path(value: &str) -> Result<String, ModelError> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return Err(ModelError::UnsafePath(value.to_owned()));
    }

    let mut segments = Vec::new();
    for component in std::path::Path::new(value).components() {
        match component {
            Component::Normal(segment) => {
                let segment = segment
                    .to_str()
                    .ok_or_else(|| ModelError::UnsafePath(value.to_owned()))?;
                segments.push(segment);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ModelError::UnsafePath(value.to_owned()));
            }
        }
    }

    if segments.is_empty() {
        return Err(ModelError::UnsafePath(value.to_owned()));
    }
    Ok(segments.join("/"))
}
