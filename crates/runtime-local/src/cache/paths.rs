use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

pub(crate) fn resolve_existing_exact(
    workspace: &Path,
    relative: &str,
) -> Result<Option<PathBuf>, String> {
    let mut current = canonical_workspace(workspace)?;
    for component in relative_path(relative).components() {
        let Component::Normal(segment) = component else {
            return Err(format!("unsafe repository-relative path {relative}"));
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("path {relative} traverses a symlink"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(Some(current))
}

pub(crate) fn canonical_workspace(workspace: &Path) -> Result<PathBuf, String> {
    let workspace = workspace
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(&workspace).map_err(|error| error.to_string())?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(workspace)
    } else {
        Err(format!(
            "workspace {} is not a real directory",
            workspace.display()
        ))
    }
}

pub(crate) fn relative_path(relative: &str) -> PathBuf {
    relative.split('/').collect()
}
