use super::{
    canonical_workspace, copy_new_tree, first_output_collision, relative_path, staging_directory,
    LocalCacheConfig, PreparedCacheStep,
};
use runtrue_cache::{CacheIdentity, CacheMiss, CacheStore, RestoreOutcome};
use runtrue_engine::ExecutorError;
use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

pub(crate) fn restore_outputs(
    store: &CacheStore,
    config: &LocalCacheConfig,
    step: &PreparedCacheStep,
    identity: &CacheIdentity,
    warnings: &mut Vec<String>,
) -> Result<(), ExecutorError> {
    if let Some(path) = first_output_collision(&config.workspace, &step.declaration.outputs) {
        warnings.push(format!(
            "cache restore skipped because output {path} already exists; outputs are never overwritten"
        ));
        return Ok(());
    }
    let entry = match store.inspect(identity) {
        Ok(Some(entry)) => entry,
        Ok(None) => return Ok(()),
        Err(error) => {
            warnings.push(format!(
                "cache metadata is unavailable; treating as a miss: {error}"
            ));
            return Ok(());
        }
    };
    if entry.manifest.tree.total_file_bytes > step.max_size_bytes {
        warnings.push(format!(
            "cache entry exceeds declared max-size of {} bytes; treating as a miss",
            step.max_size_bytes
        ));
        return Ok(());
    }
    let stage = match staging_directory(config) {
        Ok(stage) => stage,
        Err(error) => {
            warnings.push(format!("cache restore staging is unavailable: {error}"));
            return Ok(());
        }
    };
    match store.restore(&identity.trust_domain, identity, stage.path()) {
        Ok(RestoreOutcome::Miss(CacheMiss::NotFound)) => return Ok(()),
        Ok(RestoreOutcome::Miss(CacheMiss::Corrupt)) => {
            warnings.push("cache content is corrupt; treating as a miss".to_owned());
            return Ok(());
        }
        Err(error) => {
            warnings.push(format!(
                "cache restore is unavailable; treating as a miss: {error}"
            ));
            return Ok(());
        }
        Ok(RestoreOutcome::Hit(_)) => {}
    }
    match install_staged_outputs(
        &config.workspace,
        stage.path(),
        &step.declaration.outputs,
        copy_new_tree,
    ) {
        Ok(()) => Ok(()),
        Err(StagedInstallError::SafeMiss(error)) => {
            warnings.push(format!(
                "cache restore was rolled back before execution; treating as a miss: {error}"
            ));
            Ok(())
        }
        Err(StagedInstallError::UnsafeWorkspace(error)) => Err(ExecutorError::WorkingDirectory(
            format!("cache restore rollback could not recover a clean workspace: {error}"),
        )),
    }
}

#[derive(Debug)]
pub(crate) enum StagedInstallError {
    SafeMiss(String),
    UnsafeWorkspace(String),
}

pub(crate) fn install_staged_outputs<F>(
    workspace: &Path,
    stage: &Path,
    outputs: &[String],
    mut copy: F,
) -> Result<(), StagedInstallError>
where
    F: FnMut(&Path, &Path) -> Result<(), String>,
{
    let workspace = canonical_workspace(workspace).map_err(StagedInstallError::SafeMiss)?;
    let mut restorations = Vec::new();
    for relative in outputs {
        let source = stage.join(relative_path(relative));
        match fs::symlink_metadata(&source) {
            Ok(_) => validate_staged_tree(&source).map_err(StagedInstallError::SafeMiss)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(StagedInstallError::SafeMiss(format!(
                    "cache output {relative} is unavailable: {error}"
                )));
            }
        }
        let destination = workspace.join(relative_path(relative));
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(StagedInstallError::SafeMiss(format!(
                    "cache output {relative} appeared during restore"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StagedInstallError::SafeMiss(error.to_string())),
        }
        restorations.push((source, destination));
    }

    let mut created_parents = Vec::new();
    let mut created_roots = Vec::new();
    let result = (|| {
        for (_, destination) in &restorations {
            create_missing_parents(&workspace, destination, &mut created_parents)?;
        }
        for (source, destination) in &restorations {
            copy(source, destination)?;
            // A successful copy used no-replace creation, so this root is
            // known to belong to this restore and is safe to roll back if a
            // later output fails.
            created_roots.push(destination.clone());
        }
        Ok(())
    })();
    if let Err(error) = result {
        return match rollback_created_paths(&created_roots, &created_parents) {
            Ok(()) => Err(StagedInstallError::SafeMiss(error)),
            Err(cleanup) => Err(StagedInstallError::UnsafeWorkspace(format!(
                "{error}; cleanup failed: {cleanup}"
            ))),
        };
    }
    Ok(())
}

pub(crate) fn validate_staged_tree(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("staged cache content contains a symlink".to_owned());
    }
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err("staged cache content contains a special entry".to_owned());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        validate_staged_tree(&entry.path())?;
    }
    Ok(())
}

pub(crate) fn create_missing_parents(
    workspace: &Path,
    destination: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "cache output has no destination parent".to_owned())?;
    let relative = parent
        .strip_prefix(workspace)
        .map_err(|_| "cache output parent escapes the workspace".to_owned())?;
    let mut current = workspace.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err("cache output parent is not canonical".to_owned());
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "cache output parent {} is unsafe",
                    current.display()
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| error.to_string())?;
                created.push(current.clone());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

pub(crate) fn rollback_created_paths(roots: &[PathBuf], parents: &[PathBuf]) -> Result<(), String> {
    let mut errors = Vec::new();
    for path in roots.iter().rev() {
        let result = match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(path)
            }
            Ok(_) => fs::remove_file(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", path.display()));
        }
    }
    for path in parents.iter().rev() {
        match fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
