use super::{parse_strict_json, CliError, MAX_EVENT_BYTES};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Read as _,
    path::{Path, PathBuf},
};

pub(super) fn resolve_one_workflow(
    workspace: &Path,
    explicit: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(absolute(workspace, path));
    }
    let discovered = discover_workflows(workspace)?;
    if discovered.len() != 1 {
        return Err(CliError::AmbiguousWorkflows(discovered.len()));
    }
    Ok(discovered.into_iter().next().expect("one workflow"))
}

pub(super) fn discover_workflows(workspace: &Path) -> Result<Vec<PathBuf>, CliError> {
    let directory = workspace.join(".runtrue/workflows");
    let entries = fs::read_dir(&directory).map_err(|source| CliError::Discover {
        path: directory.clone(),
        source,
    })?;
    let mut workflows = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| CliError::Discover {
            path: directory.clone(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| CliError::Discover {
            path: entry.path(),
            source,
        })?;
        let path = entry.path();
        if file_type.is_file()
            && matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("yaml" | "yml")
            )
        {
            workflows.push(path);
        }
    }
    workflows.sort();
    if workflows.is_empty() {
        return Err(CliError::NoWorkflows(directory));
    }
    Ok(workflows)
}

pub(super) fn read_event(path: Option<&Path>, workspace: &Path) -> Result<Value, CliError> {
    let Some(path) = path else {
        return Ok(serde_json::json!({"type": "manual"}));
    };
    let path = absolute(workspace, path.to_path_buf());
    let source = read_bounded_file(&path, MAX_EVENT_BYTES, "event fixture")?;
    parse_strict_json(&source).map_err(|source| CliError::EventJson { path, source })
}

pub(super) fn read_bounded_file(
    path: &Path,
    limit: u64,
    kind: &'static str,
) -> Result<Vec<u8>, CliError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options.open(path).map_err(|source| CliError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::NonRegularInput {
            kind,
            path: path.to_path_buf(),
        });
    }

    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(CliError::InputTooLarge {
            kind,
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

pub(super) fn absolute(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

pub(super) fn display_path(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .ok()
        .or_else(|| path.file_name().map(Path::new))
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
