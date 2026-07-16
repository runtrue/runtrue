use crate::GuestAgentError;
use runtrue_model::{normalize_relative_path, ContentDigest};
use runtrue_workflow_ir::{Shell, StepAction, ValueBinding};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 1024;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;

pub(super) fn prepare_action(
    action: &StepAction,
) -> Result<(PathBuf, Vec<String>), GuestAgentError> {
    match action {
        StepAction::Command { program, args } => Ok((
            PathBuf::from(program),
            args.iter()
                .map(literal_string)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        StepAction::Script {
            shell,
            script,
            script_digest,
        } => {
            if script.is_empty() || script.len() > MAX_SCRIPT_BYTES {
                return Err(GuestAgentError::InvalidConfiguration(
                    "signed guest script exceeds its bound".to_owned(),
                ));
            }
            if &ContentDigest::sha256(script.as_bytes()) != script_digest {
                return Err(GuestAgentError::InvalidConfiguration(
                    "signed guest script digest mismatch".to_owned(),
                ));
            }
            let shell = match shell {
                Shell::Bash => "/bin/bash",
                Shell::Sh => "/bin/sh",
                Shell::Pwsh | Shell::Cmd => {
                    return Err(GuestAgentError::InvalidConfiguration(
                        "Windows shells are unavailable in the Linux guest".to_owned(),
                    ));
                }
            };
            Ok((PathBuf::from(shell), vec!["-c".to_owned(), script.clone()]))
        }
        StepAction::Component { .. } | StepAction::Container { .. } => {
            Err(GuestAgentError::InvalidConfiguration(
                "component and image-entrypoint actions require dedicated runtimes".to_owned(),
            ))
        }
    }
}

pub(super) fn validate_literal_bindings(
    bindings: &BTreeMap<String, ValueBinding>,
) -> Result<(), GuestAgentError> {
    if bindings
        .values()
        .any(|value| matches!(value, ValueBinding::Context(_)))
    {
        return Err(GuestAgentError::InvalidConfiguration(
            "unresolved context binding reached the guest process boundary".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn literal_environment(
    bindings: &BTreeMap<String, ValueBinding>,
) -> Result<BTreeMap<String, String>, GuestAgentError> {
    if bindings.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest environment has too many entries".to_owned(),
        ));
    }
    let mut total = 0_usize;
    bindings
        .iter()
        .map(|(name, value)| {
            if name.is_empty() || name.len() > 256 || name.contains('=') || name.contains('\0') {
                return Err(GuestAgentError::InvalidConfiguration(
                    "guest environment name is invalid".to_owned(),
                ));
            }
            let value = literal_string(value)?;
            if value.contains('\0') || value.len() > 64 * 1024 {
                return Err(GuestAgentError::InvalidConfiguration(
                    "guest environment value is invalid".to_owned(),
                ));
            }
            total = total.checked_add(name.len() + value.len()).ok_or_else(|| {
                GuestAgentError::InvalidConfiguration("guest environment size overflows".to_owned())
            })?;
            if total > MAX_ENVIRONMENT_BYTES {
                return Err(GuestAgentError::InvalidConfiguration(
                    "guest environment exceeds its byte bound".to_owned(),
                ));
            }
            Ok((name.clone(), value))
        })
        .collect()
}

pub(super) fn literal_string(value: &ValueBinding) -> Result<String, GuestAgentError> {
    match value {
        ValueBinding::Literal(value) => Ok(value.to_string()),
        ValueBinding::Context(_) => Err(GuestAgentError::InvalidConfiguration(
            "unresolved context binding reached the guest process boundary".to_owned(),
        )),
    }
}

pub(super) fn validate_executable(path: &Path) -> Result<(), GuestAgentError> {
    if !path.is_absolute() {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest command path must be absolute".to_owned(),
        ));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| GuestAgentError::Process(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest command must be a regular non-symlink executable".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(GuestAgentError::InvalidConfiguration(
                "guest command is not executable".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn resolve_working_directory(
    workspace: &Path,
    requested: Option<&str>,
) -> Result<PathBuf, GuestAgentError> {
    let path = match requested {
        Some(requested) => workspace.join(normalize_relative_path(requested).map_err(|error| {
            GuestAgentError::InvalidConfiguration(format!("invalid working directory: {error}"))
        })?),
        None => workspace.to_owned(),
    };
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| GuestAgentError::Process(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GuestAgentError::InvalidConfiguration(
            "guest working directory must be an existing non-symlink directory".to_owned(),
        ));
    }
    Ok(path)
}
