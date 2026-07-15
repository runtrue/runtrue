pub(super) fn validate_private_directory(path: &Path, kind: &str) -> Result<PathBuf, RunnerError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::WasmConfiguration(format!("inspect {kind}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunnerError::WasmConfiguration(format!(
            "{kind} is not a real directory"
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(RunnerError::WasmConfiguration(format!(
            "{kind} must have mode 0700"
        )));
    }
    path.canonicalize()
        .map_err(|error| RunnerError::WasmConfiguration(format!("canonicalize {kind}: {error}")))
}

pub(super) fn sorted_directory_files(directory: &Path) -> Result<Vec<PathBuf>, RunnerError> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| RunnerError::WasmConfiguration(error.to_string()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| RunnerError::WasmConfiguration(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    Ok(paths)
}

pub(super) fn decode_public_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    (text.len() == 64)
        .then(|| hex::decode(text).ok())
        .flatten()
        .and_then(|decoded| <[u8; 32]>::try_from(decoded.as_slice()).ok())
}

pub(super) fn decode_runtime_keys(bytes: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let decoded = Zeroizing::new(if bytes.len() == 64 {
        bytes.to_vec()
    } else {
        let text = std::str::from_utf8(bytes).ok()?.trim();
        if text.len() != 128 {
            return None;
        }
        hex::decode(text).ok()?
    });
    let aot = <[u8; 32]>::try_from(decoded.get(..32)?).ok()?;
    let handles = <[u8; 32]>::try_from(decoded.get(32..64)?).ok()?;
    (aot != handles && aot.iter().any(|byte| *byte != 0) && handles.iter().any(|byte| *byte != 0))
        .then_some((aot, handles))
}
use super::{fs, validate_no_symlink_components, Path, PathBuf, RunnerError, Zeroizing};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
