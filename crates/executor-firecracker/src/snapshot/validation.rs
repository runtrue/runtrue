use crate::FirecrackerError;
use std::{fs, path::Path};
pub(super) fn verify_immutable_mode(path: &Path) -> Result<(), FirecrackerError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| crate::state_io(path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 != 0o400
        {
            return Err(FirecrackerError::UnsafeArtifact {
                path: path.to_owned(),
                reason: "staged snapshot artifact must be an immutable mode-0400 file".to_owned(),
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(FirecrackerError::InvalidConfiguration(
            "snapshot immutability requires Unix permissions".to_owned(),
        ))
    }
}
