use super::{
    secure_fs::{cache_io, verify_private_mode, verify_single_link},
    AotCacheError,
};
use std::{fs::OpenOptions, io::Read, path::Path};
pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, AotCacheError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|source| cache_io(path, source))?;
    let metadata = file.metadata().map_err(|source| cache_io(path, source))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(AotCacheError::EntryTooLarge);
    }
    verify_private_mode(path, &metadata)?;
    verify_single_link(path, &metadata)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| AotCacheError::EntryTooLarge)?;
    let mut value = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut value)
        .map_err(|source| cache_io(path, source))?;
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > limit {
        return Err(AotCacheError::EntryTooLarge);
    }
    Ok(value)
}
