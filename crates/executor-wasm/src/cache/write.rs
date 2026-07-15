use super::{secure_fs::cache_io, AotCacheError};
use rand_core::{OsRng, RngCore as _};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Publication {
    Published,
    Existing,
}

pub(super) fn atomic_write_private(
    path: &Path,
    value: &[u8],
) -> Result<Publication, AotCacheError> {
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| AotCacheError::RandomnessUnavailable)?;
    let temp = path.with_extension(format!("tmp-{}", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|source| cache_io(&temp, source))?;
    if let Err(source) = file.write_all(value).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(cache_io(&temp, source));
    }
    drop(file);
    match fs::hard_link(&temp, path) {
        Ok(()) => {
            fs::remove_file(&temp).map_err(|source| cache_io(&temp, source))?;
            Ok(Publication::Published)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temp).map_err(|source| cache_io(&temp, source))?;
            Ok(Publication::Existing)
        }
        Err(source) => {
            let _ = fs::remove_file(&temp);
            Err(cache_io(path, source))
        }
    }
}
