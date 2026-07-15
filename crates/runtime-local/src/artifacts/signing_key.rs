use super::LocalArtifactConfig;
use crate::cache::canonical_workspace;
use rand_core::{OsRng, RngCore as _};
use runtrue_attest::CapsuleSigningKey;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroize;

pub(crate) fn load_or_create_signing_key(
    directory: &Path,
    path: &Path,
) -> Result<CapsuleSigningKey, String> {
    match load_signing_key(path) {
        Ok(key) => return Ok(key),
        Err(KeyLoadError::NotFound) => {}
        Err(KeyLoadError::Invalid(message)) => return Err(message),
    }

    let mut seed = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| "operating system randomness is unavailable".to_owned())?;
    let mut random = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| "operating system randomness is unavailable".to_owned())?;
    let temporary = directory.join(format!(
        ".local-signing-key-{}-{}.tmp",
        std::process::id(),
        hex::encode(random)
    ));
    let write_result = write_new_secret_file(&temporary, &seed);
    if let Err(error) = write_result {
        seed.zeroize();
        return Err(error);
    }
    let linked = match fs::hard_link(&temporary, path) {
        Ok(()) => {
            if let Err(error) = sync_directory_path(directory) {
                let _ = fs::remove_file(&temporary);
                seed.zeroize();
                return Err(error);
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            seed.zeroize();
            return Err(error.to_string());
        }
    };
    let _ = fs::remove_file(&temporary);
    if linked {
        let key = CapsuleSigningKey::from_seed(seed);
        seed.zeroize();
        Ok(key)
    } else {
        seed.zeroize();
        load_signing_key(path).map_err(|error| match error {
            KeyLoadError::NotFound => "artifact signing key disappeared during creation".to_owned(),
            KeyLoadError::Invalid(message) => message,
        })
    }
}

pub(crate) enum KeyLoadError {
    NotFound,
    Invalid(String),
}

pub(crate) fn load_signing_key(path: &Path) -> Result<CapsuleSigningKey, KeyLoadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(KeyLoadError::NotFound);
        }
        Err(error) => return Err(KeyLoadError::Invalid(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| KeyLoadError::Invalid(error.to_string()))?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(KeyLoadError::Invalid(
            "artifact signing key must be a 32-byte regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(KeyLoadError::Invalid(
                "artifact signing key permissions must be exactly 0600".to_owned(),
            ));
        }
    }
    let mut seed = [0_u8; 32];
    if let Err(error) = file.read_exact(&mut seed) {
        seed.zeroize();
        return Err(KeyLoadError::Invalid(error.to_string()));
    }
    let mut trailing = [0_u8; 1];
    if let Err(error) = file.read_exact(&mut trailing) {
        if error.kind() != io::ErrorKind::UnexpectedEof {
            seed.zeroize();
            return Err(KeyLoadError::Invalid(error.to_string()));
        }
    } else {
        seed.zeroize();
        return Err(KeyLoadError::Invalid(
            "artifact signing key contains trailing bytes".to_owned(),
        ));
    }
    let key = CapsuleSigningKey::from_seed(seed);
    seed.zeroize();
    Ok(key)
}

pub(crate) fn write_new_secret_file(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    let write_result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        }
        file.write_all(seed).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

pub(crate) fn ensure_private_artifact_root(config: &LocalArtifactConfig) -> Result<(), String> {
    let workspace = canonical_workspace(&config.workspace)?;
    let expected = workspace.join(".runtrue/artifacts");
    if config.artifact_root != expected {
        return Err(format!(
            "local artifact root must be {}",
            expected.display()
        ));
    }
    let mut current = workspace;
    for component in [".runtrue", "artifacts"] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "local artifact path {} is a symlink or non-directory",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| error.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                        .map_err(|error| error.to_string())?;
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

pub(crate) fn sync_directory_path(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
