use crate::{path_io, GuestAgentError};
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_guest_core::{GuestBootConfig, GuestCapsuleTrustStore, MAX_GUEST_BOOT_CONFIG_BYTES};
use std::{
    fs,
    path::{Component, Path},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use nix::{
    fcntl::{open, openat, OFlag},
    sys::stat::{fstat, Mode, SFlag},
    unistd::{close, read},
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

const MAX_KEY_BYTES: usize = 16 * 1024;

pub fn load_boot_config(path: &Path) -> Result<GuestBootConfig, GuestAgentError> {
    validate_absolute_no_symlink(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| path_io(path, source))?;
    #[cfg(unix)]
    let allowed_type = metadata.file_type().is_file() || metadata.file_type().is_block_device();
    #[cfg(not(unix))]
    let allowed_type = metadata.file_type().is_file();
    if metadata.file_type().is_symlink() || !allowed_type {
        return Err(GuestAgentError::InvalidConfiguration(
            "boot config must be a regular file or block device".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(GuestAgentError::InvalidConfiguration(
            "boot config must not be accessible by group or other".to_owned(),
        ));
    }
    let mut bytes = Zeroizing::new(read_bounded(
        path,
        MAX_GUEST_BOOT_CONFIG_BYTES,
        FilePolicy::Boot,
    )?);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(GuestAgentError::InvalidConfiguration(
            "boot config is empty".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let config = GuestBootConfig::deserialize(&mut deserializer)?;
    deserializer.end()?;
    config.validate()?;
    Ok(config)
}

pub fn load_capsule_trust_store(
    directory: &Path,
) -> Result<GuestCapsuleTrustStore, GuestAgentError> {
    validate_absolute_no_symlink(directory)?;
    let metadata = fs::symlink_metadata(directory).map_err(|source| path_io(directory, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GuestAgentError::InvalidConfiguration(
            "capsule trust path must be a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(GuestAgentError::InvalidConfiguration(
            "capsule trust directory mode must be exactly 0700".to_owned(),
        ));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|source| path_io(directory, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| path_io(directory, source))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let mut trust = GuestCapsuleTrustStore::new();
    for path in entries {
        validate_absolute_no_symlink(&path)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| path_io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(GuestAgentError::InvalidConfiguration(format!(
                "capsule trust entry {} is not a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(GuestAgentError::InvalidConfiguration(format!(
                "capsule trust entry {} mode must be exactly 0600",
                path.display()
            )));
        }
        let bytes = read_bounded(&path, MAX_KEY_BYTES, FilePolicy::CapsuleKey)?;
        let decoded = decode_key(&bytes).ok_or_else(|| {
            GuestAgentError::InvalidConfiguration(format!(
                "capsule trust entry {} is not a raw or hex Ed25519 key",
                path.display()
            ))
        })?;
        trust.insert(CapsuleVerifyingKey::from_bytes(&decoded)?)?;
    }
    // GuestSession::new performs the final empty-store rejection.
    Ok(trust)
}

fn decode_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() != 64 {
        return None;
    }
    let decoded = hex::decode(text).ok()?;
    decoded.as_slice().try_into().ok()
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Boot,
    CapsuleKey,
}

fn read_bounded(path: &Path, limit: usize, policy: FilePolicy) -> Result<Vec<u8>, GuestAgentError> {
    #[cfg(not(unix))]
    {
        let _ = (path, limit, policy);
        return Err(GuestAgentError::InvalidConfiguration(
            "race-safe guest config loading requires Unix".to_owned(),
        ));
    }
    #[cfg(unix)]
    let descriptor = open_without_symlinks(path)?;
    #[cfg(unix)]
    let stat = fstat(descriptor.raw()).map_err(|error| path_io(path, nix_io(error)))?;
    #[cfg(unix)]
    {
        let kind = SFlag::from_bits_truncate(stat.st_mode);
        let valid_kind = match policy {
            FilePolicy::Boot => kind.contains(SFlag::S_IFREG) || kind.contains(SFlag::S_IFBLK),
            FilePolicy::CapsuleKey => kind.contains(SFlag::S_IFREG),
        };
        let expected_mode = match policy {
            FilePolicy::Boot => stat.st_mode & 0o077 == 0,
            FilePolicy::CapsuleKey => stat.st_mode & 0o7777 == 0o600,
        };
        if !valid_kind || !expected_mode {
            return Err(GuestAgentError::InvalidConfiguration(format!(
                "{} changed while it was opened",
                path.display()
            )));
        }
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        #[cfg(unix)]
        let count =
            read(descriptor.raw(), &mut buffer).map_err(|error| path_io(path, nix_io(error)))?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > limit {
            return Err(GuestAgentError::InvalidConfiguration(format!(
                "{} exceeds its byte bound",
                path.display()
            )));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

#[cfg(unix)]
struct RawDescriptor(i32);

#[cfg(unix)]
impl RawDescriptor {
    const fn raw(&self) -> i32 {
        self.0
    }
}

#[cfg(unix)]
impl Drop for RawDescriptor {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

#[cfg(unix)]
fn open_without_symlinks(path: &Path) -> Result<RawDescriptor, GuestAgentError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(GuestAgentError::InvalidConfiguration(
            "security-sensitive path must be absolute".to_owned(),
        ));
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(GuestAgentError::InvalidConfiguration(
                "security-sensitive path contains a non-normal component".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (file_name, directories) = names.split_last().ok_or_else(|| {
        GuestAgentError::InvalidConfiguration("security-sensitive path cannot be root".to_owned())
    })?;
    let mut directory = RawDescriptor(
        open(
            Path::new("/"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| path_io(path, nix_io(error)))?,
    );
    for name in directories {
        directory = RawDescriptor(
            openat(
                directory.raw(),
                *name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| path_io(path, nix_io(error)))?,
        );
    }
    Ok(RawDescriptor(
        openat(
            directory.raw(),
            *file_name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| path_io(path, nix_io(error)))?,
    ))
}

#[cfg(unix)]
fn nix_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

fn validate_absolute_no_symlink(path: &Path) -> Result<(), GuestAgentError> {
    if !path.is_absolute() {
        return Err(GuestAgentError::InvalidConfiguration(
            "security-sensitive paths must be absolute".to_owned(),
        ));
    }
    let mut current = std::path::PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(GuestAgentError::InvalidConfiguration(
                "security-sensitive path contains a non-normal component".to_owned(),
            ));
        };
        current.push(name);
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| path_io(&current, source))?;
        if metadata.file_type().is_symlink() {
            return Err(GuestAgentError::InvalidConfiguration(format!(
                "security-sensitive path {} contains a symlink",
                path.display()
            )));
        }
    }
    Ok(())
}

use serde::Deserialize as _;

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_attest::CapsuleSigningKey;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn loads_private_raw_and_hex_keys() {
        let directory = TempDir::new().unwrap();
        let keys = directory.path().join("keys");
        fs::create_dir(&keys).unwrap();
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
        let key = CapsuleSigningKey::from_seed([3; 32]).verifying_key();
        let path = keys.join("capsule.pub");
        fs::write(&path, hex::encode(key.to_bytes())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_capsule_trust_store(&keys).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_boot_config() {
        use std::os::unix::fs::symlink;
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(load_boot_config(&link).is_err());
    }
}
