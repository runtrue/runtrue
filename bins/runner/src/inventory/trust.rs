const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;
pub fn load_capsule_trust_store(directory: &Path) -> Result<TrustedCapsuleKeys, InventoryError> {
    validate_private_directory(directory)?;
    let mut paths = fs::read_dir(directory)
        .map_err(|source| io_error(directory, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| io_error(directory, source))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut store = CapsuleTrustStore::new();
    let mut key_ids = Vec::new();
    for path in paths {
        let bytes = read_bounded_private_file(&path, MAX_KEY_FILE_BYTES)?;
        let key_bytes = decode_public_key(&bytes)
            .ok_or_else(|| InventoryError::InvalidPublicKey { path: path.clone() })?;
        let key = CapsuleVerifyingKey::from_bytes(&key_bytes).map_err(|source| {
            InventoryError::PublicKey {
                path: path.clone(),
                source,
            }
        })?;
        key_ids.push(store.insert(key)?);
    }
    if key_ids.is_empty() {
        return Err(InventoryError::EmptyKeyring(directory.to_owned()));
    }
    Ok(TrustedCapsuleKeys { store, key_ids })
}

fn decode_public_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() == 64 {
        let decoded = hex::decode(text).ok()?;
        return <[u8; 32]>::try_from(decoded.as_slice()).ok();
    }
    None
}

fn validate_private_directory(path: &Path) -> Result<(), InventoryError> {
    validate_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InventoryError::UnsafeKeyring(path.to_owned()));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(InventoryError::UnsafeKeyring(path.to_owned()));
    }
    Ok(())
}
use super::{error::io_error, InventoryError, TrustedCapsuleKeys};
use crate::state::{read_bounded_private_file, validate_no_symlink_components};
use runtrue_attest::CapsuleVerifyingKey;
use runtrue_runner_core::CapsuleTrustStore;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fs, path::Path};
