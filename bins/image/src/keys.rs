use crate::{
    error::ImageCliError,
    output::{self, KeygenResult},
    secure_fs::{read_bounded_regular, require_new_file_target, write_new_file},
};
use rand_core::{OsRng, RngCore};
use runtrue_attest::{ImageSigningKey, ImageVerifyingKey};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_KEY_BYTES: u64 = 4 * 1024;
pub(crate) fn generate(
    private_key: PathBuf,
    public_key: PathBuf,
    json: bool,
) -> Result<(), ImageCliError> {
    if private_key == public_key {
        return Err(ImageCliError::KeyPathsConflict);
    }
    require_new_file_target(&private_key)?;
    require_new_file_target(&public_key)?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| ImageCliError::RandomnessUnavailable)?;
    let key = ImageSigningKey::from_seed(*seed);
    write_new_file(&public_key, &key.verifying_key().to_bytes(), 0o644)?;
    write_new_file(&private_key, seed.as_ref(), 0o600)?;
    output::print(
        json,
        &KeygenResult {
            private_key,
            public_key,
            key_id: key.verifying_key().key_id(),
        },
        "generated image signing key",
    )
}
pub(crate) fn read_signing_key(path: &Path) -> Result<ImageSigningKey, ImageCliError> {
    let bytes = Zeroizing::new(read_bounded_regular(path, MAX_KEY_BYTES, true)?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ImageCliError::InvalidPrivateKeyLength(bytes.len()))?;
    Ok(ImageSigningKey::from_seed(seed))
}
pub(crate) fn read_verifying_key(path: &Path) -> Result<ImageVerifyingKey, ImageCliError> {
    let bytes = read_bounded_regular(path, MAX_KEY_BYTES, false)?;
    ImageVerifyingKey::from_bytes(&bytes).map_err(ImageCliError::ImageAttestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_fs::write_new_file;
    use std::{fs, os::unix::fs::PermissionsExt as _};
    use tempfile::TempDir;
    #[test]
    fn loader_enforces_length_and_mode() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("key");
        write_new_file(&p, &[1; 32], 0o600).unwrap();
        assert!(read_signing_key(&p).is_ok());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_signing_key(&p),
            Err(ImageCliError::InsecurePrivateKeyMode { .. })
        ));
    }
}
