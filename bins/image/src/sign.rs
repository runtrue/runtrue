use crate::{
    error::ImageCliError,
    keys::read_signing_key,
    output::{self, SignResult},
    secure_fs::{read_bounded_regular, write_new_file},
};
use runtrue_attest::ImageManifest;
use std::path::PathBuf;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) fn sign(
    manifest: PathBuf,
    private_key: PathBuf,
    output_path: PathBuf,
    json: bool,
) -> Result<(), ImageCliError> {
    let bytes = read_bounded_regular(&manifest, MAX_MANIFEST_BYTES, false)?;
    let manifest: ImageManifest = strict_json(&bytes)?;
    if manifest.canonical_bytes()? != bytes {
        return Err(ImageCliError::NonCanonicalManifest);
    }
    let key = read_signing_key(&private_key)?;
    let signed = key.sign_manifest(&manifest)?;
    let result = SignResult {
        output: output_path.clone(),
        manifest_digest: signed.manifest_digest.clone(),
        key_id: signed.key_id.clone(),
    };
    write_new_file(&output_path, &serde_json::to_vec(&signed)?, 0o600)?;
    output::print(json, &result, "signed image manifest")
}
pub(crate) fn strict_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ImageCliError> {
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut d)?;
    d.end()?;
    Ok(value)
}
