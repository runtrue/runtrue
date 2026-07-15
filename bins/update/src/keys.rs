use crate::error::CliError;
use runtrue_update::{TrustStore, UpdateSigningKey};
use std::path::PathBuf;
pub(crate) fn generate(output: PathBuf) -> Result<(), CliError> {
    let key = UpdateSigningKey::generate()?;
    TrustStore::write_new_signing_key(&output, &key)?;
    println!(
        "{}",
        serde_json::json!({"algorithm":"ed25519","key_id":key.key_id().to_string(),"public_key":key.public_key(),"private_key_file":output.display().to_string()})
    );
    Ok(())
}
