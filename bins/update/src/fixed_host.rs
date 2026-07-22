use crate::{error::CliError, verify::read_bounded};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::{OsRng, RngCore as _};
use runtrue_model::ContentDigest;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize as _, Zeroizing};

pub(crate) fn proof(
    key: PathBuf,
    pool_id: String,
    slot_id: String,
    issued_unix_ms: Option<u64>,
) -> Result<(), CliError> {
    let encoded = Zeroizing::new(read_bounded(&key, 128)?);
    let seed_hex = std::str::from_utf8(&encoded)
        .map_err(|_| CliError::InvalidRunnerProfile("updater identity key is malformed".into()))?
        .trim_end_matches(['\r', '\n']);
    let mut seed = hex::decode(seed_hex)
        .ok()
        .and_then(|value| <[u8; 32]>::try_from(value).ok())
        .ok_or_else(|| {
            CliError::InvalidRunnerProfile("updater identity key is malformed".into())
        })?;
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let issued_unix_ms = issued_unix_ms.unwrap_or(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CliError::Clock)?
            .as_millis()
            .try_into()
            .map_err(|_| CliError::Clock)?,
    );
    let mut nonce = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| runtrue_update::UpdateError::RandomnessUnavailable)?;
    let nonce_digest = ContentDigest::sha256(nonce);
    nonce.zeroize();
    let message = runtrue_update::fixed_updater_claim_proof_message(
        &pool_id,
        &slot_id,
        &nonce_digest,
        issued_unix_ms,
    )?;
    let signature = signing.sign(&message);
    let public_key = signing.verifying_key().to_bytes();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "request": {
                "public_key_hex": hex::encode(public_key),
                "signature_hex": hex::encode(signature.to_bytes()),
                "nonce_digest": nonce_digest,
                "issued_unix_ms": issued_unix_ms,
            },
            "claim_evidence": {
                "version": 1,
                "evidence_hex": hex::encode(public_key),
                "endorsement_hex": hex::encode(signature.to_bytes()),
                "nonce_digest": nonce_digest,
            },
            "registered_identity_digest": ContentDigest::sha256(public_key),
        }))?
    );
    Ok(())
}
