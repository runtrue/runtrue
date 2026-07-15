use crate::{
    error::CliError,
    verify::{read_bounded, supplied_now},
};
use runtrue_model::ContentDigest;
use runtrue_update::{
    decode_root, root_envelope_digest, TrustStore, TrustedState, MAX_METADATA_BYTES,
};
use std::path::PathBuf;
pub(crate) fn bootstrap(
    root: PathBuf,
    expected_root_digest: String,
    state: PathBuf,
    now: Option<u64>,
) -> Result<(), CliError> {
    let expected = ContentDigest::parse(expected_root_digest)
        .map_err(|_| CliError::InvalidExpectedRootDigest)?;
    let root = decode_root(&read_bounded(&root, MAX_METADATA_BYTES)?)?;
    let actual = root_envelope_digest(&root)?;
    if actual != expected {
        return Err(CliError::RootDigestMismatch { expected, actual });
    }
    let store = TrustStore::open(&state)?;
    let transaction = store.transaction()?;
    if transaction.load()?.is_some() {
        return Err(CliError::AlreadyInitialized);
    }
    let trusted = TrustedState::bootstrap(root, &expected, supplied_now(now)?)?;
    transaction.initialize(&trusted)?;
    println!(
        "{}",
        serde_json::json!({"root_digest":expected.to_string(),"root_version":trusted.trusted_root.signed.header.version,"state":store.path().display().to_string()})
    );
    Ok(())
}
