use crate::{error::CliError, output::print_verified};
use runtrue_update::{
    read_verified_file, ReleaseBundle, TrustStore, TrustedState, MAX_METADATA_BYTES,
};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const MAX_BUNDLE_BYTES: usize = MAX_METADATA_BYTES * 4;
pub(crate) const MAX_CLI_TARGET_BYTES: usize = 512 * 1024 * 1024;
pub(crate) fn command(
    state: PathBuf,
    bundle: PathBuf,
    target_path: String,
    target_file: PathBuf,
    now: Option<u64>,
) -> Result<(), CliError> {
    let store = TrustStore::open(&state)?;
    let trusted = store.load()?.ok_or(CliError::TrustNotInitialized)?;
    let verified = verify_release(
        &trusted,
        &bundle,
        &target_path,
        &target_file,
        supplied_now(now)?,
    )?;
    print_verified(&verified);
    Ok(())
}
pub(crate) fn verify_release(
    state: &TrustedState,
    bundle_path: &Path,
    target_path: &str,
    target_file: &Path,
    now: u64,
) -> Result<runtrue_update::VerifiedRelease, CliError> {
    let bundle = ReleaseBundle::decode(&read_bounded(bundle_path, MAX_BUNDLE_BYTES)?)?;
    let target = read_bounded(target_file, MAX_CLI_TARGET_BYTES)?;
    state
        .verify_release(&bundle, target_path, &target, now)
        .map_err(Into::into)
}
pub(crate) fn supplied_now(value: Option<u64>) -> Result<u64, CliError> {
    value.map_or_else(
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| CliError::Clock)
        },
        Ok,
    )
}
pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    read_verified_file(path, maximum).map_err(Into::into)
}
