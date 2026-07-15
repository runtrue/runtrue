use crate::{
    error::CliError,
    output::print_verified,
    verify::{supplied_now, verify_release},
};
use runtrue_update::TrustStore;
use std::path::PathBuf;
pub(crate) fn apply(
    state: PathBuf,
    bundle: PathBuf,
    target_path: String,
    target_file: PathBuf,
    now: Option<u64>,
) -> Result<(), CliError> {
    let store = TrustStore::open(&state)?;
    let transaction = store.transaction()?;
    let trusted = transaction.load()?.ok_or(CliError::TrustNotInitialized)?;
    let verified = verify_release(
        &trusted,
        &bundle,
        &target_path,
        &target_file,
        supplied_now(now)?,
    )?;
    transaction.replace(&trusted, &verified.next_state)?;
    print_verified(&verified);
    Ok(())
}
