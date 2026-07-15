use crate::{error::CliError, verify::read_bounded};
use runtrue_update::{decode_root, root_envelope_digest, MAX_METADATA_BYTES};
use std::path::PathBuf;
pub(crate) fn digest(root: PathBuf) -> Result<(), CliError> {
    let root = decode_root(&read_bounded(&root, MAX_METADATA_BYTES)?)?;
    println!("{}", root_envelope_digest(&root)?);
    Ok(())
}
