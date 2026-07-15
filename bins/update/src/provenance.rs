use crate::{
    error::CliError,
    verify::{read_bounded, supplied_now, MAX_CLI_TARGET_BYTES},
};
use runtrue_update::{write_new_public_file, ReleaseProvenance, ReleaseSubject};
use std::path::{Path, PathBuf};
pub(crate) fn generate(
    subjects: Vec<String>,
    source_repository: String,
    source_commit: String,
    source_ref: String,
    builder_id: String,
    output: PathBuf,
    built: Option<u64>,
) -> Result<(), CliError> {
    let subjects = subjects
        .iter()
        .map(|s| release_subject(s))
        .collect::<Result<Vec<_>, _>>()?;
    let statement = ReleaseProvenance::new(
        subjects,
        source_repository,
        source_commit,
        source_ref,
        builder_id,
        supplied_now(built)?,
    )?;
    write_new_public_file(&output, &statement.canonical_bytes()?)?;
    println!("{}", output.display());
    Ok(())
}
pub(crate) fn release_subject(value: &str) -> Result<ReleaseSubject, CliError> {
    let (name, path) = value
        .split_once('=')
        .ok_or_else(|| CliError::InvalidSubject(value.to_owned()))?;
    let bytes = read_bounded(Path::new(path), MAX_CLI_TARGET_BYTES)?;
    ReleaseSubject::from_bytes(name, &bytes).map_err(Into::into)
}
