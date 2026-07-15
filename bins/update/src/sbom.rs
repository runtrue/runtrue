use crate::{
    cargo_metadata::cargo_dependency_graph, error::CliError, provenance::release_subject,
    verify::read_bounded,
};
use runtrue_update::{write_new_public_file, CycloneDxBom};
use std::path::PathBuf;
const MAX_CARGO_METADATA_BYTES: usize = 32 * 1024 * 1024;
pub(crate) fn generate(
    components: Vec<String>,
    package: String,
    cargo_metadata: PathBuf,
    cargo_lock: PathBuf,
    version: String,
    output: PathBuf,
) -> Result<(), CliError> {
    let components = components
        .iter()
        .map(|c| release_subject(c))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata = read_bounded(&cargo_metadata, MAX_CARGO_METADATA_BYTES)?;
    let lock = read_bounded(&cargo_lock, MAX_CARGO_METADATA_BYTES)?;
    let (root_package_id, packages) = cargo_dependency_graph(&metadata, &lock, &package)?;
    let bom =
        CycloneDxBom::from_cargo_graph(package, version, components, root_package_id, packages)?;
    write_new_public_file(&output, &bom.canonical_bytes()?)?;
    println!("{}", output.display());
    Ok(())
}
