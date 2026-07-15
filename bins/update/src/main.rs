mod apply;
mod bootstrap;
mod cargo_metadata;
mod cli;
mod error;
mod keys;
mod output;
mod provenance;
mod root;
mod sbom;
mod verify;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;

fn main() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::RootDigest { root } => root::digest(root),
        Command::Bootstrap {
            root,
            expected_root_digest,
            state,
            now_unix_seconds,
        } => bootstrap::bootstrap(root, expected_root_digest, state, now_unix_seconds),
        Command::Verify {
            state,
            bundle,
            target_path,
            target_file,
            now_unix_seconds,
        } => verify::command(state, bundle, target_path, target_file, now_unix_seconds),
        Command::Apply {
            state,
            bundle,
            target_path,
            target_file,
            now_unix_seconds,
        } => apply::apply(state, bundle, target_path, target_file, now_unix_seconds),
        Command::Keygen { output } => keys::generate(output),
        Command::Provenance {
            subjects,
            source_repository,
            source_commit,
            source_ref,
            builder_id,
            output,
            built_unix_seconds,
        } => provenance::generate(
            subjects,
            source_repository,
            source_commit,
            source_ref,
            builder_id,
            output,
            built_unix_seconds,
        ),
        Command::Sbom {
            components,
            package,
            cargo_metadata,
            cargo_lock,
            version,
            output,
        } => sbom::generate(
            components,
            package,
            cargo_metadata,
            cargo_lock,
            version,
            output,
        ),
    }
}
