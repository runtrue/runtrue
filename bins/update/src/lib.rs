mod apply;
mod bootstrap;
mod cargo_metadata;
mod cli;
mod error;
mod fixed_host;
mod keys;
mod output;
mod provenance;
mod root;
mod sbom;
mod stage;
mod verify;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_inner().map_err(Into::into)
}

fn run_inner() -> Result<(), CliError> {
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
        Command::StageRunner {
            state,
            bundle,
            target_path,
            target_file,
            component_profile,
            installation_root,
            generation,
            now_unix_seconds,
        } => stage::stage_runner(
            state,
            bundle,
            target_path,
            target_file,
            component_profile,
            installation_root,
            generation,
            now_unix_seconds,
        ),
        Command::FixedHostProof {
            key,
            pool_id,
            slot_id,
            issued_unix_ms,
        } => fixed_host::proof(key, pool_id, slot_id, issued_unix_ms),
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
