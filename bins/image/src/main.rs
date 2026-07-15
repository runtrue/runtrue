mod cli;
mod digest;
mod error;
mod keys;
mod manifest;
mod output;
mod secure_fs;
mod sign;
mod snapshot;
mod verify;

use clap::Parser;
use cli::{Cli, Command};
use error::ImageCliError;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("runtrue-image: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), ImageCliError> {
    match cli.command {
        Command::Keygen {
            private_key,
            public_key,
        } => keys::generate(private_key, public_key, cli.json),
        Command::Digest { file } => digest::command(file, cli.json),
        Command::Manifest {
            kind,
            name,
            payload,
            payload_media_type,
            operating_system,
            architecture,
            builder_id,
            provenance,
            sbom,
            created_unix_ms,
            expires_unix_ms,
            snapshot_phase,
            components,
            compatibility,
            output,
        } => manifest::create(
            manifest::CreateRequest {
                kind: kind.into(),
                name,
                payload,
                payload_media_type,
                operating_system,
                architecture,
                builder_id,
                provenance,
                sbom,
                created_unix_ms,
                expires_unix_ms,
                snapshot_phase: snapshot_phase.map(Into::into),
                components,
                compatibility,
                output,
            },
            cli.json,
        ),
        Command::Sign {
            manifest,
            private_key,
            output,
        } => sign::sign(manifest, private_key, output, cli.json),
        Command::Verify {
            signed_manifest,
            public_key,
            payload,
            provenance,
            sbom,
            now_unix_ms,
            require_warm_snapshot,
        } => verify::verify(
            verify::VerifyRequest {
                signed_manifest,
                public_key,
                payload,
                provenance,
                sbom,
                now_unix_ms,
                require_warm_snapshot,
            },
            cli.json,
        ),
    }
}
