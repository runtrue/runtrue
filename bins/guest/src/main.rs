use clap::Parser;
use runtrue_guest::{
    accept_vsock, load_boot_config, load_capsule_trust_store, serve_one_job, DirectStepExecutor,
    GuestAgentError,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-guest",
    version,
    about = "Runtrue one-job microVM guest agent"
)]
struct Arguments {
    /// Protected read-only config drive (JSON followed by zero padding).
    #[arg(long, default_value = "/dev/vdb")]
    boot_config: PathBuf,
    /// Workspace mount prepared by the trusted guest init sequence.
    #[arg(long, default_value = "/workspace")]
    workspace: PathBuf,
}

fn main() {
    if let Err(error) = run(Arguments::parse()) {
        eprintln!("runtrue-guest: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Arguments) -> Result<(), GuestAgentError> {
    let boot = load_boot_config(&arguments.boot_config)?;
    let trust = load_capsule_trust_store(&boot.capsule_trust_directory)?;
    let port = boot.vsock_port;
    let stream = accept_vsock(port)?;
    let reader = stream.clone();
    let executor = Arc::new(DirectStepExecutor::new(arguments.workspace)?);
    serve_one_job(boot, trust, reader, stream, executor)
}
