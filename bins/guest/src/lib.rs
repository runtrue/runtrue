//! Runnable one-job Firecracker guest agent.
//!
//! Secure boot loading and signed-capsule admission happen before the direct
//! in-guest process adapter can be invoked. The adapter never rewrites a
//! `microvm` runner requirement to `native` merely to reuse a host executor.

mod boot;
mod error;
mod process;
mod service;
mod wire;

pub use boot::{load_boot_config, load_capsule_trust_store};
pub use error::GuestAgentError;
pub use process::{DirectStepExecutor, StepExecution, StepExecutor};
pub use service::serve_one_job;
pub use wire::{accept_vsock, GuestFrameReader, GuestFrameWriter, VsockStream};

pub(crate) fn path_io(path: &std::path::Path, source: std::io::Error) -> GuestAgentError {
    GuestAgentError::Io {
        path: path.to_owned(),
        source,
    }
}
