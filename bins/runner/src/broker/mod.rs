//! Runner-side, one-shot capability brokers for Wasm component execution.
//!
//! Secret and OIDC material exists only inside redacting, zeroizing wrappers
//! and is never placed in the process environment, runner state, or logs.

mod bindings;
mod client;
mod envelope;
mod oidc;
mod scm;
mod secrets;

pub use bindings::BrokerExecutionBinding;
pub use client::{ObjectUploadBinding, RunnerBrokerClient};
pub(crate) use scm::{ScmCredentialObserver, ScmRuntimeFiles};

use runtrue_executor_wasm::CapabilityAdapters;
use std::sync::Arc;

#[must_use]
pub fn wasm_broker_adapters(
    binding: BrokerExecutionBinding,
    client: Arc<dyn RunnerBrokerClient>,
) -> CapabilityAdapters {
    CapabilityAdapters::new()
        .with_secrets(Arc::new(secrets::RunnerSecretAdapter {
            binding: binding.clone(),
            client: client.clone(),
        }))
        .with_oidc(Arc::new(oidc::RunnerOidcAdapter { binding, client }))
}

#[cfg(test)]
mod tests;
