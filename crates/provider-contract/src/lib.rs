//! Portable Provider contracts shared by local and remote Runtrue implementations.
//!
//! This crate contains only domain-neutral protocol types and synchronous
//! facades. It deliberately has no workflow, SCM, GitHub, executor, database,
//! or transport dependency. Implementations may call the traits in process or
//! adapt them to a versioned remote protocol without changing their semantics.

mod attestation;
mod canonical;
mod capability;
mod checkpoint;
mod conformance;
mod contract;
mod effects;
mod error;
mod evidence;
mod failure;
mod package;
mod pool;
mod provider;
mod retention;
mod retry;
mod storage;

pub use attestation::*;
pub use capability::*;
pub use checkpoint::*;
pub use conformance::*;
pub use contract::*;
pub use effects::*;
pub use error::ProviderContractError;
pub use evidence::*;
pub use failure::*;
pub use package::*;
pub use pool::*;
pub use provider::*;
pub use retention::*;
pub use retry::*;
pub use storage::*;

#[cfg(test)]
mod tests;
