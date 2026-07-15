//! Portable Provider contracts shared by local and remote Runtrue implementations.
//!
//! This crate contains only domain-neutral protocol types and synchronous
//! facades. It deliberately has no workflow, SCM, GitHub, executor, database,
//! or transport dependency. Implementations may call the traits in process or
//! adapt them to a versioned remote protocol without changing their semantics.

mod canonical;
mod capability;
mod checkpoint;
mod conformance;
mod contract;
mod effects;
mod error;
mod evidence;
mod failure;
mod pool;
mod provider;
mod storage;

pub use capability::*;
pub use checkpoint::*;
pub use conformance::*;
pub use contract::*;
pub use effects::*;
pub use error::ProviderContractError;
pub use evidence::*;
pub use failure::*;
pub use pool::*;
pub use provider::*;
pub use storage::*;

#[cfg(test)]
mod tests;
