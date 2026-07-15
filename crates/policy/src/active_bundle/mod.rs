//! Canonical, bounded, deny-first active policy bundle state.

mod activation;
mod canonical;
mod model;
mod simulation;
mod snapshot;
mod validation;

pub use model::*;
pub use validation::ActivePolicyError;

#[cfg(test)]
mod tests;
