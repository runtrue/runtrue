//! Embedded Cedar authorization with a fixed, validated Runtrue schema.

mod entities;
mod evaluation;
mod model;
mod request;
mod schema;
mod validation;

pub use evaluation::CedarAuthorizationEngine;
pub use model::*;
pub use validation::CedarAuthorizationError;

#[cfg(test)]
mod tests;
