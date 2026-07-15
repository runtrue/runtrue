//! Exact-action emergency authorization with independent approval and notification.

mod lifecycle;
mod model;
mod validation;

pub use model::*;
pub use validation::BreakGlassError;

#[cfg(test)]
mod tests;
