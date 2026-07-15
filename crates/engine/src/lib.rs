//! Shared, synchronous execution state machine for Runtrue execution capsules.
//!
//! The crate root remains a compatibility facade. Domain modules expose the
//! same public API while the state machine implementation lives under
//! [`engine`].

mod bindings;
pub mod cancellation;
mod conditions;
pub mod context;
mod engine;
pub mod error;
pub mod events;
pub mod executor;
pub mod model;
pub mod native;
mod outputs;
mod validation;

pub use cancellation::*;
pub use engine::*;
pub use error::*;
pub use events::*;
pub use executor::*;
pub use model::*;
pub use native::*;
