//! Authenticated SCM webhook ingestion and provider-neutral event normalization.
//!
//! Provider payloads are read once as bounded bytes, authenticated before JSON
//! parsing, and converted into a small typed envelope. Repository workflows see
//! this normalized model rather than provider-controlled arbitrary JSON.

mod error;
pub use error::*;
mod model;
pub use model::*;
mod provider;
pub use provider::*;
mod github;
pub use github::*;
mod workflow_source;
pub use workflow_source::*;
