//! Shared run, job, and step lifecycle contracts.
//!
//! This crate has no executor or control-plane dependencies, allowing the CLI,
//! engine, scheduler, server, and runner to validate the same transitions.

mod job;
mod run;
mod step;

pub use job::JobState;
pub use run::RunState;
pub use step::{SkipReason, StepState};
