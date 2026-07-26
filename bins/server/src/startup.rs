//! Reusable server-process lifecycle for statically assembled distributions.

#[path = "main.rs"]
#[allow(dead_code)]
mod implementation;

pub use implementation::run_with_composition;
