//! Strict native-workflow compiler.
//!
//! Compilation is pure: it parses data, validates semantics, expands matrices,
//! calculates effective permissions, and emits a deterministic execution capsule.
//! It never evaluates repository code or resolves mutable network references.

use regex::Regex;
use runtrue_expression::{Context as ExpressionContext, Expression};
use runtrue_lock::{LockFile, LockRequirements};
use runtrue_model::{
    normalize_relative_path, ByteSize, ContentDigest, DurationMillis, ModelError, SecretReference,
};
use runtrue_workflow_ast as ast;
use runtrue_workflow_ir as ir;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const DEFAULT_JOB_TIMEOUT_MS: u64 = 3_600_000;
const DEFAULT_FINALIZER_TIMEOUT_MS: u64 = 120_000;
const MAX_FINALIZER_TIMEOUT_MS: u64 = 600_000;
const DEFAULT_MAX_MATRIX_JOBS: usize = 256;
const DEFAULT_MAX_REUSABLE_DEPTH: usize = 8;
const DEFAULT_MAX_REUSABLE_JOBS: usize = 256;
const MAX_WORKFLOW_JOBS: usize = 1_024;
const MAX_STEPS_PER_JOB: usize = 1_000;
const MAX_SIGNING_CAPABILITIES: usize = 32;
const MAX_SIGNING_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REUSABLE_SOURCES: usize = 256;
pub const MAX_REUSABLE_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_REUSABLE_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

mod bindings;
mod compiler;
mod context;
mod error;
mod jobs;
mod matrix;
mod permissions;
mod reusable;
mod risk;
mod settings;
mod steps;
mod triggers;
mod validation;

pub use compiler::Compiler;
pub use context::{ApprovalSubject, Compilation, CompileContext, RunnerApprovalProfile};
pub use error::CompileError;
pub use reusable::source::{
    ReusableSourceBundleError, ReusableWorkflowSource, ReusableWorkflowSources,
};
pub use risk::{semantic_risk_diff, RiskFinding, RiskReport, RiskSeverity};
pub use settings::CompilerSettings;

pub(crate) use bindings::*;
pub(crate) use context::*;
pub(crate) use jobs::*;
pub(crate) use matrix::*;
pub(crate) use permissions::*;
pub(crate) use reusable::*;
pub(crate) use risk::{collect_permission_risks, collect_step_risks};
pub(crate) use steps::*;
pub(crate) use triggers::*;
pub(crate) use validation::*;

#[cfg(test)]
mod tests {
    mod compile;
    mod matrix;
    mod reusable;
    mod risk;
    mod validation;
}
