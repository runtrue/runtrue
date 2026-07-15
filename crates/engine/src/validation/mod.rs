//! Validation of authenticated execution capsules.

mod capsule;
mod dag;
mod scalar;

pub(crate) use capsule::validate_capsule;
use dag::validate_acyclic;
use scalar::validate_scalar_invariants;
