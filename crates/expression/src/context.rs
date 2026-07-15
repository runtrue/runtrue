use crate::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A source of values for dotted lookups.
pub trait Resolver {
    /// Returns an owned value for `path`, or `None` when the path is not defined.
    fn resolve(&self, path: &[&str]) -> Option<Value>;
}

/// A deterministic, flattened workflow expression context.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Context {
    values: BTreeMap<String, Value>,
}

impl Context {
    /// Creates an empty context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Inserts a dotted path. Existing values at the exact path are replaced.
    pub fn insert(&mut self, path: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        self.values.insert(path.into(), value.into())
    }

    /// Adds a value and returns the context for builder-style construction.
    #[must_use]
    pub fn with_value(mut self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        self.insert(path, value);
        self
    }

    /// Gets a value at an exact dotted path.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Value> {
        self.values.get(path)
    }

    /// Iterates over context entries in lexicographic path order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.values
            .iter()
            .map(|(path, value)| (path.as_str(), value))
    }
}

impl Resolver for Context {
    fn resolve(&self, path: &[&str]) -> Option<Value> {
        self.values.get(&path.join(".")).cloned()
    }
}

impl Resolver for BTreeMap<String, Value> {
    fn resolve(&self, path: &[&str]) -> Option<Value> {
        self.get(&path.join(".")).cloned()
    }
}
