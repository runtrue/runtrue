use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

/// Largest integer magnitude that the current numeric representation compares exactly.
pub const MAX_EXACT_EXPRESSION_NUMBER: f64 = 9_007_199_254_740_991.0;

/// The runtime type of a workflow expression value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    /// The null value.
    Null,
    /// A boolean.
    Boolean,
    /// A finite floating-point number.
    Number,
    /// A UTF-8 string.
    String,
}

impl fmt::Display for ValueType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::String => "string",
        })
    }
}

/// Security labels propagated through expression evaluation.
///
/// Trust and confidentiality are orthogonal: a value may be both untrusted and secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Taint {
    /// The value ultimately depends on an untrusted source.
    pub untrusted: bool,
    /// The value ultimately depends on secret data.
    pub secret: bool,
}

impl Taint {
    /// A value with no security taint.
    #[must_use]
    pub const fn trusted() -> Self {
        Self {
            untrusted: false,
            secret: false,
        }
    }

    /// A public value controlled by an untrusted principal.
    #[must_use]
    pub const fn untrusted() -> Self {
        Self {
            untrusted: true,
            secret: false,
        }
    }

    /// A trusted confidential value.
    #[must_use]
    pub const fn secret() -> Self {
        Self {
            untrusted: false,
            secret: true,
        }
    }

    /// Combines two labels without ever removing taint.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self {
            untrusted: self.untrusted || other.untrusted,
            secret: self.secret || other.secret,
        }
    }

    /// Whether the value has no untrusted dependency.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        !self.untrusted
    }

    /// Whether the value is confidential.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        self.secret
    }
}

/// Security and origin metadata attached to every value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Security labels accumulated from inputs.
    pub taint: Taint,
    /// Stable, human-readable input source names.
    pub sources: Vec<String>,
}

impl Provenance {
    /// Creates provenance for one named source.
    #[must_use]
    pub fn from_source(source: impl Into<String>, taint: Taint) -> Self {
        Self {
            taint,
            sources: vec![source.into()],
        }
    }

    /// Adds a source, retaining deterministic insertion order and removing duplicates.
    pub fn add_source(&mut self, source: impl Into<String>) {
        let source = source.into();
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    /// Combines provenance without removing any source or taint.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.taint = result.taint.merge(other.taint);
        for source in &other.sources {
            result.add_source(source.clone());
        }
        result
    }
}

/// The data portion of a typed value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ValueKind {
    /// The null value.
    Null,
    /// A boolean value.
    Boolean(bool),
    /// A finite number.
    Number(f64),
    /// A string value.
    String(String),
}

impl ValueKind {
    /// Returns this value's runtime type.
    #[must_use]
    pub const fn value_type(&self) -> ValueType {
        match self {
            Self::Null => ValueType::Null,
            Self::Boolean(_) => ValueType::Boolean,
            Self::Number(_) => ValueType::Number,
            Self::String(_) => ValueType::String,
        }
    }
}

/// An invalid value supplied by an embedding application.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ValueError {
    /// NaN and infinities are intentionally outside the expression value domain.
    #[error("expression numbers must be finite")]
    NonFiniteNumber,
    /// The current f64-backed evaluator cannot safely distinguish larger integers.
    #[error("expression numbers must stay within the exact range +/-9007199254740991")]
    InexactNumberRange,
}

/// A typed scalar and its security provenance.
#[derive(Clone, PartialEq, Serialize)]
pub struct Value {
    pub(crate) kind: ValueKind,
    pub(crate) provenance: Provenance,
}

#[derive(Deserialize)]
struct ValueRepresentation {
    kind: ValueKind,
    provenance: Provenance,
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let representation = ValueRepresentation::deserialize(deserializer)?;
        Self::from_kind(representation.kind)
            .map(|value| value.with_provenance(representation.provenance))
            .map_err(de::Error::custom)
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Value");
        if self.provenance.taint.secret {
            debug.field("kind", &"<redacted>");
        } else {
            debug.field("kind", &self.kind);
        }
        debug.field("provenance", &self.provenance).finish()
    }
}

impl Value {
    /// Creates null with trusted, literal provenance.
    #[must_use]
    pub fn null() -> Self {
        Self {
            kind: ValueKind::Null,
            provenance: Provenance::default(),
        }
    }

    /// Creates a boolean with trusted, literal provenance.
    #[must_use]
    pub fn boolean(value: bool) -> Self {
        Self {
            kind: ValueKind::Boolean(value),
            provenance: Provenance::default(),
        }
    }

    /// Creates a finite number with trusted, literal provenance.
    pub fn number(value: f64) -> Result<Self, ValueError> {
        Self::from_kind(ValueKind::Number(value))
    }

    /// Creates an exactly representable integer-valued expression number.
    pub fn integer(value: i64) -> Result<Self, ValueError> {
        #[allow(clippy::cast_precision_loss)]
        let value = value as f64;
        Self::number(value)
    }

    /// Creates a string with trusted, literal provenance.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self {
            kind: ValueKind::String(value.into()),
            provenance: Provenance::default(),
        }
    }

    /// Creates a value from its data representation, validating numeric invariants.
    pub fn from_kind(kind: ValueKind) -> Result<Self, ValueError> {
        if matches!(&kind, ValueKind::Number(number) if !number.is_finite()) {
            return Err(ValueError::NonFiniteNumber);
        }
        if matches!(&kind, ValueKind::Number(number) if number.abs() > MAX_EXACT_EXPRESSION_NUMBER)
        {
            return Err(ValueError::InexactNumberRange);
        }
        Ok(Self {
            kind,
            provenance: Provenance::default(),
        })
    }

    /// Returns the data portion of this value.
    #[must_use]
    pub const fn kind(&self) -> &ValueKind {
        &self.kind
    }

    /// Consumes the value and returns its data portion.
    #[must_use]
    pub fn into_kind(self) -> ValueKind {
        self.kind
    }

    /// Returns the value's runtime type.
    #[must_use]
    pub const fn value_type(&self) -> ValueType {
        self.kind.value_type()
    }

    /// Returns the boolean payload, or `None` for every other type.
    ///
    /// This method performs no truthiness conversion.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match &self.kind {
            ValueKind::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the numeric payload, or `None` for every other type.
    #[must_use]
    pub const fn as_number(&self) -> Option<f64> {
        match &self.kind {
            ValueKind::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the string payload, or `None` for every other type.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            ValueKind::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns this value's provenance.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Replaces this value's provenance.
    #[must_use]
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Replaces this value's taint while preserving source names.
    #[must_use]
    pub fn with_taint(mut self, taint: Taint) -> Self {
        self.provenance.taint = taint;
        self
    }

    /// Marks this value as dependent on untrusted input.
    #[must_use]
    pub fn mark_untrusted(mut self) -> Self {
        self.provenance.taint.untrusted = true;
        self
    }

    /// Marks this value as secret.
    #[must_use]
    pub fn mark_secret(mut self) -> Self {
        self.provenance.taint.secret = true;
        self
    }

    /// Adds a named origin to this value.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.provenance.add_source(source);
        self
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::boolean(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::string(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::string(value)
    }
}
