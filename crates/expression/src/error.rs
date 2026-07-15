use crate::{Span, ValueType};
use std::{error::Error as StdError, fmt};
use thiserror::Error;

/// An expression syntax error with a precise location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable description of the problem.
    pub message: String,
    /// Location of the invalid input.
    pub span: Span,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at bytes {}..{}",
            self.message, self.span.start, self.span.end
        )
    }
}

impl StdError for ParseError {}

/// The reason expression evaluation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalErrorKind {
    /// A dotted path was not present in the supplied context.
    UnknownContext { path: String },
    /// An operator received a value of the wrong type.
    ExpectedBoolean {
        operator: &'static str,
        found: ValueType,
    },
    /// Relational comparison is not defined for the two operand types.
    Incomparable {
        operator: &'static str,
        left: ValueType,
        right: ValueType,
    },
    /// Evaluation exceeded the defensive recursion limit.
    DepthLimitExceeded,
}

impl fmt::Display for EvalErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContext { path } => write!(formatter, "unknown context path `{path}`"),
            Self::ExpectedBoolean { operator, found } => {
                write!(
                    formatter,
                    "operator `{operator}` requires boolean, found {found}"
                )
            }
            Self::Incomparable {
                operator,
                left,
                right,
            } => write!(
                formatter,
                "operator `{operator}` cannot compare {left} with {right}"
            ),
            Self::DepthLimitExceeded => formatter.write_str("evaluation depth limit exceeded"),
        }
    }
}

/// A runtime expression error with a location in the original expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalError {
    /// The runtime error.
    pub kind: EvalErrorKind,
    /// The expression range responsible for it.
    pub span: Span,
}

impl EvalError {
    pub(crate) fn new(kind: EvalErrorKind, span: Span) -> Self {
        Self { kind, span }
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at bytes {}..{}",
            self.kind, self.span.start, self.span.end
        )
    }
}

impl StdError for EvalError {}

/// A parse or evaluation failure from the one-shot helpers.
#[derive(Debug, Error)]
pub enum ExpressionError {
    /// The expression was invalid.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The expression could not be evaluated in the supplied context.
    #[error(transparent)]
    Evaluation(#[from] EvalError),
}
