use crate::{Span, Value, ValueKind};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnaryOperator {
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinaryOperator {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl BinaryOperator {
    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::Or => "||",
            Self::And => "&&",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::Less => "<",
            Self::LessEqual => "<=",
            Self::Greater => ">",
            Self::GreaterEqual => ">=",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SyntaxNode {
    Literal {
        value: Value,
        span: Span,
    },
    Lookup {
        path: Vec<String>,
        span: Span,
    },
    Unary {
        operator: UnaryOperator,
        operator_span: Span,
        operand: Box<Self>,
        span: Span,
    },
    Binary {
        operator: BinaryOperator,
        operator_span: Span,
        left: Box<Self>,
        right: Box<Self>,
        span: Span,
    },
}

impl SyntaxNode {
    pub(crate) const fn span(&self) -> Span {
        match self {
            Self::Literal { span, .. }
            | Self::Lookup { span, .. }
            | Self::Unary { span, .. }
            | Self::Binary { span, .. } => *span,
        }
    }

    pub(crate) fn collect_references(&self, references: &mut BTreeSet<String>) {
        match self {
            Self::Literal { .. } => {}
            Self::Lookup { path, .. } => {
                references.insert(path.join("."));
            }
            Self::Unary { operand, .. } => operand.collect_references(references),
            Self::Binary { left, right, .. } => {
                left.collect_references(references);
                right.collect_references(references);
            }
        }
    }

    pub(crate) fn write_canonical(&self, output: &mut String) {
        match self {
            Self::Literal { value, .. } => write_canonical_literal(value.kind(), output),
            Self::Lookup { path, .. } => output.push_str(&path.join(".")),
            Self::Unary {
                operator: UnaryOperator::Not,
                operand,
                ..
            } => {
                output.push_str("(!");
                operand.write_canonical(output);
                output.push(')');
            }
            Self::Binary {
                operator,
                left,
                right,
                ..
            } => {
                output.push('(');
                left.write_canonical(output);
                output.push(' ');
                output.push_str(operator.text());
                output.push(' ');
                right.write_canonical(output);
                output.push(')');
            }
        }
    }
}

fn write_canonical_literal(value: &ValueKind, output: &mut String) {
    match value {
        ValueKind::Null => output.push_str("null"),
        ValueKind::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
        ValueKind::Number(value) => {
            if *value == 0.0 {
                output.push('0');
            } else {
                output.push_str(&value.to_string());
            }
        }
        ValueKind::String(value) => {
            output.push('"');
            for character in value.chars() {
                match character {
                    '"' => output.push_str("\\\""),
                    '\\' => output.push_str("\\\\"),
                    '\u{0008}' => output.push_str("\\b"),
                    '\u{000c}' => output.push_str("\\f"),
                    '\n' => output.push_str("\\n"),
                    '\r' => output.push_str("\\r"),
                    '\t' => output.push_str("\\t"),
                    character if character.is_control() => {
                        output.push_str(&format!("\\u{:04x}", u32::from(character)));
                    }
                    character => output.push(character),
                }
            }
            output.push('"');
        }
    }
}
