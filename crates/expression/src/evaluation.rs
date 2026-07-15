use crate::{
    ast::{BinaryOperator, SyntaxNode, UnaryOperator},
    EvalError, EvalErrorKind, Expression, ExpressionError, Provenance, Resolver, Span, Value,
    ValueKind,
};

/// Maximum recursive evaluator depth.
pub const MAX_EVALUATION_DEPTH: usize = 256;

/// Parses and evaluates an expression in one call.
pub fn evaluate<R>(source: &str, resolver: &R) -> Result<Value, ExpressionError>
where
    R: Resolver + ?Sized,
{
    Ok(Expression::parse(source)?.evaluate(resolver)?)
}

/// Parses and evaluates a boolean workflow condition in one call.
pub fn evaluate_bool<R>(source: &str, resolver: &R) -> Result<bool, ExpressionError>
where
    R: Resolver + ?Sized,
{
    Ok(Expression::parse(source)?.evaluate_bool(resolver)?)
}

pub(crate) fn evaluate_node<R>(
    node: &SyntaxNode,
    resolver: &R,
    depth: usize,
) -> Result<Value, EvalError>
where
    R: Resolver + ?Sized,
{
    if depth > MAX_EVALUATION_DEPTH {
        return Err(EvalError::new(
            EvalErrorKind::DepthLimitExceeded,
            node.span(),
        ));
    }

    match node {
        SyntaxNode::Literal { value, .. } => Ok(value.clone()),
        SyntaxNode::Lookup { path, span } => {
            let path_parts: Vec<&str> = path.iter().map(String::as_str).collect();
            let joined = path.join(".");
            let mut value = resolver.resolve(&path_parts).ok_or_else(|| {
                EvalError::new(
                    EvalErrorKind::UnknownContext {
                        path: joined.clone(),
                    },
                    *span,
                )
            })?;
            value.provenance.add_source(joined);
            Ok(value)
        }
        SyntaxNode::Unary {
            operator,
            operator_span,
            operand,
            ..
        } => {
            let value = evaluate_node(operand, resolver, depth + 1)?;
            match operator {
                UnaryOperator::Not => {
                    let (boolean, provenance) = require_boolean(value, "!", *operator_span)?;
                    Ok(Value::boolean(!boolean).with_provenance(provenance))
                }
            }
        }
        SyntaxNode::Binary {
            operator,
            operator_span,
            left,
            right,
            ..
        } => evaluate_binary(*operator, *operator_span, left, right, resolver, depth),
    }
}

fn evaluate_binary<R>(
    operator: BinaryOperator,
    operator_span: Span,
    left: &SyntaxNode,
    right: &SyntaxNode,
    resolver: &R,
    depth: usize,
) -> Result<Value, EvalError>
where
    R: Resolver + ?Sized,
{
    match operator {
        BinaryOperator::And => {
            let left = evaluate_node(left, resolver, depth + 1)?;
            let (left_boolean, left_provenance) =
                require_boolean(left, operator.text(), operator_span)?;
            if !left_boolean {
                return Ok(Value::boolean(false).with_provenance(left_provenance));
            }
            let right = evaluate_node(right, resolver, depth + 1)?;
            let (right_boolean, right_provenance) =
                require_boolean(right, operator.text(), operator_span)?;
            Ok(Value::boolean(right_boolean)
                .with_provenance(left_provenance.merge(&right_provenance)))
        }
        BinaryOperator::Or => {
            let left = evaluate_node(left, resolver, depth + 1)?;
            let (left_boolean, left_provenance) =
                require_boolean(left, operator.text(), operator_span)?;
            if left_boolean {
                return Ok(Value::boolean(true).with_provenance(left_provenance));
            }
            let right = evaluate_node(right, resolver, depth + 1)?;
            let (right_boolean, right_provenance) =
                require_boolean(right, operator.text(), operator_span)?;
            Ok(Value::boolean(right_boolean)
                .with_provenance(left_provenance.merge(&right_provenance)))
        }
        BinaryOperator::Equal | BinaryOperator::NotEqual => {
            let left = evaluate_node(left, resolver, depth + 1)?;
            let right = evaluate_node(right, resolver, depth + 1)?;
            let provenance = left.provenance.merge(&right.provenance);
            let equal = values_equal(&left.kind, &right.kind);
            let result = if operator == BinaryOperator::Equal {
                equal
            } else {
                !equal
            };
            Ok(Value::boolean(result).with_provenance(provenance))
        }
        BinaryOperator::Less
        | BinaryOperator::LessEqual
        | BinaryOperator::Greater
        | BinaryOperator::GreaterEqual => {
            let left = evaluate_node(left, resolver, depth + 1)?;
            let right = evaluate_node(right, resolver, depth + 1)?;
            let provenance = left.provenance.merge(&right.provenance);
            let ordering = compare_values(&left.kind, &right.kind).ok_or_else(|| {
                EvalError::new(
                    EvalErrorKind::Incomparable {
                        operator: operator.text(),
                        left: left.value_type(),
                        right: right.value_type(),
                    },
                    operator_span,
                )
            })?;
            let result = match operator {
                BinaryOperator::Less => ordering.is_lt(),
                BinaryOperator::LessEqual => ordering.is_le(),
                BinaryOperator::Greater => ordering.is_gt(),
                BinaryOperator::GreaterEqual => ordering.is_ge(),
                _ => unreachable!("relational match arm only receives relational operators"),
            };
            Ok(Value::boolean(result).with_provenance(provenance))
        }
    }
}

fn require_boolean(
    value: Value,
    operator: &'static str,
    span: Span,
) -> Result<(bool, Provenance), EvalError> {
    let value_type = value.value_type();
    match value.kind {
        ValueKind::Boolean(boolean) => Ok((boolean, value.provenance)),
        _ => Err(EvalError::new(
            EvalErrorKind::ExpectedBoolean {
                operator,
                found: value_type,
            },
            span,
        )),
    }
}

fn values_equal(left: &ValueKind, right: &ValueKind) -> bool {
    match (left, right) {
        (ValueKind::Null, ValueKind::Null) => true,
        (ValueKind::Boolean(left), ValueKind::Boolean(right)) => left == right,
        (ValueKind::Number(left), ValueKind::Number(right)) => left == right,
        (ValueKind::String(left), ValueKind::String(right)) => left == right,
        _ => false,
    }
}

fn compare_values(left: &ValueKind, right: &ValueKind) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (ValueKind::Number(left), ValueKind::Number(right)) => left.partial_cmp(right),
        (ValueKind::String(left), ValueKind::String(right)) => Some(left.cmp(right)),
        _ => None,
    }
}
