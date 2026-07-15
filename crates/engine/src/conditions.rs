//! Runtime condition evaluation.

use crate::{EngineError, RuntimeContext};
use runtrue_expression::{Context as ExpressionContext, Value as ExpressionValue};
use runtrue_workflow_ir::ScalarValue;

pub(crate) fn evaluate_condition(
    condition: Option<&str>,
    context: &RuntimeContext,
) -> Result<bool, EngineError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let expression = unwrap_expression(condition);
    let mut expression_context = ExpressionContext::new();
    for (path, value) in context {
        let value = expression_value(value).map_err(|message| EngineError::InvalidCondition {
            expression: condition.to_owned(),
            message,
        })?;
        expression_context.insert(path.clone(), value);
    }
    runtrue_expression::evaluate_bool(expression, &expression_context).map_err(|error| {
        EngineError::InvalidCondition {
            expression: condition.to_owned(),
            message: error.to_string(),
        }
    })
}

fn unwrap_expression(expression: &str) -> &str {
    let expression = expression.trim();
    expression
        .strip_prefix("${{")
        .and_then(|inner| inner.strip_suffix("}}"))
        .map_or(expression, str::trim)
}

fn expression_value(value: &ScalarValue) -> Result<ExpressionValue, String> {
    match value {
        ScalarValue::String(value) => Ok(ExpressionValue::string(value.clone())),
        ScalarValue::Integer(value) => {
            ExpressionValue::integer(*value).map_err(|error| error.to_string())
        }
        ScalarValue::Number(value) => {
            ExpressionValue::number(*value).map_err(|error| error.to_string())
        }
        ScalarValue::Boolean(value) => Ok(ExpressionValue::boolean(*value)),
    }
}
