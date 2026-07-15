pub(crate) fn normalize_triggers(triggers: &ast::Triggers) -> ast::Triggers {
    fn normalize_git(trigger: &mut Option<ast::GitTrigger>) {
        let Some(trigger) = trigger else {
            return;
        };
        for values in [
            &mut trigger.branches,
            &mut trigger.branches_ignore,
            &mut trigger.paths,
            &mut trigger.paths_ignore,
        ] {
            values.sort();
            values.dedup();
        }
    }

    let mut normalized = triggers.clone();
    normalize_git(&mut normalized.push);
    normalize_git(&mut normalized.pull_request);
    normalized
        .schedule
        .sort_by(|left, right| (&left.cron, &left.timezone).cmp(&(&right.cron, &right.timezone)));
    normalized.schedule.dedup();
    normalized
}

pub(crate) fn validate_identifier(value: &str, path: &str) -> Result<(), CompileError> {
    let expression = Regex::new(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$").expect("static regex");
    if expression.is_match(value) {
        Ok(())
    } else {
        Err(CompileError::semantic(
            path,
            format!("`{value}` is not a valid identifier"),
        ))
    }
}

pub(crate) fn validate_environment_name(value: &str, path: &str) -> Result<(), CompileError> {
    let expression = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("static regex");
    if expression.is_match(value) {
        Ok(())
    } else {
        Err(CompileError::semantic(
            path,
            "invalid environment variable name",
        ))
    }
}

pub(crate) fn normalize_expression(value: &str, path: &str) -> Result<String, CompileError> {
    let expression = Expression::parse(value).map_err(|error| {
        CompileError::semantic(path, format!("invalid typed expression: {error}"))
    })?;
    const ALLOWED_ROOTS: [&str; 10] = [
        "event",
        "matrix",
        "vars",
        "inputs",
        "needs",
        "steps",
        "git",
        "success",
        "failure",
        "cancelled",
    ];
    let references = expression.context_references();
    for reference in &references {
        let root = reference.split('.').next().unwrap_or_default();
        if !ALLOWED_ROOTS.contains(&root) {
            return Err(CompileError::semantic(
                path,
                format!("unknown expression context root `{root}`"),
            ));
        }
    }
    if references.is_empty() {
        expression
            .evaluate_bool(&ExpressionContext::new())
            .map_err(|error| {
                CompileError::semantic(
                    path,
                    format!("condition must evaluate to a boolean: {error}"),
                )
            })?;
    }
    Ok(expression.canonical_source())
}

pub(crate) fn validate_external_reference(reference: &str, path: &str) -> Result<(), CompileError> {
    if reference.is_empty()
        || reference.chars().any(char::is_whitespace)
        || reference.chars().any(char::is_control)
    {
        return Err(CompileError::semantic(
            path,
            "reference source must be non-empty and contain no whitespace or control characters",
        ));
    }
    if let Some((source, selector)) = reference.rsplit_once('@') {
        let digest_selector = selector.eq_ignore_ascii_case("sha256")
            || selector
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"));
        if !digest_selector {
            return Ok(());
        }
        if source.is_empty() {
            return Err(CompileError::semantic(
                path,
                "reference source must be non-empty and contain no whitespace or control characters",
            ));
        }
        let Some(digest) = selector.strip_prefix("sha256:") else {
            return Err(CompileError::semantic(
                path,
                "reference digest must use the lowercase sha256 algorithm name",
            ));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CompileError::semantic(
                path,
                "reference digest must contain 64 lowercase hexadecimal characters",
            ));
        }
    }
    Ok(())
}
use super::{ast, CompileError, Expression, ExpressionContext, Regex};
