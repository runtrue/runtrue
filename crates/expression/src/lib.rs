//! A small, deliberately non-executable expression language for workflow conditions.
//!
//! The language contains scalar literals, dotted context lookups, boolean operators,
//! comparisons, and parentheses. It intentionally has no calls, indexing, arithmetic,
//! interpolation, assignment, or implicit type coercion.

mod ast;
mod context;
mod error;
mod evaluation;
mod lexer;
mod parser;
mod span;
mod value;

pub use context::{Context, Resolver};
pub use error::{EvalError, EvalErrorKind, ExpressionError, ParseError};
pub use evaluation::{evaluate, evaluate_bool, MAX_EVALUATION_DEPTH};
pub use lexer::MAX_TOKENS;
pub use parser::{Expression, MAX_EXPRESSION_BYTES, MAX_PARSE_DEPTH};
pub use span::Span;
pub use value::{
    Provenance, Taint, Value, ValueError, ValueKind, ValueType, MAX_EXACT_EXPRESSION_NUMBER,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn value(source: &str) -> Value {
        Expression::parse(source)
            .expect("expression should parse")
            .evaluate(&Context::new())
            .expect("expression should evaluate")
    }

    fn boolean(source: &str) -> bool {
        Expression::parse(source)
            .expect("expression should parse")
            .evaluate_bool(&Context::new())
            .expect("condition should evaluate")
    }

    #[test]
    fn evaluates_all_literal_types() {
        assert_eq!(value("null").kind(), &ValueKind::Null);
        assert_eq!(value("true").as_bool(), Some(true));
        assert_eq!(value("-12.5e2").as_number(), Some(-1_250.0));
        assert_eq!(value(r#""hello\nworld""#).as_str(), Some("hello\nworld"));
        assert_eq!(value(r#"'it\'s safe'"#).as_str(), Some("it's safe"));
        assert_eq!(value(r#""\uD83D\uDE00""#).as_str(), Some("😀"));
    }

    #[test]
    fn honors_operator_precedence_and_parentheses() {
        assert!(boolean("true || false && false"));
        assert!(!boolean("(true || false) && false"));
        assert!(!boolean("!(1 < 2)"));
        assert!(boolean("2 >= 2 && 3 != 4"));
    }

    #[test]
    fn canonical_source_depends_on_syntax_not_formatting() {
        let variants = [
            "event.ok==true && !(inputs.mode == 'slow')",
            " ( event.ok == true )&& ! ( inputs.mode==\"slow\" ) ",
        ];
        let canonical = variants
            .iter()
            .map(|source| Expression::parse(source).unwrap().canonical_source())
            .collect::<Vec<_>>();
        assert_eq!(canonical[0], canonical[1]);
        assert_eq!(
            canonical[0],
            "((event.ok == true) && (!(inputs.mode == \"slow\")))"
        );
        assert_eq!(Expression::parse("-0.0").unwrap().canonical_source(), "0");
        assert!(Expression::parse(&canonical[0]).is_ok());
    }

    #[test]
    fn compares_without_coercion() {
        assert!(boolean(r#""alpha" < "beta""#));
        assert!(boolean(r#"1 != "1""#));
        assert!(boolean("null == null"));

        let error = Expression::parse(r#"1 < "2""#)
            .unwrap()
            .evaluate(&Context::new())
            .unwrap_err();
        assert!(matches!(error.kind, EvalErrorKind::Incomparable { .. }));
    }

    #[test]
    fn resolves_dotted_context_and_reports_references() {
        let mut context = Context::new();
        context.insert("event.pull_request.draft", false);
        context.insert("inputs.minimum", Value::number(3.0).unwrap());
        let expression = Expression::parse(
            "!event.pull_request.draft && inputs.minimum <= 4 && inputs.minimum <= 4",
        )
        .unwrap();

        assert!(expression.evaluate_bool(&context).unwrap());
        assert_eq!(
            expression.context_references(),
            vec![
                "event.pull_request.draft".to_owned(),
                "inputs.minimum".to_owned()
            ]
        );
    }

    #[test]
    fn propagates_taint_and_provenance() {
        let title = Value::string("safe title")
            .mark_untrusted()
            .mark_secret()
            .with_source("github-webhook");
        let mut context = Context::new();
        context.insert("event.pull_request.title", title);

        let result = Expression::parse(r#"event.pull_request.title == "safe title""#)
            .unwrap()
            .evaluate(&context)
            .unwrap();

        assert_eq!(result.as_bool(), Some(true));
        assert!(result.provenance().taint.untrusted);
        assert!(result.provenance().taint.secret);
        assert_eq!(
            result.provenance().sources,
            vec![
                "github-webhook".to_owned(),
                "event.pull_request.title".to_owned()
            ]
        );
    }

    #[test]
    fn boolean_operators_short_circuit() {
        assert!(!Expression::parse("false && missing.value")
            .unwrap()
            .evaluate_bool(&Context::new())
            .unwrap());
        assert!(Expression::parse("true || missing.value")
            .unwrap()
            .evaluate_bool(&Context::new())
            .unwrap());
    }

    #[test]
    fn rejects_truthiness_and_reports_missing_values() {
        let type_error = Expression::parse(r#""nonempty" && true"#)
            .unwrap()
            .evaluate(&Context::new())
            .unwrap_err();
        assert!(matches!(
            type_error.kind,
            EvalErrorKind::ExpectedBoolean {
                found: ValueType::String,
                ..
            }
        ));

        let missing = Expression::parse("event.missing")
            .unwrap()
            .evaluate(&Context::new())
            .unwrap_err();
        assert_eq!(
            missing.kind,
            EvalErrorKind::UnknownContext {
                path: "event.missing".to_owned()
            }
        );
    }

    #[test]
    fn condition_result_must_be_boolean() {
        let error = Expression::parse("42")
            .unwrap()
            .evaluate_bool(&Context::new())
            .unwrap_err();
        assert_eq!(
            error.kind,
            EvalErrorKind::ExpectedBoolean {
                operator: "condition",
                found: ValueType::Number
            }
        );
    }

    #[test]
    fn rejects_executable_or_interpolating_constructs() {
        for invalid in [
            "${{ event.ref == 'main' }}",
            "contains(event.ref, 'main')",
            "event['ref'] == 'main'",
            "1 + 2 == 3",
            "value = true",
            "true & false",
        ] {
            assert!(
                Expression::parse(invalid).is_err(),
                "unexpectedly accepted: {invalid}"
            );
        }
    }

    #[test]
    fn rejects_malformed_literals_and_expressions() {
        for invalid in [
            "",
            "01 == 1",
            "1e",
            "1.",
            r#""unterminated"#,
            r#""\q""#,
            r#""\uD800""#,
            "(true",
            "true false",
            "event.",
        ] {
            assert!(
                Expression::parse(invalid).is_err(),
                "unexpectedly accepted: {invalid}"
            );
        }
        assert!(Value::number(f64::NAN).is_err());
        assert!(Value::number(f64::INFINITY).is_err());
    }

    #[test]
    fn rejects_numbers_that_cannot_be_compared_exactly() {
        for source in ["9007199254740992", "9007199254740993", "1e20"] {
            let error = Expression::parse(source).unwrap_err().to_string();
            assert!(error.contains("exact expression range"), "{error}");
        }
        assert!(matches!(
            Value::integer(9_007_199_254_740_992),
            Err(ValueError::InexactNumberRange)
        ));
        assert!(Value::integer(9_007_199_254_740_991).is_ok());
    }

    #[test]
    fn enforces_size_and_nesting_limits() {
        let oversized = "x".repeat(MAX_EXPRESSION_BYTES + 1);
        assert!(Expression::parse(&oversized).is_err());

        let nested = format!(
            "{}true{}",
            "(".repeat(MAX_PARSE_DEPTH + 1),
            ")".repeat(MAX_PARSE_DEPTH + 1)
        );
        assert!(Expression::parse(&nested).is_err());
    }

    #[test]
    fn debug_output_redacts_secret_payloads() {
        let value = Value::string("do-not-print").mark_secret();
        let debug = format!("{value:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-print"));
    }

    #[test]
    fn provenance_merge_is_stable_and_deduplicated() {
        let first = Provenance::from_source("event", Taint::untrusted());
        let mut second = Provenance::from_source("input", Taint::secret());
        second.add_source("event");
        let merged = first.merge(&second);

        assert_eq!(merged.sources, vec!["event", "input"]);
        assert_eq!(
            merged.taint,
            Taint {
                untrusted: true,
                secret: true
            }
        );
    }
}
