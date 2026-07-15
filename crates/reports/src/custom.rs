use crate::{
    limits::{bounded_string, checked_add},
    strict_json::{
        optional_coordinate, parse_strict_json, reject_unknown, required, safe_path,
        validate_region,
    },
    Annotation, AnnotationLevel, ParseOutput, ReportError, ReportLimits, ReportSummary,
};

const CUSTOM_SCHEMA: &str = "runtrue.report.v1";

pub(crate) fn parse_custom(input: &[u8], limits: ReportLimits) -> Result<ParseOutput, ReportError> {
    let root = parse_strict_json(input, limits)?;
    let object = root.object("custom report")?;
    reject_unknown(object, &["schema", "events"], "custom report")?;
    let schema = required(object, "schema", "custom report")?.string("custom report.schema")?;
    if schema != CUSTOM_SCHEMA {
        return Err(ReportError::UnsupportedVersion(schema.to_owned()));
    }
    let events = required(object, "events", "custom report")?.array("custom report.events")?;
    if events.len() > limits.max_results {
        return Err(ReportError::ComplexityLimit);
    }

    let mut summary = ReportSummary::default();
    let mut annotations = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let context = format!("custom report.events[{index}]");
        let event = event.object(&context)?;
        reject_unknown(
            event,
            &[
                "level",
                "message",
                "rule_id",
                "path",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
            ],
            &context,
        )?;
        let level = match required(event, "level", &context)?.string(&format!("{context}.level"))? {
            "notice" => AnnotationLevel::Notice,
            "warning" => AnnotationLevel::Warning,
            "error" => AnnotationLevel::Error,
            _ => {
                return Err(ReportError::Malformed(format!(
                    "{context}.level is invalid"
                )))
            }
        };
        let message = bounded_string(
            required(event, "message", &context)?.string(&format!("{context}.message"))?,
            limits,
        )?;
        let rule_id = event
            .get("rule_id")
            .map(|value| bounded_string(value.string(&format!("{context}.rule_id"))?, limits))
            .transpose()?;
        let path = event
            .get("path")
            .map(|value| safe_path(value.string(&format!("{context}.path"))?))
            .transpose()?;
        let start_line = optional_coordinate(event, "start_line", &context)?;
        let start_column = optional_coordinate(event, "start_column", &context)?;
        let end_line = optional_coordinate(event, "end_line", &context)?;
        let end_column = optional_coordinate(event, "end_column", &context)?;
        validate_region(start_line, start_column, end_line, end_column, &context)?;

        checked_add(&mut summary.total, 1)?;
        match level {
            AnnotationLevel::Notice => checked_add(&mut summary.passed, 1)?,
            AnnotationLevel::Warning => {
                checked_add(&mut summary.passed, 1)?;
                checked_add(&mut summary.warnings, 1)?;
            }
            AnnotationLevel::Error => checked_add(&mut summary.failed, 1)?,
        }
        annotations.push(Annotation {
            level,
            message,
            rule_id,
            path,
            start_line,
            start_column,
            end_line,
            end_column,
        });
    }
    Ok((summary, annotations, None))
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn custom_events_are_closed_and_coordinate_checked() {
        let input = br#"{
          "schema":"runtrue.report.v1",
          "events":[{"level":"error","message":"bad","rule_id":"C1",
            "path":"src/lib.rs","start_line":7,"start_column":2}]
        }"#;
        let report = ingest(ReportFormat::CustomEvents, input, ReportLimits::default()).unwrap();
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.annotations[0].rule_id.as_deref(), Some("C1"));

        let unknown = br#"{"schema":"runtrue.report.v1","events":[{
          "level":"notice","message":"ok","href":"javascript:alert(1)"}]}"#;
        assert!(matches!(
            ingest(ReportFormat::CustomEvents, unknown, ReportLimits::default()),
            Err(ReportError::Malformed(_))
        ));
        let bad_region = br#"{"schema":"runtrue.report.v1","events":[{
          "level":"notice","message":"ok","start_column":2}]}"#;
        assert!(ingest(
            ReportFormat::CustomEvents,
            bad_region,
            ReportLimits::default()
        )
        .is_err());
    }
}
