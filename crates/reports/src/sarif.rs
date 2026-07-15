use crate::{
    limits::{bounded_string, checked_add},
    strict_json::{
        optional_coordinate, parse_strict_json, required, safe_path, validate_region, StrictJson,
    },
    Annotation, AnnotationLevel, ParseOutput, ReportError, ReportLimits, ReportSummary,
};
use std::collections::BTreeMap;

const SARIF_VERSION: &str = "2.1.0";

pub(crate) fn parse_sarif(input: &[u8], limits: ReportLimits) -> Result<ParseOutput, ReportError> {
    let root = parse_strict_json(input, limits)?;
    let root = root.object("SARIF")?;
    let version = required(root, "version", "SARIF")?.string("SARIF.version")?;
    if version != SARIF_VERSION {
        return Err(ReportError::UnsupportedVersion(version.to_owned()));
    }
    let runs = required(root, "runs", "SARIF")?.array("SARIF.runs")?;
    let mut result_count = 0_usize;
    let mut summary = ReportSummary::default();
    let mut annotations = Vec::new();

    for (run_index, run) in runs.iter().enumerate() {
        let context = format!("SARIF.runs[{run_index}]");
        let run = run.object(&context)?;
        let Some(results) = run.get("results") else {
            continue;
        };
        for (result_index, result) in results
            .array(&format!("{context}.results"))?
            .iter()
            .enumerate()
        {
            result_count = result_count
                .checked_add(1)
                .ok_or(ReportError::ComplexityLimit)?;
            if result_count > limits.max_results {
                return Err(ReportError::ComplexityLimit);
            }
            let result_context = format!("{context}.results[{result_index}]");
            let result = result.object(&result_context)?;
            let level = match result
                .get("level")
                .map(|value| value.string("SARIF result.level"))
                .transpose()?
            {
                None | Some("none" | "note") => AnnotationLevel::Notice,
                Some("warning") => AnnotationLevel::Warning,
                Some("error") => AnnotationLevel::Error,
                Some(_) => {
                    return Err(ReportError::Malformed(format!(
                        "{result_context}.level is invalid"
                    )))
                }
            };
            let message = required(result, "message", &result_context)?
                .object(&format!("{result_context}.message"))?;
            let message = bounded_string(
                required(message, "text", &format!("{result_context}.message"))?
                    .string(&format!("{result_context}.message.text"))?,
                limits,
            )?;
            let rule_id = result
                .get("ruleId")
                .map(|value| bounded_string(value.string("SARIF result.ruleId")?, limits))
                .transpose()?;
            let (path, start_line, start_column, end_line, end_column) =
                sarif_location(result, &result_context)?;
            validate_region(
                start_line,
                start_column,
                end_line,
                end_column,
                &result_context,
            )?;

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
    }
    Ok((summary, annotations, None))
}

type Region = (
    Option<String>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);

fn sarif_location(
    result: &BTreeMap<String, StrictJson>,
    context: &str,
) -> Result<Region, ReportError> {
    let Some(locations) = result.get("locations") else {
        return Ok((None, None, None, None, None));
    };
    let locations = locations.array(&format!("{context}.locations"))?;
    let Some(location) = locations.first() else {
        return Ok((None, None, None, None, None));
    };
    let location = location.object(&format!("{context}.locations[0]"))?;
    let Some(physical) = location.get("physicalLocation") else {
        return Ok((None, None, None, None, None));
    };
    let physical = physical.object(&format!("{context}.locations[0].physicalLocation"))?;
    let path = physical
        .get("artifactLocation")
        .map(|artifact| {
            let artifact = artifact.object("SARIF artifactLocation")?;
            artifact
                .get("uri")
                .map(|uri| safe_path(uri.string("SARIF artifactLocation.uri")?))
                .transpose()
        })
        .transpose()?
        .flatten();
    let Some(region) = physical.get("region") else {
        return Ok((path, None, None, None, None));
    };
    let region = region.object("SARIF region")?;
    Ok((
        path,
        optional_coordinate(region, "startLine", "SARIF region")?,
        optional_coordinate(region, "startColumn", "SARIF region")?,
        optional_coordinate(region, "endLine", "SARIF region")?,
        optional_coordinate(region, "endColumn", "SARIF region")?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn sarif_extracts_only_plain_text_and_safe_locations() {
        let sarif = br#"{
          "version":"2.1.0",
          "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
          "runs":[{"tool":{"driver":{"name":"lint"}},"results":[{
            "ruleId":"R1","level":"warning",
            "message":{"text":"<b>unsafe</b>","markdown":"[click](https://evil.invalid)"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/main.rs"},
              "region":{"startLine":2,"startColumn":3,"endLine":2,"endColumn":8}}}]
          }]}]
        }"#;
        let report = ingest(ReportFormat::Sarif, sarif, ReportLimits::default()).unwrap();
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.annotations[0].message, "<b>unsafe</b>");
        assert_eq!(
            report.annotations[0].escaped_message(),
            "&lt;b&gt;unsafe&lt;/b&gt;"
        );
        assert_eq!(report.annotations[0].path.as_deref(), Some("src/main.rs"));
        assert_eq!(report.annotations[0].start_line, Some(2));
    }
}
