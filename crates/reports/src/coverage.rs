use crate::{
    strict_json::{parse_strict_json, reject_unknown, required, StrictJson},
    CoverageCounter, CoverageSummary, ParseOutput, ReportError, ReportLimits, ReportSummary,
};
use std::collections::BTreeMap;

pub(crate) fn parse_coverage(
    input: &[u8],
    limits: ReportLimits,
) -> Result<ParseOutput, ReportError> {
    let root = parse_strict_json(input, limits)?;
    let object = root.object("coverage summary")?;
    reject_unknown(
        object,
        &["lines", "functions", "branches", "statements"],
        "coverage summary",
    )?;

    fn counter(
        object: &BTreeMap<String, StrictJson>,
        key: &str,
    ) -> Result<Option<CoverageCounter>, ReportError> {
        object
            .get(key)
            .map(|value| {
                let value = value.object(key)?;
                reject_unknown(value, &["covered", "total"], key)?;
                let covered = required(value, "covered", key)?.u64(&format!("{key}.covered"))?;
                let total = required(value, "total", key)?.u64(&format!("{key}.total"))?;
                if covered > total {
                    return Err(ReportError::Malformed(format!(
                        "{key}.covered cannot exceed total"
                    )));
                }
                Ok(CoverageCounter { covered, total })
            })
            .transpose()
    }

    let coverage = CoverageSummary {
        lines: counter(object, "lines")?,
        functions: counter(object, "functions")?,
        branches: counter(object, "branches")?,
        statements: counter(object, "statements")?,
    };
    if coverage.lines.is_none()
        && coverage.functions.is_none()
        && coverage.branches.is_none()
        && coverage.statements.is_none()
    {
        return Err(ReportError::Malformed(
            "coverage summary has no counters".to_owned(),
        ));
    }
    let primary = coverage
        .lines
        .or(coverage.statements)
        .or(coverage.functions)
        .or(coverage.branches)
        .expect("at least one counter was checked");
    Ok((
        ReportSummary {
            total: primary.total,
            passed: primary.covered,
            failed: primary.total - primary.covered,
            skipped: 0,
            warnings: 0,
        },
        Vec::new(),
        Some(coverage),
    ))
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn coverage_is_validated_and_summarized() {
        let input = br#"{
          "lines":{"covered":8,"total":10},
          "branches":{"covered":4,"total":5}
        }"#;
        let report = ingest(
            ReportFormat::CoverageSummary,
            input,
            ReportLimits::default(),
        )
        .unwrap();
        assert_eq!(report.summary.total, 10);
        assert_eq!(report.summary.passed, 8);
        assert_eq!(report.summary.failed, 2);
        assert_eq!(report.coverage.unwrap().branches.unwrap().covered, 4);

        let invalid = br#"{"lines":{"covered":11,"total":10}}"#;
        assert!(ingest(
            ReportFormat::CoverageSummary,
            invalid,
            ReportLimits::default()
        )
        .is_err());
    }
}
