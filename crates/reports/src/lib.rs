//! Hardened ingestion of untrusted test and analysis reports.
//!
//! The parser accepts a deliberately small, versioned subset of JUnit, SARIF,
//! coverage summaries, and Runtrue custom events. Inputs are byte-, event-,
//! depth-, string-, and result-bounded. JSON duplicate keys are rejected and
//! XML DTD/processing-instruction content is never accepted. Normalized
//! annotations are plain text; callers must opt in to the escaping renderer
//! before placing them in HTML.

mod coverage;
mod custom;
mod error;
mod html;
mod junit;
mod limits;
mod model;
mod sarif;
mod strict_json;

pub use error::ReportError;
pub use limits::ReportLimits;
pub use model::{
    Annotation, AnnotationLevel, CoverageCounter, CoverageSummary, NormalizedReport, ReportFormat,
    ReportSummary,
};

use coverage::parse_coverage;
use custom::parse_custom;
use junit::parse_junit;
use runtrue_model::ContentDigest;
use sarif::parse_sarif;

type ParseOutput = (ReportSummary, Vec<Annotation>, Option<CoverageSummary>);

pub fn ingest(
    format: ReportFormat,
    input: &[u8],
    limits: ReportLimits,
) -> Result<NormalizedReport, ReportError> {
    let limits = limits.validate()?;
    if input.len() > limits.max_input_bytes {
        return Err(ReportError::InputTooLarge);
    }
    if input.is_empty() {
        return Err(ReportError::Malformed("report is empty".to_owned()));
    }

    let source_digest = ContentDigest::sha256(input);
    let (summary, annotations, coverage) = match format {
        ReportFormat::JunitXml => parse_junit(input, limits)?,
        ReportFormat::Sarif => parse_sarif(input, limits)?,
        ReportFormat::CoverageSummary => parse_coverage(input, limits)?,
        ReportFormat::CustomEvents => parse_custom(input, limits)?,
    };
    Ok(NormalizedReport {
        format,
        source_digest,
        summary,
        annotations,
        coverage,
    })
}
