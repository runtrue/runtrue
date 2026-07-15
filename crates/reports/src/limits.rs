#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLimits {
    pub max_input_bytes: usize,
    pub max_events: usize,
    pub max_depth: usize,
    pub max_results: usize,
    pub max_string_bytes: usize,
}

impl Default for ReportLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_events: 1_000_000,
            max_depth: 64,
            max_results: 100_000,
            max_string_bytes: 64 * 1024,
        }
    }
}

impl ReportLimits {
    pub(crate) fn validate(self) -> Result<Self, ReportError> {
        if self.max_input_bytes == 0
            || self.max_events == 0
            || self.max_depth == 0
            || self.max_results == 0
            || self.max_string_bytes == 0
        {
            return Err(ReportError::InvalidLimits);
        }
        Ok(self)
    }
}

pub(crate) fn checked_add(value: &mut u64, amount: u64) -> Result<(), ReportError> {
    *value = value
        .checked_add(amount)
        .ok_or(ReportError::ComplexityLimit)?;
    Ok(())
}

pub(crate) fn bounded_string(value: &str, limits: ReportLimits) -> Result<String, ReportError> {
    if value.len() > limits.max_string_bytes || value.contains('\0') {
        return Err(ReportError::ComplexityLimit);
    }
    Ok(value.to_owned())
}
use crate::ReportError;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn configured_bounds_are_enforced() {
        let input = br#"{"schema":"runtrue.report.v1","events":[]}"#;
        let limits = ReportLimits {
            max_input_bytes: input.len() - 1,
            ..ReportLimits::default()
        };
        assert!(matches!(
            ingest(ReportFormat::CustomEvents, input, limits),
            Err(ReportError::InputTooLarge)
        ));

        let input = br#"{"schema":"runtrue.report.v1","events":[
          {"level":"notice","message":"one"},
          {"level":"notice","message":"two"}] }"#;
        let limits = ReportLimits {
            max_results: 1,
            ..ReportLimits::default()
        };
        assert!(matches!(
            ingest(ReportFormat::CustomEvents, input, limits),
            Err(ReportError::ComplexityLimit)
        ));
    }
}
