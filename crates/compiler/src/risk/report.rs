#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskReport {
    pub score: u32,
    pub highest_severity: RiskSeverity,
    pub findings: Vec<RiskFinding>,
}

impl RiskReport {
    pub(crate) fn from_findings(findings: Vec<RiskFinding>) -> Self {
        let score = findings
            .iter()
            .map(|finding| finding.severity.weight())
            .sum::<u32>()
            .min(100);
        let highest_severity = findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(RiskSeverity::Info);
        Self {
            score,
            highest_severity,
            findings,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
    const fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 5,
            Self::Medium => 15,
            Self::High => 30,
            Self::Critical => 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskFinding {
    pub severity: RiskSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

impl RiskFinding {
    pub(crate) fn high(code: &str, path: String, message: &str) -> Self {
        Self {
            severity: RiskSeverity::High,
            code: code.to_owned(),
            path,
            message: message.to_owned(),
        }
    }

    pub(crate) fn medium(code: &str, path: String, message: &str) -> Self {
        Self {
            severity: RiskSeverity::Medium,
            code: code.to_owned(),
            path,
            message: message.to_owned(),
        }
    }

    pub(crate) fn low(code: &str, path: String, message: &str) -> Self {
        Self {
            severity: RiskSeverity::Low,
            code: code.to_owned(),
            path,
            message: message.to_owned(),
        }
    }
}
use serde::{Deserialize, Serialize};
