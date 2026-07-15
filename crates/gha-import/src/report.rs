use serde::Serialize;
use std::fmt;

/// The compatibility classification defined by the technical design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityStatus {
    Supported,
    Emulated,
    RequiresGithub,
    Unsafe,
    Unsupported,
}

impl CompatibilityStatus {
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::RequiresGithub | Self::Unsafe | Self::Unsupported
        )
    }
}

impl fmt::Display for CompatibilityStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Supported => "SUPPORTED",
            Self::Emulated => "EMULATED",
            Self::RequiresGithub => "REQUIRES_GITHUB",
            Self::Unsafe => "UNSAFE",
            Self::Unsupported => "UNSUPPORTED",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityFinding {
    pub status: CompatibilityStatus,
    pub code: String,
    pub path: String,
    pub message: String,
    pub blocking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_change: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusCounts {
    pub supported: usize,
    pub emulated: usize,
    pub requires_github: usize,
    #[serde(rename = "unsafe")]
    pub unsafe_count: usize,
    pub unsupported: usize,
}

impl StatusCounts {
    pub(crate) fn add(&mut self, status: CompatibilityStatus) {
        match status {
            CompatibilityStatus::Supported => self.supported += 1,
            CompatibilityStatus::Emulated => self.emulated += 1,
            CompatibilityStatus::RequiresGithub => self.requires_github += 1,
            CompatibilityStatus::Unsafe => self.unsafe_count += 1,
            CompatibilityStatus::Unsupported => self.unsupported += 1,
        }
    }

    pub(crate) fn total(&self) -> usize {
        self.supported + self.emulated + self.requires_github + self.unsafe_count + self.unsupported
    }
}

/// Stable machine-readable and human-renderable compatibility analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityReport {
    pub workflow: String,
    pub compatible: bool,
    pub overall_compatibility_percent: u8,
    pub mapped_jobs: usize,
    pub mapped_steps: usize,
    pub status_counts: StatusCounts,
    /// True when emitted YAML passed the authoritative strict native schema parser.
    pub schema_validated: bool,
    pub native_ast_validated: bool,
    pub compiler_validated: bool,
    pub findings: Vec<CompatibilityFinding>,
    pub required_changes: Vec<String>,
}

impl CompatibilityReport {
    /// Produce the stable human-facing report used by the CLI.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut output = format!(
            "Workflow: {}\nOverall compatibility: {}%\nMapped: {} jobs, {} steps\n",
            self.workflow, self.overall_compatibility_percent, self.mapped_jobs, self.mapped_steps
        );
        for finding in &self.findings {
            let marker = match finding.status {
                CompatibilityStatus::Supported => "✓",
                CompatibilityStatus::Emulated => "⚠",
                CompatibilityStatus::RequiresGithub
                | CompatibilityStatus::Unsafe
                | CompatibilityStatus::Unsupported => "✗",
            };
            output.push_str(&format!(
                "{marker} [{}] {}: {}\n",
                finding.status, finding.path, finding.message
            ));
        }
        if !self.required_changes.is_empty() {
            output.push_str("\nRequired changes:\n");
            for (index, change) in self.required_changes.iter().enumerate() {
                output.push_str(&format!("{}. {change}\n", index + 1));
            }
        }
        output
    }
}

/// Result of compatibility analysis. Native output is absent whenever a
/// blocking finding exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_yaml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockfile_toml: Option<String>,
    pub report: CompatibilityReport,
}
