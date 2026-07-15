use crate::LocalArtifactCapture;
use std::fmt;

#[derive(Debug)]
pub enum LocalArtifactError {
    NotPreflighted,
    CapsuleMismatch,
    MissingJob(String),
    AlreadyCaptured,
    Capture {
        job_id: String,
        output_name: String,
        message: String,
        committed: Vec<LocalArtifactCapture>,
    },
    Materialize(String),
}

impl LocalArtifactError {
    /// Artifacts that remain durably committed even though a later output in
    /// the same capture batch failed.
    #[must_use]
    pub fn committed_artifacts(&self) -> &[LocalArtifactCapture] {
        match self {
            Self::Capture { committed, .. } => committed,
            _ => &[],
        }
    }
}

impl fmt::Display for LocalArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPreflighted => {
                formatter.write_str("local artifact executor has not completed preflight")
            }
            Self::CapsuleMismatch => formatter
                .write_str("artifact capture capsule does not match the preflighted exact capsule"),
            Self::MissingJob(job_id) => {
                write!(formatter, "artifact result is missing job {job_id}")
            }
            Self::AlreadyCaptured => {
                formatter.write_str("artifacts have already been captured for this execution")
            }
            Self::Capture {
                job_id,
                output_name,
                message,
                committed,
            } => {
                write!(
                    formatter,
                    "artifact {job_id}.{output_name} failed: {message}"
                )?;
                if !committed.is_empty() {
                    write!(
                        formatter,
                        "; {} earlier artifact(s) remain committed:",
                        committed.len()
                    )?;
                    for capture in committed {
                        write!(
                            formatter,
                            " {}.{}={}",
                            capture.job_id, capture.output_name, capture.artifact_id
                        )?;
                    }
                }
                Ok(())
            }
            Self::Materialize(message) => {
                write!(formatter, "artifact materialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for LocalArtifactError {}
