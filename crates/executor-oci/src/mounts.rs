#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciMount {
    pub source: PathBuf,
    pub destination: String,
    pub read_only: bool,
}

impl OciMount {
    #[must_use]
    pub fn read_only(source: impl Into<PathBuf>, destination: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            read_only: true,
        }
    }

    #[must_use]
    pub fn read_write(source: impl Into<PathBuf>, destination: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            read_only: false,
        }
    }
}
use crate::PathBuf;
