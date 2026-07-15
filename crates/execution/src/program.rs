use crate::{canonical, validation, ContentDigest, ExecutionModelError};
use serde::{Deserialize, Serialize};

pub const PROGRAM_IDENTITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProgramKind {
    SourceTree,
    Script,
    Command,
    WasmComponent,
    OciImage,
    NativeExecutable,
    FilesystemTree,
}

/// Canonical identity of executable input, independent of an integration's
/// repository, action, job, or agent terminology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramIdentity {
    pub schema_version: u32,
    pub kind: ProgramKind,
    pub content_digest: ContentDigest,
    pub resolver_digest: ContentDigest,
    pub media_type: String,
    pub entrypoint: Vec<String>,
}

impl ProgramIdentity {
    pub fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::schema(
            "Program schema version",
            self.schema_version,
            PROGRAM_IDENTITY_SCHEMA_VERSION,
        )?;
        validation::text("Program media type", &self.media_type)?;
        if !self.media_type.contains('/') || self.media_type.contains([' ', '*']) {
            return Err(ExecutionModelError::InvalidField {
                field: "Program media type",
                reason: "must be an exact media type",
            });
        }
        validation::bounded(
            "Program entrypoint",
            self.entrypoint.len(),
            validation::MAX_ARGUMENTS,
        )?;
        if self.entrypoint.first().is_some_and(String::is_empty) {
            return Err(ExecutionModelError::InvalidField {
                field: "Program entrypoint",
                reason: "the executable entry must not be empty",
            });
        }
        for value in &self.entrypoint {
            validation::argument("Program entrypoint value", value)?;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, ExecutionModelError> {
        self.validate()?;
        canonical::canonical_digest(self)
    }
}
