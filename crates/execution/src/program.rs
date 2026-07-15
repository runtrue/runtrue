use crate::{
    canonical, validation, Architecture, ContentDigest, ExecutionModelError, OperatingSystem,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSignatureIdentity {
    pub signer_identity: String,
    pub signature_algorithm: String,
    pub signing_key_id: ContentDigest,
    pub signature_digest: ContentDigest,
    pub provenance_digest: ContentDigest,
}

impl ProgramSignatureIdentity {
    fn validate(&self) -> Result<(), ExecutionModelError> {
        validation::identifier("Program signer identity", &self.signer_identity)?;
        validation::identifier("Program signature algorithm", &self.signature_algorithm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramPlatform {
    pub operating_system: OperatingSystem,
    pub architecture: Architecture,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ProgramSignatureIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<ProgramPlatform>,
    pub compatibility_metadata: BTreeMap<String, ContentDigest>,
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
        validation::bounded(
            "Program compatibility metadata",
            self.compatibility_metadata.len(),
            validation::MAX_COLLECTION_ENTRIES,
        )?;
        for key in self.compatibility_metadata.keys() {
            validation::identifier("Program compatibility metadata key", key)?;
        }
        if let Some(signature) = &self.signature {
            signature.validate()?;
        }
        let signed_executable = matches!(
            self.kind,
            ProgramKind::WasmComponent | ProgramKind::OciImage | ProgramKind::NativeExecutable
        );
        let platform_required = matches!(
            self.kind,
            ProgramKind::OciImage | ProgramKind::NativeExecutable
        );
        if (signed_executable
            && (self.signature.is_none() || self.compatibility_metadata.is_empty()))
            || platform_required != self.platform.is_some()
            || (self.kind == ProgramKind::WasmComponent && self.platform.is_some())
        {
            return Err(ExecutionModelError::InvalidField {
                field: "Program signature, platform, or compatibility metadata",
                reason: "must match the exact resolved Program kind",
            });
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
