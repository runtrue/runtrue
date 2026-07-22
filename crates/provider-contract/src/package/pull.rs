use super::{
    credentials::RegistryCredential, reference::parse_exact_reference, RegistryCredentialSet,
};
use crate::{
    canonical::{validate_profile_name, validate_text, MAX_SHORT_TEXT_BYTES},
    ProviderContractError,
};
use runtrue_model::ContentDigest;

const MAX_PACKAGE_BYTES: u64 = 1 << 40;

/// The package protocol whose fetcher will consume a registry credential.
///
/// Named protocols keep credential selection extensible without assigning an
/// unknown package the semantics of a container image or Wasm component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageKind {
    ContainerImage,
    WasmComponent,
    Named(String),
}

impl PackageKind {
    pub fn named(name: impl Into<String>) -> Result<Self, ProviderContractError> {
        let kind = Self::Named(name.into());
        kind.validate()?;
        Ok(kind)
    }

    pub(super) fn validate(&self) -> Result<(), ProviderContractError> {
        if let Self::Named(name) = self {
            validate_profile_name(name).map_err(|_| {
                ProviderContractError::InvalidPackagePull("invalid named package kind")
            })?;
        }
        Ok(())
    }
}

/// Whether pulling may proceed anonymously when no matching credential exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRequirement {
    Optional,
    Required,
}

/// A digest-pinned package pull with an independently bounded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePullRequest {
    package_kind: PackageKind,
    reference: String,
    registry: String,
    reference_digest: ContentDigest,
    payload_digest: ContentDigest,
    expected_media_type: String,
    maximum_bytes: u64,
    credential_requirement: CredentialRequirement,
}

impl PackagePullRequest {
    pub fn new(
        package_kind: PackageKind,
        reference: impl Into<String>,
        payload_digest: ContentDigest,
        expected_media_type: impl Into<String>,
        maximum_bytes: u64,
        credential_requirement: CredentialRequirement,
    ) -> Result<Self, ProviderContractError> {
        package_kind.validate()?;
        let reference = reference.into();
        let (registry, reference_digest) = parse_exact_reference(&package_kind, &reference)?;
        let expected_media_type = expected_media_type.into();
        validate_media_type(&expected_media_type)?;
        if maximum_bytes == 0 || maximum_bytes > MAX_PACKAGE_BYTES {
            return Err(ProviderContractError::InvalidPackagePull(
                "package byte bound is zero or too large",
            ));
        }
        Ok(Self {
            package_kind,
            reference,
            registry,
            reference_digest,
            payload_digest,
            expected_media_type,
            maximum_bytes,
            credential_requirement,
        })
    }

    #[must_use]
    pub const fn package_kind(&self) -> &PackageKind {
        &self.package_kind
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    #[must_use]
    pub const fn reference_digest(&self) -> &ContentDigest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn payload_digest(&self) -> &ContentDigest {
        &self.payload_digest
    }

    #[must_use]
    pub fn expected_media_type(&self) -> &str {
        &self.expected_media_type
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    #[must_use]
    pub const fn credential_requirement(&self) -> CredentialRequirement {
        self.credential_requirement
    }
}

/// Fetch-provider response. The core re-verifies every field before returning
/// it to an executor or package-specific unpacker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedPackage {
    pub reference: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// Opaque fetch failure. Provider diagnostics must not include credentials in
/// a portable error or execution record.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("package fetch failed")]
pub struct PackageFetchError;

/// Package-specific transport adapter. Container, Wasm, and future package
/// implementations share the credential-selection and verification path.
pub trait PackageFetcher {
    fn fetch(
        &mut self,
        request: &PackagePullRequest,
        credential: Option<&RegistryCredential>,
    ) -> Result<FetchedPackage, PackageFetchError>;
}

/// Select a registry-scoped credential, perform one fetch, and verify the
/// returned package before any consumer can use it.
pub fn pull_package<F: PackageFetcher + ?Sized>(
    fetcher: &mut F,
    credentials: &RegistryCredentialSet,
    request: &PackagePullRequest,
) -> Result<FetchedPackage, ProviderContractError> {
    let credential = credentials.resolve(request);
    if request.credential_requirement == CredentialRequirement::Required && credential.is_none() {
        return Err(ProviderContractError::MissingRegistryCredential);
    }
    let fetched = fetcher
        .fetch(request, credential)
        .map_err(|_| ProviderContractError::PackageFetchFailed)?;
    if fetched.reference != request.reference {
        return Err(ProviderContractError::InvalidFetchedPackage(
            "reference changed",
        ));
    }
    if fetched.media_type != request.expected_media_type {
        return Err(ProviderContractError::InvalidFetchedPackage(
            "media type changed",
        ));
    }
    let length = u64::try_from(fetched.bytes.len())
        .map_err(|_| ProviderContractError::InvalidFetchedPackage("payload size overflow"))?;
    if length == 0 || length > request.maximum_bytes {
        return Err(ProviderContractError::InvalidFetchedPackage(
            "payload is empty or exceeds its bound",
        ));
    }
    if ContentDigest::sha256(&fetched.bytes) != request.payload_digest {
        return Err(ProviderContractError::InvalidFetchedPackage(
            "payload digest mismatch",
        ));
    }
    Ok(fetched)
}

fn validate_media_type(value: &str) -> Result<(), ProviderContractError> {
    validate_text("package media type", value, MAX_SHORT_TEXT_BYTES)
        .map_err(|_| ProviderContractError::InvalidPackagePull("invalid package media type"))?;
    if !value.contains('/') || value.contains([' ', '*']) {
        return Err(ProviderContractError::InvalidPackagePull(
            "package media type must be exact",
        ));
    }
    Ok(())
}
