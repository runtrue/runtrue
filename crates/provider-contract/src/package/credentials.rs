use super::{pull::PackageKind, reference::validate_registry, PackagePullRequest};
use crate::{
    canonical::{
        validate_collection_size, validate_profile_name, validate_text, MAX_SHORT_TEXT_BYTES,
    },
    ProviderContractError,
};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Exact registry and optional package-kind scope for one credential.
///
/// Registry matching is deliberately exact. A credential for `registry.example`
/// is never released to a subdomain, sibling host, or different port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryCredentialScope {
    registry: String,
    package_kind: Option<PackageKind>,
}

impl RegistryCredentialScope {
    pub fn registry(registry: impl Into<String>) -> Result<Self, ProviderContractError> {
        Self::new(registry.into(), None)
    }

    pub fn package(
        registry: impl Into<String>,
        package_kind: PackageKind,
    ) -> Result<Self, ProviderContractError> {
        Self::new(registry.into(), Some(package_kind))
    }

    fn new(
        registry: String,
        package_kind: Option<PackageKind>,
    ) -> Result<Self, ProviderContractError> {
        validate_registry(&registry)?;
        if let Some(kind) = &package_kind {
            kind.validate()?;
        }
        Ok(Self {
            registry,
            package_kind,
        })
    }

    #[must_use]
    pub fn registry_name(&self) -> &str {
        &self.registry
    }

    #[must_use]
    pub const fn package_kind(&self) -> Option<&PackageKind> {
        self.package_kind.as_ref()
    }
}

/// A borrowed credential view intentionally lacking `Debug`, serialization,
/// equality, and cloning implementations.
pub enum RegistryCredentialRef<'a> {
    Basic {
        username: &'a str,
        password: &'a str,
    },
    Bearer {
        token: &'a str,
    },
    Other {
        mechanism: &'a str,
        identity: Option<&'a str>,
        secret: &'a str,
    },
}

/// Runtime-only registry authentication material.
///
/// Secret values are zeroized on drop and cannot be serialized. Its debug
/// representation exposes only the mechanism.
pub enum RegistryCredential {
    Basic {
        username: String,
        password: Zeroizing<String>,
    },
    Bearer {
        token: Zeroizing<String>,
    },
    Other {
        mechanism: String,
        identity: Option<String>,
        secret: Zeroizing<String>,
    },
}

impl RegistryCredential {
    pub fn basic(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProviderContractError> {
        let username = username.into();
        validate_credential_identity(&username)?;
        let password = Zeroizing::new(password.into());
        validate_secret(password.as_str())?;
        Ok(Self::Basic { username, password })
    }

    pub fn bearer(token: impl Into<String>) -> Result<Self, ProviderContractError> {
        let token = Zeroizing::new(token.into());
        validate_secret(token.as_str())?;
        Ok(Self::Bearer { token })
    }

    pub fn other(
        mechanism: impl Into<String>,
        identity: Option<String>,
        secret: impl Into<String>,
    ) -> Result<Self, ProviderContractError> {
        let mechanism = mechanism.into();
        validate_profile_name(&mechanism).map_err(|_| {
            ProviderContractError::InvalidPackagePull("invalid credential mechanism")
        })?;
        if let Some(value) = &identity {
            validate_credential_identity(value)?;
        }
        let secret = Zeroizing::new(secret.into());
        validate_secret(secret.as_str())?;
        Ok(Self::Other {
            mechanism,
            identity,
            secret,
        })
    }

    /// Deliberately expose the secret only at the fetch-provider boundary.
    #[must_use]
    pub fn expose(&self) -> RegistryCredentialRef<'_> {
        match self {
            Self::Basic { username, password } => RegistryCredentialRef::Basic {
                username,
                password: password.as_str(),
            },
            Self::Bearer { token } => RegistryCredentialRef::Bearer {
                token: token.as_str(),
            },
            Self::Other {
                mechanism,
                identity,
                secret,
            } => RegistryCredentialRef::Other {
                mechanism,
                identity: identity.as_deref(),
                secret: secret.as_str(),
            },
        }
    }
}

impl fmt::Debug for RegistryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mechanism = match self {
            Self::Basic { .. } => "basic",
            Self::Bearer { .. } => "bearer",
            Self::Other { mechanism, .. } => mechanism,
        };
        formatter
            .debug_struct("RegistryCredential")
            .field("mechanism", &mechanism)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Installation-owned credentials selected by exact registry and package kind.
#[derive(Default)]
pub struct RegistryCredentialSet {
    credentials: BTreeMap<RegistryCredentialScope, RegistryCredential>,
}

impl RegistryCredentialSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        scope: RegistryCredentialScope,
        credential: RegistryCredential,
    ) -> Result<(), ProviderContractError> {
        validate_collection_size(self.credentials.len().saturating_add(1))?;
        if self.credentials.contains_key(&scope) {
            return Err(ProviderContractError::DuplicateRegistryCredential);
        }
        self.credentials.insert(scope, credential);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    #[must_use]
    pub fn resolve(&self, request: &PackagePullRequest) -> Option<&RegistryCredential> {
        let package_scope = RegistryCredentialScope {
            registry: request.registry().to_owned(),
            package_kind: Some(request.package_kind().clone()),
        };
        self.credentials.get(&package_scope).or_else(|| {
            self.credentials.get(&RegistryCredentialScope {
                registry: request.registry().to_owned(),
                package_kind: None,
            })
        })
    }
}

impl fmt::Debug for RegistryCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCredentialSet")
            .field("scopes", &self.credentials.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn validate_credential_identity(value: &str) -> Result<(), ProviderContractError> {
    validate_text("registry credential identity", value, MAX_SHORT_TEXT_BYTES).map_err(|_| {
        ProviderContractError::InvalidPackagePull("invalid registry credential identity")
    })
}

fn validate_secret(value: &str) -> Result<(), ProviderContractError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || value.contains('\0') {
        return Err(ProviderContractError::InvalidPackagePull(
            "invalid registry credential secret",
        ));
    }
    Ok(())
}
