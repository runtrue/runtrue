//! Registry-scoped authentication and verified package retrieval.

mod credentials;
mod pull;
mod reference;

pub use credentials::{
    RegistryCredential, RegistryCredentialRef, RegistryCredentialScope, RegistryCredentialSet,
};
pub use pull::{
    pull_package, CredentialRequirement, FetchedPackage, PackageFetchError, PackageFetcher,
    PackageKind, PackagePullRequest,
};

#[cfg(test)]
mod tests;
