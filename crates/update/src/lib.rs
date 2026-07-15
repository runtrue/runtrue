//! Rollback-resistant, offline-verifiable update metadata for Runtrue releases.
//!
//! This is a deliberately small TUF-style trust core. It implements four
//! non-delegated roles (root, targets, snapshot, and timestamp), canonical
//! signed JSON, threshold Ed25519 verification, sequential root rotation, and
//! durable monotonic client state. It does not download or execute targets.

mod canonical;
mod error;
mod keys;
mod limits;
mod metadata;
mod release;
mod roles;
mod sbom;
mod secure_fs;
mod strict_json;
mod trust_store;
mod trusted_state;
mod verification;

pub use canonical::{canonical_bytes, decode_root, root_envelope_digest};
pub use error::UpdateError;
pub use keys::{UpdatePublicKey, UpdateSigningKey};
pub use limits::*;
pub use metadata::*;
pub use release::*;
pub use roles::{MetadataHeader, RoleType};
pub use sbom::*;
pub use secure_fs::{read_verified_file, write_new_public_file};
pub use trust_store::{TrustStore, TrustStoreTransaction};
pub use trusted_state::{TrustedMetadata, TrustedState};

pub(crate) use canonical::{decode_canonical, signature_message};
pub(crate) use verification::{
    digest_hex, is_lower_hex, valid_text, validate_chain_times, verify_role_threshold,
};

#[cfg(test)]
mod tests;
