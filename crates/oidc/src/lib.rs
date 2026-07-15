//! Lease- and step-bound OIDC workload identity using short-lived EdDSA JWTs.
//!
//! The broker accepts only an audience explicitly present in a pre-authorized
//! grant. Claims bind the token to the exact capsule, repository, run, job, step,
//! execution lease, and fencing generation. Signing key material is never
//! exposed through serialization or debug output.

mod claims;
mod discovery;
mod error;
mod grant;
mod issuer;
mod jwk;
mod key_ring;
mod keys;
mod token;
mod validation;
mod verification;

pub use claims::JwtClaims;
pub use discovery::OidcDiscoveryDocument;
pub use error::OidcError;
pub use grant::OidcGrant;
pub use issuer::OidcIssuer;
pub use jwk::{Jwk, JwkSet};
pub use key_ring::{
    OidcActiveSigningKeyRecord, OidcKeyRingSnapshot, OidcRetiredSigningKeyRecord,
    OidcRevokedSigningKeyRecord, OidcSigningKeyRevocation, OidcSigningKeyRotation,
};
pub use keys::{OidcSigningKey, OidcVerifyingKey};
pub use token::{MintTokenRequest, MintedOidcToken};
pub use verification::{verify_token, verify_token_with_jwks};

#[cfg(test)]
use token::JwtHeader;

const JWT_ALGORITHM: &str = "EdDSA";
const JWT_TYPE: &str = "JWT";
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_AUDIENCES: usize = 64;
const MAX_TOKEN_BYTES: usize = 32 * 1024;
const KEY_RING_SNAPSHOT_VERSION: u32 = 1;
const WORKLOAD_IDENTITY_GRANT_TYPE: &str = "urn:runtrue:params:oauth:grant-type:workload-identity";

pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 300;
pub const MAX_TOKEN_TTL_SECONDS: u64 = 900;
pub const DEFAULT_SIGNING_KEY_OVERLAP_SECONDS: u64 = MAX_TOKEN_TTL_SECONDS;
pub const MAX_SIGNING_KEY_OVERLAP_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_RETAINED_SIGNING_KEYS: usize = 8;
pub const MAX_REVOKED_SIGNING_KEY_IDS: usize = 64;
pub const MAX_JWKS_BYTES: usize = 64 * 1024;
pub const MAX_DISCOVERY_DOCUMENT_BYTES: usize = 16 * 1024;
pub const MAX_KEY_RING_SNAPSHOT_BYTES: usize = 64 * 1024;

#[cfg(test)]
use base64ct::{Base64UrlUnpadded, Encoding as _};
#[cfg(test)]
use runtrue_model::ContentDigest;
#[cfg(test)]
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;
