//! Authenticated, single-job host/guest session state machine.
//!
//! A guest receives a one-time session key through its protected boot
//! configuration. Every host command and guest event is sequence-bound and
//! authenticated. The signed execution capsule remains the authority for job,
//! step, filesystem, secret, and OIDC capabilities; a compromised host-side
//! message router cannot enlarge those capabilities by changing a command.

mod authorization;
mod bootstrap;
mod codec;
mod commands;
mod error;
mod events;
mod protocol;
mod session;
mod trust;

pub use authorization::{
    step_capability_digest, AuthorizedStep, GuestAction, OidcToken, SecretMaterial,
};
pub use bootstrap::{GuestBootConfig, GuestBootstrap, GuestSessionKey};
pub use codec::HostSessionCodec;
pub use commands::{
    HostCommand, MountDescriptor, MountPurpose, OidcEnvelope, SecretEnvelope, StepSignal,
};
pub use error::GuestError;
pub use events::{GuestEvent, GuestStepResult, LogFrame, LogStream, ResourceSample};
pub use protocol::{
    AuthenticatedEnvelope, GUEST_BOOT_CONFIG_VERSION, GUEST_PROTOCOL_VERSION,
    MAX_GUEST_BOOT_CONFIG_BYTES, MAX_GUEST_CAPSULE_BYTES, MAX_GUEST_MESSAGE_BYTES,
    MAX_GUEST_MOUNTS, MAX_LOG_FRAME_BYTES, MAX_OIDC_TOKEN_BYTES, MAX_SECRET_ENVELOPE_BYTES,
};
pub use session::{GuestSession, GuestSessionState};
pub use trust::GuestCapsuleTrustStore;

#[cfg(test)]
mod tests;
