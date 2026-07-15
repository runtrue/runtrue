//! Approval- and MFA-gated interactive debug sessions.
//!
//! Sessions are reverse-tunnel-only, use one-time HMAC-digested tokens and an
//! externally issued ephemeral client identity, and always block future secret
//! release before the relay opens. Production, public-untrusted, and retained-
//! secret sessions are disabled by default. A debugged run is permanently
//! marked ineligible for direct artifact promotion.

mod audit;
mod broker;
mod error;
mod identity;
mod model;
mod policy;
mod relay;
mod secret_gate;
mod token;
mod validation;

pub use audit::{DebugAuditEvent, DebugAuditKind, DebugAuditSink};
pub use broker::DebugSessionBroker;
pub use error::DebugSessionError;
pub use identity::{ClientIdentityRequest, EphemeralClientIdentity, EphemeralIdentityIssuer};
pub use model::{
    DebugApproval, DebugApprovalSubject, DebugSessionRecord, DebugSessionRequest,
    DebugSessionState, EnvironmentClass, IssuedDebugSession, PromotionGate, SecretState,
    TranscriptMode, WorkloadTrust,
};
pub use policy::DebugSessionPolicy;
pub use relay::{DebugRelay, RelayRegistration, TunnelDirection};
pub use secret_gate::{DebugSecretGate, SecretBlockRequest};
pub use token::{OneUseTunnelToken, TunnelTokenDigest, TunnelTokenKey};

use audit::debug_audit_event;
use model::SESSION_VERSION;
use policy::MAX_DURATION_MS;
use token::{generate_tunnel_token, valid_token_text};
use validation::{canonical_digest, validate_client_identity, validate_identifier, validate_open};
