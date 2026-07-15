//! Domain-neutral identities and lifecycle rules for Runtrue execution.
//!
//! This crate deliberately has no workflow, SCM, GitHub, transport, storage,
//! executor, or control-plane dependencies. Integrations translate their own
//! concepts into these canonical types.

mod canonical;
mod capsule;
mod contracts;
mod error;
mod lifecycle;
mod program;
mod reservation;
mod runtime;
mod seal;
mod validation;
mod workspace;

pub use capsule::{
    ApprovalSubject, CapsuleKind, DelegationGrant, DelegationPolicy, DelegationValidationContext,
    ExecutionCapsule, ParentBinding, SessionCapsule, EXECUTION_CAPSULE_SCHEMA_VERSION,
};
pub use contracts::{
    CapabilityBudget, CapabilityContract, CapabilityGrant, DeviceRequirement, EvidenceContract,
    EvidenceProfile, ExternalEffectContract, ExternalEffectDeclaration, NondeterminismContract,
    NondeterministicInputClass, NondeterministicInputGrant, OutputContract, PlacementConstraints,
    ResourceLimits,
};
pub use error::ExecutionModelError;
pub use lifecycle::{ExecutionState, FailureClass, SessionState, TerminalCause, TerminalDecision};
pub use program::{
    ProgramIdentity, ProgramKind, ProgramPlatform, ProgramSignatureIdentity,
    PROGRAM_IDENTITY_SCHEMA_VERSION,
};
pub use reservation::{
    CapabilityUsage, ChildAdmissionRequest, ChildReservationRecord, ChildReservationRequest,
    ChildResourceReservation, ReservationResult, ReservationState, ReservationTerminalOutcome,
    ReservationTransitionRequest, SessionReservationLedger, SessionReservationLedgerStore,
    SESSION_RESERVATION_SCHEMA_VERSION,
};
pub use runtime::{
    Architecture, OperatingSystem, RuntimeCompatibilityProfile, RuntimeComponents, RuntimeFamily,
    RuntimePlatform, RUNTIME_PROFILE_SCHEMA_VERSION,
};
pub use runtrue_model::ContentDigest;
pub use seal::{
    Seal, SealSignatureVerifier, MAX_SEAL_LIFETIME_MS, MAX_SEAL_SIGNATURE_BYTES,
    MIN_SEAL_SIGNATURE_BYTES, SEAL_SCHEMA_VERSION,
};
pub use workspace::{
    FinalizeAndPublishResult, SessionLedgerCommitStore, WorkspaceGeneration,
    WorkspacePublicationLedger, WorkspacePublicationLedgerStore, WorkspacePublicationRecord,
    WorkspacePublicationRequest, WorkspacePublicationResult, WORKSPACE_PUBLICATION_SCHEMA_VERSION,
};
