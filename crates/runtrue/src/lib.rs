//! Stable, domain-neutral Rust facade for Runtrue execution.
//!
//! This crate intentionally exposes the product-level vocabulary while the
//! implementation remains split into focused crates. Workflow and GitHub
//! Actions support is retained as an integration, not as the execution model.

/// Immutable Programs and their canonical identity.
pub mod program {
    pub use runtrue_execution::{ProgramIdentity, ProgramKind, PROGRAM_IDENTITY_SCHEMA_VERSION};
}

/// Exact runtime compatibility contracts.
pub mod runtime {
    pub use runtrue_execution::{
        Architecture, OperatingSystem, RuntimeCompatibilityProfile, RuntimeComponents,
        RuntimeFamily, RuntimePlatform, RUNTIME_PROFILE_SCHEMA_VERSION,
    };
}

/// Immutable Execution and Session Capsules.
pub mod capsule {
    pub use runtrue_execution::{
        ApprovalSubject, CapsuleKind, DelegationGrant, DelegationPolicy, ExecutionCapsule,
        ParentBinding, SessionCapsule, EXECUTION_CAPSULE_SCHEMA_VERSION,
    };
}

/// Exact-subject Capsule approval evidence.
pub mod seal {
    pub use runtrue_execution::{
        Seal, MAX_SEAL_LIFETIME_MS, MAX_SEAL_SIGNATURE_BYTES, MIN_SEAL_SIGNATURE_BYTES,
        SEAL_SCHEMA_VERSION,
    };
}

/// Portable lifecycle and terminal classifications.
pub mod lifecycle {
    pub use runtrue_execution::{
        ExecutionState, FailureClass, SessionState, TerminalCause, TerminalDecision,
    };
}

/// Durable Session child reservation and workspace publication primitives.
pub mod session {
    pub use runtrue_execution::{
        ChildReservationRecord, ChildReservationRequest, ChildResourceReservation,
        ReservationResult, ReservationState, ReservationTerminalOutcome,
        ReservationTransitionRequest, SessionReservationLedger, WorkspaceGeneration,
        WorkspacePublicationLedger, WorkspacePublicationRecord, WorkspacePublicationRequest,
        WorkspacePublicationResult, SESSION_RESERVATION_SCHEMA_VERSION,
        WORKSPACE_PUBLICATION_SCHEMA_VERSION,
    };
}

/// Default-deny capabilities and invocation-local authority.
pub mod capability {
    pub use runtrue_execution::{CapabilityBudget, CapabilityContract, CapabilityGrant};
    pub use runtrue_provider_contract::{
        CapabilityBudgetLedger, CapabilityBudgetReservation, InvocationBudget, InvocationHandle,
        InvocationSubject,
    };
}

/// Portable Checkpoint and Replay Bundle manifests.
pub mod replay {
    pub use runtrue_provider_contract::{
        CheckpointCompatibilityGrade, CheckpointManifest, CheckpointTaint, EffectLedgerFrontier,
        RemainingExecutionBudget, ReplayBundleManifest,
    };
}

/// Signed, append-only portable Evidence.
pub mod evidence {
    pub use runtrue_provider_contract::{
        verify_evidence_chain_structure, verify_evidence_chain_with, AppendEvidenceOutcome,
        EvidenceCheckpoint, EvidenceEnvelope, EvidenceEvent, EvidenceIdentities, EvidenceLink,
        EvidenceObservedTime, EvidencePage, EvidenceProducerIdentity, EvidenceProducerKind,
        EvidenceRangeRequest, EvidenceScopeKind, EvidenceSignature, EvidenceSignatureVerifier,
        EvidenceStore,
    };
}

/// Write-ahead external-effect contracts.
pub mod effects {
    pub use runtrue_provider_contract::{
        verify_external_effect_chain, ExternalEffectIdentity, ExternalEffectJournal,
        ExternalEffectReconciliation, ExternalEffectState, ExternalEffectTransition,
    };
}

/// Integrity-preserving logical storage contracts.
pub mod storage {
    pub use runtrue_provider_contract::{
        LogicalObjectClass, LogicalObjectMetadata, LogicalObjectScope, LogicalObjectState,
        LogicalObjectStore, ObjectChunk, ObjectReadChunk, ObjectReadRequest, ObjectTombstone,
        ObjectWriteDeclaration, ObjectWriteLease, PublicationCondition, PublishObjectOutcome,
        StorageAuthority,
    };
}

/// One-shot sterile warm-pool lifecycle.
pub mod pool {
    pub use runtrue_provider_contract::{
        PoolAssignmentBinding, PoolAssignmentSubjectKind, PoolMemberRecord, PoolMemberState,
        PoolMemberTransition,
    };
}

/// Provider-neutral capabilities, Evidence, storage, lifecycle operations,
/// checkpoints, Replay Bundles, warm pools, external effects, and Bisim.
pub mod provider {
    pub use runtrue_provider_contract::*;
}

/// Provider-neutral Bisim conformance primitives.
pub mod bisim {
    pub use runtrue_provider_contract::{
        BisimComparisonRole, BisimLifecycleObservation, BisimOperationalContext,
        BisimPortableObservation, ConformanceCaseOutcome, ConformanceCaseResult,
        ConformanceStatement, ConformanceSuiteIdentity, ProfileConformance,
        SignedConformanceMetadata,
    };
}

/// Transitional workflow integration. These types retain their existing
/// canonical identities while clients migrate to generic Execution Capsules.
pub mod workflow {
    pub use runtrue_policy::CapsuleSeal;
    pub use runtrue_workflow_ir::{ExecutionCapsule, CAPSULE_SCHEMA_VERSION};

    pub mod replay {
        pub use runtrue_replay::{ReplayBundle, ReplayEnvelope, ReplayError};
    }

    pub mod bisim {
        pub use runtrue_bisim::{
            compare_bisim, observe_backend, BackendIdentity, BisimComparison, BisimError,
            BisimObservation, SecretCanary,
        };
    }
}

pub use capsule::{ExecutionCapsule, SessionCapsule};
pub use program::{ProgramIdentity, ProgramKind};
pub use runtrue_execution::{
    CapabilityBudget, CapabilityContract, CapabilityGrant, ContentDigest, EvidenceContract,
    EvidenceProfile, ExecutionModelError, OutputContract, PlacementConstraints, ResourceLimits,
};
pub use seal::Seal;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_and_workflow_capsules_remain_explicitly_distinct() {
        assert_ne!(
            std::any::type_name::<ExecutionCapsule>(),
            std::any::type_name::<workflow::ExecutionCapsule>()
        );
        assert_eq!(
            capsule::EXECUTION_CAPSULE_SCHEMA_VERSION,
            runtrue_execution::EXECUTION_CAPSULE_SCHEMA_VERSION
        );
        assert_eq!(
            workflow::CAPSULE_SCHEMA_VERSION,
            runtrue_workflow_ir::CAPSULE_SCHEMA_VERSION
        );
    }

    #[test]
    fn provider_contract_is_reachable_only_through_domain_neutral_vocabulary() {
        let generation = provider::ContractGeneration::new(1).unwrap();
        assert_eq!(generation.get(), 1);
        let type_name = std::any::type_name::<provider::AdmissionRequest>();
        assert!(!type_name.contains("github"));
        assert!(!type_name.contains("workflow"));
    }
}
