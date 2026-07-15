use runtrue_execution::{
    ApprovalSubject, Architecture, CapabilityBudget, CapabilityContract, CapabilityGrant,
    CapabilityUsage, CapsuleKind, ChildAdmissionRequest, ChildResourceReservation, ContentDigest,
    DelegationGrant, DelegationPolicy, DelegationValidationContext, EvidenceContract,
    EvidenceProfile, ExecutionCapsule, ExecutionModelError, ExecutionState, ExternalEffectContract,
    ExternalEffectDeclaration, FailureClass, NondeterminismContract, NondeterministicInputClass,
    NondeterministicInputGrant, OperatingSystem, OutputContract, ParentBinding,
    PlacementConstraints, ProgramIdentity, ProgramKind, ProgramPlatform, ProgramSignatureIdentity,
    ReservationState, ReservationTerminalOutcome, ReservationTransitionRequest, ResourceLimits,
    RuntimeCompatibilityProfile, RuntimeComponents, RuntimeFamily, RuntimePlatform, Seal,
    SealSignatureVerifier, SessionCapsule, SessionReservationLedger, SessionState, TerminalCause,
    TerminalDecision, WorkspacePublicationLedger, WorkspacePublicationRequest,
    EXECUTION_CAPSULE_SCHEMA_VERSION, MAX_SEAL_LIFETIME_MS, PROGRAM_IDENTITY_SCHEMA_VERSION,
    RUNTIME_PROFILE_SCHEMA_VERSION, SEAL_SCHEMA_VERSION,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn runtime() -> RuntimeCompatibilityProfile {
    RuntimeCompatibilityProfile {
        schema_version: RUNTIME_PROFILE_SCHEMA_VERSION,
        family: RuntimeFamily::WasmtimeComponent,
        implementation_generation: "wasmtime-46-p3".to_owned(),
        platform: RuntimePlatform {
            operating_system: OperatingSystem::Linux,
            architecture: Architecture::Amd64,
            cpu_feature_floor: ["sse2".to_owned()].into_iter().collect(),
        },
        components: RuntimeComponents {
            engine: Some(digest("wasmtime")),
            vmm: None,
            container_runtime: None,
            kernel: None,
            rootfs: None,
            guest: None,
            compiler: Some(digest("cranelift")),
        },
        program_abi: "component-model".to_owned(),
        wit_world: Some("runtrue-action-0.3".to_owned()),
        syscall_contract: "wasi-0.3".to_owned(),
        memory_model: "wasm-linear-memory-v1".to_owned(),
        task_model: "wasi-tasks-v1".to_owned(),
        filesystem_model: "wasi-filesystem-v1".to_owned(),
        network_model: "brokered-network-v1".to_owned(),
        device_model: "no-devices-v1".to_owned(),
        aot_compatibility: Some(digest("aot")),
        snapshot_compatibility: None,
        mitigation_profile: "wasmtime-default-v1".to_owned(),
        capability_adapter_generation: "adapter-v1".to_owned(),
        guest_protocol_generation: "guest-v1".to_owned(),
        security_patch_generation: 1,
        revocation_generation: 1,
    }
}

fn resources() -> ResourceLimits {
    ResourceLimits {
        cpu_millis: 2_000,
        memory_bytes: 512 * 1024 * 1024,
        storage_bytes: 1024 * 1024 * 1024,
        task_count: 64,
        process_count: 1,
        network_egress_bytes: 16 * 1024 * 1024,
        maximum_duration_ms: 3_600_000,
    }
}

fn placement() -> PlacementConstraints {
    PlacementConstraints {
        allowed_provider_ids: ["provider-local".to_owned()].into_iter().collect(),
        allowed_pool_trust_profiles: [digest("pool-trust")].into_iter().collect(),
        administrative_trust_domains: ["developer-machine".to_owned()].into_iter().collect(),
        allowed_regions: BTreeSet::new(),
        allowed_localities: BTreeSet::new(),
        data_residency: BTreeSet::new(),
        required_devices: BTreeMap::new(),
    }
}

fn capabilities() -> CapabilityContract {
    CapabilityContract {
        grants: [(
            "artifact-read".to_owned(),
            CapabilityGrant {
                class: "artifact".to_owned(),
                resource: "tenant://example/input".to_owned(),
                operations: ["read".to_owned()].into_iter().collect(),
                destinations: BTreeSet::new(),
                external_effect_class: None,
                budget: CapabilityBudget {
                    maximum_calls: 100,
                    maximum_request_bytes: 1024 * 1024,
                    maximum_response_bytes: 8 * 1024 * 1024,
                    maximum_external_effects: 0,
                },
                constraints_digest: digest("artifact-constraints"),
            },
        )]
        .into_iter()
        .collect(),
        aggregate_budget: CapabilityBudget {
            maximum_calls: 100,
            maximum_request_bytes: 1024 * 1024,
            maximum_response_bytes: 8 * 1024 * 1024,
            maximum_external_effects: 0,
        },
    }
}

fn output() -> OutputContract {
    OutputContract {
        stdout_max_bytes: 1024 * 1024,
        stderr_max_bytes: 1024 * 1024,
        structured_output_schema: Some(digest("output-schema")),
        artifact_classes: ["report".to_owned()].into_iter().collect(),
        filesystem_change_roots: ["target".to_owned()].into_iter().collect(),
    }
}

fn evidence() -> EvidenceContract {
    EvidenceContract {
        profile: EvidenceProfile::Baseline,
        maximum_events: 10_000,
        maximum_log_bytes: 8 * 1024 * 1024,
        retention_ms: 86_400_000,
    }
}

fn execution() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: EXECUTION_CAPSULE_SCHEMA_VERSION,
        kind: CapsuleKind::Execution,
        tenant_id: "tenant-example".to_owned(),
        principal_id: "principal-developer".to_owned(),
        program: ProgramIdentity {
            schema_version: PROGRAM_IDENTITY_SCHEMA_VERSION,
            kind: ProgramKind::WasmComponent,
            content_digest: digest("program"),
            resolver_digest: digest("resolver"),
            media_type: "application/wasm".to_owned(),
            entrypoint: vec!["run".to_owned()],
            signature: Some(ProgramSignatureIdentity {
                signer_identity: "program-signer".to_owned(),
                signature_algorithm: "ed25519-v1".to_owned(),
                signing_key_id: digest("program-signing-key"),
                signature_digest: digest("program-signature"),
                provenance_digest: digest("program-provenance"),
            }),
            platform: None,
            compatibility_metadata: [("component-model".to_owned(), digest("component-model-v1"))]
                .into_iter()
                .collect(),
        },
        arguments: vec!["--locked".to_owned()],
        working_directory: Some("workspace".to_owned()),
        input_artifacts: [digest("input")].into_iter().collect(),
        runtime: runtime(),
        placement: placement(),
        resources: resources(),
        capabilities: capabilities(),
        nondeterminism: NondeterminismContract::default(),
        external_effects: ExternalEffectContract::default(),
        output: output(),
        evidence: evidence(),
        parent: Some(ParentBinding {
            session_capsule_digest: digest("session-parent"),
            session_seal_digest: digest("seal-parent"),
            delegation_id: "delegation-default".to_owned(),
            delegation_grant_digest: digest("delegation-grant"),
            workspace_generation_digest: digest("workspace"),
            containment_proof_digest: digest("containment"),
        }),
    }
}

fn session() -> SessionCapsule {
    let runtime = runtime();
    let runtime_digest = runtime.digest().unwrap();
    let maximum_resources = resources();
    SessionCapsule {
        schema_version: EXECUTION_CAPSULE_SCHEMA_VERSION,
        kind: CapsuleKind::Session,
        tenant_id: "tenant-example".to_owned(),
        principal_id: "principal-developer".to_owned(),
        initial_workspace_digest: digest("initial-workspace"),
        mutable_workspace_roots: ["workspace".to_owned()].into_iter().collect(),
        runtime,
        placement: placement(),
        maximum_resources: maximum_resources.clone(),
        capabilities: capabilities(),
        nondeterminism: NondeterminismContract::default(),
        output: output(),
        evidence: evidence(),
        idle_timeout_ms: 60_000,
        hard_lifetime_ms: 3_600_000,
        maximum_child_count: 100,
        maximum_concurrency: 4,
        delegation_policies: [(
            "delegation-default".to_owned(),
            DelegationPolicy {
                planner_principal: "planner-default".to_owned(),
                planner_implementation_digest: digest("planner"),
                allowed_program_kinds: [ProgramKind::WasmComponent].into_iter().collect(),
                allowed_program_resolvers: [digest("resolver")].into_iter().collect(),
                allowed_runtime_profiles: [runtime_digest].into_iter().collect(),
                maximum_resources,
                placement: placement(),
                capabilities: capabilities(),
                nondeterminism: NondeterminismContract::default(),
                output: output(),
                maximum_child_count: 100,
                maximum_concurrency: 4,
                maximum_child_duration_ms: 3_600_000,
                subdelegation_allowed: false,
                policy_version_id: "delegation-policy-v1".to_owned(),
                policy_version_digest: digest("delegation-policy-v1"),
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn seal(subject: &ApprovalSubject) -> Seal {
    let mut seal = Seal {
        schema_version: SEAL_SCHEMA_VERSION,
        approval_subject_digest: subject.digest().unwrap(),
        capsule_kind: subject.capsule_kind,
        capsule_digest: subject.capsule_digest.clone(),
        signer_identity: "signer-security-team".to_owned(),
        authority_identity: "authority-tenant-policy".to_owned(),
        issued_unix_ms: 1_000,
        expires_unix_ms: 10_000,
        revocation_generation: 7,
        signature_algorithm: "ed25519-v1".to_owned(),
        signing_key_id: digest("seal-signing-key"),
        signature: vec![0; 32],
    };
    seal.signature = ContentDigest::sha256(seal.signing_bytes().unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    seal
}

struct TestSealVerifier;

impl SealSignatureVerifier for TestSealVerifier {
    fn verify_signature(&self, seal: &Seal, signing_bytes: &[u8]) -> bool {
        seal.signature == ContentDigest::sha256(signing_bytes).as_str().as_bytes()
    }
}

#[test]
fn golden_execution_capsule_is_canonical_and_stable() {
    let capsule = execution();
    let bytes = capsule.canonical_bytes().unwrap();
    assert_eq!(
        capsule.digest().unwrap().to_string(),
        "sha256:0ccf08a17b9bb6a7f7b49f966b6ade63d155a63eb8679c60448c3f466c4a7ab2"
    );
    let decoded: ExecutionCapsule = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
}

#[test]
fn golden_session_capsule_and_approval_subject_are_distinct() {
    let capsule = session();
    assert_eq!(
        capsule.digest().unwrap().to_string(),
        "sha256:badc27069a095014214e749adf998ea4a751ce5a9be314551b310d7b18c1e02c"
    );
    let subject = capsule
        .approval_subject(digest("policy"), digest("authority"))
        .unwrap();
    assert_ne!(subject.digest().unwrap(), capsule.digest().unwrap());
    assert_eq!(subject.capsule_digest, capsule.digest().unwrap());
}

#[test]
fn map_and_set_insertion_order_cannot_change_identity() {
    let mut left = execution();
    let mut right = execution();
    left.capabilities.grants.insert(
        "network-read".to_owned(),
        CapabilityGrant {
            class: "network".to_owned(),
            resource: "https://example.invalid".to_owned(),
            operations: ["connect".to_owned(), "resolve".to_owned()]
                .into_iter()
                .collect(),
            destinations: ["example.invalid".to_owned()].into_iter().collect(),
            external_effect_class: None,
            budget: CapabilityBudget {
                maximum_calls: 10,
                maximum_request_bytes: 1024,
                maximum_response_bytes: 1024,
                maximum_external_effects: 0,
            },
            constraints_digest: digest("network"),
        },
    );
    right.capabilities.grants = left
        .capabilities
        .grants
        .iter()
        .rev()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    assert_eq!(
        left.canonical_bytes().unwrap(),
        right.canonical_bytes().unwrap()
    );
    assert_eq!(left.digest().unwrap(), right.digest().unwrap());
}

#[test]
fn canonical_roots_and_nested_contracts_reject_unknown_fields() {
    let mut execution_value = serde_json::to_value(execution()).unwrap();
    execution_value.as_object_mut().unwrap().insert(
        "job_id".to_owned(),
        Value::String("integration-leak".to_owned()),
    );
    assert!(serde_json::from_value::<ExecutionCapsule>(execution_value).is_err());

    let mut runtime_value = serde_json::to_value(runtime()).unwrap();
    runtime_value
        .as_object_mut()
        .unwrap()
        .insert("fallback".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<RuntimeCompatibilityProfile>(runtime_value).is_err());

    let mut session_value = serde_json::to_value(session()).unwrap();
    session_value.as_object_mut().unwrap().insert(
        "workflow".to_owned(),
        Value::String("integration-leak".to_owned()),
    );
    assert!(serde_json::from_value::<SessionCapsule>(session_value).is_err());

    let mut nested_value = serde_json::to_value(execution()).unwrap();
    nested_value["placement"].as_object_mut().unwrap().insert(
        "concrete_pool_id".to_owned(),
        Value::String("pool-1".to_owned()),
    );
    assert!(serde_json::from_value::<ExecutionCapsule>(nested_value).is_err());

    let subject = ApprovalSubject {
        schema_version: 1,
        capsule_kind: CapsuleKind::Execution,
        capsule_digest: digest("capsule"),
        policy_digest: digest("policy"),
        authority_context_digest: digest("authority"),
    };
    let mut subject_value = serde_json::to_value(subject).unwrap();
    subject_value.as_object_mut().unwrap().insert(
        "repository".to_owned(),
        Value::String("forbidden".to_owned()),
    );
    assert!(serde_json::from_value::<ApprovalSubject>(subject_value).is_err());

    let subject = execution()
        .approval_subject(digest("policy"), digest("authority"))
        .unwrap();
    let mut seal_value = serde_json::to_value(seal(&subject)).unwrap();
    seal_value.as_object_mut().unwrap().insert(
        "workflow_approval_id".to_owned(),
        Value::String("forbidden".to_owned()),
    );
    assert!(serde_json::from_value::<Seal>(seal_value).is_err());
}

#[test]
fn capsule_kind_and_paths_are_fail_closed() {
    let mut capsule = execution();
    capsule.kind = CapsuleKind::Session;
    assert!(capsule.validate().is_err());
    capsule.kind = CapsuleKind::Execution;
    capsule.working_directory = Some("../escape".to_owned());
    assert!(capsule.validate().is_err());
}

#[test]
fn exact_argument_contract_preserves_empty_and_multiline_values_but_rejects_nul() {
    let mut capsule = execution();
    capsule.arguments = vec![String::new(), "line one\nline two".to_owned()];
    assert!(capsule.validate().is_ok());
    capsule.arguments.push("bad\0argument".to_owned());
    assert!(capsule.validate().is_err());
}

#[test]
fn resolved_executable_programs_require_signature_platform_and_compatibility_identity() {
    let wasm = execution().program;
    wasm.validate().unwrap();
    let mut unsigned = wasm.clone();
    unsigned.signature = None;
    assert!(unsigned.validate().is_err());

    for kind in [ProgramKind::OciImage, ProgramKind::NativeExecutable] {
        let mut resolved = wasm.clone();
        resolved.kind = kind;
        resolved.platform = Some(ProgramPlatform {
            operating_system: OperatingSystem::Linux,
            architecture: Architecture::Amd64,
        });
        resolved.validate().unwrap();
        resolved.platform = None;
        assert!(resolved.validate().is_err());
    }
}

#[test]
fn effects_and_nondeterminism_are_explicit_canonical_capsule_inputs() {
    let mut capsule = execution();
    let baseline = capsule.digest().unwrap();
    capsule.capabilities.grants.insert(
        "deployment-write".to_owned(),
        CapabilityGrant {
            class: "deployment".to_owned(),
            resource: "environment://production".to_owned(),
            operations: ["write".to_owned()].into_iter().collect(),
            destinations: ["deployment.example".to_owned()].into_iter().collect(),
            external_effect_class: Some("deployment".to_owned()),
            budget: CapabilityBudget {
                maximum_calls: 1,
                maximum_request_bytes: 1024,
                maximum_response_bytes: 1024,
                maximum_external_effects: 1,
            },
            constraints_digest: digest("deployment-constraints"),
        },
    );
    capsule
        .capabilities
        .aggregate_budget
        .maximum_external_effects = 1;
    capsule.external_effects.operations.insert(
        "deploy-1".to_owned(),
        ExternalEffectDeclaration {
            operation_id: "deploy-1".to_owned(),
            idempotency_key: "deploy-idempotency-1".to_owned(),
            capability_grant_id: "deployment-write".to_owned(),
            effect_class: "deployment".to_owned(),
            destination_digest: digest("deployment-destination"),
            idempotency_contract_digest: digest("deployment-idempotency-contract"),
            bounded_request_digest: digest("deployment-request"),
        },
    );
    capsule.nondeterminism.inputs.insert(
        "clock".to_owned(),
        NondeterministicInputGrant {
            class: NondeterministicInputClass::LiveClock,
            profile_digest: digest("clock-profile"),
            maximum_uses: 4,
            maximum_bytes: 64,
        },
    );
    capsule.validate().unwrap();
    assert_ne!(capsule.digest().unwrap(), baseline);

    let mut mismatched = capsule;
    mismatched
        .external_effects
        .operations
        .get_mut("deploy-1")
        .unwrap()
        .effect_class = "payment".to_owned();
    assert!(mismatched.validate().is_err());
}

#[test]
fn runtime_profile_rejects_missing_and_inapplicable_components() {
    let mut profile = runtime();
    profile.components.engine = None;
    assert!(profile.validate().is_err());
    let mut profile = runtime();
    profile.components.kernel = Some(digest("ambient-host-kernel"));
    assert!(profile.validate().is_err());
    let mut profile = runtime();
    profile.implementation_generation = "*".to_owned();
    assert!(profile.validate().is_err());
}

#[test]
fn every_runtime_identity_field_changes_the_digest() {
    let baseline = runtime().digest().unwrap();
    let mut changed = runtime();
    changed.security_patch_generation += 1;
    assert_ne!(changed.digest().unwrap(), baseline);
    let mut changed = runtime();
    changed.capability_adapter_generation = "adapter-v2".to_owned();
    assert_ne!(changed.digest().unwrap(), baseline);
    let mut changed = runtime();
    changed.platform.cpu_feature_floor.insert("avx2".to_owned());
    assert_ne!(changed.digest().unwrap(), baseline);
}

#[test]
fn delegation_must_be_a_strict_session_envelope_subset() {
    let mut capsule = session();
    capsule
        .delegation_policies
        .get_mut("delegation-default")
        .unwrap()
        .maximum_resources
        .memory_bytes += 1;
    assert!(capsule.validate().is_err());

    let mut capsule = session();
    capsule
        .delegation_policies
        .get_mut("delegation-default")
        .unwrap()
        .capabilities
        .aggregate_budget
        .maximum_calls += 1;
    assert!(capsule.validate().is_err());
}

#[test]
fn execution_state_machine_accepts_only_documented_edges() {
    let states = [
        ExecutionState::Proposed,
        ExecutionState::Admitted,
        ExecutionState::Queued,
        ExecutionState::Leased,
        ExecutionState::Running,
        ExecutionState::Finalizing,
        ExecutionState::Terminal,
    ];
    let allowed = [
        (ExecutionState::Proposed, ExecutionState::Admitted),
        (ExecutionState::Proposed, ExecutionState::Terminal),
        (ExecutionState::Admitted, ExecutionState::Queued),
        (ExecutionState::Admitted, ExecutionState::Terminal),
        (ExecutionState::Queued, ExecutionState::Leased),
        (ExecutionState::Queued, ExecutionState::Terminal),
        (ExecutionState::Leased, ExecutionState::Running),
        (ExecutionState::Leased, ExecutionState::Finalizing),
        (ExecutionState::Running, ExecutionState::Finalizing),
        (ExecutionState::Finalizing, ExecutionState::Terminal),
    ];
    for from in states {
        for to in states {
            assert_eq!(
                from.can_transition_to(to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
    let mut terminal = ExecutionState::Terminal;
    assert!(terminal.transition(ExecutionState::Running).is_err());
}

#[test]
fn session_state_machine_covers_suspend_restore_recovery() {
    let mut state = SessionState::Proposed;
    for next in [
        SessionState::Admitted,
        SessionState::Provisioning,
        SessionState::Active,
        SessionState::Suspending,
        SessionState::Suspended,
        SessionState::Restoring,
        SessionState::Active,
        SessionState::Destroying,
        SessionState::Terminal,
    ] {
        state.transition(next).unwrap();
    }
    assert!(state.is_terminal());
    assert!(!state.can_transition_to(SessionState::Active));
    assert!(SessionState::Suspending.can_transition_to(SessionState::Active));
    assert!(SessionState::Restoring.can_transition_to(SessionState::Suspended));
}

#[test]
fn session_state_machine_rejects_every_undocumented_edge() {
    let states = [
        SessionState::Proposed,
        SessionState::Admitted,
        SessionState::Provisioning,
        SessionState::Active,
        SessionState::Suspending,
        SessionState::Suspended,
        SessionState::Restoring,
        SessionState::Destroying,
        SessionState::Terminal,
    ];
    let allowed = [
        (SessionState::Proposed, SessionState::Admitted),
        (SessionState::Proposed, SessionState::Terminal),
        (SessionState::Admitted, SessionState::Provisioning),
        (SessionState::Admitted, SessionState::Destroying),
        (SessionState::Provisioning, SessionState::Active),
        (SessionState::Provisioning, SessionState::Destroying),
        (SessionState::Active, SessionState::Suspending),
        (SessionState::Active, SessionState::Destroying),
        (SessionState::Suspending, SessionState::Suspended),
        (SessionState::Suspending, SessionState::Active),
        (SessionState::Suspending, SessionState::Destroying),
        (SessionState::Suspended, SessionState::Restoring),
        (SessionState::Suspended, SessionState::Destroying),
        (SessionState::Restoring, SessionState::Active),
        (SessionState::Restoring, SessionState::Suspended),
        (SessionState::Restoring, SessionState::Destroying),
        (SessionState::Destroying, SessionState::Terminal),
    ];
    for from in states {
        for to in states {
            assert_eq!(
                from.can_transition_to(to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn first_ordinary_terminal_cause_wins_and_all_causes_remain() {
    let mut decision = TerminalDecision::default();
    assert!(decision.commit(TerminalCause::Failed(FailureClass::TimedOut)));
    assert!(!decision.commit(TerminalCause::Failed(FailureClass::Canceled)));
    assert_eq!(
        decision.primary(),
        Some(TerminalCause::Failed(FailureClass::TimedOut))
    );
    assert!(decision
        .observed_failures()
        .contains(&FailureClass::TimedOut));
    assert!(decision
        .observed_failures()
        .contains(&FailureClass::Canceled));
}

#[test]
fn safety_overrides_replace_success_and_ordinary_failures_in_order() {
    let mut decision = TerminalDecision::default();
    assert!(decision.commit(TerminalCause::Succeeded));
    assert!(decision.commit(TerminalCause::Failed(
        FailureClass::ExternalEffectIndeterminate
    )));
    assert!(decision.commit(TerminalCause::Failed(FailureClass::RunnerIntegrityFailure)));
    assert!(!decision.commit(TerminalCause::Failed(FailureClass::ProgramFailure)));
    assert_eq!(
        decision.primary(),
        Some(TerminalCause::Failed(FailureClass::RunnerIntegrityFailure))
    );
    assert!(decision.success_observed());
    assert!(decision
        .observed_failures()
        .contains(&FailureClass::ExternalEffectIndeterminate));
    assert!(decision
        .observed_failures()
        .contains(&FailureClass::RunnerIntegrityFailure));
    assert!(decision
        .observed_failures()
        .contains(&FailureClass::ProgramFailure));
}

#[test]
fn terminal_commit_is_idempotent() {
    let mut decision = TerminalDecision::default();
    let cause = TerminalCause::Failed(FailureClass::RuntimeFailure);
    assert!(decision.commit(cause));
    assert!(!decision.commit(cause));
    assert_eq!(decision.observed_failures().len(), 1);
}

#[test]
fn golden_seal_binds_exact_subject_and_has_distinct_signed_identity() {
    let capsule = execution();
    let subject = capsule
        .approval_subject(digest("policy"), digest("authority-context"))
        .unwrap();
    let seal = seal(&subject);
    seal.validate_for_subject(&subject, 5_000, 7, &TestSealVerifier)
        .unwrap();
    assert_eq!(
        seal.digest().unwrap().to_string(),
        "sha256:77615e52f495a9f3966140cd545792c938536264f049c8e35d464ae501ee2d0e"
    );
    assert_ne!(seal.digest().unwrap(), subject.digest().unwrap());
    assert_ne!(
        seal.signing_bytes().unwrap(),
        seal.canonical_bytes().unwrap()
    );
    let mut differently_signed = seal.clone();
    differently_signed.signature = vec![0xa5; 64];
    assert_eq!(
        differently_signed.signing_bytes().unwrap(),
        seal.signing_bytes().unwrap()
    );
    assert_ne!(differently_signed.digest().unwrap(), seal.digest().unwrap());
    assert_eq!(
        differently_signed
            .validate_for_subject(&subject, 5_000, 7, &TestSealVerifier)
            .unwrap_err(),
        ExecutionModelError::InvalidSealSignature
    );
    let mut unsigned = seal.clone();
    unsigned.signature.clear();
    assert_eq!(
        unsigned.signing_bytes().unwrap(),
        seal.signing_bytes().unwrap()
    );
    assert!(unsigned.validate().is_err());
}

#[test]
fn seal_rejects_subject_and_capsule_substitution() {
    let capsule = execution();
    let subject = capsule
        .approval_subject(digest("policy"), digest("authority-context"))
        .unwrap();
    let seal = seal(&subject);

    let mut changed_subject = subject.clone();
    changed_subject.policy_digest = digest("different-policy");
    assert!(matches!(
        seal.validate_for_subject(&changed_subject, 5_000, 7, &TestSealVerifier),
        Err(runtrue_execution::ExecutionModelError::SealSubjectMismatch)
    ));

    let mut changed_seal = seal.clone();
    changed_seal.capsule_digest = digest("different-capsule");
    assert!(matches!(
        changed_seal.validate_for_subject(&subject, 5_000, 7, &TestSealVerifier),
        Err(runtrue_execution::ExecutionModelError::SealSubjectMismatch)
    ));
}

#[test]
fn seal_validity_window_and_revocation_are_fail_closed() {
    let capsule = execution();
    let subject = capsule
        .approval_subject(digest("policy"), digest("authority-context"))
        .unwrap();
    let seal = seal(&subject);
    assert!(matches!(
        seal.validate_for_subject(&subject, 999, 7, &TestSealVerifier),
        Err(runtrue_execution::ExecutionModelError::SealNotYetValid)
    ));
    assert!(matches!(
        seal.validate_for_subject(&subject, 10_000, 7, &TestSealVerifier),
        Err(runtrue_execution::ExecutionModelError::SealExpired)
    ));
    assert!(matches!(
        seal.validate_for_subject(&subject, 5_000, 8, &TestSealVerifier),
        Err(runtrue_execution::ExecutionModelError::SealRevoked { .. })
    ));

    let mut invalid = seal.clone();
    invalid.expires_unix_ms = invalid.issued_unix_ms;
    assert!(invalid.validate().is_err());
    invalid.expires_unix_ms = invalid
        .issued_unix_ms
        .saturating_add(MAX_SEAL_LIFETIME_MS)
        .saturating_add(1);
    assert!(invalid.validate().is_err());
    invalid.expires_unix_ms = 10_000;
    invalid.signature.clear();
    assert!(invalid.validate().is_err());
}

fn sealed_session_grant() -> (SessionCapsule, ApprovalSubject, Seal, DelegationGrant) {
    let session = session();
    let subject = session
        .approval_subject(digest("session-policy"), digest("session-authority"))
        .unwrap();
    let seal = seal(&subject);
    let policy = session
        .delegation_policies
        .get("delegation-default")
        .unwrap()
        .clone();
    let grant = DelegationGrant {
        schema_version: EXECUTION_CAPSULE_SCHEMA_VERSION,
        delegation_id: "delegation-issued-1".to_owned(),
        parent_session_capsule_digest: session.digest().unwrap(),
        parent_session_seal_digest: seal.digest().unwrap(),
        policy_id: "delegation-default".to_owned(),
        policy_digest: policy.digest().unwrap(),
        planner_principal: policy.planner_principal,
        planner_implementation_digest: policy.planner_implementation_digest,
        allowed_program_kinds: policy.allowed_program_kinds,
        allowed_program_resolvers: policy.allowed_program_resolvers,
        allowed_runtime_profiles: policy.allowed_runtime_profiles,
        maximum_resources: policy.maximum_resources,
        placement: policy.placement,
        capabilities: policy.capabilities,
        nondeterminism: policy.nondeterminism,
        output: policy.output,
        maximum_child_count: policy.maximum_child_count,
        maximum_concurrency: policy.maximum_concurrency,
        maximum_child_duration_ms: policy.maximum_child_duration_ms,
        subdelegation_allowed: policy.subdelegation_allowed,
        policy_version_id: policy.policy_version_id,
        policy_version_digest: policy.policy_version_digest,
        issued_unix_ms: 2_000,
        expires_unix_ms: 9_000,
        revocation_generation: 1,
    };
    (session, subject, seal, grant)
}

fn delegated_child(grant: &DelegationGrant) -> ExecutionCapsule {
    let mut child = execution();
    child.resources.cpu_millis = 500;
    child.resources.memory_bytes = 64 * 1024 * 1024;
    child.resources.storage_bytes = 128 * 1024 * 1024;
    child.resources.task_count = 4;
    child.capabilities.aggregate_budget = CapabilityBudget {
        maximum_calls: 40,
        maximum_request_bytes: 256 * 1024,
        maximum_response_bytes: 2 * 1024 * 1024,
        maximum_external_effects: 0,
    };
    child.parent = Some(ParentBinding {
        session_capsule_digest: grant.parent_session_capsule_digest.clone(),
        session_seal_digest: grant.parent_session_seal_digest.clone(),
        delegation_id: grant.delegation_id.clone(),
        delegation_grant_digest: grant.digest().unwrap(),
        workspace_generation_digest: digest("workspace-generation-1"),
        containment_proof_digest: digest("containment-proof-1"),
    });
    child
}

#[test]
fn issued_grant_binds_sealed_parent_and_contains_child() {
    let (session, subject, seal, grant) = sealed_session_grant();
    grant
        .validate_against_parent(&DelegationValidationContext {
            session: &session,
            subject: &subject,
            seal: &seal,
            verifier: &TestSealVerifier,
            now_unix_ms: 5_000,
            current_seal_revocation_generation: 7,
            current_grant_revocation_generation: 1,
        })
        .unwrap();
    grant.contains_child(&delegated_child(&grant)).unwrap();

    let mut wrong_resolver = delegated_child(&grant);
    wrong_resolver.program.resolver_digest = digest("unapproved-resolver");
    assert!(matches!(
        grant.contains_child(&wrong_resolver),
        Err(ExecutionModelError::ContainmentViolation {
            field: "Program resolver"
        })
    ));

    let mut expanded = delegated_child(&grant);
    expanded
        .placement
        .allowed_regions
        .insert("moon-1".to_owned());
    assert!(matches!(
        grant.contains_child(&expanded),
        Err(ExecutionModelError::ContainmentViolation { field: "placement" })
    ));

    let mut undeclared_randomness = delegated_child(&grant);
    undeclared_randomness.nondeterminism.inputs.insert(
        "randomness".to_owned(),
        NondeterministicInputGrant {
            class: NondeterministicInputClass::LiveRandomness,
            profile_digest: digest("randomness-profile"),
            maximum_uses: 1,
            maximum_bytes: 32,
        },
    );
    assert!(matches!(
        grant.contains_child(&undeclared_randomness),
        Err(ExecutionModelError::ContainmentViolation {
            field: "nondeterminism"
        })
    ));
}

fn admission_request(
    session_id: &str,
    reservation_id: &str,
    child_id: &str,
    key: &str,
    expected_ledger_revision: u64,
) -> ChildAdmissionRequest {
    ChildAdmissionRequest {
        schema_version: 1,
        reservation_id: reservation_id.to_owned(),
        session_id: session_id.to_owned(),
        child_execution_id: child_id.to_owned(),
        idempotency_key: key.to_owned(),
        session_fence: 11,
        expected_ledger_revision,
        created_unix_ms: 5_000,
    }
}

fn admit_child(
    ledger: &mut SessionReservationLedger,
    request: ChildAdmissionRequest,
    session: &SessionCapsule,
    subject: &ApprovalSubject,
    seal: &Seal,
    grant: &DelegationGrant,
    child: &ExecutionCapsule,
) -> Result<runtrue_execution::ReservationResult, ExecutionModelError> {
    ledger.admit_child(
        request,
        session,
        subject,
        seal,
        &TestSealVerifier,
        grant,
        child,
        5_000,
        &subject.policy_digest,
        7,
        1,
    )
}

#[test]
fn atomic_child_admission_rejects_invalid_authority_and_containment_without_mutation() {
    let (session, subject, valid_seal, grant) = sealed_session_grant();
    let child = delegated_child(&grant);
    let request = admission_request("session-1", "reservation-1", "child-1", "reserve-key-1", 0);
    let mut ledger = SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();

    let mut invalid_seal = valid_seal.clone();
    invalid_seal.signature[0] ^= 0xff;
    assert_eq!(
        admit_child(
            &mut ledger,
            request.clone(),
            &session,
            &subject,
            &invalid_seal,
            &grant,
            &child,
        )
        .unwrap_err(),
        ExecutionModelError::InvalidSealSignature
    );
    assert_eq!(ledger.ledger_revision, 0);
    assert_eq!(ledger.active_concurrency, 0);

    assert_eq!(
        ledger
            .admit_child(
                request.clone(),
                &session,
                &subject,
                &valid_seal,
                &TestSealVerifier,
                &grant,
                &child,
                5_000,
                &digest("superseding-session-policy"),
                7,
                1,
            )
            .unwrap_err(),
        ExecutionModelError::ReservationIdentityConflict
    );
    assert_eq!(ledger.ledger_revision, 0);
    assert_eq!(ledger.active_concurrency, 0);

    let mut overbroad_child = child;
    overbroad_child.resources.memory_bytes = grant.maximum_resources.memory_bytes + 1;
    assert!(matches!(
        admit_child(
            &mut ledger,
            request,
            &session,
            &subject,
            &valid_seal,
            &grant,
            &overbroad_child,
        ),
        Err(ExecutionModelError::ContainmentViolation {
            field: "resource limits"
        })
    ));
    assert_eq!(ledger.ledger_revision, 0);
    assert_eq!(ledger.active_concurrency, 0);
    assert_eq!(ledger.admitted_child_count, 0);
}

#[test]
fn reservations_are_atomic_bounded_and_idempotent() {
    let (session, subject, seal, grant) = sealed_session_grant();
    let child = delegated_child(&grant);
    let mut ledger = SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();
    let request = admission_request("session-1", "reservation-1", "child-1", "reserve-key-1", 0);
    let first = admit_child(
        &mut ledger,
        request.clone(),
        &session,
        &subject,
        &seal,
        &grant,
        &child,
    )
    .unwrap();
    assert!(!first.replayed);
    assert_eq!(
        first.record.request.child_capsule_digest,
        child.digest().unwrap()
    );
    assert_eq!(
        first.record.request.resources,
        ChildResourceReservation::from_child(&child)
    );
    assert_eq!(ledger.active_concurrency, 1);
    assert!(
        admit_child(
            &mut ledger,
            request.clone(),
            &session,
            &subject,
            &seal,
            &grant,
            &child,
        )
        .unwrap()
        .replayed
    );
    assert_eq!(ledger.active_concurrency, 1);

    assert_eq!(
        admit_child(
            &mut ledger,
            admission_request(
                "session-1",
                "reservation-stale",
                "child-stale",
                "reserve-key-stale",
                0,
            ),
            &session,
            &subject,
            &seal,
            &grant,
            &child,
        )
        .unwrap_err(),
        ExecutionModelError::StaleLedgerRevision
    );
    assert_eq!(ledger.ledger_revision, 1);
    assert_eq!(ledger.active_concurrency, 1);

    let mut conflicting_child = child.clone();
    conflicting_child.arguments.push("different".to_owned());
    assert_eq!(
        admit_child(
            &mut ledger,
            request,
            &session,
            &subject,
            &seal,
            &grant,
            &conflicting_child,
        )
        .unwrap_err(),
        ExecutionModelError::IdempotencyConflict
    );

    let transition = ReservationTransitionRequest {
        schema_version: 1,
        reservation_id: "reservation-1".to_owned(),
        child_execution_id: "child-1".to_owned(),
        idempotency_key: "transition-key-1".to_owned(),
        session_fence: 11,
        expected_ledger_revision: 1,
        outcome: ReservationTerminalOutcome::Released {
            reason_digest: digest("canceled"),
        },
        actual_usage: CapabilityUsage {
            capability_calls: 2,
            capability_request_bytes: 100,
            capability_response_bytes: 200,
            external_effect_count: 0,
        },
        observed_unix_ms: 6_000,
    };
    let released = ledger.release(transition.clone()).unwrap();
    assert_eq!(released.record.state, ReservationState::Released);
    assert_eq!(ledger.active_concurrency, 0);
    assert_eq!(ledger.admitted_child_count, 1);
    assert!(ledger.release(transition).unwrap().replayed);

    let mut finalize_late = ReservationTransitionRequest {
        schema_version: 1,
        reservation_id: "reservation-1".to_owned(),
        child_execution_id: "child-1".to_owned(),
        idempotency_key: "transition-key-2".to_owned(),
        session_fence: 11,
        expected_ledger_revision: 2,
        outcome: ReservationTerminalOutcome::Finalized {
            result_digest: digest("result"),
        },
        actual_usage: CapabilityUsage::default(),
        observed_unix_ms: 6_001,
    };
    assert_eq!(
        ledger.release(finalize_late.clone()).unwrap_err(),
        ExecutionModelError::InvalidReservationTransition
    );
    finalize_late.outcome = ReservationTerminalOutcome::Released {
        reason_digest: digest("late"),
    };
    finalize_late.session_fence = 10;
    assert_eq!(
        ledger.release(finalize_late).unwrap_err(),
        ExecutionModelError::StaleSessionFence
    );
}

#[test]
fn reservations_enforce_aggregate_capability_and_byte_budgets() {
    let (session, subject, seal, grant) = sealed_session_grant();
    let mut ledger = SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();
    let mut child = delegated_child(&grant);
    child.capabilities.aggregate_budget.maximum_response_bytes = 5 * 1024 * 1024;
    admit_child(
        &mut ledger,
        admission_request("session-1", "reservation-1", "child-1", "reserve-1", 0),
        &session,
        &subject,
        &seal,
        &grant,
        &child,
    )
    .unwrap();
    assert_eq!(
        admit_child(
            &mut ledger,
            admission_request("session-1", "reservation-2", "child-2", "reserve-2", 1),
            &session,
            &subject,
            &seal,
            &grant,
            &child,
        )
        .unwrap_err(),
        ExecutionModelError::ReservationCapacityUnavailable
    );
    assert_eq!(ledger.active_concurrency, 1);
    assert_eq!(ledger.admitted_child_count, 1);
}

#[test]
fn terminal_capability_spend_is_never_recycled() {
    let (session, subject, seal, grant) = sealed_session_grant();
    let mut ledger = SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();
    let mut first_child = delegated_child(&grant);
    first_child.capabilities.aggregate_budget.maximum_calls = 60;
    admit_child(
        &mut ledger,
        admission_request("session-1", "reservation-1", "child-1", "reserve-1", 0),
        &session,
        &subject,
        &seal,
        &grant,
        &first_child,
    )
    .unwrap();
    ledger
        .release(ReservationTransitionRequest {
            schema_version: 1,
            reservation_id: "reservation-1".to_owned(),
            child_execution_id: "child-1".to_owned(),
            idempotency_key: "release-1".to_owned(),
            session_fence: 11,
            expected_ledger_revision: 1,
            outcome: ReservationTerminalOutcome::Released {
                reason_digest: digest("failed-after-effects"),
            },
            actual_usage: CapabilityUsage {
                capability_calls: 60,
                ..CapabilityUsage::default()
            },
            observed_unix_ms: 6_000,
        })
        .unwrap();
    assert_eq!(ledger.cumulative_usage.capability_calls, 60);

    let mut second_child = delegated_child(&grant);
    second_child.capabilities.aggregate_budget.maximum_calls = 50;
    assert_eq!(
        admit_child(
            &mut ledger,
            admission_request("session-1", "reservation-2", "child-2", "reserve-2", 2),
            &session,
            &subject,
            &seal,
            &grant,
            &second_child,
        )
        .unwrap_err(),
        ExecutionModelError::ReservationCapacityUnavailable
    );
}

#[test]
fn deserialized_reservation_ledger_rejects_tampered_accounting() {
    let (session, subject, seal, grant) = sealed_session_grant();
    let child = delegated_child(&grant);
    let mut ledger = SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();
    admit_child(
        &mut ledger,
        admission_request("session-1", "reservation-1", "child-1", "reserve-1", 0),
        &session,
        &subject,
        &seal,
        &grant,
        &child,
    )
    .unwrap();
    let mut value = serde_json::to_value(&ledger).unwrap();
    value["allocated"]["capability_calls"] = Value::from(0);
    let tampered: SessionReservationLedger = serde_json::from_value(value).unwrap();
    assert_eq!(
        tampered.validate().unwrap_err(),
        ExecutionModelError::AccountingFailure
    );
}

fn publication_request(
    session_digest: ContentDigest,
    reservation_id: &str,
    child_id: &str,
    key: &str,
    output: &str,
    expected_publication_revision: u64,
    expected_reservation_revision: u64,
) -> WorkspacePublicationRequest {
    WorkspacePublicationRequest {
        schema_version: 1,
        session_id: "session-1".to_owned(),
        session_capsule_digest: session_digest,
        reservation_id: reservation_id.to_owned(),
        child_execution_id: child_id.to_owned(),
        input_generation: 0,
        input_workspace_digest: digest("initial-workspace"),
        output_workspace_digest: digest(output),
        output_manifest_digest: digest(&format!("manifest-{output}")),
        idempotency_key: key.to_owned(),
        session_fence: 11,
        expected_publication_revision,
        expected_reservation_revision,
        committed_unix_ms: 7_000,
    }
}

#[test]
fn workspace_publication_is_generation_fenced_and_idempotent() {
    let (session, subject, seal, grant) = sealed_session_grant();
    let session_digest = session.digest().unwrap();
    let child = delegated_child(&grant);
    let mut reservations =
        SessionReservationLedger::new("session-1".to_owned(), &session, 11).unwrap();
    for (reservation, child_id, key, revision) in [
        ("reservation-1", "child-1", "reserve-1", 0),
        ("reservation-2", "child-2", "reserve-2", 1),
    ] {
        admit_child(
            &mut reservations,
            admission_request("session-1", reservation, child_id, key, revision),
            &session,
            &subject,
            &seal,
            &grant,
            &child,
        )
        .unwrap();
    }
    let mut publications = WorkspacePublicationLedger::new(
        "session-1".to_owned(),
        session_digest.clone(),
        11,
        digest("initial-workspace"),
    )
    .unwrap();
    let first = publication_request(
        session_digest.clone(),
        "reservation-1",
        "child-1",
        "publish-1",
        "workspace-1",
        0,
        2,
    );
    let finalize_first = ReservationTransitionRequest {
        schema_version: 1,
        reservation_id: "reservation-1".to_owned(),
        child_execution_id: "child-1".to_owned(),
        idempotency_key: "finalize-1".to_owned(),
        session_fence: 11,
        expected_ledger_revision: 2,
        outcome: ReservationTerminalOutcome::Finalized {
            result_digest: digest("result-1"),
        },
        actual_usage: CapabilityUsage::default(),
        observed_unix_ms: 7_000,
    };
    assert!(
        !publications
            .finalize_and_publish(&mut reservations, finalize_first.clone(), first.clone())
            .unwrap()
            .replayed
    );
    assert_eq!(
        reservations.reservation("reservation-1").unwrap().state,
        ReservationState::Finalized
    );
    assert!(
        publications
            .finalize_and_publish(&mut reservations, finalize_first, first)
            .unwrap()
            .replayed
    );

    let stale_competing = publication_request(
        session_digest,
        "reservation-2",
        "child-2",
        "publish-2",
        "workspace-2",
        1,
        3,
    );
    assert_eq!(
        publications
            .finalize_and_publish(
                &mut reservations,
                ReservationTransitionRequest {
                    schema_version: 1,
                    reservation_id: "reservation-2".to_owned(),
                    child_execution_id: "child-2".to_owned(),
                    idempotency_key: "finalize-2".to_owned(),
                    session_fence: 11,
                    expected_ledger_revision: 3,
                    outcome: ReservationTerminalOutcome::Finalized {
                        result_digest: digest("result-2"),
                    },
                    actual_usage: CapabilityUsage::default(),
                    observed_unix_ms: 7_001,
                },
                stale_competing.clone(),
            )
            .unwrap_err(),
        ExecutionModelError::WorkspaceGenerationConflict
    );

    reservations
        .release(ReservationTransitionRequest {
            schema_version: 1,
            reservation_id: "reservation-2".to_owned(),
            child_execution_id: "child-2".to_owned(),
            idempotency_key: "release-2".to_owned(),
            session_fence: 11,
            expected_ledger_revision: 3,
            outcome: ReservationTerminalOutcome::Released {
                reason_digest: digest("superseded"),
            },
            actual_usage: CapabilityUsage::default(),
            observed_unix_ms: 7_001,
        })
        .unwrap();
    let mut stale_competing = stale_competing;
    stale_competing.expected_reservation_revision = 4;
    assert_eq!(
        publications
            .finalize_and_publish(
                &mut reservations,
                ReservationTransitionRequest {
                    schema_version: 1,
                    reservation_id: "reservation-2".to_owned(),
                    child_execution_id: "child-2".to_owned(),
                    idempotency_key: "finalize-after-release".to_owned(),
                    session_fence: 11,
                    expected_ledger_revision: 4,
                    outcome: ReservationTerminalOutcome::Finalized {
                        result_digest: digest("impossible"),
                    },
                    actual_usage: CapabilityUsage::default(),
                    observed_unix_ms: 7_002,
                },
                stale_competing,
            )
            .unwrap_err(),
        ExecutionModelError::WorkspaceReservationInactive
    );

    let mut value = serde_json::to_value(&publications).unwrap();
    value["current"]["generation"] = Value::from(99);
    let tampered: WorkspacePublicationLedger = serde_json::from_value(value).unwrap();
    assert_eq!(
        tampered.validate().unwrap_err(),
        ExecutionModelError::AccountingFailure
    );
}
