use super::*;
use runtrue_model::ContentDigest;
use std::collections::{BTreeMap, BTreeSet};

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value)
}

fn provider_identity() -> ProviderIdentity {
    ProviderIdentity {
        provider_id: "provider-1".into(),
        administrative_trust_domain: "example.internal".into(),
        authentication_key_digest: digest("provider-authentication-key"),
    }
}

fn deployed_provider() -> DeployedProviderGeneration {
    DeployedProviderGeneration {
        provider: provider_identity(),
        generation: 7,
        binary_digest: digest("binary"),
        configuration_digest: digest("configuration"),
        policy_digest: digest("policy"),
        key_set_digest: digest("key-set"),
        signing_key_generation: 3,
    }
}

fn profile_id() -> FeatureProfileId {
    FeatureProfileId {
        name: "execution.core".into(),
        generation: 1,
    }
}

fn descriptor() -> ProviderDescriptor {
    let profile = FeatureProfile {
        id: profile_id(),
        compatibility_digest: digest("execution-core-compatibility"),
        limits: BTreeMap::from([("maximum_cpu".into(), 8)]),
        compatibility_metadata: BTreeMap::new(),
    };
    ProviderDescriptor {
        contract_generation: ContractGeneration::new(2).unwrap(),
        deployed_generation: deployed_provider(),
        feature_profiles: BTreeMap::from([(profile.id.name.clone(), profile)]),
        replay_grades: BTreeSet::from(["exact".into()]),
        evidence_grades: BTreeSet::from(["subject_chained".into()]),
        attestation_grades: BTreeSet::from(["signed".into()]),
    }
}

fn inventory() -> RuntimeInventoryEntry {
    RuntimeInventoryEntry {
        inventory_generation: 2,
        runtime_id: "runtime-1".into(),
        deployed_provider: deployed_provider(),
        pool_id: "pool-1".into(),
        pool_trust_domain: "pool.example.internal".into(),
        pool_trust_profile_digest: digest("pool-trust-profile"),
        runtime_compatibility_digest: digest("runtime-compatibility"),
        security_generation: 4,
        revocation_generation: 1,
        placement_attributes: BTreeMap::from([("region".into(), "test".into())]),
        devices: BTreeSet::from(["cpu".into()]),
        limits: BTreeMap::from([("maximum_cpu".into(), 8)]),
        feature_profiles: BTreeSet::from([profile_id()]),
    }
}

fn producer(kind: EvidenceProducerKind) -> EvidenceProducerIdentity {
    EvidenceProducerIdentity {
        kind,
        producer_id: "producer-1".into(),
        authentication_identity_digest: digest("producer-authentication"),
        signing_key_id: digest("producer-signing-key"),
        signing_key_generation: 1,
    }
}

fn evidence_signature() -> EvidenceSignature {
    EvidenceSignature {
        algorithm: "ed25519".into(),
        signing_key_id: digest("producer-signing-key"),
        signing_key_generation: 1,
        signature: vec![7; 64],
    }
}

struct FakeEvidenceVerifier;

impl EvidenceSignatureVerifier for FakeEvidenceVerifier {
    fn verify_signature(
        &self,
        _producer: &EvidenceProducerIdentity,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

fn cryptographically_seal(event: EvidenceEvent) -> EvidenceEnvelope {
    let mut envelope = event.seal(evidence_signature()).unwrap();
    envelope.signature.signature = ContentDigest::sha256(envelope.signature_message().unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    envelope
}

fn evidence_event(sequence: u64, previous: Option<ContentDigest>) -> EvidenceEvent {
    EvidenceEvent {
        envelope_version: 1,
        scope_kind: EvidenceScopeKind::Execution,
        subject_id: "execution-1".into(),
        tenant_id: Some("tenant-1".into()),
        administrative_trust_domain: Some("example.internal".into()),
        identities: EvidenceIdentities {
            execution_id: Some("execution-1".into()),
            ..EvidenceIdentities::default()
        },
        subject_sequence: sequence,
        previous_event_digest: previous,
        event_type: "execution.state".into(),
        schema_generation: 1,
        payload_digest: digest(&format!("payload-{sequence}")),
        payload_size_bytes: 32,
        producer: producer(EvidenceProducerKind::ExecutionPlane),
        observed_time: EvidenceObservedTime {
            wall_unix_nanoseconds: sequence,
            wall_precision_nanoseconds: 1,
            monotonic_nanoseconds: sequence,
            monotonic_precision_nanoseconds: 1,
        },
        links: Vec::new(),
        provider_diagnostics: BTreeMap::new(),
    }
}

fn cause(sequence: u64, class: PortableFailureClass, phase: FailurePhase) -> ObservedCause {
    ObservedCause {
        sequence,
        class,
        subject_kind: FailureSubjectKind::Execution,
        phase,
        evidence_event_digest: digest(&format!("cause-{sequence}")),
        diagnostic_code: None,
        retry_hint: None,
    }
}

#[test]
fn generation_negotiation_selects_newest_and_rejects_downgrades() {
    let range = |minimum, maximum| {
        ContractGenerationRange::new(
            ContractGeneration::new(minimum).unwrap(),
            ContractGeneration::new(maximum).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        negotiate_contract_generation(range(1, 4), range(2, 3), None)
            .unwrap()
            .get(),
        3
    );
    assert_eq!(
        negotiate_contract_generation(range(1, 2), range(3, 4), None),
        Err(ProviderContractError::NoCompatibleGeneration)
    );
    assert!(matches!(
        negotiate_contract_generation(
            range(1, 2),
            range(1, 2),
            Some(ContractGeneration::new(3).unwrap())
        ),
        Err(ProviderContractError::DowngradeRejected { .. })
    ));

    let zero: ContractGenerationRange =
        serde_json::from_str(r#"{"minimum":0,"maximum":1}"#).unwrap();
    assert_eq!(
        zero.validate(),
        Err(ProviderContractError::InvalidGenerationRange)
    );
}

#[test]
fn profiles_inventory_and_capacity_are_exactly_bound() {
    let descriptor = descriptor();
    let inventory = inventory();
    inventory.validate_against(&descriptor).unwrap();
    descriptor
        .require_profiles(&[FeatureRequirement {
            id: profile_id(),
            compatibility_digest: Some(digest("execution-core-compatibility")),
            minimum_limits: BTreeMap::from([("maximum_cpu".into(), 4)]),
        }])
        .unwrap();

    let observation = CapacityObservation {
        inventory_digest: inventory.digest().unwrap(),
        observation_sequence: 1,
        available_slots: 2,
        available_cpu: 4,
        available_memory_bytes: 1024,
        available_storage_bytes: 2048,
        observed_unix_ms: 100,
        expires_unix_ms: 200,
        producer: provider_identity(),
    };
    observation.validate_against(&inventory, 150).unwrap();
    assert_eq!(
        observation.validate_against(&inventory, 200),
        Err(ProviderContractError::InvalidCapacityObservation)
    );

    let mut substituted = inventory.clone();
    substituted.runtime_id = "runtime-2".into();
    assert_eq!(
        observation.validate_against(&substituted, 150),
        Err(ProviderContractError::InvalidCapacityObservation)
    );
    let mut unrevocable = inventory.clone();
    unrevocable.revocation_generation = 0;
    assert!(unrevocable.validate().is_err());

    let requirement = RuntimeSelectionRequirement {
        runtime_compatibility_digest: inventory.runtime_compatibility_digest.clone(),
        allowed_provider_identity_digests: BTreeSet::from([inventory
            .deployed_provider
            .provider
            .digest()
            .unwrap()]),
        allowed_administrative_trust_domains: BTreeSet::from(["example.internal".into()]),
        allowed_pool_trust_profile_digests: BTreeSet::from([inventory
            .pool_trust_profile_digest
            .clone()]),
        exact_placement_attributes: BTreeMap::from([("region".into(), "test".into())]),
        required_devices: BTreeSet::from(["cpu".into()]),
        minimum_limits: BTreeMap::from([("maximum_cpu".into(), 8)]),
        required_feature_profiles: BTreeSet::from([profile_id()]),
    };
    requirement.require_exact_match(&inventory).unwrap();
    let mut one_field_wrong = requirement;
    one_field_wrong.runtime_compatibility_digest = digest("near-match");
    assert!(one_field_wrong.require_exact_match(&inventory).is_err());
}

#[test]
fn safety_failures_override_ordinary_causes_and_gate_retry() {
    let resolution = FailureResolution::resolve(vec![
        cause(
            1,
            PortableFailureClass::RuntimeFailure,
            FailurePhase::Running,
        ),
        cause(
            2,
            PortableFailureClass::ExternalEffectIndeterminate,
            FailurePhase::Finalizing,
        ),
        cause(
            3,
            PortableFailureClass::RunnerIntegrityFailure,
            FailurePhase::Finalizing,
        ),
    ])
    .unwrap();
    assert_eq!(
        resolution.primary_class,
        PortableFailureClass::RunnerIntegrityFailure
    );
    let denied = RetryDecision::evaluate(
        &resolution,
        RetrySafetyProof {
            policy_authorization_digest: Some(digest("retry-policy")),
            effect_safety_digest: None,
            runner_remediation_digest: None,
        },
    )
    .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.denials.len(), 2);

    let allowed = RetryDecision::evaluate(
        &resolution,
        RetrySafetyProof {
            policy_authorization_digest: Some(digest("retry-policy")),
            effect_safety_digest: Some(digest("effect-safety")),
            runner_remediation_digest: Some(digest("remediation")),
        },
    )
    .unwrap();
    assert!(allowed.allowed);
    allowed.validate().unwrap();
}

#[test]
fn evidence_chain_detects_tampering_gaps_and_subject_substitution() {
    let first = evidence_event(1, None).seal(evidence_signature()).unwrap();
    let second = evidence_event(2, Some(first.event_digest.clone()))
        .seal(evidence_signature())
        .unwrap();
    verify_evidence_chain_structure(&[first.clone(), second.clone()]).unwrap();
    EvidenceCheckpoint::for_chain(
        &[first.clone(), second.clone()],
        producer(EvidenceProducerKind::ProviderControlPlane),
        100,
        evidence_signature(),
    )
    .unwrap();

    let mut tampered = second.clone();
    tampered.event.payload_size_bytes += 1;
    assert!(matches!(
        verify_evidence_chain_structure(&[first.clone(), tampered]),
        Err(ProviderContractError::EvidenceDigestMismatch { .. })
    ));

    let gap = evidence_event(3, Some(first.event_digest.clone()))
        .seal(evidence_signature())
        .unwrap();
    assert!(matches!(
        verify_evidence_chain_structure(&[first.clone(), gap]),
        Err(ProviderContractError::EvidenceSequence {
            expected: 2,
            actual: 3
        })
    ));

    let mut substituted = second.event.clone();
    substituted.subject_id = "execution-2".into();
    let substituted = substituted.seal(evidence_signature()).unwrap();
    assert_eq!(
        verify_evidence_chain_structure(&[first, substituted]),
        Err(ProviderContractError::EvidenceSubjectChanged)
    );
}

#[test]
fn clients_cannot_mint_provider_evidence() {
    let mut event = evidence_event(1, None);
    event.producer = producer(EvidenceProducerKind::Client);
    assert!(matches!(
        event.validate(),
        Err(ProviderContractError::InvalidEvidence(_))
    ));
    event.scope_kind = EvidenceScopeKind::ClientClaim;
    event.validate().unwrap();
}

#[test]
fn protected_objects_require_exact_tenant_authority() {
    let authority = StorageAuthority {
        principal_digest: digest("principal"),
        tenant_id: Some("tenant-1".into()),
        administrative_trust_domain: "example.internal".into(),
        purpose: "artifact.write".into(),
        authorization_decision_digest: digest("authorization"),
    };
    let scope = LogicalObjectScope::Tenant {
        tenant_id: "tenant-1".into(),
        administrative_trust_domain: "example.internal".into(),
        encryption_context_digest: digest("encryption-context"),
    };
    ObjectWriteDeclaration {
        object_class: LogicalObjectClass::Secret,
        scope: scope.clone(),
        expected_digest: digest("secret"),
        expected_size_bytes: 64,
        media_type: "application/octet-stream".into(),
        maximum_chunk_bytes: 16,
        publication: PublicationCondition::CreateOnce,
        authority: authority.clone(),
    }
    .validate()
    .unwrap();
    assert!(LogicalObjectScope::Public {
        sharing_policy_digest: digest("sharing-policy")
    }
    .validate_for(LogicalObjectClass::Secret)
    .is_err());
    let mut wrong = authority;
    wrong.tenant_id = Some("tenant-2".into());
    assert!(wrong.authorize_scope(&scope).is_err());
}

fn pool_transition(
    record: &PoolMemberRecord,
    to: PoolMemberState,
    assignment: Option<PoolAssignmentBinding>,
    destruction_proof_digest: Option<ContentDigest>,
) -> PoolMemberTransition {
    PoolMemberTransition {
        member_id: record.member_id.clone(),
        member_generation: record.member_generation,
        pool_id: record.pool_id.clone(),
        sequence: record.transition_sequence + 1,
        previous_transition_digest: record.last_transition_digest.clone(),
        from: record.state,
        to,
        assignment,
        destruction_proof_digest,
        reason_digest: digest("reason"),
        observed_unix_ms: 100,
    }
}

#[test]
fn pool_members_are_one_shot_and_used_members_never_become_sterile() {
    let sterile = digest("sterile-template");
    let mut member = PoolMemberRecord {
        member_id: "member-1".into(),
        member_generation: 4,
        pool_id: "pool-1".into(),
        pool_trust_domain: "pool.example.internal".into(),
        provider: provider_identity(),
        state: PoolMemberState::Creating,
        transition_sequence: 0,
        fence_generation: 1,
        runtime_inventory_digest: digest("runtime-inventory"),
        sterile_template_digest: sterile.clone(),
        assignment: None,
        last_transition_digest: None,
    };
    member = member
        .apply(&pool_transition(
            &member,
            PoolMemberState::Sterile,
            None,
            None,
        ))
        .unwrap();
    let assignment = PoolAssignmentBinding {
        tenant_id: "tenant-1".into(),
        capsule_digest: digest("capsule"),
        subject_kind: PoolAssignmentSubjectKind::Execution,
        subject_id: "execution-1".into(),
        lease_id: "lease-1".into(),
        fence_generation: 2,
        sterile_template_digest: sterile,
        member_generation: 4,
    };
    member = member
        .apply(&pool_transition(
            &member,
            PoolMemberState::Assigning,
            Some(assignment),
            None,
        ))
        .unwrap();
    assert_eq!(member.fence_generation, 2);
    member = member
        .apply(&pool_transition(
            &member,
            PoolMemberState::TenantUsed,
            None,
            None,
        ))
        .unwrap();
    assert!(!PoolMemberState::TenantUsed.can_transition_to(PoolMemberState::Sterile));
    let forged_resterilization = PoolMemberTransition {
        to: PoolMemberState::Sterile,
        ..pool_transition(&member, PoolMemberState::Destroying, None, None)
    };
    assert!(member.apply(&forged_resterilization).is_err());
}

#[test]
fn external_effects_are_write_ahead_identity_bound_and_reconciled_separately() {
    let identity = ExternalEffectIdentity {
        operation_id: "operation-1".into(),
        idempotency_key: "idem-1".into(),
        tenant_id: "tenant-1".into(),
        execution_id: "execution-1".into(),
        capsule_digest: digest("capsule"),
        capability_grant_digest: digest("grant"),
        lease_id: "lease-1".into(),
        fence_generation: 2,
        destination_digest: digest("destination"),
        bounded_request_digest: digest("request"),
    };
    let requested = ExternalEffectTransition::requested(identity, digest("producer"), 100).unwrap();
    let indeterminate = ExternalEffectTransition::terminal(
        &requested,
        ExternalEffectState::Indeterminate,
        digest("uncertainty-proof"),
        digest("producer"),
        101,
    )
    .unwrap();
    verify_external_effect_chain(&[requested.clone(), indeterminate.clone()]).unwrap();

    let mut substituted = indeterminate.clone();
    substituted.identity.destination_digest = digest("other-destination");
    assert!(verify_external_effect_chain(&[requested, substituted]).is_err());
    ExternalEffectReconciliation::for_indeterminate(
        &indeterminate,
        ExternalEffectState::Accepted,
        "destination.query".into(),
        digest("authoritative-result"),
        digest("reconciler"),
        102,
    )
    .unwrap();
    assert!(ExternalEffectReconciliation::for_indeterminate(
        &indeterminate,
        ExternalEffectState::Indeterminate,
        "destination.query".into(),
        digest("authoritative-result"),
        digest("reconciler"),
        102,
    )
    .is_err());
}

fn conformance_statement(outcome: ConformanceCaseOutcome) -> ConformanceStatement {
    let case = ConformanceCaseResult {
        case_id: "execution.core.exact".into(),
        outcome,
        result_digest: digest("case-result"),
        evidence_event_digest: digest("case-evidence"),
    };
    ConformanceStatement {
        statement_version: 1,
        contract_generation: ContractGeneration::new(2).unwrap(),
        deployed_provider: deployed_provider(),
        provider_image_digest: digest("image"),
        suite: ConformanceSuiteIdentity {
            name: "bisim".into(),
            generation: 1,
            fixture_digest: digest("fixtures"),
            harness_digest: digest("harness"),
        },
        advertised_profiles: BTreeMap::from([(
            "execution.core".into(),
            ProfileConformance {
                profile: profile_id(),
                compatibility_digest: digest("execution-core-compatibility"),
                required_case_ids: BTreeSet::from(["execution.core.exact".into()]),
            },
        )]),
        cases: BTreeMap::from([(case.case_id.clone(), case)]),
        backend_security_result_digest: digest("backend-security"),
        runtime_inventory_digests: BTreeSet::from([digest("runtime-inventory")]),
        issued_unix_ms: 100,
        expires_unix_ms: 200,
    }
}

#[test]
fn signed_conformance_rejects_skips_expiry_and_digest_substitution() {
    assert!(conformance_statement(ConformanceCaseOutcome::Skipped)
        .validate(150)
        .is_err());
    let statement = conformance_statement(ConformanceCaseOutcome::Passed);
    assert!(statement.validate(200).is_err());
    let statement_digest = statement.digest(150).unwrap();
    let mut signed = SignedConformanceMetadata {
        media_type: "runtrue.conformance".into(),
        signature_algorithm: "ed25519".into(),
        signing_key_id: "key-3".into(),
        signing_key_generation: 3,
        statement,
        statement_digest,
        signature: vec![1; 64],
    };
    assert!(!signed.signature_message(150).unwrap().is_empty());
    signed.statement_digest = digest("substituted-statement");
    assert!(signed.validate_structure(150).is_err());
}

#[test]
fn provider_requests_pin_identity_and_terminal_outcomes() {
    let descriptor = descriptor();
    let mut request = AdmissionRequest {
        mutation: IdempotentMutation {
            tenant_id: "tenant-1".into(),
            principal_digest: digest("principal"),
            idempotency_key: "admission-1".into(),
        },
        capsule_digest: digest("capsule"),
        seal_digest: digest("seal"),
        program_digest: digest("program"),
        policy_digest: digest("policy"),
        required_profiles: Vec::new(),
        allowed_provider_identity_digests: BTreeSet::from([descriptor
            .deployed_generation
            .provider
            .digest()
            .unwrap()]),
    };
    request.validate_against(&descriptor).unwrap();
    request.allowed_provider_identity_digests = BTreeSet::from([digest("other-provider")]);
    assert!(request.validate_against(&descriptor).is_err());

    let snapshot = ExecutionSnapshot {
        execution_id: "execution-1".into(),
        tenant_id: "tenant-1".into(),
        state: ExecutionState::Terminal,
        capsule_digest: digest("capsule"),
        seal_digest: digest("seal"),
        program_digest: digest("program"),
        deployed_provider: deployed_provider(),
        lease_id: Some("lease-1".into()),
        fence_generation: Some(2),
        terminal_outcome: Some(TerminalOutcome::Succeeded),
        failure: None,
        evidence_sequence: 4,
        evidence_event_digest: digest("terminal-evidence"),
    };
    snapshot.validate().unwrap();
    let mut invalid = snapshot;
    invalid.terminal_outcome = None;
    assert!(invalid.validate().is_err());
}

fn checkpoint_manifest() -> CheckpointManifest {
    CheckpointManifest {
        manifest_version: 1,
        program_digest: digest("program"),
        dependency_digests: BTreeSet::from([digest("dependency")]),
        capsule_digest: digest("capsule"),
        seal_digest: digest("seal"),
        policy_digest: digest("policy"),
        runtime_compatibility_digest: digest("runtime-compatibility"),
        workspace_generations: vec![WorkspaceGeneration {
            workspace_id_digest: digest("workspace"),
            base_generation: 1,
            current_generation: 3,
            content_digest: digest("workspace-content"),
        }],
        deterministic_guest_state_digest: digest("guest-state"),
        capability_state_digest: digest("capability-state"),
        effect_ledger_frontier: EffectLedgerFrontier {
            through_sequence: 2,
            terminal_effect_digest: Some(digest("effect-frontier")),
        },
        remaining_budget: RemainingExecutionBudget {
            remaining_cpu_milliseconds: 10_000,
            remaining_effect_uses: 2,
            remaining_effect_bytes: 512,
            deadline_unix_ms: 500,
        },
        taint: CheckpointTaint::default(),
        compatibility_grade: CheckpointCompatibilityGrade::Exact,
        created_unix_ms: 100,
    }
}

#[test]
fn replay_bundles_pin_checkpoint_identity_and_reject_credentials() {
    let checkpoint = checkpoint_manifest();
    let bundle = ReplayBundleManifest::from_checkpoint(
        &checkpoint,
        CheckpointCompatibilityGrade::Exact,
        digest("evidence-checkpoint"),
        vec![digest("evidence-event")],
        BTreeMap::from([("checkpoint".into(), checkpoint.digest().unwrap())]),
    )
    .unwrap();
    bundle.validate_against(&checkpoint).unwrap();
    let mut substituted = bundle;
    substituted.program_digest = digest("other-program");
    assert!(substituted.validate_against(&checkpoint).is_err());

    let mut tainted = checkpoint;
    tainted.taint = CheckpointTaint {
        contains_credentials: true,
        unresolved_external_effect: false,
        nondeterministic_guest_state: false,
        reasons: BTreeSet::from(["credential".into()]),
    };
    assert!(ReplayBundleManifest::from_checkpoint(
        &tainted,
        CheckpointCompatibilityGrade::Exact,
        digest("evidence-checkpoint"),
        vec![digest("evidence-event")],
        BTreeMap::from([("checkpoint".into(), digest("checkpoint"))]),
    )
    .is_err());
}

#[test]
fn invocation_handles_reject_stale_substituted_expired_and_overspent_use() {
    let subject = InvocationSubject {
        tenant_id: "tenant-1".into(),
        program_digest: digest("program"),
        capsule_digest: digest("capsule"),
        execution_id: "execution-1".into(),
        session_id: None,
        session_operation_id: None,
    };
    let handle = InvocationHandle::new(
        "invocation-1".into(),
        subject.clone(),
        digest("resource"),
        digest("grant"),
        "lease-1".into(),
        3,
        200,
        InvocationBudget {
            maximum_uses: 2,
            maximum_effect_bytes: 10,
        },
    )
    .unwrap();
    handle
        .authorize(&subject, &digest("resource"), "lease-1", 3, 100)
        .unwrap();
    assert!(handle
        .authorize(&subject, &digest("resource"), "lease-1", 2, 100)
        .is_err());
    assert!(handle
        .authorize(&subject, &digest("other-resource"), "lease-1", 3, 100)
        .is_err());
    let mut other_subject = subject.clone();
    other_subject.execution_id = "execution-2".into();
    assert!(handle
        .authorize(&other_subject, &digest("resource"), "lease-1", 3, 100)
        .is_err());
    assert!(handle
        .authorize(&subject, &digest("resource"), "lease-1", 3, 200)
        .is_err());

    let first =
        CapabilityBudgetReservation::reserve(&handle, None, digest("effect-1"), 1, 6).unwrap();
    assert!(
        CapabilityBudgetReservation::reserve(&handle, Some(&first), digest("effect-2"), 1, 5,)
            .is_err()
    );
}

fn bisim_observation(role: BisimComparisonRole) -> BisimPortableObservation {
    BisimPortableObservation {
        observation_version: 1,
        capsule_digest: digest("capsule"),
        program_digest: digest("program"),
        runtime_compatibility_digest: digest("runtime"),
        lifecycle: BisimLifecycleObservation {
            execution_state: Some(ExecutionState::Terminal),
            session_state: None,
            terminal_outcome: Some(TerminalOutcome::Succeeded),
            failure: None,
        },
        normalized_outputs: BTreeMap::from([("stdout".into(), digest("stdout"))]),
        normalized_artifacts: BTreeMap::from([("result".into(), digest("artifact"))]),
        capability_state_digest: digest("capability"),
        external_effect_state_digest: digest("effects"),
        checkpoint_grade: CheckpointCompatibilityGrade::Exact,
        replay_bundle_digest: digest("replay"),
        cleanup_result_digest: digest("cleanup"),
        evidence_identity_digest: digest("evidence"),
        backend_security_result_digest: digest("security"),
        operational: BisimOperationalContext {
            comparison_role: role,
            observed_unix_ms: 100,
            worker_id: match role {
                BisimComparisonRole::Baseline => "worker-local",
                BisimComparisonRole::Candidate => "worker-remote",
            }
            .into(),
            pool_id: None,
            warm_acquisition: role == BisimComparisonRole::Candidate,
        },
    }
}

#[test]
fn bisim_excludes_only_operational_context_from_comparison() {
    let baseline = bisim_observation(BisimComparisonRole::Baseline);
    let mut candidate = bisim_observation(BisimComparisonRole::Candidate);
    baseline.require_equivalent(&candidate).unwrap();
    candidate.capability_state_digest = digest("different-capability-state");
    assert!(baseline.require_equivalent(&candidate).is_err());
    candidate = bisim_observation(BisimComparisonRole::Candidate);
    candidate.evidence_identity_digest = digest("missing-or-other-evidence");
    assert!(baseline.require_equivalent(&candidate).is_err());
}

#[test]
fn evidence_requires_a_signature_from_the_declared_producer_key() {
    let event = evidence_event(1, None);
    let mut wrong = evidence_signature();
    wrong.signing_key_id = digest("other-key");
    assert!(event.clone().seal(wrong).is_err());
    let signed = event.seal(evidence_signature()).unwrap();
    assert!(!signed.signature_message().unwrap().is_empty());
}

#[test]
fn evidence_chain_and_checkpoint_require_cryptographic_verification() {
    let first = cryptographically_seal(evidence_event(1, None));
    let second = cryptographically_seal(evidence_event(2, Some(first.event_digest.clone())));
    let events = vec![first, second];
    verify_evidence_chain_with(&events, &FakeEvidenceVerifier).unwrap();

    let mut checkpoint = EvidenceCheckpoint::for_chain(
        &events,
        producer(EvidenceProducerKind::ProviderControlPlane),
        100,
        evidence_signature(),
    )
    .unwrap();
    checkpoint.signature.signature = ContentDigest::sha256(checkpoint.signature_message().unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    checkpoint
        .verify_with(&events, &FakeEvidenceVerifier)
        .unwrap();

    let mut altered_event = events.clone();
    altered_event[1].signature.signature[0] ^= 1;
    assert!(verify_evidence_chain_with(&altered_event, &FakeEvidenceVerifier).is_err());

    checkpoint.signature.signature[0] ^= 1;
    assert!(checkpoint
        .verify_with(&events, &FakeEvidenceVerifier)
        .is_err());
}
