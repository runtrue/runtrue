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

fn inventory_authority() -> SignedInventoryAuthoritySnapshot {
    let snapshot = InventoryAuthoritySnapshot {
        snapshot_version: 1,
        expected_deployed_provider: deployed_provider(),
        minimum_inventory_generation: 2,
        minimum_security_generation: 4,
        current_revocation_generation: 1,
        valid_from_unix_ms: 100,
        expires_unix_ms: 200,
        authority_evidence_digest: digest("inventory-authority"),
    };
    let mut signed = SignedInventoryAuthoritySnapshot {
        snapshot_digest: canonical::canonical_digest(
            b"runtrue.provider.inventory-authority-snapshot.v1\0",
            &snapshot,
        )
        .unwrap(),
        snapshot,
        authority_identity_digest: digest("inventory-authority-identity"),
        signing_key_id: digest("inventory-authority-key"),
        signing_key_generation: 1,
        signature_algorithm: "ed25519".into(),
        signature: vec![1],
    };
    signed.signature = ContentDigest::sha256(signed.signature_message(150).unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    signed
}

fn signed_inventory() -> SignedRuntimeInventoryEntry {
    let inventory = inventory();
    let mut signed = SignedRuntimeInventoryEntry {
        inventory_digest: inventory.digest().unwrap(),
        signature: ProviderContractSignature {
            algorithm: "ed25519".into(),
            signing_key_generation: inventory.deployed_provider.signing_key_generation,
            signature: vec![1],
        },
        inventory,
    };
    signed.signature.signature = ContentDigest::sha256(signed.signature_message().unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    signed
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

struct FakeProviderVerifier;

impl ProviderContractSignatureVerifier for FakeProviderVerifier {
    fn verify_provider_signature(
        &self,
        _provider: &ProviderIdentity,
        _signing_key_generation: u64,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

impl InventoryAuthoritySignatureVerifier for FakeProviderVerifier {
    fn verify_inventory_authority_signature(
        &self,
        _authority_identity_digest: &ContentDigest,
        _signing_key_id: &ContentDigest,
        _signing_key_generation: u64,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

impl SterileTemplateSignatureVerifier for FakeProviderVerifier {
    fn verify_sterile_template_signature(
        &self,
        _authority_identity_digest: &ContentDigest,
        _signing_key_id: &ContentDigest,
        _signing_key_generation: u64,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

struct FakeRetryProofVerifier;

impl RetryProofSignatureVerifier for FakeRetryProofVerifier {
    fn verify_retry_proof_signature(
        &self,
        _issuer_identity_digest: &ContentDigest,
        _signing_key_id: &ContentDigest,
        _signing_key_generation: u64,
        _algorithm: &str,
        _message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == [7; 64]
    }
}

struct FakeReplayGradeVerifier;

impl ReplayGradeProofSignatureVerifier for FakeReplayGradeVerifier {
    fn verify_replay_grade_proof_signature(
        &self,
        _issuer_identity_digest: &ContentDigest,
        _signing_key_id: &ContentDigest,
        _signing_key_generation: u64,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

fn replay_grade_proof(checkpoint: &CheckpointManifest, grade: ReplayGrade) -> ReplayGradeProof {
    let strong = grade != ReplayGrade::EvidenceOnly;
    let mut proof = ReplayGradeProof {
        proof_version: 1,
        declared_grade: grade,
        checkpoint_state_digest: checkpoint.digest().unwrap(),
        credential_exclusion_evidence_digest: strong.then(|| digest("credential-exclusion")),
        effect_safety_evidence_digest: strong.then(|| digest("effect-safety")),
        determinism_evidence_digest: strong.then(|| digest("determinism")),
        object_graph_evidence_digest: strong.then(|| digest("object-graph-proof")),
        evidence_chain_checkpoint_digest: strong.then(|| digest("evidence-checkpoint")),
        recorded_interaction_contract_digest: (grade == ReplayGrade::Exact)
            .then(|| digest("recorded-interactions")),
        issuer_identity_digest: digest("replay-proof-issuer"),
        signing_key_id: digest("replay-proof-key"),
        signing_key_generation: 1,
        issued_unix_ms: 100,
        expires_unix_ms: 200,
        signature_algorithm: "ed25519".into(),
        signature: vec![1],
    };
    proof.signature = ContentDigest::sha256(
        proof
            .signature_message(grade, &checkpoint.digest().unwrap())
            .unwrap(),
    )
    .as_str()
    .as_bytes()
    .to_vec();
    proof
}

fn retry_authorization(prior_execution_id: &str) -> RetryAuthorization {
    RetryAuthorization {
        authorization_version: 1,
        execution_id: "execution-2".into(),
        retry_of_execution_id: prior_execution_id.into(),
        retry_of_effect_frontier_digest: digest("effect-frontier"),
        effect_proof_digests: vec![digest("effect-proof")],
        signed_evidence_event_digest: digest("effect-safety-evidence"),
    }
}

fn authenticated_retry_proof(
    kind: RetryProofKind,
    subject_digest: ContentDigest,
) -> AuthenticatedRetryProof {
    AuthenticatedRetryProof {
        proof_version: 1,
        kind,
        subject_digest,
        evidence_event_digest: digest("retry-proof-evidence"),
        issuer_identity_digest: digest("retry-proof-issuer"),
        signing_key_id: digest("retry-proof-key"),
        signing_key_generation: 1,
        issued_unix_ms: 100,
        expires_unix_ms: 200,
        algorithm: "ed25519".into(),
        signature: vec![7; 64],
    }
}

struct FakeConformanceVerifier;

impl ConformanceSignatureVerifier for FakeConformanceVerifier {
    fn verify_conformance_signature(
        &self,
        _deployed_provider: &DeployedProviderGeneration,
        _signing_key_id: &str,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == ContentDigest::sha256(message).as_str().as_bytes()
    }
}

struct FakeAttestationVerifier;

impl AttestationSignatureVerifier for FakeAttestationVerifier {
    fn verify_attestation_signature(
        &self,
        _issuer_id: &str,
        _signing_key_id: &str,
        _signing_key_generation: u64,
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
        subject_id: "execution-1".into(),
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
    let authority = inventory_authority();
    requirement
        .require_exact_match(&inventory, &authority, 150, &FakeProviderVerifier)
        .unwrap();
    let mut one_field_wrong = requirement;
    one_field_wrong.runtime_compatibility_digest = digest("near-match");
    assert!(one_field_wrong
        .require_exact_match(&inventory, &authority, 150, &FakeProviderVerifier)
        .is_err());
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
    let resolution_digest = resolution.digest().unwrap();
    let denied = RetryDecision::evaluate(
        &resolution,
        RetrySafetyProof {
            policy_authorization: Some(authenticated_retry_proof(
                RetryProofKind::PolicyAuthorization,
                resolution_digest.clone(),
            )),
            effect_authorization: None,
            effect_safety: None,
            runner_remediation: None,
        },
        150,
        &FakeRetryProofVerifier,
    )
    .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.denials.len(), 2);

    let effect_authorization = retry_authorization("execution-1");
    let allowed = RetryDecision::evaluate(
        &resolution,
        RetrySafetyProof {
            policy_authorization: Some(authenticated_retry_proof(
                RetryProofKind::PolicyAuthorization,
                resolution_digest.clone(),
            )),
            effect_safety: Some(authenticated_retry_proof(
                RetryProofKind::EffectSafety,
                effect_authorization.digest().unwrap(),
            )),
            effect_authorization: Some(effect_authorization),
            runner_remediation: Some(authenticated_retry_proof(
                RetryProofKind::RunnerRemediation,
                resolution_digest,
            )),
        },
        150,
        &FakeRetryProofVerifier,
    )
    .unwrap();
    assert!(allowed.allowed);
    allowed.validate_with(150, &FakeRetryProofVerifier).unwrap();
    let lineage = RetryLineage::from_decision(&allowed, 150, &FakeRetryProofVerifier).unwrap();
    let request = CreateExecutionRequest {
        mutation: IdempotentMutation {
            tenant_id: "tenant-1".into(),
            principal_digest: digest("principal"),
            idempotency_key: "retry-create".into(),
        },
        admission_id: "admission-1".into(),
        capsule_digest: digest("capsule"),
        seal_digest: digest("seal"),
        retry: Some(RetryExecutionAuthorization {
            lineage,
            decision: allowed.clone(),
        }),
    };
    assert!(request.validate().is_err());
    request.validate_with(150, &FakeRetryProofVerifier).unwrap();
    let mut forged = request;
    forged
        .retry
        .as_mut()
        .unwrap()
        .decision
        .proof
        .policy_authorization
        .as_mut()
        .unwrap()
        .signature[0] ^= 1;
    assert!(forged.validate_with(150, &FakeRetryProofVerifier).is_err());
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
    substituted.identities.execution_id = Some("execution-2".into());
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

    let session = CreateSessionRequest {
        mutation: IdempotentMutation {
            tenant_id: "tenant-1".into(),
            principal_digest: digest("principal"),
            idempotency_key: "session-1".into(),
        },
        capsule_digest: digest("session-capsule"),
        seal_digest: digest("session-seal"),
        runtime_requirement: RuntimeSelectionRequirement {
            runtime_compatibility_digest: digest("runtime-compatibility"),
            allowed_provider_identity_digests: BTreeSet::from([descriptor
                .deployed_generation
                .provider
                .digest()
                .unwrap()]),
            allowed_administrative_trust_domains: BTreeSet::from(["example.internal".into()]),
            allowed_pool_trust_profile_digests: BTreeSet::from([digest("pool-trust-profile")]),
            exact_placement_attributes: BTreeMap::new(),
            required_devices: BTreeSet::new(),
            minimum_limits: BTreeMap::new(),
            required_feature_profiles: BTreeSet::new(),
        },
        required_profiles: Vec::new(),
    };
    session.validate_against(&descriptor).unwrap();
    assert!(serde_json::to_value(&session)
        .unwrap()
        .get("sterile_template_digest")
        .is_none());

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
        terminal_cause: Some(TerminalCause::Succeeded),
        failure: None,
        evidence_sequence: 4,
        evidence_event_digest: digest("terminal-evidence"),
    };
    snapshot.validate().unwrap();
    let mut invalid = snapshot;
    invalid.terminal_cause = None;
    assert!(invalid.validate().is_err());
}

fn checkpoint_manifest() -> CheckpointManifest {
    CheckpointManifest {
        manifest_version: 1,
        tenant_id: "tenant-1".into(),
        program_digest: digest("program"),
        dependency_digests: BTreeSet::from([digest("dependency")]),
        capsule_digest: digest("capsule"),
        seal_digest: digest("seal"),
        policy_digest: digest("policy"),
        runtime_compatibility_digest: digest("runtime-compatibility"),
        object_graph_root_digest: digest("object-graph"),
        sanitization_evidence_digest: digest("sanitization-evidence"),
        credential_exclusion_evidence_digest: digest("credential-exclusion-evidence"),
        effect_quiescence_evidence_digest: digest("effect-quiescence-evidence"),
        capability_revocation_evidence_digest: digest("capability-revocation-evidence"),
        workspace_generations: vec![WorkspaceGeneration {
            workspace_id_digest: digest("workspace"),
            base_generation: 1,
            current_generation: 3,
            content_digest: digest("workspace-content"),
        }],
        deterministic_guest_state_digest: digest("guest-state"),
        capability_accounting_digest: digest("capability-accounting"),
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
        compatibility_grade: CheckpointCompatibilityGrade::Exact,
        created_unix_ms: 100,
    }
}

#[test]
fn replay_bundles_pin_checkpoint_identity_and_reject_credentials() {
    let checkpoint = checkpoint_manifest();
    let proof = replay_grade_proof(&checkpoint, ReplayGrade::Hermetic);
    let bundle = ReplayBundleManifest::from_checkpoint(
        &checkpoint,
        ReplayGrade::Hermetic,
        proof,
        ReplayBundleMaterial {
            evidence_checkpoint_digest: digest("evidence-checkpoint"),
            evidence_event_digests: vec![digest("evidence-event")],
            included_object_digests: BTreeMap::from([(
                "checkpoint".into(),
                checkpoint.digest().unwrap(),
            )]),
        },
        150,
        &FakeReplayGradeVerifier,
    )
    .unwrap();
    bundle
        .validate_against(&checkpoint, 150, &FakeReplayGradeVerifier)
        .unwrap();
    let mut substituted = bundle;
    substituted.program_digest = digest("other-program");
    assert!(substituted
        .validate_against(&checkpoint, 150, &FakeReplayGradeVerifier)
        .is_err());

    let mut forged_proof = replay_grade_proof(&checkpoint, ReplayGrade::Hermetic);
    forged_proof.signature[0] ^= 1;
    assert!(ReplayBundleManifest::from_checkpoint(
        &checkpoint,
        ReplayGrade::Hermetic,
        forged_proof,
        ReplayBundleMaterial {
            evidence_checkpoint_digest: digest("evidence-checkpoint"),
            evidence_event_digests: vec![digest("evidence-event")],
            included_object_digests: BTreeMap::from([(
                "checkpoint".into(),
                checkpoint.digest().unwrap(),
            )]),
        },
        150,
        &FakeReplayGradeVerifier,
    )
    .is_err());
}

#[test]
fn replay_grades_require_distinct_positive_proofs() {
    let checkpoint = checkpoint_manifest();
    let mut exact_without_interactions = replay_grade_proof(&checkpoint, ReplayGrade::Exact);
    exact_without_interactions.recorded_interaction_contract_digest = None;
    assert!(ReplayBundleManifest::from_checkpoint(
        &checkpoint,
        ReplayGrade::Exact,
        exact_without_interactions,
        ReplayBundleMaterial {
            evidence_checkpoint_digest: digest("evidence-checkpoint"),
            evidence_event_digests: vec![digest("event")],
            included_object_digests: BTreeMap::from([(
                "checkpoint".into(),
                checkpoint.digest().unwrap(),
            )]),
        },
        150,
        &FakeReplayGradeVerifier,
    )
    .is_err());

    let evidence_only = replay_grade_proof(&checkpoint, ReplayGrade::EvidenceOnly);
    ReplayBundleManifest::from_checkpoint(
        &checkpoint,
        ReplayGrade::EvidenceOnly,
        evidence_only,
        ReplayBundleMaterial {
            evidence_checkpoint_digest: digest("evidence-checkpoint"),
            evidence_event_digests: vec![digest("event")],
            included_object_digests: BTreeMap::from([(
                "checkpoint".into(),
                checkpoint.digest().unwrap(),
            )]),
        },
        150,
        &FakeReplayGradeVerifier,
    )
    .unwrap();

    let mut first_storage = CheckpointStorageEnvelope {
        envelope_version: 1,
        tenant_id: checkpoint.tenant_id.clone(),
        checkpoint_state_digest: checkpoint.digest().unwrap(),
        encryption_key_generation: 3,
        encryption_algorithm: "xchacha20-poly1305".into(),
        encrypted_envelope_digest: digest("ciphertext-one"),
        associated_data_digest: digest("pending-associated-data"),
        object_metadata_digest: digest("object-metadata"),
    };
    first_storage.associated_data_digest = canonical::canonical_digest(
        b"runtrue.provider.checkpoint-storage-associated-data.v1\0",
        &(
            first_storage.envelope_version,
            &first_storage.tenant_id,
            &first_storage.checkpoint_state_digest,
            first_storage.encryption_key_generation,
            &first_storage.encryption_algorithm,
            &first_storage.object_metadata_digest,
        ),
    )
    .unwrap();
    let mut rotated_storage = first_storage.clone();
    rotated_storage.encryption_key_generation = 4;
    rotated_storage.encrypted_envelope_digest = digest("ciphertext-two");
    rotated_storage.associated_data_digest = canonical::canonical_digest(
        b"runtrue.provider.checkpoint-storage-associated-data.v1\0",
        &(
            rotated_storage.envelope_version,
            &rotated_storage.tenant_id,
            &rotated_storage.checkpoint_state_digest,
            rotated_storage.encryption_key_generation,
            &rotated_storage.encryption_algorithm,
            &rotated_storage.object_metadata_digest,
        ),
    )
    .unwrap();
    assert_ne!(
        first_storage.storage_digest(&checkpoint).unwrap(),
        rotated_storage.storage_digest(&checkpoint).unwrap()
    );
    assert_eq!(
        first_storage.checkpoint_state_digest,
        rotated_storage.checkpoint_state_digest
    );
}

#[test]
fn retry_authorization_consumes_effect_history_and_binds_retry_lineage() {
    let identity = ExternalEffectIdentity {
        operation_id: "operation-1".into(),
        idempotency_key: "idempotency-1".into(),
        tenant_id: "tenant-1".into(),
        execution_id: "execution-1".into(),
        capsule_digest: digest("capsule"),
        capability_grant_digest: digest("grant"),
        lease_id: "lease-1".into(),
        fence_generation: 1,
        destination_digest: digest("destination"),
        bounded_request_digest: digest("request"),
    };
    let requested = ExternalEffectTransition::requested(identity, digest("broker"), 100).unwrap();
    let accepted = ExternalEffectTransition::terminal(
        &requested,
        ExternalEffectState::Accepted,
        digest("ack"),
        digest("broker"),
        101,
    )
    .unwrap();
    let unsafe_proof = RetryEffectProof {
        transitions: vec![requested.clone(), accepted],
        reconciliation: None,
        admitted_effect_declaration_digest: digest("effect-declaration"),
        capability_grant_digest: digest("grant"),
        safety: RetryEffectSafety::Mutation {
            destination_idempotency_contract_digest: None,
            contract_verification_evidence_digest: None,
        },
    };
    assert!(RetryAuthorization::decide(
        "execution-2".into(),
        "execution-1".into(),
        std::slice::from_ref(&unsafe_proof),
        digest("signed-retry-denial-evidence"),
    )
    .is_err());
    let safe_proof = RetryEffectProof {
        safety: RetryEffectSafety::Mutation {
            destination_idempotency_contract_digest: Some(digest("idempotency-contract")),
            contract_verification_evidence_digest: Some(digest("contract-verification")),
        },
        ..unsafe_proof
    };
    let authorization = RetryAuthorization::decide(
        "execution-2".into(),
        "execution-1".into(),
        &[safe_proof],
        digest("signed-retry-authorization-evidence"),
    )
    .unwrap();
    assert_eq!(authorization.retry_of_execution_id, "execution-1");
    authorization.digest().unwrap();
}

#[test]
fn sterile_template_publication_rejects_stale_inventory_or_revocation() {
    let inventory = signed_inventory();
    let authority = inventory_authority();
    let member = PoolMemberRecord {
        member_id: "member-template".into(),
        member_generation: 1,
        pool_id: "pool-1".into(),
        pool_trust_domain: "pool.example.internal".into(),
        provider: provider_identity(),
        state: PoolMemberState::Creating,
        transition_sequence: 0,
        fence_generation: 1,
        runtime_inventory_digest: inventory.inventory_digest.clone(),
        sterile_template_digest: digest("template"),
        assignment: None,
        last_transition_digest: None,
    };
    let publication = SterileTemplatePublication {
        publication_version: 1,
        template_digest: digest("template"),
        builder_definition_digest: digest("builder-definition"),
        builder_identity_digest: digest("builder"),
        runtime_inventory_digest: inventory.inventory_digest.clone(),
        runtime_compatibility_digest: digest("runtime-compatibility"),
        snapshot_compatibility_digest: digest("snapshot-compatibility"),
        provenance_digest: digest("provenance"),
        sbom_digest: digest("sbom"),
        vulnerability_evidence_digest: digest("vulnerability"),
        policy_evidence_digest: digest("policy"),
        sterility_scan_digest: digest("sterility"),
        cold_boot_probe_digest: digest("cold-probe"),
        restore_probe_digest: digest("restore-probe"),
        inventory_generation: inventory.inventory.inventory_generation,
        revocation_generation: inventory.inventory.revocation_generation,
        created_unix_ms: 100,
        expires_unix_ms: 200,
    };
    let mut publication = SignedSterileTemplatePublication {
        publication_digest: publication.digest().unwrap(),
        publication,
        authority_identity_digest: digest("template-authority"),
        signing_key_id: digest("template-authority-key"),
        signing_key_generation: 1,
        signature_algorithm: "ed25519".into(),
        signature: vec![1],
    };
    publication.signature = ContentDigest::sha256(publication.signature_message().unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    publication
        .authorize_member(&member, &inventory, &authority, 150, &FakeProviderVerifier)
        .unwrap();
    let mut forged = publication.clone();
    forged.signature[0] ^= 1;
    assert!(forged
        .authorize_member(&member, &inventory, &authority, 150, &FakeProviderVerifier,)
        .is_err());
    let mut stale_authority = authority.clone();
    stale_authority.snapshot.current_revocation_generation = 2;
    assert!(publication
        .authorize_member(
            &member,
            &inventory,
            &stale_authority,
            150,
            &FakeProviderVerifier,
        )
        .is_err());
    let mut quarantined = member;
    quarantined.state = PoolMemberState::Quarantined;
    quarantined.transition_sequence = 1;
    quarantined.last_transition_digest = Some(digest("quarantined-transition"));
    assert!(publication
        .authorize_member(
            &quarantined,
            &inventory,
            &authority,
            150,
            &FakeProviderVerifier,
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
    let sealed_grant = runtrue_execution::CapabilityGrant {
        class: "scm.publish".into(),
        resource: "resource".into(),
        operations: BTreeSet::from(["status.write".into()]),
        destinations: BTreeSet::from(["destination".into()]),
        external_effect_class: Some("scm-mutation".into()),
        budget: runtrue_execution::CapabilityBudget {
            maximum_calls: 2,
            maximum_request_bytes: 8,
            maximum_response_bytes: 8,
            maximum_external_effects: 2,
        },
        constraints_digest: digest("capability-constraints"),
    };
    let grant = InvocationCapabilityGrant {
        grant_version: 1,
        grant_id: "grant-1".into(),
        sealed_capability_grant_digest: sealed_grant.digest().unwrap(),
        subject: subject.clone(),
        resource_identity_digest: digest("resource"),
        capability_type: "scm.publish".into(),
        external_effect_class: Some("scm-mutation".into()),
        permitted_operations: BTreeSet::from(["status.write".into()]),
        permitted_destination_digests: BTreeSet::from([digest("destination")]),
        request_contract_digest: sealed_grant.constraints_digest.clone(),
        response_contract_digest: sealed_grant.constraints_digest.clone(),
        lease_id: "lease-1".into(),
        fence_generation: 3,
        revocation_generation: 4,
        not_before_unix_ms: 50,
        expires_unix_ms: 200,
        maximum_concurrency: 1,
        maximum_request_bytes: 8,
        maximum_response_bytes: 8,
        rate_window_milliseconds: 1_000,
        maximum_uses_per_window: 2,
        budget: InvocationBudget {
            maximum_uses: 2,
            maximum_external_effects: 1,
            maximum_effect_bytes: 10,
        },
    };
    let handle =
        InvocationHandle::new("invocation-1".into(), grant.clone(), &sealed_grant, 100).unwrap();
    let mut expanded_effect_budget = grant.clone();
    expanded_effect_budget.budget.maximum_external_effects = 3;
    assert!(InvocationHandle::new(
        "expanded-effects".into(),
        expanded_effect_budget,
        &sealed_grant,
        100,
    )
    .is_err());
    let mut substituted_contract = grant.clone();
    substituted_contract.request_contract_digest = digest("substituted-contract");
    assert!(InvocationHandle::new(
        "substituted-contract".into(),
        substituted_contract,
        &sealed_grant,
        100,
    )
    .is_err());
    let mut expanded_sealed_authority = sealed_grant.clone();
    expanded_sealed_authority.operations.clear();
    assert!(InvocationHandle::new(
        "expanded-invocation".into(),
        grant,
        &expanded_sealed_authority,
        100,
    )
    .is_err());
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

    let grant_digest = handle.capability_grant_digest().clone();
    let destination = digest("destination");
    let call = CapabilityCallAuthorization {
        subject: &subject,
        resource_identity_digest: &digest("resource"),
        capability_grant_digest: &grant_digest,
        lease_id: "lease-1",
        fence_generation: 3,
        current_revocation_generation: 4,
        operation: "status.write",
        destination_digest: &destination,
        request_bytes: 4,
        maximum_response_bytes: 4,
        current_concurrency: 0,
        rate_window_started_unix_ms: 90,
        uses_in_current_rate_window: 0,
        now_unix_ms: 100,
        call_deadline_unix_ms: 150,
        canceled: false,
        external_effecting: true,
    };
    handle.authorize_call(&call).unwrap();
    let mut hidden_effect = call.clone();
    hidden_effect.external_effecting = false;
    assert!(handle.authorize_call(&hidden_effect).is_err());
    let mut revoked = call.clone();
    revoked.current_revocation_generation = 5;
    assert!(handle.authorize_call(&revoked).is_err());
    let mut wrong_operation = call.clone();
    wrong_operation.operation = "deployment.write";
    assert!(handle.authorize_call(&wrong_operation).is_err());

    let first = CapabilityBudgetReservation::reserve_call(&handle, None, &call, digest("effect-1"))
        .unwrap();
    assert!(CapabilityBudgetReservation::reserve_call(
        &handle,
        Some(&first),
        &call,
        digest("effect-2"),
    )
    .is_err());
    let incomplete =
        CapabilityBudgetCompletion::reconcile(&first, 2, digest("ambiguous-response"), false)
            .unwrap();
    assert_eq!(incomplete.unused_effect_bytes_released, 0);
    incomplete.validate_against(&first).unwrap();
    let mut forged_release = incomplete;
    forged_release.unused_effect_bytes_released = 6;
    assert!(forged_release.validate_against(&first).is_err());

    let complete =
        CapabilityBudgetCompletion::reconcile(&first, 2, digest("response"), true).unwrap();
    assert_eq!(complete.unused_effect_bytes_released, 6);
    complete.validate_against(&first).unwrap();
}

fn bisim_observation(role: BisimComparisonRole) -> BisimPortableObservation {
    let provider = digest(match role {
        BisimComparisonRole::Baseline => "provider-local",
        BisimComparisonRole::Candidate => "provider-remote",
    });
    let pool = digest(match role {
        BisimComparisonRole::Baseline => "pool-local",
        BisimComparisonRole::Candidate => "pool-remote",
    });
    let runtime = digest(match role {
        BisimComparisonRole::Baseline => "inventory-local",
        BisimComparisonRole::Candidate => "inventory-remote",
    });
    let evidence_producer = digest(match role {
        BisimComparisonRole::Baseline => "evidence-local",
        BisimComparisonRole::Candidate => "evidence-remote",
    });
    BisimPortableObservation {
        observation_version: 1,
        capsule_digest: digest("capsule"),
        program_digest: digest("program"),
        allowed_provider_identity_digests: BTreeSet::from([
            digest("provider-local"),
            digest("provider-remote"),
        ]),
        provider_identity_digest: provider,
        allowed_pool_trust_profile_digests: BTreeSet::from([
            digest("pool-local"),
            digest("pool-remote"),
        ]),
        pool_trust_profile_digest: pool,
        allowed_runtime_inventory_digests: BTreeSet::from([
            digest("inventory-local"),
            digest("inventory-remote"),
        ]),
        runtime_inventory_digest: runtime,
        allowed_evidence_producer_identity_digests: BTreeSet::from([
            digest("evidence-local"),
            digest("evidence-remote"),
        ]),
        evidence_producer_identity_digest: evidence_producer,
        runtime_compatibility_digest: digest("runtime"),
        lifecycle: BisimLifecycleObservation {
            execution_state: Some(ExecutionState::Terminal),
            session_state: None,
            terminal_cause: Some(TerminalCause::Succeeded),
            failure: None,
        },
        normalized_outputs: BTreeMap::from([("stdout".into(), digest("stdout"))]),
        normalized_artifacts: BTreeMap::from([("result".into(), digest("artifact"))]),
        capability_state_digest: digest("capability"),
        external_effect_state_digest: digest("effects"),
        checkpoint_grade: CheckpointCompatibilityGrade::Exact,
        replay_bundle_digest: digest("replay"),
        cleanup_result_digest: digest("cleanup"),
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
    candidate.allowed_evidence_producer_identity_digests =
        BTreeSet::from([digest("missing-or-other-evidence")]);
    candidate.evidence_producer_identity_digest = digest("missing-or-other-evidence");
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

#[test]
fn evidence_profiles_enforce_identities_producers_bounds_and_append_authentication() {
    let requirement = EvidenceEventRequirement {
        event_type: "execution.state".into(),
        allowed_producers: BTreeSet::from([EvidenceProducerKind::ExecutionPlane]),
        required_identities: BTreeSet::from([
            EvidenceIdentityField::Execution,
            EvidenceIdentityField::Program,
            EvidenceIdentityField::Capsule,
            EvidenceIdentityField::Provider,
            EvidenceIdentityField::DeployedProviderGeneration,
        ]),
        maximum_payload_bytes: 64,
    };
    let profile = EvidenceProfile {
        id: FeatureProfileId {
            name: "evidence.execution".into(),
            generation: 1,
        },
        scope_kind: EvidenceScopeKind::Execution,
        requirements: BTreeMap::from([("execution.state".into(), requirement)]),
    };
    let mut event = evidence_event(1, None);
    event.identities.program_digest = Some(digest("program"));
    event.identities.capsule_digest = Some(digest("capsule"));
    event.identities.provider_identity_digest = Some(digest("provider"));
    event.identities.deployed_provider_generation_digest = Some(digest("deployment"));
    let context = AuthenticatedEvidenceAppendContext {
        authenticated_producer: event.producer.clone(),
        tenant_id: event.tenant_id.clone(),
        administrative_trust_domain: event.administrative_trust_domain.clone(),
        authentication_evidence_digest: digest("authentication"),
    };
    context.authorize(&event, &profile).unwrap();

    let mut missing = event.clone();
    missing.identities.capsule_digest = None;
    assert!(context.authorize(&missing, &profile).is_err());
    let mut runner_claim = event.clone();
    runner_claim.producer = producer(EvidenceProducerKind::Runner);
    assert!(profile.validate_event(&runner_claim).is_err());
    let mut oversized = event;
    oversized.payload_size_bytes = 65;
    assert!(profile.validate_event(&oversized).is_err());
}

#[test]
fn signed_inventory_and_capacity_reject_signature_and_identity_substitution() {
    let inventory = inventory();
    let mut signed_inventory = SignedRuntimeInventoryEntry {
        inventory_digest: inventory.digest().unwrap(),
        signature: ProviderContractSignature {
            algorithm: "ed25519".into(),
            signing_key_generation: inventory.deployed_provider.signing_key_generation,
            signature: vec![1],
        },
        inventory,
    };
    signed_inventory.signature.signature =
        ContentDigest::sha256(signed_inventory.signature_message().unwrap())
            .as_str()
            .as_bytes()
            .to_vec();
    let authority = inventory_authority();
    signed_inventory
        .verify_with(&authority, 150, &FakeProviderVerifier)
        .unwrap();

    let observation = CapacityObservation {
        inventory_digest: signed_inventory.inventory_digest.clone(),
        observation_sequence: 1,
        available_slots: 1,
        available_cpu: 2,
        available_memory_bytes: 1024,
        available_storage_bytes: 1024,
        observed_unix_ms: 100,
        expires_unix_ms: 200,
        producer: provider_identity(),
    };
    let mut signed_capacity = SignedCapacityObservation {
        observation_digest: observation.digest().unwrap(),
        deployed_provider: deployed_provider(),
        signature: ProviderContractSignature {
            algorithm: "ed25519".into(),
            signing_key_generation: 3,
            signature: vec![1],
        },
        observation,
    };
    signed_capacity.signature.signature = ContentDigest::sha256(
        signed_capacity
            .signature_message(&signed_inventory, 150)
            .unwrap(),
    )
    .as_str()
    .as_bytes()
    .to_vec();
    signed_capacity
        .verify_with(&signed_inventory, &authority, 150, &FakeProviderVerifier)
        .unwrap();
    let valid_capacity = signed_capacity.clone();
    signed_capacity.signature.signature[0] ^= 1;
    assert!(signed_capacity
        .verify_with(&signed_inventory, &authority, 150, &FakeProviderVerifier)
        .is_err());
    let mut substituted_inventory = signed_inventory.clone();
    substituted_inventory.inventory.runtime_id = "runtime-other".into();
    assert!(signed_capacity
        .validate_against(&substituted_inventory, 150)
        .is_err());

    let mut stale_authority = authority;
    stale_authority.snapshot.minimum_security_generation = 5;
    assert!(signed_inventory
        .verify_with(&stale_authority, 150, &FakeProviderVerifier)
        .is_err());
    assert!(valid_capacity
        .verify_with(
            &signed_inventory,
            &stale_authority,
            150,
            &FakeProviderVerifier,
        )
        .is_err());
    stale_authority.snapshot.minimum_security_generation = 4;
    stale_authority.snapshot.current_revocation_generation = 2;
    assert!(signed_inventory
        .verify_with(&stale_authority, 150, &FakeProviderVerifier)
        .is_err());
}

#[test]
fn conformance_requires_crypto_pinned_cases_and_descriptor_compatibility() {
    let statement = conformance_statement(ConformanceCaseOutcome::Passed);
    let mut signed = SignedConformanceMetadata {
        media_type: "runtrue.conformance".into(),
        signature_algorithm: "ed25519".into(),
        signing_key_id: "key-3".into(),
        signing_key_generation: 3,
        statement_digest: statement.digest(150).unwrap(),
        statement,
        signature: vec![1],
    };
    signed.signature = ContentDigest::sha256(signed.signature_message(150).unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    let pinned = PinnedConformanceSuite {
        suite: signed.statement.suite.clone(),
        positive_vectors_digest: digest("positive-vectors"),
        negative_vectors_digest: digest("negative-vectors"),
        required_cases_by_profile: BTreeMap::from([(
            profile_id(),
            BTreeSet::from(["execution.core.exact".into()]),
        )]),
    };
    signed
        .verify_with(150, &pinned, &descriptor(), &FakeConformanceVerifier)
        .unwrap();
    let mut substituted_descriptor = descriptor();
    substituted_descriptor
        .feature_profiles
        .get_mut("execution.core")
        .unwrap()
        .compatibility_digest = digest("other-compatibility");
    assert!(signed
        .verify_with(
            150,
            &pinned,
            &substituted_descriptor,
            &FakeConformanceVerifier
        )
        .is_err());
    signed.signature[0] ^= 1;
    assert!(signed
        .verify_with(150, &pinned, &descriptor(), &FakeConformanceVerifier)
        .is_err());
}

#[test]
fn attestation_binds_final_cleanup_prefix_and_revocation_and_verifies_signature() {
    let first = cryptographically_seal(evidence_event(1, None));
    let mut cleanup_event = evidence_event(2, Some(first.event_digest.clone()));
    cleanup_event.event_type = "execution.cleanup".into();
    let cleanup = cryptographically_seal(cleanup_event);
    let events = vec![first, cleanup.clone()];
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
    let statement = AttestationStatement {
        statement_version: 1,
        evidence_schema_generation: 1,
        evidence_scope_kind: EvidenceScopeKind::Execution,
        subject_id: "execution-1".into(),
        identities: cleanup.event.identities.clone(),
        evidence_chain_root_digest: checkpoint.chain_root_digest.clone(),
        evidence_from_sequence: 1,
        evidence_through_sequence: 2,
        terminal_cleanup_event_digest: cleanup.event_digest.clone(),
        admission_summary_digest: digest("admission"),
        lease_fence_summary_digest: digest("lease-fence"),
        capability_summary_digest: digest("capability"),
        external_effect_summary_digest: digest("effects"),
        failure_resolution: None,
        output_manifest_digests: BTreeSet::from([digest("outputs")]),
        artifact_manifest_digests: BTreeSet::new(),
        checkpoint_manifest_digests: BTreeSet::new(),
        replay_bundle_manifest_digests: BTreeSet::new(),
        cleanup_result_digest: digest("cleanup-result"),
        issuer_id: "provider-issuer".into(),
        evidence_grade: "baseline".into(),
        isolation_grade: "native".into(),
        issued_unix_ms: 100,
        expires_unix_ms: 200,
        revocation_reference_digest: digest("revocation"),
        extension_claim_digests: BTreeMap::new(),
    };
    statement
        .validate_finalized_prefix(&checkpoint, &events)
        .unwrap();
    let mut signed = SignedAttestation {
        statement_digest: statement.digest().unwrap(),
        statement,
        signature_algorithm: "ed25519".into(),
        signing_key_id: "key-1".into(),
        signing_key_generation: 1,
        signature: vec![1],
    };
    signed.signature = ContentDigest::sha256(signed.signature_message(150).unwrap())
        .as_str()
        .as_bytes()
        .to_vec();
    signed.verify_with(150, &FakeAttestationVerifier).unwrap();
    signed.signature[0] ^= 1;
    assert!(signed.verify_with(150, &FakeAttestationVerifier).is_err());

    let mut substituted = signed.statement.clone();
    substituted.terminal_cleanup_event_digest = digest("other-cleanup");
    assert!(substituted
        .validate_finalized_prefix(&checkpoint, &events)
        .is_err());
    let mut substituted_identity = signed.statement.clone();
    substituted_identity.identities.program_digest = Some(digest("other-program"));
    assert!(substituted_identity
        .validate_finalized_prefix(&checkpoint, &events)
        .is_err());
}

#[test]
fn retention_export_and_storage_reads_fail_closed() {
    let first = evidence_event(1, None).seal(evidence_signature()).unwrap();
    let checkpoint = EvidenceCheckpoint::for_chain(
        std::slice::from_ref(&first),
        producer(EvidenceProducerKind::ProviderControlPlane),
        100,
        evidence_signature(),
    )
    .unwrap();
    let scope = LogicalObjectScope::Tenant {
        tenant_id: "tenant-1".into(),
        administrative_trust_domain: "example.internal".into(),
        encryption_context_digest: digest("encryption"),
    };
    let tombstone = ObjectTombstone {
        tombstone_version: 1,
        object_class: LogicalObjectClass::EvidencePayload,
        scope: scope.clone(),
        original_digest: digest("payload"),
        original_size_bytes: 7,
        retention_policy_digest: digest("retention"),
        deleted_unix_ms: 200,
        deletion_method: "crypto_shred".into(),
        deletion_proof_digest: Some(digest("deletion-proof")),
    };
    let export = EvidenceExportManifest {
        export_version: 1,
        events: vec![first],
        checkpoint,
        tombstones: vec![tombstone.clone()],
        manifest_digests: BTreeSet::from([digest("manifest")]),
        payloads: BTreeMap::from([(
            digest("payload"),
            PayloadAvailability::Expired {
                tombstone_digest: tombstone.digest().unwrap(),
            },
        )]),
    };
    export.validate_structure().unwrap();
    let receipt = EvidenceExportReceipt {
        export_digest: export.digest().unwrap(),
        evidence_checkpoint_digest: export.checkpoint.chain_root_digest.clone(),
        event_count: 1,
        manifest: export.clone(),
    };
    receipt.validate().unwrap();
    let mut mismatched_receipt = receipt;
    mismatched_receipt.event_count = 2;
    assert!(mismatched_receipt.validate().is_err());
    let mut bad_export = export;
    bad_export.payloads.insert(
        digest("other"),
        PayloadAvailability::Expired {
            tombstone_digest: digest("missing-tombstone"),
        },
    );
    assert!(bad_export.validate_structure().is_err());

    assert!(LogicalObjectClass::Artifact.forbids_cross_tenant_deduplication());
    assert!(LogicalObjectClass::Cache.forbids_cross_tenant_deduplication());
    let bytes = b"verified".to_vec();
    let authority = StorageAuthority {
        principal_digest: digest("principal"),
        tenant_id: Some("tenant-1".into()),
        administrative_trust_domain: "example.internal".into(),
        purpose: "artifact.read".into(),
        authorization_decision_digest: digest("authorization"),
    };
    let request = ObjectReadRequest {
        object_class: LogicalObjectClass::Artifact,
        scope,
        digest: ContentDigest::sha256(&bytes),
        expected_size_bytes: bytes.len() as u64,
        expected_object_verification_digest: digest("verification-record"),
        offset: 0,
        maximum_bytes: 64,
        authority,
    };
    let mut chunk = ObjectReadChunk {
        digest: request.digest.clone(),
        total_size_bytes: bytes.len() as u64,
        offset: 0,
        chunk_digest: ContentDigest::sha256(&bytes),
        object_verification_digest: request.expected_object_verification_digest.clone(),
        bytes,
        complete: true,
    };
    chunk.verify_against(&request).unwrap();
    chunk.object_verification_digest = digest("substituted-verification-record");
    assert!(chunk.verify_against(&request).is_err());
    chunk.object_verification_digest = request.expected_object_verification_digest.clone();
    chunk.bytes[0] ^= 1;
    assert!(chunk.verify_against(&request).is_err());
}

#[test]
fn failure_resolution_and_retry_are_exact_subject_and_recomputed() {
    let first = cause(
        1,
        PortableFailureClass::RuntimeFailure,
        FailurePhase::Running,
    );
    let mut other = cause(2, PortableFailureClass::TimedOut, FailurePhase::Running);
    other.subject_id = "execution-2".into();
    assert!(FailureResolution::resolve(vec![first.clone(), other]).is_err());

    let session_operation = ObservedCause {
        sequence: 1,
        subject_id: "session-op-1".into(),
        class: PortableFailureClass::PolicyDenied,
        subject_kind: FailureSubjectKind::SessionOperation,
        phase: FailurePhase::SessionRecovery,
        evidence_event_digest: digest("operation-evidence"),
        diagnostic_code: None,
        retry_hint: None,
    };
    session_operation.validate().unwrap();
    let program_resolution = FailureResolution::resolve(vec![cause(
        1,
        PortableFailureClass::ProgramFailure,
        FailurePhase::Running,
    )])
    .unwrap();
    let program_retry_without_effect_frontier = RetryDecision::evaluate(
        &program_resolution,
        RetrySafetyProof {
            policy_authorization: Some(authenticated_retry_proof(
                RetryProofKind::PolicyAuthorization,
                program_resolution.digest().unwrap(),
            )),
            effect_authorization: None,
            effect_safety: None,
            runner_remediation: None,
        },
        150,
        &FakeRetryProofVerifier,
    )
    .unwrap();
    assert!(!program_retry_without_effect_frontier.allowed);
    assert!(program_retry_without_effect_frontier
        .denials
        .contains(&RetryDenial::EffectSafetyUnproven));
    assert!(FailureResolution::resolve(vec![
        first,
        cause(
            2,
            PortableFailureClass::CapacityUnavailable,
            FailurePhase::Queued,
        ),
    ])
    .is_err());

    let resolution = FailureResolution::resolve(vec![cause(
        1,
        PortableFailureClass::RuntimeFailure,
        FailurePhase::Running,
    )])
    .unwrap();
    let mut decision = RetryDecision::evaluate(
        &resolution,
        RetrySafetyProof {
            policy_authorization: Some(authenticated_retry_proof(
                RetryProofKind::PolicyAuthorization,
                resolution.digest().unwrap(),
            )),
            effect_safety: Some(authenticated_retry_proof(
                RetryProofKind::EffectSafety,
                retry_authorization("execution-1").digest().unwrap(),
            )),
            effect_authorization: Some(retry_authorization("execution-1")),
            runner_remediation: None,
        },
        150,
        &FakeRetryProofVerifier,
    )
    .unwrap();
    decision.denials.insert(RetryDenial::EffectSafetyUnproven);
    assert!(decision.validate().is_err());
}
