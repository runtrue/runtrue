use crate::{
    evidence_producer_identity_digest, portable_evidence_payload_digest,
    portable_evidence_payload_size, BackendIdentity, BisimError, BisimPortableEvidence,
    BisimResultBinding,
};
use runtrue_engine::{
    ExecutionResult, Executor, ExecutorError, ExecutorOutput, JobAttemptOutcome,
    StepExecutionRequest,
};
use runtrue_model::ContentDigest;
use runtrue_provider_contract::{
    BisimComparisonRole, BisimLifecycleObservation, BisimOperationalContext,
    BisimPortableObservation, CheckpointCompatibilityGrade, DeployedProviderGeneration,
    EvidenceCheckpoint, EvidenceEvent, EvidenceIdentities, EvidenceObservedTime,
    EvidenceProducerIdentity, EvidenceProducerKind, EvidenceScopeKind, EvidenceSignature,
    EvidenceSignatureVerifier, ExecutionState, ProviderIdentity, TerminalCause,
};
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements,
    ScalarValue, StepAction, StepCapabilitySet, Trust, ValueBinding, WorkflowIdentity,
    CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(super) struct ScriptedExecutor {
    pub(super) outputs: VecDeque<ExecutorOutput>,
}

impl Executor for ScriptedExecutor {
    fn preflight(&self, _capsule: &ExecutionCapsule) -> Result<(), ExecutorError> {
        Ok(())
    }

    fn execute(
        &mut self,
        _request: &StepExecutionRequest,
    ) -> Result<ExecutorOutput, ExecutorError> {
        self.outputs
            .pop_front()
            .ok_or_else(|| ExecutorError::Wait("missing scripted output".to_owned()))
    }

    fn finish_job_attempt(
        &mut self,
        _job: &PlannedJob,
        _attempt: u32,
        _outcome: JobAttemptOutcome,
    ) -> Result<(), ExecutorError> {
        Ok(())
    }
}

pub(super) fn capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "conformance".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "0123456789012345678901234567890123456789".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::from([("MODE".to_owned(), ScalarValue::String("test".to_owned()))]),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "job".to_owned(),
            base_id: "job".to_owned(),
            name: "job".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::TrustedOnly,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Native,
                image: None,
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: None,
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 1_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: vec![PlannedStep {
                id: "step".to_owned(),
                name: "step".to_owned(),
                condition: None,
                action: StepAction::Command {
                    program: "echo".to_owned(),
                    args: vec![ValueBinding::Literal(ScalarValue::String(
                        "hello".to_owned(),
                    ))],
                },
                inputs: BTreeMap::new(),
                environment: BTreeMap::new(),
                capabilities: StepCapabilitySet::default(),
                cache: None,
                timeout_ms: None,
                continue_on_error: false,
                outputs: BTreeMap::new(),
                working_directory: None,
            }],
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::DNonReplayable,
    }
}

pub(super) fn backend() -> BackendIdentity {
    BackendIdentity {
        name: "scripted".to_owned(),
        version: "1".to_owned(),
        isolation: Isolation::Native,
        parity: ParityGrade::DNonReplayable,
    }
}

pub(super) fn portable(capsule: &ExecutionCapsule) -> BisimPortableObservation {
    let provider = provider_generation().provider.digest().unwrap();
    let pool = ContentDigest::sha256(b"pool-profile");
    let runtime = ContentDigest::sha256(b"runtime-inventory");
    let evidence = evidence_producer_identity_digest(&evidence_producer()).unwrap();
    BisimPortableObservation {
        observation_version: 1,
        capsule_digest: capsule.digest().unwrap(),
        program_digest: ContentDigest::sha256(b"program"),
        allowed_provider_identity_digests: BTreeSet::from([provider.clone()]),
        provider_identity_digest: provider,
        allowed_pool_trust_profile_digests: BTreeSet::from([pool.clone()]),
        pool_trust_profile_digest: pool,
        allowed_runtime_inventory_digests: BTreeSet::from([runtime.clone()]),
        runtime_inventory_digest: runtime,
        allowed_evidence_producer_identity_digests: BTreeSet::from([evidence.clone()]),
        evidence_producer_identity_digest: evidence,
        runtime_compatibility_digest: ContentDigest::sha256(b"runtime-compatibility"),
        lifecycle: BisimLifecycleObservation {
            execution_state: Some(ExecutionState::Terminal),
            session_state: None,
            terminal_cause: Some(TerminalCause::Succeeded),
            failure: None,
        },
        normalized_outputs: BTreeMap::new(),
        normalized_artifacts: BTreeMap::new(),
        capability_state_digest: ContentDigest::sha256(b"capabilities"),
        external_effect_state_digest: ContentDigest::sha256(b"effects"),
        checkpoint_grade: CheckpointCompatibilityGrade::DiagnosticOnly,
        replay_bundle_digest: ContentDigest::sha256(b"replay"),
        cleanup_result_digest: ContentDigest::sha256(b"cleanup"),
        backend_security_result_digest: ContentDigest::sha256(b"backend-security"),
        operational: BisimOperationalContext {
            comparison_role: BisimComparisonRole::Baseline,
            observed_unix_ms: 1,
            worker_id: "worker".to_owned(),
            pool_id: Some("pool".to_owned()),
            warm_acquisition: false,
        },
    }
}

pub(super) fn portable_evidence(
    capsule: &ExecutionCapsule,
    result_binding: &BisimResultBinding,
) -> BisimPortableEvidence {
    let portable = portable(capsule);
    let deployed_provider = provider_generation();
    let producer = evidence_producer();
    let event = EvidenceEvent {
        envelope_version: 1,
        scope_kind: EvidenceScopeKind::Execution,
        subject_id: "execution-1".to_owned(),
        tenant_id: Some("tenant-1".to_owned()),
        administrative_trust_domain: Some("trust.example".to_owned()),
        identities: EvidenceIdentities {
            provider_identity_digest: Some(deployed_provider.provider.digest().unwrap()),
            deployed_provider_generation_digest: Some(deployed_provider.digest().unwrap()),
            program_digest: Some(portable.program_digest.clone()),
            capsule_digest: Some(portable.capsule_digest.clone()),
            execution_id: Some("execution-1".to_owned()),
            runtime_compatibility_digest: Some(portable.runtime_compatibility_digest.clone()),
            ..EvidenceIdentities::default()
        },
        subject_sequence: 1,
        previous_event_digest: None,
        event_type: "bisim.portable-observation".to_owned(),
        schema_generation: 1,
        payload_digest: portable_evidence_payload_digest(&portable, result_binding).unwrap(),
        payload_size_bytes: portable_evidence_payload_size(&portable, result_binding).unwrap(),
        producer: producer.clone(),
        observed_time: EvidenceObservedTime {
            wall_unix_nanoseconds: 1_000_000,
            wall_precision_nanoseconds: 1,
            monotonic_nanoseconds: 1,
            monotonic_precision_nanoseconds: 1,
        },
        links: Vec::new(),
        provider_diagnostics: BTreeMap::new(),
    };
    let mut envelope = event.seal(signature(&producer)).unwrap();
    envelope.signature.signature = envelope.signature_message().unwrap();
    let events = vec![envelope];
    let mut checkpoint =
        EvidenceCheckpoint::for_chain(&events, producer.clone(), 1, signature(&producer)).unwrap();
    checkpoint.signature.signature = checkpoint.signature_message().unwrap();
    BisimPortableEvidence {
        deployed_provider,
        events,
        checkpoint,
    }
}

pub(super) fn evidence_factory(
    capsule: &ExecutionCapsule,
) -> impl FnOnce(
    &BisimResultBinding,
    &ExecutionResult,
) -> Result<(BisimPortableObservation, BisimPortableEvidence), BisimError>
       + '_ {
    move |result_binding, _result| {
        Ok((
            portable(capsule),
            portable_evidence(capsule, result_binding),
        ))
    }
}

pub(super) struct TestEvidenceVerifier;

impl EvidenceSignatureVerifier for TestEvidenceVerifier {
    fn verify_signature(
        &self,
        _producer: &EvidenceProducerIdentity,
        _algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature == message
    }
}

fn provider_generation() -> DeployedProviderGeneration {
    DeployedProviderGeneration {
        provider: ProviderIdentity {
            provider_id: "provider-1".to_owned(),
            administrative_trust_domain: "trust.example".to_owned(),
            authentication_key_digest: ContentDigest::sha256(b"authentication-key"),
        },
        generation: 1,
        binary_digest: ContentDigest::sha256(b"provider-binary"),
        configuration_digest: ContentDigest::sha256(b"provider-configuration"),
        policy_digest: ContentDigest::sha256(b"provider-policy"),
        key_set_digest: ContentDigest::sha256(b"provider-key-set"),
        signing_key_generation: 1,
    }
}

fn evidence_producer() -> EvidenceProducerIdentity {
    EvidenceProducerIdentity {
        kind: EvidenceProducerKind::ProviderControlPlane,
        producer_id: "provider-1".to_owned(),
        authentication_identity_digest: ContentDigest::sha256(b"authentication-key"),
        signing_key_id: ContentDigest::sha256(b"evidence-signing-key"),
        signing_key_generation: 1,
    }
}

fn signature(producer: &EvidenceProducerIdentity) -> EvidenceSignature {
    EvidenceSignature {
        algorithm: "test-signature".to_owned(),
        signing_key_id: producer.signing_key_id.clone(),
        signing_key_generation: producer.signing_key_generation,
        signature: vec![1],
    }
}

pub(super) fn output(stdout: &str, duration_ms: u64) -> ExecutorOutput {
    ExecutorOutput {
        stdout: stdout.to_owned(),
        duration_ms,
        ..ExecutorOutput::success()
    }
}
