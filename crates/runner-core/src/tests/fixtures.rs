use crate::{
    validation::{architecture_name, isolation_name, os_name},
    CapsuleTrustStore, RunnerAdmission, VerifiedRunnerProfile,
};
use prost_types::Timestamp;
use runtrue_attest::{CapsuleSigningKey, CAPSULE_MEDIA_TYPE};
use runtrue_model::ContentDigest;
use runtrue_protocol::v1;
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, RunnerRequirements, SourceTrust,
    Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn capsule(capabilities: Vec<String>) -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "test".to_owned(),
        workflow: WorkflowIdentity {
            name: "test".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/test.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "commit".to_owned(),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: vec!["policy-v1".to_owned()],
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "Build".to_owned(),
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
                cpu: 2,
                memory_bytes: 1024,
                storage_bytes: Some(2048),
                region: Some("test-region".to_owned()),
                capabilities,
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
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
        expected_parity: ParityGrade::AExact,
    }
}

fn timestamp(millis: u64) -> Timestamp {
    Timestamp {
        seconds: i64::try_from(millis / 1000).expect("test seconds"),
        nanos: i32::try_from((millis % 1000) * 1_000_000).expect("test nanos"),
    }
}

pub(super) fn profile(capabilities: BTreeSet<String>) -> VerifiedRunnerProfile {
    VerifiedRunnerProfile {
        runner_id: "runner-1".to_owned(),
        os: OperatingSystem::Linux,
        architecture: Architecture::Amd64,
        logical_cpus: 4,
        memory_bytes: 4096,
        storage_bytes: 8192,
        max_concurrent_wasm_jobs: 1,
        isolation_backends: BTreeSet::from([Isolation::Native]),
        capabilities,
        region: Some("test-region".to_owned()),
        posture_digest: ContentDigest::sha256(b"posture"),
    }
}

pub(super) fn admission(
    key: &CapsuleSigningKey,
    profile: VerifiedRunnerProfile,
) -> RunnerAdmission {
    let mut trust = CapsuleTrustStore::new();
    trust.insert(key.verifying_key()).expect("trust key");
    RunnerAdmission::new(trust, profile, 9).expect("admission")
}

pub(super) fn offer_and_capsule(
    key: &CapsuleSigningKey,
    capsule: &ExecutionCapsule,
) -> (v1::LeaseOffer, v1::FetchExecutionCapsuleResponse) {
    let signature = key.sign_capsule(capsule).expect("sign");
    let digest = v1::Digest::try_from(&signature.capsule_digest).expect("wire digest");
    let posture = v1::Digest::try_from(ContentDigest::sha256(b"posture")).expect("posture digest");
    let requirements = &capsule.jobs[0].runner;
    let wire_requirements = v1::RunnerRequirements {
        os: os_name(requirements.os).to_owned(),
        architecture: architecture_name(requirements.arch).to_owned(),
        isolation_floor: isolation_name(requirements.isolation).to_owned(),
        cpu: u32::from(requirements.cpu),
        memory_bytes: requirements.memory_bytes,
        storage_bytes: requirements.storage_bytes.unwrap_or_default(),
        region: requirements.region.clone().unwrap_or_default(),
        required_capabilities: requirements.capabilities.clone(),
        posture_digest: Some(posture),
    };
    let offer = v1::LeaseOffer {
        lease_id: "lease-1".to_owned(),
        job_id: "build".to_owned(),
        runner_id: "runner-1".to_owned(),
        fencing_generation: 3,
        installation_fencing_epoch: 9,
        capsule_digest: Some(digest.clone()),
        capsule_signature: signature.signature.clone(),
        capsule_signing_key_id: signature.key_id.to_string(),
        issued_at: Some(timestamp(1000)),
        accept_by: Some(timestamp(2000)),
        expires_at: Some(timestamp(3000)),
        hard_deadline: Some(timestamp(10_000)),
        requirements: Some(wire_requirements),
        secret_broker_audience: String::new(),
    };
    let fetched = v1::FetchExecutionCapsuleResponse {
        canonical_capsule: capsule.canonical_bytes().expect("canonical capsule"),
        digest: Some(digest),
        signature: signature.signature,
        signing_key_id: signature.key_id.to_string(),
        media_type: CAPSULE_MEDIA_TYPE.to_owned(),
    };
    (offer, fetched)
}
