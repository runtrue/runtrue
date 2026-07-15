use super::*;
use crate::{
    broker::RunnerBrokerClient,
    daemon::{
        clock::{now_unix_ms, timestamp},
        executor::JobExecution,
        observations::publish_step_observation,
        remote::{reject_remote_retries, RemoteJobExecutor},
        source::digest_from_wire,
    },
    transport::TransportError,
};
use async_trait::async_trait;
use rcgen::{
    string::Ia5String, BasicConstraints, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SanType, PKCS_ED25519,
};
use runtrue_attest::{CapsuleSigningKey, CAPSULE_MEDIA_TYPE};
use runtrue_model::{SecretReference, DIGEST_ALGORITHM};
use runtrue_protocol::{
    v1::{control_message, runner_message},
    v2, PROTOCOL_MAX,
};
use runtrue_runner_core::AdmittedLease;
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, OperatingSystem,
    ParityGrade, PermissionSet, PlannedJob, PlannedStep, RunnerRequirements, SourceTrust,
    StepAction, StepCapabilitySet, Trust, WorkflowIdentity, CAPSULE_SCHEMA_VERSION,
    ENGINE_COMPATIBILITY_VERSION,
};
use rustls_pki_types::{pem::PemObject as _, CertificateDer, CertificateSigningRequestDer};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::File,
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Clone)]
struct FakeExecutor {
    wait_for_cancel: bool,
}

impl JobExecutor for FakeExecutor {
    fn preflight(&self, _lease: &AdmittedLease) -> Result<(), RunnerError> {
        Ok(())
    }

    fn execute(
        &self,
        _lease: &AdmittedLease,
        _workspace: &Path,
        cancellation: CancellationToken,
    ) -> Result<JobExecution, RunnerError> {
        if self.wait_for_cancel {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !cancellation.is_cancelled() {
                if std::time::Instant::now() >= deadline {
                    return Err(RunnerError::DeadlineElapsed);
                }
                thread::sleep(Duration::from_millis(5));
            }
            return Ok(JobExecution {
                final_state: "canceled".to_owned(),
                exit_code: None,
                error_code: "canceled".to_owned(),
                result_digest: ContentDigest::sha256(b"canceled"),
                log_frames: Vec::new(),
                final_job_attempt: 0,
                artifact_ids: Vec::new(),
                cache_entry_ids: Vec::new(),
                credential_taint: runtrue_engine::CredentialTaint::None,
            });
        }
        Ok(JobExecution {
            final_state: "succeeded".to_owned(),
            exit_code: Some(0),
            error_code: String::new(),
            result_digest: ContentDigest::sha256(b"result"),
            log_frames: Vec::new(),
            final_job_attempt: 0,
            artifact_ids: Vec::new(),
            cache_entry_ids: Vec::new(),
            credential_taint: runtrue_engine::CredentialTaint::None,
        })
    }

    fn cleanup_stale(&self) -> Result<(), RunnerError> {
        Ok(())
    }
}

#[derive(Default)]
struct FakeState {
    hellos: Vec<v1::RunnerHello>,
    controls: VecDeque<v1::ControlMessage>,
    fetched: Option<v1::FetchExecutionCapsuleResponse>,
    sent: Vec<v1::RunnerMessage>,
    completions: Vec<v1::CompleteLeaseRequest>,
    completion_attempts: usize,
    rotation_requests: Vec<v1::RotateCertificateRequest>,
    rotation_failures_remaining: usize,
    completion_count_when_rotated: Option<usize>,
    rotation_authority: Option<TestCertificateAuthority>,
}

#[derive(Clone)]
struct FakeTransport(Arc<Mutex<FakeState>>);

#[async_trait]
impl RunnerTransport for FakeTransport {
    async fn open(&mut self, hello: v1::RunnerHello) -> Result<v1::ControlHello, TransportError> {
        self.0.lock().await.hellos.push(hello.clone());
        Ok(v1::ControlHello {
            connection_id: hello.connection_id,
            heartbeat_interval: Some(prost_types::Duration {
                seconds: 0,
                nanos: 100_000_000,
            }),
            server_time: Some(timestamp(now_unix_ms().unwrap())),
            installation_fencing_epoch: 4,
        })
    }

    async fn send(&mut self, message: v1::RunnerMessage) -> Result<(), TransportError> {
        self.0.lock().await.sent.push(message);
        Ok(())
    }

    async fn next_control(&mut self) -> Result<Option<v1::ControlMessage>, TransportError> {
        let control = self.0.lock().await.controls.pop_front();
        if control.is_some() {
            return Ok(control);
        }
        std::future::pending().await
    }

    async fn fetch_capsule(
        &mut self,
        _request: v1::FetchExecutionCapsuleRequest,
    ) -> Result<v1::FetchExecutionCapsuleResponse, TransportError> {
        self.0
            .lock()
            .await
            .fetched
            .clone()
            .ok_or(TransportError::StreamClosed)
    }

    async fn complete_lease(
        &mut self,
        request: v1::CompleteLeaseRequest,
    ) -> Result<v1::CompleteLeaseResponse, TransportError> {
        let mut state = self.0.lock().await;
        state.completions.push(request);
        state.completion_attempts += 1;
        if state.completion_attempts == 1 {
            return Err(TransportError::Status {
                code: tonic::Code::Unavailable,
                message: "test transport unavailable".to_owned(),
            });
        }
        Ok(v1::CompleteLeaseResponse {
            accepted: true,
            resulting_job_state: "succeeded".to_owned(),
        })
    }

    async fn rotate_certificate(
        &mut self,
        request: v1::RotateCertificateRequest,
    ) -> Result<v1::RotateCertificateResponse, TransportError> {
        let mut state = self.0.lock().await;
        let response = signed_rotation_response(
            &request,
            state
                .rotation_authority
                .as_ref()
                .expect("rotation test requires an authority"),
        );
        state.completion_count_when_rotated = Some(state.completions.len());
        state.rotation_requests.push(request);
        if state.rotation_failures_remaining != 0 {
            state.rotation_failures_remaining -= 1;
            return Err(TransportError::Status {
                code: tonic::Code::Unavailable,
                message: "rotation response lost".to_owned(),
            });
        }
        Ok(response)
    }
}

struct TestCertificateAuthority {
    params: CertificateParams,
    key: KeyPair,
    certificate: rcgen::Certificate,
}

fn test_ca() -> TestCertificateAuthority {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(4_102_444_800).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    TestCertificateAuthority {
        params,
        key,
        certificate,
    }
}

fn client_certificate(
    public_key: &impl rcgen::PublicKeyData,
    runner_id: &str,
    pool_id: &str,
    authority: &TestCertificateAuthority,
) -> (String, u64) {
    let mut params = CertificateParams::default();
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, runner_id);
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, pool_id);
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(format!("urn:runtrue:runner:{pool_id}:{runner_id}")).unwrap(),
    )];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = Issuer::from_params(&authority.params, &authority.key);
    let certificate = params.signed_by(public_key, &issuer).unwrap();
    (
        format!(
            "{}\n{}\n",
            certificate.pem().trim(),
            authority.certificate.pem().trim()
        ),
        2_000_000_000_000,
    )
}

fn initial_credentials(authority: &TestCertificateAuthority) -> crate::NewRunnerCredentials {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let (certificate_chain_pem, certificate_expires_unix_ms) =
        client_certificate(&key, "runner-1", "pool-1", authority);
    crate::NewRunnerCredentials {
        runner_id: "runner-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        certificate_expires_unix_ms,
        private_key_pem: Zeroizing::new(key.serialize_pem()),
        certificate_chain_pem: certificate_chain_pem.into_bytes(),
        authoritative_posture_digest: None,
        selected_protocol_version: PROTOCOL_MAX,
    }
}

fn signed_rotation_response(
    request: &v1::RotateCertificateRequest,
    authority: &TestCertificateAuthority,
) -> v1::RotateCertificateResponse {
    let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(
        request.certificate_signing_request.as_slice(),
    ))
    .unwrap();
    let (certificate_chain_pem, certificate_expires_unix_ms) =
        client_certificate(&csr.public_key, &request.runner_id, "pool-1", authority);
    let certificate_chain_pem = certificate_chain_pem.into_bytes();
    let leaf = CertificateDer::from_pem_slice(&certificate_chain_pem).unwrap();
    v1::RotateCertificateResponse {
        certificate_chain_pem,
        certificate_expires_at: Some(timestamp(certificate_expires_unix_ms)),
        csr_digest: Some(
            v1::Digest::try_from(ContentDigest::sha256(&request.certificate_signing_request))
                .unwrap(),
        ),
        certificate_fingerprint: Some(
            v1::Digest::try_from(ContentDigest::sha256(leaf.as_ref())).unwrap(),
        ),
    }
}

fn capsule() -> ExecutionCapsule {
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
            source_commit: "a".repeat(40),
            source_tree_digest: None,
            base_commit: None,
            source_trust: SourceTrust::Trusted,
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: Vec::new(),
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
                cpu: 1,
                memory_bytes: 1024,
                storage_bytes: Some(1024),
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 1000,
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

fn fixture() -> (
    RunnerDaemonConfig,
    v1::LeaseOffer,
    v1::FetchExecutionCapsuleResponse,
) {
    let capsule = capsule();
    let signing = CapsuleSigningKey::from_seed([5; 32]);
    let signature = signing.sign_capsule(&capsule).unwrap();
    let digest = v1::Digest::try_from(&signature.capsule_digest).unwrap();
    let profile = runtrue_runner_core::VerifiedRunnerProfile {
        runner_id: "runner-1".to_owned(),
        os: OperatingSystem::Linux,
        architecture: Architecture::Amd64,
        logical_cpus: 2,
        memory_bytes: 4096,
        storage_bytes: 4096,
        isolation_backends: BTreeSet::from([Isolation::Native]),
        capabilities: BTreeSet::new(),
        region: None,
        posture_digest: ContentDigest::sha256(b"posture"),
    };
    let wire_inventory = v1::RunnerInventory {
        hostname: "test".to_owned(),
        os: "linux".to_owned(),
        architecture: "amd64".to_owned(),
        logical_cpus: 2,
        memory_bytes: 4096,
        local_storage_bytes: 4096,
        isolation_backends: vec!["native".to_owned()],
        capabilities: Vec::new(),
        runner_binary_digest: Some(v1::Digest::try_from(ContentDigest::sha256(b"bin")).unwrap()),
        runner_image_digest: None,
        runner_version: "test".to_owned(),
        engine_version: "test".to_owned(),
        protocol_version: PROTOCOL_MAX,
        region: String::new(),
        labels: Default::default(),
    };
    let mut trust_store = CapsuleTrustStore::new();
    trust_store.insert(signing.verifying_key()).unwrap();
    let now = now_unix_ms().unwrap();
    let offer = v1::LeaseOffer {
        lease_id: "lease-1".to_owned(),
        job_id: "build".to_owned(),
        runner_id: "runner-1".to_owned(),
        fencing_generation: 2,
        installation_fencing_epoch: 4,
        capsule_digest: Some(digest.clone()),
        capsule_signature: signature.signature.clone(),
        capsule_signing_key_id: signature.key_id.to_string(),
        issued_at: Some(timestamp(now.saturating_sub(100))),
        accept_by: Some(timestamp(now + 10_000)),
        expires_at: Some(timestamp(now + 60_000)),
        hard_deadline: Some(timestamp(now + 3_600_000)),
        requirements: Some(v1::RunnerRequirements {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            isolation_floor: "native".to_owned(),
            cpu: 1,
            memory_bytes: 1024,
            storage_bytes: 1024,
            region: String::new(),
            required_capabilities: Vec::new(),
            posture_digest: Some(v1::Digest::try_from(&profile.posture_digest).unwrap()),
        }),
        secret_broker_audience: String::new(),
    };
    let fetched = v1::FetchExecutionCapsuleResponse {
        canonical_capsule: capsule.canonical_bytes().unwrap(),
        digest: Some(digest),
        signature: signature.signature,
        signing_key_id: signature.key_id.to_string(),
        media_type: CAPSULE_MEDIA_TYPE.to_owned(),
    };
    (
        RunnerDaemonConfig {
            runner_id: "runner-1".to_owned(),
            inventory: VerifiedInventory {
                profile,
                wire: wire_inventory,
                binary_digest: ContentDigest::sha256(b"bin"),
            },
            trust_store,
            allow_trusted_native: true,
            mode: RunMode::Once,
            max_capsule_bytes: 1024 * 1024,
            credential_store: None,
        },
        offer,
        fetched,
    )
}

mod cancellation;
mod executor;
mod lifecycle;
mod loop_behavior;
mod source;
