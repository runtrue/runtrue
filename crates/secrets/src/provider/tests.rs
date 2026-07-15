use super::*;
use super::{vault::reference::VaultSecretReference, vault::transport::dns_answers_are_public};
use runtrue_model::ContentDigest;
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

type RecordedVaultRequest = (VaultHttpMethod, String, Option<String>, String, Vec<u8>);

#[derive(Default)]
struct MockTransport {
    requests: Mutex<Vec<RecordedVaultRequest>>,
    responses: Mutex<Vec<VaultHttpResponse>>,
}

impl MockTransport {
    fn with_response(response: VaultHttpResponse) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![response]),
        }
    }
}

impl VaultTransport for MockTransport {
    fn execute(&self, request: VaultHttpRequest) -> Result<VaultHttpResponse, ProviderError> {
        self.requests.lock().unwrap().push((
            request.method(),
            request.url().to_owned(),
            request.namespace().map(str::to_owned),
            request.token().to_owned(),
            request.body().to_vec(),
        ));
        self.responses
            .lock()
            .unwrap()
            .pop()
            .ok_or(ProviderError::Transport)
    }
}

fn request(reference: &str) -> ExternalSecretLeaseRequest {
    let mut request = ExternalSecretLeaseRequest {
        release_id: "external-release-1".to_owned(),
        release_subject_digest: ContentDigest::sha256([]),
        provider_id: "vault-kv-v2".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        run_id: "run".to_owned(),
        runner_id: "runner".to_owned(),
        secret_metadata_id: "secret".to_owned(),
        provider_reference: reference.to_owned(),
        execution_lease_id: "lease".to_owned(),
        fencing_generation: 4,
        installation_fencing_epoch: 7,
        job_id: "job".to_owned(),
        job_attempt: 2,
        step_id: "step".to_owned(),
        purpose: "publish".to_owned(),
        expires_unix_ms: 20_000,
    };
    request.release_subject_digest = request.expected_release_subject_digest().unwrap();
    request
}

fn request_for(provider_id: &str, reference: &str) -> ExternalSecretLeaseRequest {
    let mut request = request(reference);
    request.provider_id = provider_id.to_owned();
    request.release_subject_digest = request.expected_release_subject_digest().unwrap();
    request
}

fn response(value: &str) -> VaultHttpResponse {
    VaultHttpResponse::new(
            200,
            format!(
                r#"{{"lease_id":"vault-lease","renewable":true,"lease_duration":5,"data":{{"data":{{"token":"{value}"}},"metadata":{{"version":3}}}}}}"#
            )
            .into_bytes(),
        )
}

fn provider(
    response: VaultHttpResponse,
) -> VaultKvV2Provider<MockTransport, StaticVaultTokenSource> {
    VaultKvV2Provider::new(
        "https://vault.example",
        Some("team/platform".to_owned()),
        MockTransport::with_response(response),
        StaticVaultTokenSource::new(VaultToken::new("root-token").unwrap()),
        10_000,
    )
    .unwrap()
}

#[test]
fn kv_v2_lease_is_exactly_bound_and_response_is_redacted() {
    let provider = provider(response("sensitive"));
    let lease = provider
        .lease(
            &request("kv-v2://secret/data/release#token?version=3"),
            1_000,
        )
        .unwrap();
    assert_eq!(lease.plaintext().as_bytes(), b"sensitive");
    assert_eq!(lease.metadata.fencing_generation, 4);
    assert_eq!(lease.metadata.installation_fencing_epoch, 7);
    assert_eq!(lease.metadata.job_attempt, 2);
    assert_eq!(
        lease.metadata.release_subject_digest,
        request("kv-v2://secret/data/release#token?version=3").release_subject_digest
    );
    assert_eq!(lease.metadata.provider_version, Some(3));
    assert_eq!(lease.metadata.expires_unix_ms, 6_000);
    assert!(!format!("{lease:?}").contains("sensitive"));

    let requests = provider.transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].1,
        "https://vault.example/v1/secret/data/data/release?version=3"
    );
    assert_eq!(requests[0].2.as_deref(), Some("team/platform"));
    assert_eq!(requests[0].3, "root-token");
}

#[test]
fn release_subject_is_deterministic_and_binds_provider_attempt_and_fence() {
    let original = request("kv-v2://secret/release#token?version=3");
    let identical = request("kv-v2://secret/release#token?version=3");
    assert_eq!(
        original.release_subject_digest,
        identical.release_subject_digest
    );

    let mut changed = original.clone();
    changed.job_attempt += 1;
    assert_ne!(
        original.release_subject_digest,
        changed.expected_release_subject_digest().unwrap()
    );
    assert!(matches!(
        changed.validate(1_000),
        Err(ProviderError::ReleaseSubjectMismatch)
    ));

    changed = original.clone();
    changed.provider_id = "other-vault".to_owned();
    assert_ne!(
        original.release_subject_digest,
        changed.expected_release_subject_digest().unwrap()
    );
    changed = original.clone();
    changed.fencing_generation += 1;
    assert_ne!(
        original.release_subject_digest,
        changed.expected_release_subject_digest().unwrap()
    );
}

#[test]
fn base64_values_decode_and_invalid_or_duplicate_fields_fail_closed() {
    let provider = provider(response("c2VjcmV0"));
    let lease = provider
        .lease(&request("kv-v2://secret/release#token?encoding=base64"), 1)
        .unwrap();
    assert_eq!(lease.plaintext().as_bytes(), b"secret");

    let duplicate = VaultHttpResponse::new(
        200,
        br#"{"data":{"data":{"token":"a","token":"b"},"metadata":{"version":1}}}"#.to_vec(),
    );
    assert!(matches!(
        provider_with_new_response(duplicate).lease(&request("kv-v2://kv/x#token"), 1),
        Err(ProviderError::InvalidProviderResponse)
    ));
    assert!(VaultSecretReference::parse("kv-v2://kv/../x#token").is_err());
    assert!(VaultSecretReference::parse("kv-v2://kv/x#token?unknown=x").is_err());
}

fn provider_with_new_response(
    response: VaultHttpResponse,
) -> VaultKvV2Provider<MockTransport, StaticVaultTokenSource> {
    provider(response)
}

#[test]
fn non_tls_remote_addresses_and_expired_or_stale_bindings_fail() {
    assert!(VaultKvV2Provider::new(
        "http://vault.example",
        None,
        MockTransport::default(),
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .is_err());
    assert!(VaultKvV2Provider::new(
        "http://127.0.0.1:8200",
        None,
        MockTransport::default(),
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .is_err());
    assert!(VaultKvV2Provider::new_loopback_test_only(
        "http://127.0.0.1:8200",
        None,
        MockTransport::default(),
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .is_ok());
    let mut expired = request("kv-v2://kv/x#token");
    expired.expires_unix_ms = 1;
    assert!(matches!(
        provider(response("x")).lease(&expired, 1),
        Err(ProviderError::InvalidLeaseRequest)
    ));
}

#[test]
fn revoke_uses_only_provider_lease_id_and_status_is_checked() {
    let transport = MockTransport::with_response(VaultHttpResponse::new(204, Vec::new()));
    let provider = VaultKvV2Provider::new(
        "https://vault.example",
        None,
        transport,
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .unwrap();
    let mut release_request = request("kv-v2://kv/x#token");
    release_request.fencing_generation = 1;
    release_request.installation_fencing_epoch = 1;
    release_request.job_attempt = 1;
    release_request.purpose = "purpose".to_owned();
    release_request.expires_unix_ms = 100;
    release_request.release_subject_digest =
        release_request.expected_release_subject_digest().unwrap();
    let metadata = ExternalSecretLeaseMetadata {
        release_id: "external-release-1".to_owned(),
        release_subject_digest: release_request.release_subject_digest,
        provider: "vault-kv-v2".to_owned(),
        tenant_id: "tenant".to_owned(),
        repository_id: "repository".to_owned(),
        run_id: "run".to_owned(),
        runner_id: "runner".to_owned(),
        secret_metadata_id: "secret".to_owned(),
        execution_lease_id: "lease".to_owned(),
        fencing_generation: 1,
        installation_fencing_epoch: 1,
        job_id: "job".to_owned(),
        job_attempt: 1,
        step_id: "step".to_owned(),
        purpose: "purpose".to_owned(),
        provider_lease_id: Some("provider-lease".to_owned()),
        provider_version: Some(1),
        renewable: false,
        expires_unix_ms: 100,
    };
    provider.revoke(&metadata, 10).unwrap();
    let requests = provider.transport.requests.lock().unwrap();
    assert_eq!(requests[0].0, VaultHttpMethod::Post);
    assert_eq!(requests[0].1, "https://vault.example/v1/sys/leases/revoke");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].4).unwrap(),
        serde_json::json!({"lease_id":"provider-lease"})
    );
}

fn one_shot_http_server(
    response: Vec<u8>,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        sender.send(request).unwrap();
        stream.write_all(&response).unwrap();
    });
    (format!("http://{address}"), receiver, handle)
}

#[test]
fn hardened_loopback_transport_is_explicit_bounded_and_origin_pinned() {
    let body = br#"{"lease_id":"","renewable":false,"lease_duration":1,"data":{"data":{"token":"transport-secret"},"metadata":{"version":8}}}"#;
    let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect();
    let (origin, captured, handle) = one_shot_http_server(response);
    let transport = HardenedVaultTransport::loopback_test_only(
        &origin,
        VaultTransportLimits {
            max_response_bytes: 1024,
            ..VaultTransportLimits::default()
        },
    )
    .unwrap();
    let provider = VaultKvV2Provider::new_loopback_test_only(
        &origin,
        Some("test/namespace".to_owned()),
        transport.clone(),
        StaticVaultTokenSource::new(VaultToken::new("test-token").unwrap()),
        5_000,
    )
    .unwrap();
    let lease = provider
        .lease(&request("kv-v2://secret/release#token"), 1_000)
        .unwrap();
    assert_eq!(lease.plaintext().as_bytes(), b"transport-secret");
    let captured = String::from_utf8(captured.recv().unwrap()).unwrap();
    assert!(captured
        .to_ascii_lowercase()
        .contains("x-vault-token: test-token"));
    assert!(captured
        .to_ascii_lowercase()
        .contains("x-vault-namespace: test/namespace"));
    handle.join().unwrap();

    let wrong_origin = VaultHttpRequest {
        method: VaultHttpMethod::Get,
        url: "http://127.0.0.1:1/v1/secret/data/x".to_owned(),
        namespace: None,
        token: VaultToken::new("test-token").unwrap(),
        body: Zeroizing::new(Vec::new()),
    };
    assert!(matches!(
        transport.execute(wrong_origin),
        Err(ProviderError::InvalidTransportRequest)
    ));
}

#[test]
fn hardened_transport_does_not_follow_redirects_and_bounds_response_bytes() {
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (origin, _captured, handle) = one_shot_http_server(redirect);
    let transport =
        HardenedVaultTransport::loopback_test_only(&origin, VaultTransportLimits::default())
            .unwrap();
    let response = transport
        .execute(VaultHttpRequest {
            method: VaultHttpMethod::Get,
            url: format!("{origin}/v1/secret/data/x"),
            namespace: None,
            token: VaultToken::new("token").unwrap(),
            body: Zeroizing::new(Vec::new()),
        })
        .unwrap();
    assert_eq!(response.status(), 302);
    handle.join().unwrap();

    let oversized_body = vec![b'x'; 65];
    let oversized_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        oversized_body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(oversized_body)
    .collect();
    let (origin, _captured, handle) = one_shot_http_server(oversized_response);
    let transport = HardenedVaultTransport::loopback_test_only(
        &origin,
        VaultTransportLimits {
            max_response_bytes: 64,
            ..VaultTransportLimits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        transport.execute(VaultHttpRequest {
            method: VaultHttpMethod::Get,
            url: format!("{origin}/v1/secret/data/x"),
            namespace: None,
            token: VaultToken::new("token").unwrap(),
            body: Zeroizing::new(Vec::new()),
        }),
        Err(ProviderError::ProviderResponseTooLarge)
    ));
    handle.join().unwrap();
}

#[test]
fn reviewed_ca_and_all_answer_dns_policies_fail_closed() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let certificate = rcgen::CertificateParams::default()
        .self_signed(&key)
        .unwrap();
    assert!(HardenedVaultTransport::public_https(
        "https://vault.example",
        certificate.pem().as_bytes(),
        VaultTransportLimits::default(),
    )
    .is_ok());
    assert!(matches!(
        HardenedVaultTransport::public_https(
            "https://vault.example",
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
            VaultTransportLimits::default(),
        ),
        Err(ProviderError::InvalidCaBundle)
    ));
    assert!(matches!(
        HardenedVaultTransport::public_https(
            "https://127.0.0.1:8200",
            certificate.pem().as_bytes(),
            VaultTransportLimits::default(),
        ),
        Err(ProviderError::InvalidProviderAddress)
    ));
    assert!(dns_answers_are_public(&[
        "8.8.8.8".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
    ]));
    assert!(!dns_answers_are_public(&[
        "8.8.8.8".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
    ]));
    assert!(!dns_answers_are_public(&["203.0.113.1".parse().unwrap()]));
}

#[test]
fn explicit_provider_registry_has_no_fallback_and_counts_rejections() {
    let provider = VaultKvV2Provider::new_named(
        "team-vault",
        "https://vault.example",
        None,
        MockTransport::with_response(response("registry-secret")),
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .unwrap();
    let mut registry = ExternalSecretProviderRegistry::new();
    registry.register("team-vault", provider).unwrap();
    let lease = registry
        .lease(
            "team-vault",
            &request_for("team-vault", "kv-v2://secret/release#token"),
            1_000,
        )
        .unwrap();
    assert_eq!(lease.metadata.provider, "team-vault");
    assert_eq!(lease.plaintext().as_bytes(), b"registry-secret");
    assert!(matches!(
        registry.lease(
            "missing-provider",
            &request_for("missing-provider", "kv-v2://secret/release#token"),
            1_000,
        ),
        Err(ProviderError::UnknownProvider)
    ));
    let metrics = registry.metrics();
    assert_eq!(metrics.lease_attempts, 2);
    assert_eq!(metrics.lease_successes, 1);
    assert_eq!(metrics.rejected_requests, 1);

    let duplicate = VaultKvV2Provider::new_named(
        "team-vault",
        "https://vault.example",
        None,
        MockTransport::default(),
        StaticVaultTokenSource::new(VaultToken::new("token").unwrap()),
        1_000,
    )
    .unwrap();
    assert!(matches!(
        registry.register("team-vault", duplicate),
        Err(ProviderError::DuplicateProviderRegistration)
    ));
}
