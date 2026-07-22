use super::{
    bindings::*, client::*, envelope::*, oidc::RunnerOidcAdapter, secrets::RunnerSecretAdapter,
};
use crate::transport::TransportError;
use chacha20poly1305::{
    aead::{Aead as _, Payload},
    KeyInit as _, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use runtrue_engine::CancellationToken;
use runtrue_executor_wasm::{
    CapabilityAdapterError, CapabilityCallContext, OidcAdapter, SecretAdapter,
};
use runtrue_model::SecretReference;
use runtrue_protocol::v1;
use sha2::Sha256;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum EnvelopeMutation {
    None,
    WrongStep,
    WrongKey,
}

struct FakeBroker {
    mutation: EnvelopeMutation,
    running_failures: AtomicUsize,
    terminal_status: Option<(tonic::Code, &'static str)>,
    cancel_on_secret: Option<CancellationToken>,
    secret_consumed: AtomicBool,
    oidc_consumed: AtomicBool,
    requests: AtomicUsize,
    revocations: AtomicUsize,
    last_secret_request: Mutex<Option<v1::SecretLeaseRequest>>,
}

impl FakeBroker {
    fn new(mutation: EnvelopeMutation) -> Self {
        Self {
            mutation,
            running_failures: AtomicUsize::new(0),
            terminal_status: None,
            cancel_on_secret: None,
            secret_consumed: AtomicBool::new(false),
            oidc_consumed: AtomicBool::new(false),
            requests: AtomicUsize::new(0),
            revocations: AtomicUsize::new(0),
            last_secret_request: Mutex::new(None),
        }
    }

    fn with_running_failures(failures: usize) -> Self {
        let broker = Self::new(EnvelopeMutation::None);
        broker.running_failures.store(failures, Ordering::Release);
        broker
    }

    fn with_status(code: tonic::Code, message: &'static str) -> Self {
        Self {
            terminal_status: Some((code, message)),
            ..Self::new(EnvelopeMutation::None)
        }
    }

    fn cancel_after_issuance(cancellation: CancellationToken) -> Self {
        Self {
            cancel_on_secret: Some(cancellation),
            ..Self::new(EnvelopeMutation::None)
        }
    }
}

impl RunnerBrokerClient for FakeBroker {
    fn request_secret_lease(
        &self,
        request: v1::SecretLeaseRequest,
        _timeout: Duration,
    ) -> Result<v1::SecretLeaseResponse, TransportError> {
        self.requests.fetch_add(1, Ordering::AcqRel);
        if self
            .running_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(status(
                tonic::Code::FailedPrecondition,
                "broker request requires the declared step to be currently running",
            ));
        }
        if let Some((code, message)) = self.terminal_status {
            return Err(status(code, message));
        }
        if self.secret_consumed.swap(true, Ordering::AcqRel) {
            return Err(status(
                tonic::Code::AlreadyExists,
                "runner broker request was already consumed",
            ));
        }
        *self.last_secret_request.lock().unwrap() = Some(request.clone());
        let response = seal_test_envelope(&request, self.mutation);
        if let Some(cancellation) = &self.cancel_on_secret {
            cancellation.cancel();
        }
        Ok(response)
    }

    fn revoke_secret_lease(
        &self,
        _request: v1::RevokeSecretLeaseRequest,
        _timeout: Duration,
    ) -> Result<(), TransportError> {
        self.revocations.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn mint_oidc_token(
        &self,
        _request: v1::OidcTokenRequest,
        _timeout: Duration,
    ) -> Result<v1::OidcTokenResponse, TransportError> {
        self.requests.fetch_add(1, Ordering::AcqRel);
        if self.oidc_consumed.swap(true, Ordering::AcqRel) {
            return Err(status(
                tonic::Code::AlreadyExists,
                "runner broker request was already consumed",
            ));
        }
        Ok(v1::OidcTokenResponse {
            token: "header.payload.signature".to_owned(),
            expires_at: Some(prost_types::Timestamp {
                seconds: 99,
                nanos: 0,
            }),
            jti: "oidc-jti-1".to_owned(),
        })
    }
}

fn status(code: tonic::Code, message: &str) -> TransportError {
    TransportError::Status {
        code,
        message: message.to_owned(),
    }
}

fn binding() -> BrokerExecutionBinding {
    BrokerExecutionBinding {
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 7,
        installation_fencing_epoch: 3,
        execution_hard_deadline_unix_ms: 100_000,
        job_id: "job-1".to_owned(),
    }
}

fn context(cancellation: CancellationToken) -> CapabilityCallContext {
    CapabilityCallContext::new(
        std::time::Instant::now() + Duration::from_secs(2),
        cancellation,
        1024,
        1024,
    )
    .with_step_binding("job-1", 1, "publish")
}

fn grant() -> SecretReference {
    SecretReference {
        metadata_id: "secret-1".to_owned(),
        name: "TOKEN".to_owned(),
        purpose: Some("publish".to_owned()),
        resolution: None,
    }
}

fn seal_test_envelope(
    request: &v1::SecretLeaseRequest,
    mutation: EnvelopeMutation,
) -> v1::SecretLeaseResponse {
    let guest_public: [u8; 32] = request
        .guest_session_key
        .as_ref()
        .unwrap()
        .value
        .as_slice()
        .try_into()
        .unwrap();
    let target = if matches!(mutation, EnvelopeMutation::WrongKey) {
        PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes()
    } else {
        guest_public
    };
    let server_secret = StaticSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret).to_bytes();
    let shared = Zeroizing::new(
        server_secret
            .diffie_hellman(&PublicKey::from(target))
            .to_bytes(),
    );
    let expires_unix_ms = 99_000;
    let step_id = if matches!(mutation, EnvelopeMutation::WrongStep) {
        "other-step"
    } else {
        request.step_id.as_str()
    };
    let envelope_binding = SecretEnvelopeBinding {
        execution_lease_id: &request.execution_lease_id,
        fencing_generation: request.fencing_generation,
        installation_fencing_epoch: 3,
        job_id: &request.job_id,
        job_attempt: request.job_attempt,
        step_id,
        secret_lease_id: "secret-lease-1",
        secret_metadata_id: &request.secret_metadata_id,
        purpose: &request.purpose,
        expires_unix_ms,
    };
    let aad = envelope_binding.aad().unwrap();
    let hkdf = Hkdf::<Sha256>::new(Some(ENVELOPE_DOMAIN), shared.as_slice());
    let mut info = Vec::new();
    info.extend_from_slice(ENVELOPE_DOMAIN);
    info.extend_from_slice(&aad);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut()).unwrap();
    let nonce = [9_u8; XCHACHA_NONCE_BYTES];
    let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: b"canary-secret",
                aad: &aad,
            },
        )
        .unwrap();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.extend_from_slice(&server_public);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    v1::SecretLeaseResponse {
        secret_lease_id: "secret-lease-1".to_owned(),
        encrypted_envelope: envelope,
        delivery_kind: ENVELOPE_DELIVERY_KIND.to_owned(),
        expires_at: Some(prost_types::Timestamp {
            seconds: 99,
            nanos: 0,
        }),
    }
}

#[test]
fn exact_secret_and_oidc_grants_are_one_use_and_secret_is_revoked() {
    let client = Arc::new(FakeBroker::new(EnvelopeMutation::None));
    let secret = RunnerSecretAdapter {
        binding: binding(),
        client: client.clone(),
    };
    let value = secret
        .read_secret(&context(CancellationToken::default()), &grant())
        .unwrap();
    assert_eq!(value.as_bytes(), b"canary-secret");
    assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
    assert_eq!(client.revocations.load(Ordering::Acquire), 1);
    let request = client.last_secret_request.lock().unwrap().clone().unwrap();
    assert_eq!(request.fencing_generation, 7);
    assert_eq!(request.job_id, "job-1");
    assert_eq!(request.step_id, "publish");
    assert_eq!(request.guest_session_key.unwrap().algorithm, "x25519");
    let replay = secret
        .read_secret(&context(CancellationToken::default()), &grant())
        .unwrap_err();
    assert!(replay.to_string().contains("AlreadyExists"));
    assert!(!replay.to_string().contains("canary-secret"));

    let oidc = RunnerOidcAdapter {
        binding: binding(),
        client: client.clone(),
    };
    let token = oidc
        .mint_token(
            &context(CancellationToken::default()),
            "https://registry.example",
        )
        .unwrap();
    assert_eq!(token.as_bytes(), b"header.payload.signature");
    assert_eq!(format!("{token:?}"), "OidcToken(<redacted>)");
    assert!(oidc
        .mint_token(
            &context(CancellationToken::default()),
            "https://registry.example",
        )
        .unwrap_err()
        .to_string()
        .contains("AlreadyExists"));
}

#[test]
fn running_observation_is_the_only_bounded_retry() {
    let client = Arc::new(FakeBroker::with_running_failures(2));
    let adapter = RunnerSecretAdapter {
        binding: binding(),
        client: client.clone(),
    };
    assert_eq!(
        adapter
            .read_secret(&context(CancellationToken::default()), &grant())
            .unwrap()
            .as_bytes(),
        b"canary-secret"
    );
    assert_eq!(client.requests.load(Ordering::Acquire), 3);

    for (code, message) in [
        (
            tonic::Code::FailedPrecondition,
            "durable runner lease is stale or in the wrong state",
        ),
        (
            tonic::Code::PermissionDenied,
            "certificate does not own session",
        ),
    ] {
        let client = Arc::new(FakeBroker::with_status(code, message));
        let adapter = RunnerSecretAdapter {
            binding: binding(),
            client: client.clone(),
        };
        assert!(adapter
            .read_secret(&context(CancellationToken::default()), &grant())
            .is_err());
        assert_eq!(client.requests.load(Ordering::Acquire), 1);
    }
}

#[test]
fn wrong_key_or_aad_fails_closed_and_still_revokes() {
    for mutation in [EnvelopeMutation::WrongStep, EnvelopeMutation::WrongKey] {
        let client = Arc::new(FakeBroker::new(mutation));
        let adapter = RunnerSecretAdapter {
            binding: binding(),
            client: client.clone(),
        };
        let error = adapter
            .read_secret(&context(CancellationToken::default()), &grant())
            .unwrap_err();
        assert!(error.to_string().contains("authentication failed"));
        assert!(!error.to_string().contains("canary-secret"));
        assert_eq!(client.revocations.load(Ordering::Acquire), 1);
    }
}

#[test]
fn cancellation_before_broker_call_releases_no_material() {
    let client = Arc::new(FakeBroker::new(EnvelopeMutation::None));
    let adapter = RunnerSecretAdapter {
        binding: binding(),
        client: client.clone(),
    };
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    assert!(matches!(
        adapter.read_secret(&context(cancellation), &grant()),
        Err(CapabilityAdapterError::Canceled)
    ));
    assert_eq!(client.requests.load(Ordering::Acquire), 0);
    assert_eq!(client.revocations.load(Ordering::Acquire), 0);

    let cancellation = CancellationToken::default();
    let client = Arc::new(FakeBroker::cancel_after_issuance(cancellation.clone()));
    let adapter = RunnerSecretAdapter {
        binding: binding(),
        client: client.clone(),
    };
    assert!(matches!(
        adapter.read_secret(&context(cancellation), &grant()),
        Err(CapabilityAdapterError::Canceled)
    ));
    assert_eq!(client.requests.load(Ordering::Acquire), 1);
    assert_eq!(client.revocations.load(Ordering::Acquire), 1);
}
