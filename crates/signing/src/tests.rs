use super::*;
use ed25519_dalek::{Signature, VerifyingKey};
use runtrue_model::ContentDigest;
use rusqlite::{params, Connection};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

const NOW: u64 = 1_000;

fn digest(name: &str) -> ContentDigest {
    ContentDigest::sha256(name.as_bytes())
}

fn request() -> SigningRequest {
    SigningRequest {
        request_id: "sign-request-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repository-1".to_owned(),
        run_id: "run-1".to_owned(),
        job_id: "release".to_owned(),
        step_id: "sign".to_owned(),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 4,
        installation_fencing_epoch: 9,
        requester_identity: "workload:release".to_owned(),
        capsule_digest: digest("capsule"),
        artifact_digest: digest("artifact"),
        provenance_digest: digest("provenance"),
        purpose: "release-artifact".to_owned(),
        operation: SigningOperation::SignDigest,
        approval_id: "approval-1".to_owned(),
        policy_version_ids: vec!["policy-a".to_owned(), "policy-b".to_owned()],
        requested_at_unix_seconds: NOW - 10,
        expires_at_unix_seconds: NOW + 300,
    }
}

fn grant(request: &SigningRequest) -> SigningGrant {
    SigningGrant {
        tenant_id: request.tenant_id.clone(),
        repository_id: request.repository_id.clone(),
        run_id: request.run_id.clone(),
        job_id: request.job_id.clone(),
        step_id: request.step_id.clone(),
        execution_lease_id: request.execution_lease_id.clone(),
        fencing_generation: request.fencing_generation,
        installation_fencing_epoch: request.installation_fencing_epoch,
        requester_identity: request.requester_identity.clone(),
        capsule_digest: request.capsule_digest.clone(),
        artifact_digest: request.artifact_digest.clone(),
        provenance_digest: request.provenance_digest.clone(),
        purpose: request.purpose.clone(),
        operation: request.operation,
        policy_version_ids: request.policy_version_ids.clone(),
        expires_at_unix_seconds: NOW + 60,
    }
}

fn approval(request: &SigningRequest) -> SigningApproval {
    SigningApproval {
        approval_id: request.approval_id.clone(),
        subject_digest: request.approval_subject().unwrap().digest().unwrap(),
        approver_identities: vec!["approver:alice".to_owned(), "approver:bob".to_owned()],
        policy_version_ids: request.policy_version_ids.clone(),
        approved_at_unix_seconds: NOW - 5,
        expires_at_unix_seconds: NOW + 60,
    }
}

#[derive(Clone)]
struct FixedAuthorizer {
    grant: SigningGrant,
    approval: SigningApproval,
}

impl SigningAuthorizer for FixedAuthorizer {
    fn authorize(
        &self,
        _request: &SigningRequest,
        _now_unix_seconds: u64,
    ) -> Result<(SigningGrant, SigningApproval), SigningError> {
        Ok((self.grant.clone(), self.approval.clone()))
    }
}

struct FakeSigner {
    calls: usize,
    payloads: Vec<Vec<u8>>,
    wrong_key: bool,
}

impl FakeSigner {
    fn new() -> Self {
        Self {
            calls: 0,
            payloads: Vec::new(),
            wrong_key: false,
        }
    }
}

impl NonExportableSigner for FakeSigner {
    fn key_id(&self) -> &str {
        "kms:key/release"
    }

    fn algorithm(&self) -> &str {
        "ecdsa-p256-sha256"
    }

    fn purpose(&self) -> &str {
        "release-artifact"
    }

    fn sign(
        &mut self,
        _request_id: &str,
        domain_separated_payload: &[u8],
    ) -> Result<RawSignature, SigningError> {
        self.calls += 1;
        self.payloads.push(domain_separated_payload.to_vec());
        Ok(RawSignature {
            key_id: if self.wrong_key {
                "kms:key/other".to_owned()
            } else {
                self.key_id().to_owned()
            },
            algorithm: self.algorithm().to_owned(),
            bytes: vec![7; 64],
        })
    }
}

#[derive(Default)]
struct TestAudit {
    events: Mutex<BTreeMap<ContentDigest, SigningAuditEvent>>,
    fail_completed: Mutex<usize>,
}

impl TestAudit {
    fn fail_completed_once() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            fail_completed: Mutex::new(1),
        }
    }
}

impl SigningAuditSink for TestAudit {
    fn record(&self, event: &SigningAuditEvent) -> Result<(), SigningError> {
        if event.kind == SigningAuditKind::Completed {
            let mut remaining = self
                .fail_completed
                .lock()
                .map_err(|_| SigningError::Audit)?;
            if *remaining > 0 {
                *remaining -= 1;
                return Err(SigningError::Audit);
            }
        }
        self.events
            .lock()
            .map_err(|_| SigningError::Audit)?
            .insert(event.event_id.clone(), event.clone());
        Ok(())
    }
}

fn broker(
    request: &SigningRequest,
) -> SigningBroker<FakeSigner, FixedAuthorizer, MemorySigningLedger, TestAudit> {
    SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(request),
            approval: approval(request),
        },
        MemorySigningLedger::default(),
        TestAudit::default(),
        2,
    )
    .unwrap()
}

#[test]
fn signs_only_domain_separated_approved_digests() {
    let request = request();
    let mut broker = broker(&request);
    assert!(format!("{broker:?}").contains("<non-exportable>"));
    assert!(!format!("{broker:?}").contains("kms:key/release"));
    let envelope = broker.sign(&request, NOW).unwrap();
    assert_eq!(envelope.artifact_digest, request.artifact_digest);
    assert_eq!(envelope.provenance_digest, request.provenance_digest);
    assert_eq!(envelope.approver_identities.len(), 2);
    assert_eq!(envelope.signature, vec![7; 64]);

    let (signer, _, _, audit) = broker.into_parts();
    assert_eq!(signer.calls, 1);
    assert!(signer.payloads[0].starts_with(SIGNING_DOMAIN));
    let payload: serde_json::Value =
        serde_json::from_slice(&signer.payloads[0][SIGNING_DOMAIN.len()..]).expect("payload JSON");
    assert_eq!(
        payload["artifact_digest"].as_str(),
        Some(request.artifact_digest.as_str())
    );
    assert_eq!(audit.events.lock().unwrap().len(), 2);
}

#[test]
fn exact_duplicate_is_idempotent_but_changed_content_conflicts() {
    let request = request();
    let mut broker = broker(&request);
    let first = broker.sign(&request, NOW).unwrap();
    let second = broker.sign(&request, NOW + 1).unwrap();
    assert_eq!(first, second);

    let mut changed = request;
    changed.artifact_digest = digest("substitution");
    assert!(matches!(
        broker.sign(&changed, NOW + 1),
        Err(SigningError::IdempotencyConflict)
    ));
    let (signer, _, _, _) = broker.into_parts();
    assert_eq!(signer.calls, 1);
}

#[test]
fn stale_fence_or_artifact_substitution_is_denied_before_signer() {
    let request = request();
    let mut stale_grant = grant(&request);
    stale_grant.fencing_generation += 1;
    let mut invalid_broker = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: stale_grant,
            approval: approval(&request),
        },
        MemorySigningLedger::default(),
        TestAudit::default(),
        2,
    )
    .unwrap();
    assert!(matches!(
        invalid_broker.sign(&request, NOW),
        Err(SigningError::Unauthorized)
    ));
    let (signer, _, _, _) = invalid_broker.into_parts();
    assert_eq!(signer.calls, 0);
}

#[test]
fn approval_requires_exact_subject_dual_control_and_no_self_approval() {
    let request = request();
    let mut invalid = approval(&request);
    invalid.approver_identities = vec![
        "approver:alice".to_owned(),
        request.requester_identity.clone(),
    ];
    invalid.approver_identities.sort();
    let mut invalid_broker = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: invalid,
        },
        MemorySigningLedger::default(),
        TestAudit::default(),
        2,
    )
    .unwrap();
    assert!(matches!(
        invalid_broker.sign(&request, NOW),
        Err(SigningError::InvalidApproval)
    ));

    let mut altered = request.clone();
    altered.provenance_digest = digest("other-provenance");
    let mut broker = broker(&request);
    assert!(matches!(
        broker.sign(&altered, NOW),
        Err(SigningError::Unauthorized | SigningError::InvalidApproval)
    ));
}

#[test]
fn signed_result_survives_audit_outage_without_resigning() {
    let request = request();
    let mut broker = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        MemorySigningLedger::default(),
        TestAudit::fail_completed_once(),
        2,
    )
    .unwrap();
    assert!(matches!(
        broker.sign(&request, NOW),
        Err(SigningError::Audit)
    ));
    let envelope = broker.sign(&request, NOW + 1).unwrap();
    assert_eq!(envelope.request_id, request.request_id);
    let (signer, _, _, audit) = broker.into_parts();
    assert_eq!(signer.calls, 1);
    assert_eq!(audit.events.lock().unwrap().len(), 2);
}

#[test]
fn invalid_signer_identity_is_never_released() {
    let request = request();
    let mut signer = FakeSigner::new();
    signer.wrong_key = true;
    let mut broker = SigningBroker::new(
        signer,
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        MemorySigningLedger::default(),
        TestAudit::default(),
        2,
    )
    .unwrap();
    assert!(matches!(
        broker.sign(&request, NOW),
        Err(SigningError::InvalidSignatureResponse)
    ));
}

#[test]
fn expired_new_request_fails_but_completed_idempotent_result_is_retrievable() {
    let request = request();
    let mut broker = broker(&request);
    let expected = broker.sign(&request, NOW).unwrap();
    assert_eq!(
        broker
            .sign(&request, request.expires_at_unix_seconds + 1)
            .unwrap(),
        expected
    );

    let mut expired = request.clone();
    expired.request_id = "sign-request-expired".to_owned();
    assert!(matches!(
        broker.sign(&expired, expired.expires_at_unix_seconds + 1),
        Err(SigningError::InvalidRequest)
    ));
}

#[test]
fn sqlite_ledger_survives_restart_and_prevents_resigning() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("signing.db");
    let request = request();
    let ledger = SqliteSigningLedger::from_connection(Connection::open(&path).unwrap()).unwrap();
    let mut first = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        ledger,
        TestAudit::default(),
        2,
    )
    .unwrap();
    let expected = first.sign(&request, NOW).unwrap();
    let (signer, _, ledger, _) = first.into_parts();
    assert_eq!(signer.calls, 1);
    drop(ledger.into_connection().unwrap());

    let ledger = SqliteSigningLedger::from_connection(Connection::open(&path).unwrap()).unwrap();
    let mut restarted = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        ledger,
        TestAudit::default(),
        2,
    )
    .unwrap();
    assert_eq!(restarted.sign(&request, NOW + 1).unwrap(), expected);
    let (signer, _, _, _) = restarted.into_parts();
    assert_eq!(signer.calls, 0);
}

#[test]
fn sqlite_signed_pending_audit_recovers_without_resigning() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("signing.db");
    let request = request();
    let ledger = SqliteSigningLedger::from_connection(Connection::open(&path).unwrap()).unwrap();
    let mut first = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        ledger,
        TestAudit::fail_completed_once(),
        2,
    )
    .unwrap();
    assert!(matches!(
        first.sign(&request, NOW),
        Err(SigningError::Audit)
    ));
    let (signer, _, ledger, _) = first.into_parts();
    assert_eq!(signer.calls, 1);
    drop(ledger.into_connection().unwrap());

    let ledger = SqliteSigningLedger::from_connection(Connection::open(&path).unwrap()).unwrap();
    let mut restarted = SigningBroker::new(
        FakeSigner::new(),
        FixedAuthorizer {
            grant: grant(&request),
            approval: approval(&request),
        },
        ledger,
        TestAudit::default(),
        2,
    )
    .unwrap();
    assert!(restarted.sign(&request, NOW + 1).is_ok());
    let (signer, _, _, _) = restarted.into_parts();
    assert_eq!(signer.calls, 0);
}

#[test]
fn sqlite_ledger_rejects_tampered_or_noncanonical_envelopes() {
    let request = request();
    let ledger =
        SqliteSigningLedger::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    let request_digest = request.request_digest().unwrap();
    assert!(ledger
        .reserve(&request.request_id, &request_digest)
        .unwrap()
        .is_none());
    let connection = ledger.into_connection().unwrap();
    connection
        .execute(
            "UPDATE runtrue_signing_operations
                 SET state = 'signed', envelope_json = ?1 WHERE request_id = ?2",
            params![b"{}".as_slice(), request.request_id],
        )
        .unwrap();
    let ledger = SqliteSigningLedger::from_connection(connection).unwrap();
    assert!(matches!(
        ledger.reserve(&request.request_id, &request_digest),
        Err(SigningError::Ledger)
    ));
}

#[test]
fn local_signer_lost_response_replays_exactly_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("local-signer.db");
    let payload = b"runtrue.test-domain\0exact-payload";
    let seed = [7_u8; 32];

    let mut first = LocalEd25519Signer::from_connection(
        Connection::open(&path).unwrap(),
        LocalSigningKey::from_seed(Zeroizing::new(seed)),
        "release-artifact",
    )
    .unwrap();
    let public_key = first.verifying_key_bytes();
    let key_id = first.key_id().to_owned();
    let expected = first.sign("local-request-1", payload).unwrap();
    assert_eq!(first.metrics().signatures_created, 1);
    assert_eq!(expected.key_id, key_id);
    assert!(!format!("{first:?}").contains("0707070707070707"));
    drop(first);

    let mut restarted = LocalEd25519Signer::from_connection(
        Connection::open(&path).unwrap(),
        LocalSigningKey::from_seed(Zeroizing::new(seed)),
        "release-artifact",
    )
    .unwrap();
    let replayed = restarted.sign("local-request-1", payload).unwrap();
    assert_eq!(replayed.bytes, expected.bytes);
    assert_eq!(restarted.metrics().exact_replays, 1);
    assert_eq!(restarted.metrics().signatures_created, 0);
    assert!(matches!(
        restarted.sign("local-request-1", b"substitution"),
        Err(SigningError::IdempotencyConflict)
    ));

    let signature_bytes: [u8; 64] = replayed.bytes.try_into().unwrap();
    VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify_strict(payload, &Signature::from_bytes(&signature_bytes))
        .unwrap();
    drop(restarted);

    let database = std::fs::read(&path).unwrap();
    assert!(!database.windows(seed.len()).any(|window| window == seed));
    let connection = Connection::open(&path).unwrap();
    let columns = connection
        .prepare("PRAGMA table_info(runtrue_local_signer_effects)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!columns.iter().any(|column| {
        column.contains("private") || column.contains("seed") || column.contains("payload_bytes")
    }));
}

#[test]
fn local_signer_recovers_reserved_effect_and_rejects_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("local-signer-recovery.db");
    let seed = [11_u8; 32];
    let payload = b"runtrue.test-domain\0recovery";
    let payload_digest = ContentDigest::sha256(payload);

    let first = LocalEd25519Signer::from_connection(
        Connection::open(&path).unwrap(),
        LocalSigningKey::from_seed(Zeroizing::new(seed)),
        "release-artifact",
    )
    .unwrap();
    first
        .connection
        .execute(
            "INSERT INTO runtrue_local_signer_effects
                 (request_id, payload_digest, key_id, algorithm, state, signature)
                 VALUES (?1, ?2, ?3, ?4, 'reserved', NULL)",
            params![
                "reserved-request",
                payload_digest.to_string(),
                first.key_id(),
                first.algorithm()
            ],
        )
        .unwrap();
    drop(first);

    let mut restarted = LocalEd25519Signer::from_connection(
        Connection::open(&path).unwrap(),
        LocalSigningKey::from_seed(Zeroizing::new(seed)),
        "release-artifact",
    )
    .unwrap();
    let signature = restarted.sign("reserved-request", payload).unwrap();
    assert_eq!(signature.bytes.len(), 64);
    assert_eq!(restarted.metrics().reserved_recoveries, 1);
    drop(restarted);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE runtrue_local_signer_effects SET signature = ?1
                 WHERE request_id = 'reserved-request'",
            [vec![0_u8; 64]],
        )
        .unwrap();
    drop(connection);
    let mut corrupt = LocalEd25519Signer::from_connection(
        Connection::open(&path).unwrap(),
        LocalSigningKey::from_seed(Zeroizing::new(seed)),
        "release-artifact",
    )
    .unwrap();
    assert!(matches!(
        corrupt.sign("reserved-request", payload),
        Err(SigningError::Ledger)
    ));
    assert!(matches!(
        corrupt.sign("oversized", &vec![0; MAX_LOCAL_SIGNER_PAYLOAD_BYTES + 1]),
        Err(SigningError::InvalidRequest)
    ));
}
