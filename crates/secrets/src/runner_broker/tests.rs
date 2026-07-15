use super::*;
use crate::{
    ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretLeaseRequest,
    ExternalSecretProvider, ExternalSecretProviderRegistry, ProviderError, SecretPlaintext,
};
use runtrue_model::ContentDigest;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone)]
struct FixedAuthority {
    grant: Arc<Mutex<AuthorizedExternalSecretRelease>>,
}

impl ExternalSecretReleaseAuthority for FixedAuthority {
    fn authorize(
        &self,
        _request: &RunnerExternalSecretRequest,
        _now_unix_ms: u64,
    ) -> Result<AuthorizedExternalSecretRelease, ExternalSecretBrokerError> {
        Ok(self.grant.lock().unwrap().clone())
    }
}

#[derive(Default, Clone)]
struct TestJournal {
    entries: Arc<Mutex<BTreeMap<String, ExternalSecretReleaseJournalEntry>>>,
    fail_delivery: Arc<AtomicBool>,
}

impl ExternalSecretReleaseJournal for TestJournal {
    fn reserve(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretReserveOutcome, ExternalSecretBrokerError> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(&reservation.release_id) {
            return Ok(ExternalSecretReserveOutcome {
                created: false,
                entry: entry.clone(),
            });
        }
        let entry = ExternalSecretReleaseJournalEntry {
            reservation: reservation.clone(),
            state: ExternalSecretReleaseState::Reserved,
        };
        entries.insert(reservation.release_id.clone(), entry.clone());
        Ok(ExternalSecretReserveOutcome {
            created: true,
            entry,
        })
    }

    fn mark_delivered(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: &ExternalSecretLeaseMetadata,
    ) -> Result<(), ExternalSecretBrokerError> {
        if self.fail_delivery.load(Ordering::Relaxed) {
            return Err(ExternalSecretBrokerError::Journal);
        }
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&reservation.release_id)
            .ok_or(ExternalSecretBrokerError::Journal)?;
        if entry.reservation != *reservation
            || !matches!(entry.state, ExternalSecretReleaseState::Reserved)
        {
            return Err(ExternalSecretBrokerError::Journal);
        }
        entry.state = ExternalSecretReleaseState::Delivered {
            provider_metadata: provider_metadata.clone(),
        };
        Ok(())
    }

    fn mark_indeterminate(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: Option<&ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&reservation.release_id)
            .ok_or(ExternalSecretBrokerError::Journal)?;
        if entry.reservation != *reservation {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        entry.state = ExternalSecretReleaseState::Indeterminate {
            provider_metadata: provider_metadata.cloned(),
            observed_unix_ms,
        };
        Ok(())
    }

    fn load(
        &self,
        release_id: &str,
    ) -> Result<ExternalSecretReleaseJournalEntry, ExternalSecretBrokerError> {
        self.entries
            .lock()
            .unwrap()
            .get(release_id)
            .cloned()
            .ok_or(ExternalSecretBrokerError::Journal)
    }

    fn begin_revoke(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretRevokeOutcome, ExternalSecretBrokerError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&reservation.release_id)
            .ok_or(ExternalSecretBrokerError::Journal)?;
        if entry.reservation != *reservation {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        let started = match &entry.state {
            ExternalSecretReleaseState::Delivered { provider_metadata } => {
                entry.state = ExternalSecretReleaseState::Revoking {
                    provider_metadata: provider_metadata.clone(),
                };
                true
            }
            _ => false,
        };
        Ok(ExternalSecretRevokeOutcome {
            started,
            entry: entry.clone(),
        })
    }

    fn mark_revoked(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        revoked_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&reservation.release_id)
            .ok_or(ExternalSecretBrokerError::Journal)?;
        if entry.reservation != *reservation {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        let ExternalSecretReleaseState::Revoking { provider_metadata } = &entry.state else {
            return Err(ExternalSecretBrokerError::Journal);
        };
        entry.state = ExternalSecretReleaseState::Revoked {
            provider_metadata: provider_metadata.clone(),
            revoked_unix_ms,
        };
        Ok(())
    }
}

struct MockProvider {
    provider_id: String,
    lease_calls: Arc<AtomicUsize>,
    revoke_calls: Arc<AtomicUsize>,
    substitute_tenant: bool,
    substitute_subject: bool,
}

impl ExternalSecretProvider for MockProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn lease(
        &self,
        request: &ExternalSecretLeaseRequest,
        _now_unix_ms: u64,
    ) -> Result<ExternalSecretLease, ProviderError> {
        self.lease_calls.fetch_add(1, Ordering::Relaxed);
        let metadata = ExternalSecretLeaseMetadata {
            release_id: request.release_id.clone(),
            release_subject_digest: if self.substitute_subject {
                ContentDigest::sha256(b"substituted-release-subject")
            } else {
                request.release_subject_digest.clone()
            },
            provider: request.provider_id.clone(),
            tenant_id: if self.substitute_tenant {
                "other-tenant".to_owned()
            } else {
                request.tenant_id.clone()
            },
            repository_id: request.repository_id.clone(),
            run_id: request.run_id.clone(),
            runner_id: request.runner_id.clone(),
            secret_metadata_id: request.secret_metadata_id.clone(),
            execution_lease_id: request.execution_lease_id.clone(),
            fencing_generation: request.fencing_generation,
            installation_fencing_epoch: request.installation_fencing_epoch,
            job_id: request.job_id.clone(),
            job_attempt: request.job_attempt,
            step_id: request.step_id.clone(),
            purpose: request.purpose.clone(),
            provider_lease_id: Some("provider-lease-1".to_owned()),
            provider_version: Some(7),
            renewable: false,
            expires_unix_ms: request.expires_unix_ms,
        };
        ExternalSecretLease::from_parts(
            metadata,
            SecretPlaintext::new(b"broker-secret-value".to_vec()),
        )
    }

    fn revoke(
        &self,
        _metadata: &ExternalSecretLeaseMetadata,
        _now_unix_ms: u64,
    ) -> Result<(), ProviderError> {
        self.revoke_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn request() -> RunnerExternalSecretRequest {
    RunnerExternalSecretRequest {
        runner_id: "runner-1".to_owned(),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 5,
        installation_fencing_epoch: 3,
        job_id: "job-1".to_owned(),
        job_attempt: 2,
        step_id: "step-1".to_owned(),
        secret_metadata_id: "secret-1".to_owned(),
        purpose: "publish".to_owned(),
        expires_unix_ms: 2_000,
    }
}

fn grant() -> AuthorizedExternalSecretRelease {
    AuthorizedExternalSecretRelease {
        release_id: "external-release-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repository-1".to_owned(),
        run_id: "run-1".to_owned(),
        runner_id: "runner-1".to_owned(),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 5,
        installation_fencing_epoch: 3,
        job_id: "job-1".to_owned(),
        job_attempt: 2,
        step_id: "step-1".to_owned(),
        secret_metadata_id: "secret-1".to_owned(),
        purpose: "publish".to_owned(),
        provider_id: "team-vault".to_owned(),
        provider_reference: "kv-v2://release/credentials#token?version=7".to_owned(),
        expires_unix_ms: 2_000,
    }
}

fn fixture(
    journal: TestJournal,
    substitute_tenant: bool,
    substitute_subject: bool,
) -> (
    ExternalSecretRunnerBroker<FixedAuthority, TestJournal>,
    FixedAuthority,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let authority = FixedAuthority {
        grant: Arc::new(Mutex::new(grant())),
    };
    let lease_calls = Arc::new(AtomicUsize::new(0));
    let revoke_calls = Arc::new(AtomicUsize::new(0));
    let provider = MockProvider {
        provider_id: "team-vault".to_owned(),
        lease_calls: Arc::clone(&lease_calls),
        revoke_calls: Arc::clone(&revoke_calls),
        substitute_tenant,
        substitute_subject,
    };
    let mut registry = ExternalSecretProviderRegistry::new();
    registry.register("team-vault", provider).unwrap();
    (
        ExternalSecretRunnerBroker::new(registry, authority.clone(), journal),
        authority,
        lease_calls,
        revoke_calls,
    )
}

#[test]
fn delivery_is_committed_before_plaintext_and_exact_replay_never_releases_again() {
    let journal = TestJournal::default();
    let (broker, _, lease_calls, _) = fixture(journal.clone(), false, false);
    let lease = broker.issue(&request(), 1_000).unwrap();
    assert_eq!(lease.plaintext().as_bytes(), b"broker-secret-value");
    assert!(matches!(
        journal.load("external-release-1").unwrap().state,
        ExternalSecretReleaseState::Delivered { .. }
    ));
    assert!(matches!(
        broker.issue(&request(), 1_001),
        Err(ExternalSecretBrokerError::AlreadyDelivered)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
    assert_eq!(broker.metrics().exact_replays_denied, 1);
}

#[test]
fn restart_with_reserved_subject_is_indeterminate_and_changed_replay_conflicts() {
    let journal = TestJournal::default();
    let provider_request = grant().provider_request(&request(), 1_000).unwrap();
    let reservation = ExternalSecretReleaseReservation::from_provider_request(&provider_request);
    journal.reserve(&reservation).unwrap();
    let (broker, authority, lease_calls, _) = fixture(journal, false, false);
    assert!(matches!(
        broker.issue(&request(), 1_001),
        Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);

    authority.grant.lock().unwrap().purpose = "deploy".to_owned();
    let mut changed_request = request();
    changed_request.purpose = "deploy".to_owned();
    assert!(matches!(
        broker.issue(&changed_request, 1_001),
        Err(ExternalSecretBrokerError::SubjectConflict)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn stale_attempt_fence_and_provider_metadata_substitution_fail_closed() {
    let (broker, _, lease_calls, revoke_calls) = fixture(TestJournal::default(), true, false);
    assert!(matches!(
        broker.issue(&request(), 1_000),
        Err(ExternalSecretBrokerError::Provider(
            ProviderError::ReleaseSubjectMismatch
        ))
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
    assert_eq!(revoke_calls.load(Ordering::Relaxed), 1);

    let (broker, _, lease_calls, _) = fixture(TestJournal::default(), false, false);
    let mut stale = request();
    stale.fencing_generation += 1;
    assert!(matches!(
        broker.issue(&stale, 1_000),
        Err(ExternalSecretBrokerError::AuthorizationBindingMismatch)
    ));
    stale = request();
    stale.job_attempt += 1;
    assert!(matches!(
        broker.issue(&stale, 1_000),
        Err(ExternalSecretBrokerError::AuthorizationBindingMismatch)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn provider_cannot_substitute_the_reserved_subject_after_provider_io() {
    let journal = TestJournal::default();
    let (broker, _, lease_calls, revoke_calls) = fixture(journal.clone(), false, true);
    assert!(matches!(
        broker.issue(&request(), 1_000),
        Err(ExternalSecretBrokerError::Provider(
            ProviderError::ReleaseSubjectMismatch
        ))
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
    assert_eq!(revoke_calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        journal.load("external-release-1").unwrap().state,
        ExternalSecretReleaseState::Indeterminate { .. }
    ));
}

#[test]
fn journal_commit_failure_revokes_and_never_returns_plaintext() {
    let journal = TestJournal::default();
    journal.fail_delivery.store(true, Ordering::Relaxed);
    let (broker, _, lease_calls, revoke_calls) = fixture(journal.clone(), false, false);
    assert!(matches!(
        broker.issue(&request(), 1_000),
        Err(ExternalSecretBrokerError::Journal)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
    assert_eq!(revoke_calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        journal.load("external-release-1").unwrap().state,
        ExternalSecretReleaseState::Indeterminate { .. }
    ));
    assert!(matches!(
        broker.issue(&request(), 1_001),
        Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired)
    ));
    assert_eq!(lease_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn revoke_uses_exact_binding_and_replays_without_second_provider_call() {
    let journal = TestJournal::default();
    let (broker, _, _, revoke_calls) = fixture(journal, false, false);
    broker.issue(&request(), 1_000).unwrap();
    let revoke = ExternalSecretRevocationRequest {
        release_id: "external-release-1".to_owned(),
        runner_id: "runner-1".to_owned(),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 5,
        installation_fencing_epoch: 3,
        job_id: "job-1".to_owned(),
        job_attempt: 2,
        step_id: "step-1".to_owned(),
    };
    let mut stale = revoke.clone();
    stale.fencing_generation += 1;
    assert!(matches!(
        broker.revoke(&stale, 1_100),
        Err(ExternalSecretBrokerError::AuthorizationBindingMismatch)
    ));
    assert_eq!(revoke_calls.load(Ordering::Relaxed), 0);

    broker.revoke(&revoke, 1_100).unwrap();
    broker.revoke(&revoke, 1_101).unwrap();
    assert_eq!(revoke_calls.load(Ordering::Relaxed), 1);
    assert_eq!(broker.metrics().revoke_successes, 2);
}
