//! One-shot release delivery, provider revocation, and broker metrics.
use super::{
    audit::{
        ExternalSecretReleaseJournal, ExternalSecretReleaseJournalEntry,
        ExternalSecretReleaseReservation, ExternalSecretReleaseState,
    },
    authorization::ExternalSecretReleaseAuthority,
    model::{
        ExternalSecretBrokerError, ExternalSecretRevocationRequest, RunnerExternalSecretRequest,
    },
};
use crate::{ExternalSecretLease, ExternalSecretLeaseMetadata, ExternalSecretProviderRegistry};
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExternalSecretBrokerMetrics {
    pub issue_attempts: u64,
    pub issue_successes: u64,
    pub exact_replays_denied: u64,
    pub rejected_bindings: u64,
    pub provider_failures: u64,
    pub journal_failures: u64,
    pub revoke_attempts: u64,
    pub revoke_successes: u64,
    pub indeterminate_recoveries: u64,
}

#[derive(Default)]
struct ExternalSecretBrokerCounters {
    issue_attempts: AtomicU64,
    issue_successes: AtomicU64,
    exact_replays_denied: AtomicU64,
    rejected_bindings: AtomicU64,
    provider_failures: AtomicU64,
    journal_failures: AtomicU64,
    revoke_attempts: AtomicU64,
    revoke_successes: AtomicU64,
    indeterminate_recoveries: AtomicU64,
}

/// External provider broker. It never contains a default provider and never
/// accepts provider configuration from a runner request.
pub struct ExternalSecretRunnerBroker<A, J> {
    registry: ExternalSecretProviderRegistry,
    authority: A,
    journal: J,
    counters: ExternalSecretBrokerCounters,
}

impl<A, J> fmt::Debug for ExternalSecretRunnerBroker<A, J>
where
    A: ExternalSecretReleaseAuthority,
    J: ExternalSecretReleaseJournal,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalSecretRunnerBroker")
            .field("registry", &self.registry)
            .field("authority", &"<authorization boundary>")
            .field("journal", &"<durable journal>")
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl<A, J> ExternalSecretRunnerBroker<A, J>
where
    A: ExternalSecretReleaseAuthority,
    J: ExternalSecretReleaseJournal,
{
    #[must_use]
    pub fn new(registry: ExternalSecretProviderRegistry, authority: A, journal: J) -> Self {
        Self {
            registry,
            authority,
            journal,
            counters: ExternalSecretBrokerCounters::default(),
        }
    }

    /// Issue one external value. The journal reservation precedes provider I/O
    /// and delivered provider metadata is durable before plaintext is returned.
    pub fn issue(
        &self,
        request: &RunnerExternalSecretRequest,
        now_unix_ms: u64,
    ) -> Result<ExternalSecretLease, ExternalSecretBrokerError> {
        increment(&self.counters.issue_attempts);
        request.validate(now_unix_ms)?;
        let grant = self
            .authority
            .authorize(request, now_unix_ms)
            .inspect_err(|_| increment(&self.counters.rejected_bindings))?;
        let provider_request = grant
            .provider_request(request, now_unix_ms)
            .inspect_err(|_| increment(&self.counters.rejected_bindings))?;
        let reservation =
            ExternalSecretReleaseReservation::from_provider_request(&provider_request);
        let outcome = self
            .journal
            .reserve(&reservation)
            .inspect_err(|_| increment(&self.counters.journal_failures))?;
        validate_journal_subject(&outcome.entry, &reservation)?;
        if !outcome.created {
            return self.reject_existing_issue(&outcome.entry.state);
        }
        if !matches!(outcome.entry.state, ExternalSecretReleaseState::Reserved) {
            increment(&self.counters.journal_failures);
            return Err(ExternalSecretBrokerError::Journal);
        }

        let lease =
            match self
                .registry
                .lease(&reservation.provider_id, &provider_request, now_unix_ms)
            {
                Ok(lease) => lease,
                Err(error) => {
                    increment(&self.counters.provider_failures);
                    self.best_effort_indeterminate(&reservation, None, now_unix_ms);
                    return Err(ExternalSecretBrokerError::Provider(error));
                }
            };
        let (provider_metadata, plaintext) = lease.into_parts();
        if let Err(error) = provider_metadata.validate_against(&provider_request) {
            increment(&self.counters.rejected_bindings);
            let _ = self.registry.revoke(&provider_metadata, now_unix_ms);
            self.best_effort_indeterminate(&reservation, Some(&provider_metadata), now_unix_ms);
            return Err(ExternalSecretBrokerError::Provider(error));
        }
        if self
            .journal
            .mark_delivered(&reservation, &provider_metadata)
            .is_err()
        {
            increment(&self.counters.journal_failures);
            let revoke_failed = self
                .registry
                .revoke(&provider_metadata, now_unix_ms)
                .is_err();
            if revoke_failed {
                increment(&self.counters.provider_failures);
            }
            self.best_effort_indeterminate(&reservation, Some(&provider_metadata), now_unix_ms);
            return Err(if revoke_failed {
                ExternalSecretBrokerError::IndeterminateRecoveryRequired
            } else {
                ExternalSecretBrokerError::Journal
            });
        }

        let lease = ExternalSecretLease::from_parts(provider_metadata, plaintext)
            .map_err(ExternalSecretBrokerError::Provider)?;
        increment(&self.counters.issue_successes);
        Ok(lease)
    }

    fn reject_existing_issue(
        &self,
        state: &ExternalSecretReleaseState,
    ) -> Result<ExternalSecretLease, ExternalSecretBrokerError> {
        match state {
            ExternalSecretReleaseState::Delivered { .. }
            | ExternalSecretReleaseState::Revoking { .. }
            | ExternalSecretReleaseState::Revoked { .. } => {
                increment(&self.counters.exact_replays_denied);
                Err(ExternalSecretBrokerError::AlreadyDelivered)
            }
            ExternalSecretReleaseState::Reserved
            | ExternalSecretReleaseState::Indeterminate { .. } => {
                increment(&self.counters.indeterminate_recoveries);
                Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired)
            }
        }
    }

    fn best_effort_indeterminate(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: Option<&ExternalSecretLeaseMetadata>,
        now_unix_ms: u64,
    ) {
        increment(&self.counters.indeterminate_recoveries);
        if self
            .journal
            .mark_indeterminate(reservation, provider_metadata, now_unix_ms)
            .is_err()
        {
            increment(&self.counters.journal_failures);
        }
    }

    /// Revoke the exact delivered provider lease. A crash after the durable
    /// revoking transition is intentionally indeterminate: this adapter will
    /// not guess that repeating an arbitrary provider side effect is safe.
    pub fn revoke(
        &self,
        request: &ExternalSecretRevocationRequest,
        now_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError> {
        increment(&self.counters.revoke_attempts);
        request.validate()?;
        let entry = self
            .journal
            .load(&request.release_id)
            .inspect_err(|_| increment(&self.counters.journal_failures))?;
        if !entry.reservation.matches_revocation(request) {
            increment(&self.counters.rejected_bindings);
            return Err(ExternalSecretBrokerError::AuthorizationBindingMismatch);
        }
        match &entry.state {
            ExternalSecretReleaseState::Revoked { .. } => {
                increment(&self.counters.revoke_successes);
                return Ok(());
            }
            ExternalSecretReleaseState::Delivered { .. } => {}
            ExternalSecretReleaseState::Reserved
            | ExternalSecretReleaseState::Revoking { .. }
            | ExternalSecretReleaseState::Indeterminate { .. } => {
                increment(&self.counters.indeterminate_recoveries);
                return Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired);
            }
        }
        let outcome = self
            .journal
            .begin_revoke(&entry.reservation)
            .inspect_err(|_| increment(&self.counters.journal_failures))?;
        validate_journal_subject(&outcome.entry, &entry.reservation)?;
        if !outcome.started {
            increment(&self.counters.indeterminate_recoveries);
            return Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired);
        }
        let ExternalSecretReleaseState::Revoking { provider_metadata } = &outcome.entry.state
        else {
            increment(&self.counters.journal_failures);
            return Err(ExternalSecretBrokerError::Journal);
        };
        self.registry
            .revoke(provider_metadata, now_unix_ms)
            .inspect_err(|_| increment(&self.counters.provider_failures))
            .map_err(ExternalSecretBrokerError::Provider)?;
        self.journal
            .mark_revoked(&entry.reservation, now_unix_ms)
            .inspect_err(|_| increment(&self.counters.journal_failures))?;
        increment(&self.counters.revoke_successes);
        Ok(())
    }

    #[must_use]
    pub fn metrics(&self) -> ExternalSecretBrokerMetrics {
        ExternalSecretBrokerMetrics {
            issue_attempts: self.counters.issue_attempts.load(Ordering::Relaxed),
            issue_successes: self.counters.issue_successes.load(Ordering::Relaxed),
            exact_replays_denied: self.counters.exact_replays_denied.load(Ordering::Relaxed),
            rejected_bindings: self.counters.rejected_bindings.load(Ordering::Relaxed),
            provider_failures: self.counters.provider_failures.load(Ordering::Relaxed),
            journal_failures: self.counters.journal_failures.load(Ordering::Relaxed),
            revoke_attempts: self.counters.revoke_attempts.load(Ordering::Relaxed),
            revoke_successes: self.counters.revoke_successes.load(Ordering::Relaxed),
            indeterminate_recoveries: self
                .counters
                .indeterminate_recoveries
                .load(Ordering::Relaxed),
        }
    }
}

fn validate_journal_subject(
    entry: &ExternalSecretReleaseJournalEntry,
    expected: &ExternalSecretReleaseReservation,
) -> Result<(), ExternalSecretBrokerError> {
    if entry.reservation.release_id != expected.release_id
        || entry.reservation.release_subject_digest != expected.release_subject_digest
        || entry.reservation != *expected
    {
        return Err(ExternalSecretBrokerError::SubjectConflict);
    }
    Ok(())
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
