use crate::{
    matching, resources, validation, Lease, LeaseState, QueuedJob, RunnerRecord, RunnerStatus,
    SchedulerError, TenantQuota,
};
use runtrue_model::ContentDigest;
use std::collections::BTreeMap;

pub const DEFAULT_ACCEPT_WINDOW_MS: u64 = 15_000;
pub const DEFAULT_LEASE_DURATION_MS: u64 = 60_000;
pub const PRIORITY_AGING_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone)]
pub struct Scheduler {
    installation_fencing_epoch: u64,
    runners: BTreeMap<String, RunnerRecord>,
    queue: BTreeMap<String, QueuedJob>,
    leases: BTreeMap<String, Lease>,
    leased_jobs: BTreeMap<String, QueuedJob>,
    active_lease_by_job: BTreeMap<String, String>,
    generation_by_job: BTreeMap<String, u64>,
    quotas: BTreeMap<String, TenantQuota>,
    running_by_tenant: BTreeMap<String, u32>,
    next_lease_id: u64,
}

impl Scheduler {
    #[must_use]
    pub fn new(installation_fencing_epoch: u64) -> Self {
        Self {
            installation_fencing_epoch,
            runners: BTreeMap::new(),
            queue: BTreeMap::new(),
            leases: BTreeMap::new(),
            leased_jobs: BTreeMap::new(),
            active_lease_by_job: BTreeMap::new(),
            generation_by_job: BTreeMap::new(),
            quotas: BTreeMap::new(),
            running_by_tenant: BTreeMap::new(),
            next_lease_id: 1,
        }
    }

    #[must_use]
    pub const fn installation_fencing_epoch(&self) -> u64 {
        self.installation_fencing_epoch
    }

    pub fn set_quota(
        &mut self,
        tenant_id: impl Into<String>,
        quota: TenantQuota,
    ) -> Result<(), SchedulerError> {
        validation::quota(quota)?;
        self.quotas.insert(tenant_id.into(), quota);
        Ok(())
    }

    pub fn register_runner(&mut self, runner: RunnerRecord) -> Result<(), SchedulerError> {
        validation::runner(&runner)?;
        if self.runners.contains_key(&runner.id) {
            return Err(SchedulerError::DuplicateRunner(runner.id));
        }
        self.runners.insert(runner.id.clone(), runner);
        Ok(())
    }

    pub fn update_runner_status(
        &mut self,
        runner_id: &str,
        status: RunnerStatus,
    ) -> Result<(), SchedulerError> {
        let runner = self
            .runners
            .get_mut(runner_id)
            .ok_or_else(|| SchedulerError::UnknownRunner(runner_id.to_owned()))?;
        if runner.status == RunnerStatus::Revoked && status != RunnerStatus::Revoked {
            return Err(SchedulerError::RunnerRevoked(runner_id.to_owned()));
        }
        runner.status = status;
        Ok(())
    }

    pub fn enqueue(&mut self, job: QueuedJob) -> Result<(), SchedulerError> {
        validation::job(&job)?;
        if self.queue.contains_key(&job.id) || self.active_lease_by_job.contains_key(&job.id) {
            return Err(SchedulerError::DuplicateJob(job.id));
        }
        self.queue.insert(job.id.clone(), job);
        Ok(())
    }

    /// Offer at most one job to a polling runner.
    pub fn offer_for_runner(
        &mut self,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<Option<Lease>, SchedulerError> {
        self.expire(now_unix_ms)?;
        let runner = self
            .runners
            .get(runner_id)
            .ok_or_else(|| SchedulerError::UnknownRunner(runner_id.to_owned()))?;
        if runner.status != RunnerStatus::Online {
            return Ok(None);
        }

        let chosen = self
            .queue
            .values()
            .filter(|job| self.hard_filters(job, runner))
            .min_by_key(|job| self.score_key(job, runner, now_unix_ms))
            .map(|job| job.id.clone());
        let Some(job_id) = chosen else {
            return Ok(None);
        };
        let job = self
            .queue
            .remove(&job_id)
            .ok_or_else(|| SchedulerError::UnknownJob(job_id.clone()))?;
        let generation = self.generation_by_job.entry(job.id.clone()).or_default();
        *generation = generation
            .checked_add(1)
            .ok_or(SchedulerError::GenerationOverflow)?;
        let lease_id = format!("lease-{}", self.next_lease_id);
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .ok_or(SchedulerError::LeaseIdOverflow)?;
        let lease = Lease {
            id: lease_id.clone(),
            job_id: job.id.clone(),
            tenant_id: job.tenant_id.clone(),
            runner_id: runner_id.to_owned(),
            fencing_generation: *generation,
            installation_fencing_epoch: self.installation_fencing_epoch,
            capsule_digest: job.capsule_digest.clone(),
            issued_unix_ms: now_unix_ms,
            accept_by_unix_ms: now_unix_ms.saturating_add(DEFAULT_ACCEPT_WINDOW_MS),
            expires_unix_ms: now_unix_ms.saturating_add(DEFAULT_LEASE_DURATION_MS),
            state: LeaseState::Offered,
            terminal_result_digest: None,
        };
        self.active_lease_by_job
            .insert(job.id.clone(), lease_id.clone());
        self.leased_jobs.insert(lease_id.clone(), job);
        self.leases.insert(lease_id, lease.clone());
        Ok(Some(lease))
    }

    pub fn decide_offer(
        &mut self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        accepted: bool,
        now_unix_ms: u64,
    ) -> Result<LeaseState, SchedulerError> {
        self.validate_fence(
            lease_id,
            runner_id,
            generation,
            self.installation_fencing_epoch,
        )?;
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| SchedulerError::UnknownLease(lease_id.to_owned()))?;
        if lease.state != LeaseState::Offered {
            return Err(SchedulerError::InvalidLeaseState {
                expected: LeaseState::Offered,
                actual: lease.state,
            });
        }
        if now_unix_ms > lease.accept_by_unix_ms {
            lease.state = LeaseState::Expired;
            self.active_lease_by_job.remove(&lease.job_id);
            if let Some(job) = self.leased_jobs.remove(lease_id) {
                self.queue.insert(job.id.clone(), job);
            }
            return Err(SchedulerError::OfferExpired);
        }
        if accepted {
            lease.state = LeaseState::Active;
            *self
                .running_by_tenant
                .entry(lease.tenant_id.clone())
                .or_default() += 1;
            let runner = self
                .runners
                .get_mut(runner_id)
                .ok_or_else(|| SchedulerError::UnknownRunner(runner_id.to_owned()))?;
            let requirements = &self
                .leased_jobs
                .get(lease_id)
                .ok_or_else(|| SchedulerError::UnknownLease(lease_id.to_owned()))?
                .requirements;
            resources::reserve(runner, requirements);
        } else {
            lease.state = LeaseState::Rejected;
            self.active_lease_by_job.remove(&lease.job_id);
            if let Some(job) = self.leased_jobs.remove(lease_id) {
                self.queue.insert(job.id.clone(), job);
            }
        }
        Ok(lease.state)
    }

    pub fn heartbeat(
        &mut self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        now_unix_ms: u64,
    ) -> Result<u64, SchedulerError> {
        self.validate_fence(lease_id, runner_id, generation, epoch)?;
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| SchedulerError::UnknownLease(lease_id.to_owned()))?;
        if !matches!(
            lease.state,
            LeaseState::Active | LeaseState::CancelRequested
        ) {
            return Err(SchedulerError::LeaseNotActive(lease.state));
        }
        lease.expires_unix_ms = now_unix_ms.saturating_add(DEFAULT_LEASE_DURATION_MS);
        if let Some(runner) = self.runners.get_mut(runner_id) {
            runner.last_heartbeat_unix_ms = now_unix_ms;
        }
        Ok(lease.expires_unix_ms)
    }

    pub fn request_cancel(&mut self, job_id: &str) -> Result<(), SchedulerError> {
        let lease_id = self
            .active_lease_by_job
            .get(job_id)
            .ok_or_else(|| SchedulerError::UnknownJob(job_id.to_owned()))?
            .clone();
        let lease = self
            .leases
            .get_mut(&lease_id)
            .ok_or_else(|| SchedulerError::UnknownLease(lease_id.clone()))?;
        if matches!(lease.state, LeaseState::Offered | LeaseState::Active) {
            lease.state = LeaseState::CancelRequested;
            Ok(())
        } else {
            Err(SchedulerError::LeaseNotActive(lease.state))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete(
        &mut self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        result_digest: ContentDigest,
    ) -> Result<(), SchedulerError> {
        self.validate_fence(lease_id, runner_id, generation, epoch)?;
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or_else(|| SchedulerError::UnknownLease(lease_id.to_owned()))?;
        if lease.state == LeaseState::Completed {
            if lease.terminal_result_digest.as_ref() == Some(&result_digest) {
                return Ok(());
            }
            return Err(SchedulerError::ConflictingCompletion);
        }
        if !matches!(
            lease.state,
            LeaseState::Active | LeaseState::CancelRequested
        ) {
            return Err(SchedulerError::LeaseNotActive(lease.state));
        }
        lease.state = LeaseState::Completed;
        lease.terminal_result_digest = Some(result_digest);
        self.active_lease_by_job.remove(&lease.job_id);
        decrement(&mut self.running_by_tenant, &lease.tenant_id);
        let job = self.leased_jobs.remove(lease_id);
        if let Some(runner) = self.runners.get_mut(runner_id) {
            resources::release(runner, job.as_ref().map(|job| &job.requirements));
        }
        Ok(())
    }

    pub fn validate_fence(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
    ) -> Result<(), SchedulerError> {
        if epoch != self.installation_fencing_epoch {
            return Err(SchedulerError::StaleInstallationEpoch {
                expected: self.installation_fencing_epoch,
                actual: epoch,
            });
        }
        let lease = self
            .leases
            .get(lease_id)
            .ok_or_else(|| SchedulerError::UnknownLease(lease_id.to_owned()))?;
        if lease.runner_id != runner_id {
            return Err(SchedulerError::WrongRunner);
        }
        if lease.fencing_generation != generation {
            return Err(SchedulerError::StaleGeneration {
                expected: lease.fencing_generation,
                actual: generation,
            });
        }
        Ok(())
    }

    pub fn restore_fencing_epoch(&mut self, new_epoch: u64) -> Result<(), SchedulerError> {
        if new_epoch <= self.installation_fencing_epoch {
            return Err(SchedulerError::EpochMustIncrease);
        }
        self.installation_fencing_epoch = new_epoch;
        let affected = self
            .leases
            .iter()
            .filter_map(|(id, lease)| {
                matches!(
                    lease.state,
                    LeaseState::Offered | LeaseState::Active | LeaseState::CancelRequested
                )
                .then_some(id.clone())
            })
            .collect::<Vec<_>>();
        for lease in self.leases.values_mut() {
            if matches!(
                lease.state,
                LeaseState::Offered | LeaseState::Active | LeaseState::CancelRequested
            ) {
                lease.state = LeaseState::Expired;
            }
        }
        self.active_lease_by_job.clear();
        self.running_by_tenant.clear();
        for runner in self.runners.values_mut() {
            resources::reset(runner);
        }
        for lease_id in affected {
            if let Some(job) = self.leased_jobs.remove(&lease_id) {
                if job.retryable_after_runner_loss {
                    self.queue.insert(job.id.clone(), job);
                }
            }
        }
        Ok(())
    }

    pub fn expire(&mut self, now_unix_ms: u64) -> Result<Vec<String>, SchedulerError> {
        let expired = self
            .leases
            .iter()
            .filter_map(|(id, lease)| {
                let deadline = if lease.state == LeaseState::Offered {
                    lease.accept_by_unix_ms
                } else {
                    lease.expires_unix_ms
                };
                (matches!(
                    lease.state,
                    LeaseState::Offered | LeaseState::Active | LeaseState::CancelRequested
                ) && now_unix_ms > deadline)
                    .then_some(id.clone())
            })
            .collect::<Vec<_>>();
        for lease_id in &expired {
            let lease = self
                .leases
                .get_mut(lease_id)
                .ok_or_else(|| SchedulerError::UnknownLease(lease_id.clone()))?;
            let was_running = matches!(
                lease.state,
                LeaseState::Active | LeaseState::CancelRequested
            );
            let was_cancel_requested = lease.state == LeaseState::CancelRequested;
            lease.state = LeaseState::Expired;
            self.active_lease_by_job.remove(&lease.job_id);
            if was_running {
                decrement(&mut self.running_by_tenant, &lease.tenant_id);
                if let Some(runner) = self.runners.get_mut(&lease.runner_id) {
                    resources::release(
                        runner,
                        self.leased_jobs.get(lease_id).map(|job| &job.requirements),
                    );
                }
            }
            if let Some(job) = self.leased_jobs.remove(lease_id) {
                if job.retryable_after_runner_loss && !was_cancel_requested {
                    self.queue.insert(job.id.clone(), job);
                }
            }
        }
        Ok(expired)
    }

    #[must_use]
    pub fn lease(&self, id: &str) -> Option<&Lease> {
        self.leases.get(id)
    }

    fn hard_filters(&self, job: &QueuedJob, runner: &RunnerRecord) -> bool {
        let quota = self.quotas.get(&job.tenant_id).copied().unwrap_or_default();
        let running = self
            .running_by_tenant
            .get(&job.tenant_id)
            .copied()
            .unwrap_or(0);
        matching::passes_hard_filters(job, runner, quota, running)
    }

    fn score_key(
        &self,
        job: &QueuedJob,
        runner: &RunnerRecord,
        now_unix_ms: u64,
    ) -> matching::ScoreKey {
        let quota = self.quotas.get(&job.tenant_id).copied().unwrap_or_default();
        let running = self
            .running_by_tenant
            .get(&job.tenant_id)
            .copied()
            .unwrap_or(0);
        matching::score(
            job,
            runner,
            quota,
            running,
            now_unix_ms,
            PRIORITY_AGING_INTERVAL_MS,
        )
    }
}

fn decrement(counts: &mut BTreeMap<String, u32>, key: &str) {
    if let Some(value) = counts.get_mut(key) {
        *value = value.saturating_sub(1);
        if *value == 0 {
            counts.remove(key);
        }
    }
}
