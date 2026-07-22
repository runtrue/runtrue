use super::*;

pub(in crate::store) const IMAGE_ADMISSION_RETRY_DELAY_MILLIS: u64 = 1_000;
pub(in crate::store) const MAX_RUNNER_JOB_REJECTIONS: u64 = 3;

fn runner_structurally_matches(
    runner: &RunnerRecord,
    pool_status: &str,
    pool_region: Option<&str>,
    requirements: &SchedulingRequirements,
) -> Result<bool, ControlPlaneError> {
    if parse_runner_pool_status(pool_status)? != RunnerPoolStatus::Active
        || runner.status != RunnerStatus::Online
        || pool_region.is_some_and(|region| runner.region.as_deref() != Some(region))
    {
        return Ok(false);
    }
    Ok(requirements.os == runner.os
        && requirements.arch == runner.arch
        && runner.isolation_backends.contains(&requirements.isolation)
        && (requirements.allowed_pools.is_empty()
            || requirements.allowed_pools.contains(&runner.pool_id))
        && requirements.region.as_ref().is_none_or(|region| {
            runner.region.as_ref() == Some(region) && pool_region.is_none_or(|pool| pool == region)
        })
        && requirements
            .required_capabilities
            .is_subset(&runner.verified_capabilities)
        && u64::from(requirements.cpu) <= u64::from(runner.logical_cpus)
        && requirements.memory_bytes <= runner.memory_bytes
        && requirements.storage_bytes <= runner.storage_bytes)
}

fn all_eligible_runners_exhausted_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    job_id: &str,
    requirements: &SchedulingRequirements,
) -> Result<bool, ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT r.id, r.runner_json, p.status, p.region
         FROM runners r JOIN runner_pools p ON p.id = r.pool_id
         WHERE p.tenant_id = ?1
         ORDER BY r.id",
    )?;
    let candidates = statement
        .query_map([tenant_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut eligible = Vec::new();
    for (runner_id, runner_json, pool_status, pool_region) in candidates {
        let runner: RunnerRecord = serde_json::from_str(&runner_json)?;
        if runner_structurally_matches(&runner, &pool_status, pool_region.as_deref(), requirements)?
        {
            eligible.push(runner_id);
        }
    }
    if eligible.is_empty() {
        return Ok(false);
    }
    for runner_id in eligible {
        let exhausted: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM runner_job_rejections
                 WHERE runner_id = ?1 AND job_id = ?2
                   AND rejection_count >= ?3
                   AND last_code != 'image_admission_pending'
             )",
            params![runner_id, job_id, to_i64(MAX_RUNNER_JOB_REJECTIONS)?],
            |row| row.get(0),
        )?;
        if !exhausted {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(in crate::store) fn runner_reserved_requirements_tx(
    transaction: &Transaction<'_>,
    runner_id: &str,
) -> Result<Vec<SchedulingRequirements>, ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT j.requirements_json FROM leases l
         JOIN jobs j ON j.id = l.job_id
         WHERE l.runner_id = ?1 AND l.state IN ('offered', 'active', 'cancel_requested')
         ORDER BY l.id",
    )?;
    let values = statement
        .query_map([runner_id], |row| {
            json_column::<SchedulingRequirements>(row, 0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(values)
}

pub(in crate::store) fn runner_reserved_resources_tx(
    transaction: &Transaction<'_>,
    runner_id: &str,
) -> Result<(u64, u64, u64), ControlPlaneError> {
    let requirements = runner_reserved_requirements_tx(transaction, runner_id)?;
    let mut cpu = 0_u64;
    let mut memory = 0_u64;
    let mut storage = 0_u64;
    for requirement in requirements {
        cpu =
            cpu.checked_add(u64::from(requirement.cpu))
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "runner reserved CPU",
                })?;
        memory = memory.checked_add(requirement.memory_bytes).ok_or(
            ControlPlaneError::IntegerRange {
                field: "runner reserved memory",
            },
        )?;
        storage = storage.checked_add(requirement.storage_bytes).ok_or(
            ControlPlaneError::IntegerRange {
                field: "runner reserved storage",
            },
        )?;
    }
    Ok((cpu, memory, storage))
}

pub(in crate::store) fn scheduler_candidate_page_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    after_job_id: &str,
) -> Result<Vec<String>, ControlPlaneError> {
    let mut statement = transaction.prepare(
        "SELECT j.id FROM jobs j
         JOIN runs r ON r.id = j.run_id
         JOIN repositories repo ON repo.id = r.repository_id
         WHERE j.status = 'queued' AND r.remote = 1
           AND r.status IN ('created', 'running') AND repo.tenant_id = ?1
           AND j.id > ?2
         ORDER BY j.id LIMIT ?3",
    )?;
    let values = statement
        .query_map(
            params![
                tenant_id,
                after_job_id,
                to_i64(MAX_SCHEDULER_CANDIDATES as u64)?,
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(values)
}

pub(in crate::store) fn concurrency_group_available_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    repository_id: &str,
    group: &str,
    candidate_job_id: &str,
) -> Result<bool, ControlPlaneError> {
    let first: Option<String> = transaction
        .query_row(
            "SELECT j.id FROM jobs j
             JOIN runs r ON r.id = j.run_id
             JOIN repositories repo ON repo.id = r.repository_id
             WHERE repo.tenant_id = ?1 AND r.repository_id = ?2
               AND j.concurrency_group = ?3
               AND j.status IN ('queued', 'leased', 'preparing', 'running', 'finalizing')
             ORDER BY j.created_unix_ms, j.id LIMIT 1",
            params![tenant_id, repository_id, group],
            |row| row.get(0),
        )
        .optional()?;
    Ok(first.as_deref() == Some(candidate_job_id))
}

pub(in crate::store) fn signed_job_locality_hits(
    job: &runtrue_workflow_ir::PlannedJob,
    source_tree_digest: Option<&ContentDigest>,
    locality: &BTreeSet<ContentDigest>,
) -> usize {
    signed_job_preferred_content(job, source_tree_digest)
        .intersection(locality)
        .count()
}

fn signed_job_preferred_content(
    job: &runtrue_workflow_ir::PlannedJob,
    source_tree_digest: Option<&ContentDigest>,
) -> BTreeSet<ContentDigest> {
    let mut preferred = BTreeSet::new();
    if let Some(source) = source_tree_digest {
        preferred.insert(source.clone());
    }
    if let Some(image) = job.runner.image.as_deref().and_then(digest_from_reference) {
        preferred.insert(image);
    }
    for service in &job.services {
        if let Some(image) = digest_from_reference(&service.image) {
            preferred.insert(image);
        }
    }
    for step in &job.steps {
        if let runtrue_workflow_ir::StepAction::Component { reference } = &step.action {
            if let Some(component) = digest_from_reference(reference) {
                preferred.insert(component);
            }
        }
        if let runtrue_workflow_ir::StepAction::Script { script_digest, .. } = &step.action {
            preferred.insert(script_digest.clone());
        }
    }
    preferred
}

fn digest_from_reference(value: &str) -> Option<ContentDigest> {
    let encoded = value.rsplit_once('@').map_or(value, |(_, digest)| digest);
    ContentDigest::parse(encoded).ok()
}

pub(in crate::store) fn signed_job_package_tier(
    job: &runtrue_workflow_ir::PlannedJob,
    source_tree_digest: Option<&ContentDigest>,
    package_tiers: &BTreeMap<ContentDigest, runtrue_scheduler::PackagePreparationTier>,
) -> u8 {
    signed_job_preferred_content(job, source_tree_digest)
        .iter()
        .filter_map(|digest| package_tiers.get(digest))
        .map(|tier| tier.placement_rank())
        .max()
        .unwrap_or(0)
}

pub(in crate::store) fn scheduler_maintenance_tx(
    transaction: &Transaction<'_>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let expired_ids = {
        let mut statement = transaction.prepare(
            "SELECT id FROM leases
             WHERE state IN ('offered', 'active', 'cancel_requested')
               AND ((state = 'offered' AND accept_by_unix_ms <= ?1)
                 OR (state != 'offered' AND expires_unix_ms <= ?1)
                 OR hard_deadline_unix_ms <= ?1)
             ORDER BY COALESCE(hard_deadline_unix_ms, expires_unix_ms), id
             LIMIT ?2",
        )?;
        let values = statement
            .query_map(
                params![to_i64(now_unix_ms)?, to_i64(MAX_MAINTENANCE_LEASES as u64)?],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        values
    };
    for id in expired_ids {
        let lease = lease_tx(transaction, &id)?;
        let hard_deadline = lease_hard_deadline_tx(transaction, &id)?;
        if lease.state == LeaseState::Offered {
            expire_unaccepted_offer_tx(transaction, &lease, now_unix_ms)?;
            continue;
        }
        let preferred = if lease.state == LeaseState::CancelRequested {
            JobState::Canceled
        } else if now_unix_ms >= hard_deadline {
            JobState::TimedOut
        } else {
            JobState::Lost
        };
        expire_lease_with_state_tx(transaction, &lease, preferred, now_unix_ms)?;
        conclude_run_if_terminal_tx(transaction, &lease.job_id, now_unix_ms)?;
    }

    let offline_before = now_unix_ms.saturating_sub(DEFAULT_RUNNER_OFFLINE_AFTER_MS);
    let runner_ids = {
        let mut statement = transaction.prepare(
            "SELECT id FROM runners WHERE status = 'online' AND updated_unix_ms <= ?1
             ORDER BY updated_unix_ms, id LIMIT ?2",
        )?;
        let values = statement
            .query_map(
                params![
                    to_i64(offline_before)?,
                    to_i64(MAX_MAINTENANCE_RUNNERS as u64)?
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        values
    };
    for runner_id in runner_ids {
        let mut persisted = persisted_runner_tx(transaction, &runner_id)?;
        if persisted.runner.status != RunnerStatus::Online {
            continue;
        }
        persisted.runner.status = RunnerStatus::Offline;
        transaction.execute(
            "UPDATE runners SET status = 'offline', runner_json = ?2,
             updated_unix_ms = ?3 WHERE id = ?1 AND status = 'online'",
            params![
                runner_id,
                serde_json::to_string(&persisted.runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
    }

    let ephemeral_before = now_unix_ms.saturating_sub(DEFAULT_EPHEMERAL_RUNNER_RETENTION_MS);
    let ephemeral_ids = {
        let mut statement = transaction.prepare(
            "SELECT r.id FROM runners r
             WHERE r.status = 'offline' AND r.updated_unix_ms <= ?1
               AND json_extract(r.runner_json, '$.ephemeral') = 1
               AND COALESCE(json_extract(r.runner_json, '$.retired'), 0) = 0
             ORDER BY r.updated_unix_ms, r.id LIMIT ?2",
        )?;
        let values = statement
            .query_map(
                params![
                    to_i64(ephemeral_before)?,
                    to_i64(MAX_MAINTENANCE_RUNNERS as u64)?
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        values
    };
    for runner_id in ephemeral_ids {
        let has_durable_history: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM leases WHERE runner_id = ?1
                UNION ALL
                SELECT 1 FROM runner_fleet_requests WHERE runner_id = ?1
                UNION ALL
                SELECT 1 FROM runner_launch_claims WHERE runner_id = ?1
                UNION ALL
                SELECT 1 FROM runner_slots WHERE active_runner_id = ?1
                UNION ALL
                SELECT 1 FROM runner_replacements
                    WHERE source_runner_id = ?1 OR target_runner_id = ?1
                UNION ALL
                SELECT 1 FROM runner_software_update_claims
                    WHERE runner_id = ?1 OR source_runner_id = ?1
             )",
            [&runner_id],
            |row| row.get(0),
        )?;
        if has_durable_history {
            let mut persisted = persisted_runner_tx(transaction, &runner_id)?;
            persisted.runner.retired = true;
            transaction.execute(
                "UPDATE runners SET runner_json = ?2, updated_unix_ms = ?3
                 WHERE id = ?1 AND status = 'offline'",
                params![
                    runner_id,
                    serde_json::to_string(&persisted.runner)?,
                    to_i64(now_unix_ms)?,
                ],
            )?;
            continue;
        }
        // Ephemeral identities with no execution or fleet history have no
        // durable audit state. Remove their enrollment-only children before
        // the runner row.
        transaction.execute(
            "DELETE FROM runner_certificate_rotations WHERE runner_id = ?1",
            [&runner_id],
        )?;
        transaction.execute(
            "DELETE FROM runner_certificates WHERE runner_id = ?1",
            [&runner_id],
        )?;
        transaction.execute(
            "DELETE FROM runner_job_rejections WHERE runner_id = ?1",
            [&runner_id],
        )?;
        transaction.execute(
            "DELETE FROM runner_scheduler_cursors WHERE runner_id = ?1",
            [&runner_id],
        )?;
        transaction.execute(
            "DELETE FROM runner_enrollment_postures WHERE runner_id = ?1",
            [&runner_id],
        )?;
        transaction.execute(
            "DELETE FROM runners WHERE id = ?1 AND status = 'offline'
             AND NOT EXISTS (SELECT 1 FROM leases WHERE runner_id = ?1)",
            [&runner_id],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn scheduler_runner_maintenance_tx(
    transaction: &Transaction<'_>,
    runner_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let ids = {
        let mut statement = transaction.prepare(
            "SELECT id FROM leases WHERE runner_id = ?1
             AND state IN ('offered', 'active', 'cancel_requested')
             AND ((state = 'offered' AND accept_by_unix_ms <= ?2)
               OR (state != 'offered' AND expires_unix_ms <= ?2)
               OR hard_deadline_unix_ms <= ?2)
             ORDER BY COALESCE(hard_deadline_unix_ms, expires_unix_ms), id
             LIMIT ?3",
        )?;
        let values = statement
            .query_map(
                params![
                    runner_id,
                    to_i64(now_unix_ms)?,
                    to_i64(MAX_MAINTENANCE_LEASES as u64)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        values
    };
    for id in ids {
        let lease = lease_tx(transaction, &id)?;
        if lease.state == LeaseState::Offered {
            expire_unaccepted_offer_tx(transaction, &lease, now_unix_ms)?;
        } else {
            let hard_deadline = lease_hard_deadline_tx(transaction, &id)?;
            let state = if lease.state == LeaseState::CancelRequested {
                JobState::Canceled
            } else if now_unix_ms >= hard_deadline {
                JobState::TimedOut
            } else {
                JobState::Lost
            };
            expire_lease_with_state_tx(transaction, &lease, state, now_unix_ms)?;
            conclude_run_if_terminal_tx(transaction, &lease.job_id, now_unix_ms)?;
        }
    }
    Ok(())
}

pub(in crate::store) fn expire_unaccepted_offer_tx(
    transaction: &Transaction<'_>,
    lease: &Lease,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if lease.state != LeaseState::Offered {
        return Err(ControlPlaneError::InvalidLeaseState {
            expected: "offered",
            actual: lease_state_name(lease.state),
        });
    }
    transaction.execute(
        "UPDATE leases SET state = 'expired' WHERE id = ?1 AND state = 'offered'",
        [&lease.id],
    )?;
    revoke_runner_broker_state_tx(
        transaction,
        &lease.id,
        lease.fencing_generation,
        now_unix_ms,
        "expired",
    )?;
    let job = job_tx(transaction, &lease.job_id)?;
    if job.status == JobState::Leased {
        transition_job_tx(transaction, &lease.job_id, JobState::Queued, now_unix_ms)?;
    }
    Ok(())
}

impl ControlPlane {
    pub fn set_tenant_scheduler_quota(
        &self,
        tenant_id: &str,
        maximum_running_jobs: u32,
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        validate_text("scheduler quota tenant", tenant_id)?;
        if maximum_running_jobs == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "scheduler quota must permit at least one running job",
            ));
        }
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO tenant_scheduler_quotas
             (tenant_id, maximum_running_jobs, updated_unix_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(tenant_id) DO UPDATE SET
               maximum_running_jobs = excluded.maximum_running_jobs,
               updated_unix_ms = excluded.updated_unix_ms",
            params![
                tenant_id,
                i64::from(maximum_running_jobs),
                to_i64(now_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn perform_scheduler_maintenance(&self, now_unix_ms: u64) -> Result<(), ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        scheduler_maintenance_tx(&transaction, now_unix_ms)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically expire stale state, hard-filter queued work against the
    /// durable runner/pool/capsule, and reserve at most one fenced lease.
    pub fn offer_next_lease_for_runner(
        &self,
        runner_id: &str,
        now_unix_ms: u64,
    ) -> Result<Option<Lease>, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        scheduler_maintenance_tx(&transaction, now_unix_ms)?;
        scheduler_runner_maintenance_tx(&transaction, runner_id, now_unix_ms)?;
        let safe_mode: bool = transaction.query_row(
            "SELECT safe_mode FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if safe_mode {
            return Err(ControlPlaneError::InstallationSafeMode);
        }

        let existing_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM leases WHERE runner_id = ?1
                 AND state = 'offered'
                 AND accept_by_unix_ms > ?2 AND expires_unix_ms > ?2
                 AND hard_deadline_unix_ms > ?2
                 ORDER BY issued_unix_ms, id LIMIT 1",
                params![runner_id, to_i64(now_unix_ms)?],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_id) = existing_id {
            let lease = lease_tx(&transaction, &existing_id)?;
            transaction.commit()?;
            return Ok(Some(lease));
        }

        let runner_row: Option<(String, String, String, String, Option<String>)> = transaction
            .query_row(
                "SELECT r.runner_json, r.status, p.tenant_id, p.status, p.region
                 FROM runners r JOIN runner_pools p ON p.id = r.pool_id
                 WHERE r.id = ?1",
                [runner_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((runner_json, runner_status, tenant_id, pool_status, pool_region)) = runner_row
        else {
            return Err(not_found("runner", runner_id));
        };
        let runner: RunnerRecord = serde_json::from_str(&runner_json)?;
        if runner.id != runner_id
            || runner.tenant_id != tenant_id
            || parse_runner_status(&runner_status)? != runner.status
        {
            return Err(ControlPlaneError::CorruptState(
                "runner registry fields do not match its authoritative pool".to_owned(),
            ));
        }
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            transaction.commit()?;
            return Ok(None);
        }
        if pool_region
            .as_ref()
            .is_some_and(|region| runner.region.as_ref() != Some(region))
        {
            return Err(ControlPlaneError::CorruptState(
                "runner region does not match its configured pool".to_owned(),
            ));
        }
        if runner.status != RunnerStatus::Online {
            transaction.commit()?;
            return Ok(None);
        }
        let (bound_pool_id, _) = authoritative_runner_binding_tx(&transaction, runner_id)?;
        if bound_pool_id != runner.pool_id {
            return Err(ControlPlaneError::RunnerInventoryMismatch);
        }

        let quota: u64 = transaction
            .query_row(
                "SELECT maximum_running_jobs FROM tenant_scheduler_quotas
                 WHERE tenant_id = ?1",
                [&tenant_id],
                |row| u64_column(row, 0, "maximum_running_jobs"),
            )
            .optional()?
            .unwrap_or(DEFAULT_TENANT_MAXIMUM_RUNNING_JOBS);
        let reserved_for_tenant: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM leases
             WHERE tenant_id = ?1 AND state IN ('offered', 'active', 'cancel_requested')",
            [&tenant_id],
            |row| u64_column(row, 0, "tenant running lease count"),
        )?;
        if reserved_for_tenant >= quota {
            transaction.commit()?;
            return Ok(None);
        }

        let reserved_requirements = runner_reserved_requirements_tx(&transaction, runner_id)?;
        let (reserved_cpu, reserved_memory, reserved_storage) =
            runner_reserved_resources_tx(&transaction, runner_id)?;
        let used_cpu = reserved_cpu.max(u64::from(runner.used_cpus));
        let used_memory = reserved_memory.max(runner.used_memory_bytes);
        let used_storage = reserved_storage.max(runner.used_storage_bytes);
        let cursor: Option<String> = transaction
            .query_row(
                "SELECT last_job_id FROM runner_scheduler_cursors WHERE runner_id = ?1",
                [runner_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut candidate_ids =
            scheduler_candidate_page_tx(&transaction, &tenant_id, cursor.as_deref().unwrap_or(""))?;
        if candidate_ids.is_empty() && cursor.as_deref().is_some_and(|value| !value.is_empty()) {
            candidate_ids = scheduler_candidate_page_tx(&transaction, &tenant_id, "")?;
        }
        if let Some(last_job_id) = candidate_ids.last() {
            transaction.execute(
                "INSERT INTO runner_scheduler_cursors(runner_id, last_job_id, updated_unix_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(runner_id) DO UPDATE SET
                   last_job_id = excluded.last_job_id,
                   updated_unix_ms = excluded.updated_unix_ms",
                params![runner_id, last_job_id, to_i64(now_unix_ms)?],
            )?;
        }

        struct AdmissibleCandidate {
            job: JobRecord,
            planned: runtrue_workflow_ir::PlannedJob,
            digest: ContentDigest,
            score: (Reverse<i64>, Reverse<u8>, Reverse<usize>, u64, String),
        }
        let mut admissible = Vec::new();
        for job_id in candidate_ids {
            let job = job_tx(&transaction, &job_id)?;
            let (repository_id, capsule_id, priority, stored_digest, canonical_capsule): (
                String,
                String,
                i32,
                String,
                Vec<u8>,
            ) = transaction.query_row(
                "SELECT r.repository_id, r.capsule_id, r.priority, p.digest, p.canonical_capsule
                 FROM runs r JOIN capsules p ON p.id = r.capsule_id WHERE r.id = ?1",
                [&job.run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )?;
            let capsule: ExecutionCapsule = serde_json::from_slice(&canonical_capsule)?;
            let digest = capsule.digest()?;
            let planned_jobs = materialized_planned_jobs_conn(&transaction, &job.run_id, &capsule)?;
            let job_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM jobs WHERE run_id = ?1",
                [&job.run_id],
                |row| row.get(0),
            )?;
            if capsule.canonical_bytes()? != canonical_capsule
                || digest.as_str() != stored_digest
                || i64::try_from(planned_jobs.len()).ok() != Some(job_count)
            {
                return Err(ControlPlaneError::NonCanonicalCapsule);
            }
            let planned = planned_jobs
                .get(&job.job_key)
                .ok_or(ControlPlaneError::CorruptState(
                    "queued job is absent from its signed capsule".to_owned(),
                ))?;
            if job.attempt != 1 || job.requirements != planned_scheduling_requirements(planned) {
                return Err(ControlPlaneError::CorruptState(
                    "queued job requirements differ from its signed capsule".to_owned(),
                ));
            }
            let stored_concurrency: Option<String> = transaction.query_row(
                "SELECT concurrency_group FROM jobs WHERE id = ?1",
                [&job.id],
                |row| row.get(0),
            )?;
            if stored_concurrency != planned.concurrency {
                return Err(ControlPlaneError::CorruptState(
                    "queued job concurrency differs from its signed capsule".to_owned(),
                ));
            }
            if !capsule.context.source_trust.satisfies(planned.trust) {
                transaction.execute(
                    "UPDATE jobs SET status = 'blocked_policy', completed_unix_ms = ?2
                     WHERE id = ?1 AND status = 'queued'",
                    params![job.id, to_i64(now_unix_ms)?],
                )?;
                conclude_run_if_terminal_tx(&transaction, &job.id, now_unix_ms)?;
                continue;
            }
            match runner_approval_subject_tx(&transaction, &capsule_id, &job.run_id, &capsule) {
                Ok(_) => {}
                Err(ControlPlaneError::ApprovalRequired) => continue,
                Err(error) => return Err(error),
            }
            let (runner_rejections, last_rejection_code, last_rejection_unix_ms): (
                u64,
                String,
                u64,
            ) = transaction
                .query_row(
                    "SELECT rejection_count, last_code, updated_unix_ms
                     FROM runner_job_rejections
                     WHERE runner_id = ?1 AND job_id = ?2",
                    params![runner_id, job.id],
                    |row| {
                        Ok((
                            u64_column(row, 0, "runner job rejection count")?,
                            row.get(1)?,
                            u64_column(row, 2, "runner job rejection update")?,
                        ))
                    },
                )
                .optional()?
                .unwrap_or((0, String::new(), 0));
            let image_admission_backoff = last_rejection_code == "image_admission_pending"
                && now_unix_ms
                    < last_rejection_unix_ms.saturating_add(IMAGE_ADMISSION_RETRY_DELAY_MILLIS);
            if image_admission_backoff {
                continue;
            }
            if last_rejection_code != "image_admission_pending"
                && runner_rejections >= MAX_RUNNER_JOB_REJECTIONS
            {
                if all_eligible_runners_exhausted_tx(
                    &transaction,
                    &tenant_id,
                    &job.id,
                    &job.requirements,
                )? {
                    transaction.execute(
                        "UPDATE jobs SET status = 'blocked_policy', completed_unix_ms = ?2
                         WHERE id = ?1 AND status = 'queued'",
                        params![job.id, to_i64(now_unix_ms)?],
                    )?;
                    conclude_run_if_terminal_tx(&transaction, &job.id, now_unix_ms)?;
                }
                continue;
            }
            if let Some(group) = &planned.concurrency {
                if !concurrency_group_available_tx(
                    &transaction,
                    &tenant_id,
                    &repository_id,
                    group,
                    &job.id,
                )? {
                    continue;
                }
            }
            if !deployment_job_gate_ready_tx(&transaction, &tenant_id, &job, planned, now_unix_ms)?
            {
                continue;
            }
            let requirements = &job.requirements;
            let isolation_capacity_available = match requirements.isolation {
                runtrue_workflow_ir::Isolation::Wasm => {
                    reserved_requirements
                        .iter()
                        .all(|reserved| reserved.isolation == runtrue_workflow_ir::Isolation::Wasm)
                        && reserved_requirements.len() < runner.max_concurrent_wasm_jobs as usize
                }
                runtrue_workflow_ir::Isolation::Oci
                | runtrue_workflow_ir::Isolation::Microvm
                | runtrue_workflow_ir::Isolation::Native => reserved_requirements.is_empty(),
            };
            if !isolation_capacity_available
                || requirements.os != runner.os
                || requirements.arch != runner.arch
                || !runner.isolation_backends.contains(&requirements.isolation)
                || (!requirements.allowed_pools.is_empty()
                    && !requirements.allowed_pools.contains(&runner.pool_id))
                || requirements.region.as_ref().is_some_and(|region| {
                    runner.region.as_ref() != Some(region)
                        || pool_region.as_ref().is_some_and(|pool| pool != region)
                })
                || !requirements
                    .required_capabilities
                    .is_subset(&runner.verified_capabilities)
                || u64::from(requirements.cpu)
                    > u64::from(runner.logical_cpus).saturating_sub(used_cpu)
                || requirements.memory_bytes > runner.memory_bytes.saturating_sub(used_memory)
                || requirements.storage_bytes > runner.storage_bytes.saturating_sub(used_storage)
            {
                continue;
            }
            let age = now_unix_ms.saturating_sub(job.created_unix_ms)
                / runtrue_scheduler::PRIORITY_AGING_INTERVAL_MS;
            let effective_priority =
                i64::from(priority).saturating_add(i64::try_from(age).unwrap_or(i64::MAX));
            let locality_hits = signed_job_locality_hits(
                planned,
                capsule.context.source_tree_digest.as_ref(),
                &runner.locality,
            );
            let package_tier = signed_job_package_tier(
                planned,
                capsule.context.source_tree_digest.as_ref(),
                &runner.package_tiers,
            );
            admissible.push(AdmissibleCandidate {
                score: (
                    Reverse(effective_priority),
                    Reverse(package_tier),
                    Reverse(locality_hits),
                    job.created_unix_ms,
                    job.id.clone(),
                ),
                job,
                planned: planned.clone(),
                digest,
            });
        }

        if let Some(candidate) = admissible
            .into_iter()
            .min_by_key(|value| value.score.clone())
        {
            let hard_deadline = now_unix_ms
                .checked_add(LEASE_SETUP_GRACE_MS)
                .and_then(|value| value.checked_add(candidate.planned.timeout_ms))
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "lease hard deadline",
                })?;
            let accept_by = now_unix_ms
                .checked_add(LEASE_ACCEPT_WINDOW_MS)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "lease accept deadline",
                })?
                .min(hard_deadline);
            let expires = now_unix_ms
                .checked_add(LEASE_EXTENSION_MS)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "lease soft expiry",
                })?
                .min(hard_deadline);
            if accept_by <= now_unix_ms || expires <= accept_by {
                return Err(ControlPlaneError::InvalidInput(
                    "signed job timeout is too short for remote lease admission",
                ));
            }
            let current_generation: i64 = transaction.query_row(
                "SELECT last_generation FROM job_fencing WHERE job_id = ?1",
                [&candidate.job.id],
                |row| row.get(0),
            )?;
            let generation = from_i64("generation", current_generation)?
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "generation",
                })?;
            let epoch = installation_epoch_tx(&transaction)?;
            let lease_id = random_broker_id("lease")?;
            transaction.execute(
                "UPDATE job_fencing SET last_generation = ?2 WHERE job_id = ?1",
                params![candidate.job.id, to_i64(generation)?],
            )?;
            transaction.execute(
                "INSERT INTO leases
                 (id, job_id, tenant_id, runner_id, fencing_generation,
                  installation_fencing_epoch, capsule_digest, state, issued_unix_ms,
                  accept_by_unix_ms, expires_unix_ms, hard_deadline_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'offered', ?8, ?9, ?10, ?11)",
                params![
                    lease_id,
                    candidate.job.id,
                    tenant_id,
                    runner_id,
                    to_i64(generation)?,
                    to_i64(epoch)?,
                    candidate.digest.as_str(),
                    to_i64(now_unix_ms)?,
                    to_i64(accept_by)?,
                    to_i64(expires)?,
                    to_i64(hard_deadline)?,
                ],
            )?;
            bind_deployment_gate_offer_tx(
                &transaction,
                &tenant_id,
                &candidate.job,
                &lease_id,
                generation,
                epoch,
                now_unix_ms,
            )?;
            transition_job_tx(
                &transaction,
                &candidate.job.id,
                JobState::Leased,
                now_unix_ms,
            )?;
            let lease = lease_tx(&transaction, &lease_id)?;
            transaction.commit()?;
            return Ok(Some(lease));
        }
        transaction.commit()?;
        Ok(None)
    }
}
