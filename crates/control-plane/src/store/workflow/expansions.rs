use super::super::*;

fn validate_expanded_job_set_record(
    record: &ExpandedJobSetRecord,
    verifying_key: &CapsuleVerifyingKey,
) -> Result<runtrue_workflow_ir::ExpandedJobSet, ControlPlaneError> {
    validate_text("expanded job set id", &record.id)?;
    validate_text("expanded job set tenant", &record.tenant_id)?;
    validate_text("expanded job set repository", &record.repository_id)?;
    validate_text("expanded job set run", &record.run_id)?;
    validate_text("expanded job set template", &record.template_id)?;
    validate_text("expanded job set producer", &record.producer_job_id)?;
    validate_text(
        "expanded job set producer output",
        &record.producer_output_name,
    )?;
    validate_text("expanded job set signing key", &record.signing_key_id)?;
    if record.generated_job_count == 0
        || record.generated_job_count > MAX_REMOTE_WORKFLOW_JOBS as u64
        || record.canonical_job_set.is_empty()
        || record.canonical_job_set.len() > MAX_EXPANDED_JOB_SET_BYTES
        || record.signature.len() != 64
    {
        return Err(ControlPlaneError::InvalidInput(
            "expanded job set exceeds its signed resource bounds",
        ));
    }
    let job_set: runtrue_workflow_ir::ExpandedJobSet =
        serde_json::from_slice(&record.canonical_job_set)?;
    let canonical = job_set.canonical_bytes()?;
    if canonical != record.canonical_job_set {
        return Err(ControlPlaneError::InvalidInput(
            "expanded job set is not canonical",
        ));
    }
    let digest = ContentDigest::sha256(&canonical);
    if digest != record.job_set_digest
        || job_set.parent_capsule_digest != record.parent_capsule_digest
        || job_set.producer_job_id != record.producer_job_id
        || job_set.producer_output_name != record.producer_output_name
        || job_set.matrix_input_digest != record.matrix_input_digest
        || job_set.policy_epoch != record.policy_epoch
        || job_set.generated_job_ids.len() as u64 != record.generated_job_count
        || job_set.jobs.len() as u64 != record.generated_job_count
        || job_set
            .jobs
            .iter()
            .map(|job| &job.id)
            .ne(job_set.generated_job_ids.iter())
        || job_set
            .generated_job_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != job_set.generated_job_ids.len()
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let signature = runtrue_attest::ExpandedJobSetSignature {
        signature_version: 1,
        algorithm: runtrue_attest::CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
        key_id: ContentDigest::parse(&record.signing_key_id)?,
        job_set_digest: record.job_set_digest.clone(),
        signature: record.signature.clone(),
    };
    verifying_key.verify_expanded_job_set(&job_set, &signature)?;
    Ok(job_set)
}

fn authorize_expanded_job_set_tx(
    transaction: &Transaction<'_>,
    record: &ExpandedJobSetRecord,
    job_set: &runtrue_workflow_ir::ExpandedJobSet,
) -> Result<(ExecutionCapsule, runtrue_workflow_ir::DynamicJobTemplate), ControlPlaneError> {
    let parent_capsule_bytes: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT p.canonical_capsule FROM runs r
             JOIN repositories repo ON repo.id = r.repository_id
             JOIN capsules p ON p.id = r.capsule_id
             WHERE r.id = ?1 AND r.repository_id = ?2
               AND repo.tenant_id = ?3 AND p.digest = ?4",
            params![
                record.run_id,
                record.repository_id,
                record.tenant_id,
                record.parent_capsule_digest.as_str()
            ],
            |row| row.get(0),
        )
        .optional()?;
    let parent_capsule_bytes =
        parent_capsule_bytes.ok_or_else(|| not_found("run", &record.run_id))?;
    let parent_capsule: ExecutionCapsule = serde_json::from_slice(&parent_capsule_bytes)?;
    if parent_capsule.canonical_bytes()? != parent_capsule_bytes {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let template = parent_capsule
        .dynamic_jobs
        .iter()
        .find(|template| template.id == record.template_id)
        .cloned()
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    if template.source.producer_job_id != job_set.producer_job_id
        || template.source.output_name != job_set.producer_output_name
        || template.source.maximum_jobs < job_set.jobs.len()
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    for expanded in &job_set.jobs {
        let mut normalized = expanded.clone();
        normalized.id = template.template.id.clone();
        normalized.matrix.clear();
        if normalized != template.template {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    Ok((parent_capsule, template))
}

fn persist_expanded_job_set_tx(
    transaction: &Transaction<'_>,
    record: &ExpandedJobSetRecord,
) -> Result<bool, ControlPlaneError> {
    let existing = transaction
        .query_row(
            "SELECT id, parent_capsule_digest, producer_job_id, producer_output_name,
                    matrix_input_digest, policy_epoch, generated_job_count,
                    canonical_job_set, job_set_digest, signing_key_id, signature,
                    created_unix_ms
             FROM expanded_job_sets
             WHERE tenant_id = ?1 AND repository_id = ?2
               AND run_id = ?3 AND template_id = ?4",
            params![
                record.tenant_id,
                record.repository_id,
                record.run_id,
                record.template_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?;
    if let Some(existing) = existing {
        let exact = existing.0 == record.id
            && existing.1 == record.parent_capsule_digest.as_str()
            && existing.2 == record.producer_job_id
            && existing.3 == record.producer_output_name
            && existing.4 == record.matrix_input_digest.as_str()
            && existing.5 == to_i64(record.policy_epoch)?
            && existing.6 == to_i64(record.generated_job_count)?
            && existing.7 == record.canonical_job_set
            && existing.8 == record.job_set_digest.as_str()
            && existing.9 == record.signing_key_id
            && existing.10 == record.signature
            && existing.11 == to_i64(record.created_unix_ms)?;
        return if exact {
            Ok(true)
        } else {
            Err(ControlPlaneError::IdempotencyConflict)
        };
    }
    transaction.execute(
        "INSERT INTO expanded_job_sets
         (id, tenant_id, repository_id, run_id, parent_capsule_digest,
          template_id, producer_job_id, producer_output_name,
          matrix_input_digest, policy_epoch, generated_job_count,
          canonical_job_set, job_set_digest, signing_key_id, signature,
          created_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, ?16)",
        params![
            record.id,
            record.tenant_id,
            record.repository_id,
            record.run_id,
            record.parent_capsule_digest.as_str(),
            record.template_id,
            record.producer_job_id,
            record.producer_output_name,
            record.matrix_input_digest.as_str(),
            to_i64(record.policy_epoch)?,
            to_i64(record.generated_job_count)?,
            record.canonical_job_set,
            record.job_set_digest.as_str(),
            record.signing_key_id,
            record.signature,
            to_i64(record.created_unix_ms)?,
        ],
    )?;
    Ok(false)
}

fn append_expanded_job_set_audit_tx(
    transaction: &Transaction<'_>,
    installation_id: &str,
    record: &ExpandedJobSetRecord,
) -> Result<(), ControlPlaneError> {
    append_audit_event_tx(
        transaction,
        installation_id,
        AuditEventData {
            observed_unix_ms: record.created_unix_ms,
            tenant_id: record.tenant_id.clone(),
            actor: AuditPrincipal {
                kind: "worker".to_owned(),
                id: "workflow-expander".to_owned(),
            },
            action: "workflow.expand".to_owned(),
            resource: AuditResource {
                kind: "expanded-job-set".to_owned(),
                id: record.id.clone(),
            },
            result: "persisted".to_owned(),
            request_id: record.id.clone(),
            decision_id: Some(record.parent_capsule_digest.to_string()),
            metadata: BTreeMap::from([
                (
                    "job_set_digest".to_owned(),
                    AuditValue::Digest(record.job_set_digest.clone()),
                ),
                (
                    "matrix_input_digest".to_owned(),
                    AuditValue::Digest(record.matrix_input_digest.clone()),
                ),
                (
                    "generated_job_count".to_owned(),
                    AuditValue::Integer(to_i64(record.generated_job_count)?),
                ),
            ]),
        },
    )?;
    Ok(())
}

fn expanded_scheduler_job_id(record_id: &str, job_key: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.expanded-scheduler-job.v1\0");
    for value in [record_id.as_bytes(), job_key.as_bytes()] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    format!("expanded-job-{}", hex::encode(hash.finalize()))
}

fn materialize_expanded_jobs_tx(
    transaction: &Transaction<'_>,
    record: &ExpandedJobSetRecord,
    job_set: &runtrue_workflow_ir::ExpandedJobSet,
    parent_capsule: &ExecutionCapsule,
    template: &runtrue_workflow_ir::DynamicJobTemplate,
) -> Result<u64, ControlPlaneError> {
    let expanded_total: i64 = transaction.query_row(
        "SELECT COALESCE(SUM(generated_job_count), 0)
         FROM expanded_job_sets WHERE run_id = ?1",
        [&record.run_id],
        |row| row.get(0),
    )?;
    let expanded_total = usize::try_from(expanded_total).map_err(|_| {
        ControlPlaneError::CorruptState("expanded job count is negative".to_owned())
    })?;
    if parent_capsule.jobs.len().saturating_add(expanded_total) > MAX_REMOTE_WORKFLOW_JOBS {
        return Err(ControlPlaneError::InvalidInput(
            "materialized run exceeds the signed workflow job bound",
        ));
    }
    let mut existing = Vec::new();
    for planned in &job_set.jobs {
        validate_text("expanded scheduler job key", &planned.id)?;
        let expected_id = expanded_scheduler_job_id(&record.id, &planned.id);
        let row: Option<(String, i64, String, Option<String>)> = transaction
            .query_row(
                "SELECT id, attempt, requirements_json, concurrency_group
                 FROM jobs WHERE run_id = ?1 AND job_key = ?2",
                params![record.run_id, planned.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((id, attempt, requirements, concurrency)) = row {
            if id != expected_id
                || attempt != 1
                || serde_json::from_str::<SchedulingRequirements>(&requirements)?
                    != planned_scheduling_requirements(planned)
                || concurrency != planned.concurrency
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            existing.push(planned.id.as_str());
        }
    }
    if existing.len() == job_set.jobs.len() {
        return Ok(0);
    }
    if !existing.is_empty() {
        return Err(ControlPlaneError::CorruptState(
            "expanded scheduler job materialization is partial".to_owned(),
        ));
    }

    let mut state_rows = transaction
        .prepare("SELECT job_key, status FROM jobs WHERE run_id = ?1 ORDER BY job_key")?;
    let states = state_rows
        .query_map([&record.run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(|(key, status)| Ok((key, parse_job_state(&status)?)))
        .collect::<Result<BTreeMap<_, _>, ControlPlaneError>>()?;
    drop(state_rows);
    for planned in &job_set.jobs {
        if planned.needs != template.template.needs {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let dependencies = planned
            .needs
            .iter()
            .map(|need| {
                states.get(need).copied().ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "expanded job dependency is absent from its run".to_owned(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let status = if !parent_capsule.context.source_trust.satisfies(planned.trust) {
            JobState::BlockedPolicy
        } else if dependencies
            .iter()
            .all(|state| *state == JobState::Succeeded)
        {
            JobState::Queued
        } else if dependencies.iter().any(|state| {
            (*state != JobState::Succeeded && state.is_terminal())
                || *state == JobState::BlockedPolicy
        }) {
            JobState::Skipped
        } else {
            JobState::Created
        };
        let job_id = expanded_scheduler_job_id(&record.id, &planned.id);
        let completed = (status.is_terminal() || status == JobState::BlockedPolicy)
            .then_some(to_i64(record.created_unix_ms)?);
        transaction.execute(
            "INSERT INTO jobs
             (id, run_id, job_key, attempt, status, requirements_json,
              created_unix_ms, completed_unix_ms, concurrency_group)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8)",
            params![
                job_id,
                record.run_id,
                planned.id,
                job_state_name(status),
                serde_json::to_string(&planned_scheduling_requirements(planned))?,
                to_i64(record.created_unix_ms)?,
                completed,
                planned.concurrency,
            ],
        )?;
        transaction.execute(
            "INSERT INTO job_fencing(job_id, last_generation) VALUES (?1, 0)",
            [&job_id],
        )?;
    }
    Ok(job_set.jobs.len() as u64)
}

impl ControlPlane {
    /// Persist an already signed expansion after re-verifying its canonical
    /// bytes and tenant/run/capsule binding. Exact replay is accepted; changing
    /// any field for the same run/template conflicts.
    pub fn record_expanded_job_set(
        &self,
        record: &ExpandedJobSetRecord,
        verifying_key: &CapsuleVerifyingKey,
    ) -> Result<bool, ControlPlaneError> {
        const MAX_EXPANDED_JOB_SET_BYTES: usize = 8 * 1024 * 1024;
        validate_text("expanded job set id", &record.id)?;
        validate_text("expanded job set tenant", &record.tenant_id)?;
        validate_text("expanded job set repository", &record.repository_id)?;
        validate_text("expanded job set run", &record.run_id)?;
        validate_text("expanded job set template", &record.template_id)?;
        validate_text("expanded job set producer", &record.producer_job_id)?;
        validate_text(
            "expanded job set producer output",
            &record.producer_output_name,
        )?;
        validate_text("expanded job set signing key", &record.signing_key_id)?;
        if record.generated_job_count == 0
            || record.generated_job_count > 1_024
            || record.canonical_job_set.is_empty()
            || record.canonical_job_set.len() > MAX_EXPANDED_JOB_SET_BYTES
            || record.signature.len() != 64
        {
            return Err(ControlPlaneError::InvalidInput(
                "expanded job set exceeds its signed resource bounds",
            ));
        }
        let job_set: runtrue_workflow_ir::ExpandedJobSet =
            serde_json::from_slice(&record.canonical_job_set)?;
        let canonical = job_set.canonical_bytes()?;
        if canonical != record.canonical_job_set {
            return Err(ControlPlaneError::InvalidInput(
                "expanded job set is not canonical",
            ));
        }
        let digest = ContentDigest::sha256(&canonical);
        if digest != record.job_set_digest
            || job_set.parent_capsule_digest != record.parent_capsule_digest
            || job_set.producer_job_id != record.producer_job_id
            || job_set.producer_output_name != record.producer_output_name
            || job_set.matrix_input_digest != record.matrix_input_digest
            || job_set.policy_epoch != record.policy_epoch
            || job_set.generated_job_ids.len() as u64 != record.generated_job_count
            || job_set.jobs.len() as u64 != record.generated_job_count
            || job_set
                .jobs
                .iter()
                .map(|job| &job.id)
                .ne(job_set.generated_job_ids.iter())
            || job_set
                .generated_job_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != job_set.generated_job_ids.len()
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let signature = runtrue_attest::ExpandedJobSetSignature {
            signature_version: 1,
            algorithm: runtrue_attest::CAPSULE_SIGNATURE_ALGORITHM.to_owned(),
            key_id: ContentDigest::parse(&record.signing_key_id)?,
            job_set_digest: record.job_set_digest.clone(),
            signature: record.signature.clone(),
        };
        verifying_key.verify_expanded_job_set(&job_set, &signature)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent_capsule_bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT p.canonical_capsule FROM runs r
             JOIN repositories repo ON repo.id = r.repository_id
             JOIN capsules p ON p.id = r.capsule_id
             WHERE r.id = ?1 AND r.repository_id = ?2
               AND repo.tenant_id = ?3 AND p.digest = ?4",
                params![
                    record.run_id,
                    record.repository_id,
                    record.tenant_id,
                    record.parent_capsule_digest.as_str()
                ],
                |row| row.get(0),
            )
            .optional()?;
        let parent_capsule_bytes =
            parent_capsule_bytes.ok_or_else(|| not_found("run", &record.run_id))?;
        let parent_capsule: ExecutionCapsule = serde_json::from_slice(&parent_capsule_bytes)?;
        let template = parent_capsule
            .dynamic_jobs
            .iter()
            .find(|template| template.id == record.template_id)
            .ok_or(ControlPlaneError::IdempotencyConflict)?;
        if template.source.producer_job_id != job_set.producer_job_id
            || template.source.output_name != job_set.producer_output_name
            || template.source.maximum_jobs < job_set.jobs.len()
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        for expanded in &job_set.jobs {
            let mut normalized = expanded.clone();
            normalized.id = template.template.id.clone();
            normalized.matrix.clear();
            if normalized != template.template {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        }
        let existing = transaction
            .query_row(
                "SELECT id, parent_capsule_digest, producer_job_id, producer_output_name,
                        matrix_input_digest, policy_epoch, generated_job_count,
                        canonical_job_set, job_set_digest, signing_key_id, signature,
                        created_unix_ms
                 FROM expanded_job_sets
                 WHERE tenant_id = ?1 AND repository_id = ?2
                   AND run_id = ?3 AND template_id = ?4",
                params![
                    record.tenant_id,
                    record.repository_id,
                    record.run_id,
                    record.template_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, i64>(11)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            let exact = existing.0 == record.id
                && existing.1 == record.parent_capsule_digest.as_str()
                && existing.2 == record.producer_job_id
                && existing.3 == record.producer_output_name
                && existing.4 == record.matrix_input_digest.as_str()
                && existing.5 == to_i64(record.policy_epoch)?
                && existing.6 == to_i64(record.generated_job_count)?
                && existing.7 == record.canonical_job_set
                && existing.8 == record.job_set_digest.as_str()
                && existing.9 == record.signing_key_id
                && existing.10 == record.signature
                && existing.11 == to_i64(record.created_unix_ms)?;
            if exact {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO expanded_job_sets
             (id, tenant_id, repository_id, run_id, parent_capsule_digest,
              template_id, producer_job_id, producer_output_name,
              matrix_input_digest, policy_epoch, generated_job_count,
              canonical_job_set, job_set_digest, signing_key_id, signature,
              created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16)",
            params![
                record.id,
                record.tenant_id,
                record.repository_id,
                record.run_id,
                record.parent_capsule_digest.as_str(),
                record.template_id,
                record.producer_job_id,
                record.producer_output_name,
                record.matrix_input_digest.as_str(),
                to_i64(record.policy_epoch)?,
                to_i64(record.generated_job_count)?,
                record.canonical_job_set,
                record.job_set_digest.as_str(),
                record.signing_key_id,
                record.signature,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: record.created_unix_ms,
                tenant_id: record.tenant_id.clone(),
                actor: AuditPrincipal {
                    kind: "worker".to_owned(),
                    id: "workflow-expander".to_owned(),
                },
                action: "workflow.expand".to_owned(),
                resource: AuditResource {
                    kind: "expanded-job-set".to_owned(),
                    id: record.id.clone(),
                },
                result: "persisted".to_owned(),
                request_id: record.id.clone(),
                decision_id: Some(record.parent_capsule_digest.to_string()),
                metadata: BTreeMap::from([
                    (
                        "job_set_digest".to_owned(),
                        AuditValue::Digest(record.job_set_digest.clone()),
                    ),
                    (
                        "matrix_input_digest".to_owned(),
                        AuditValue::Digest(record.matrix_input_digest.clone()),
                    ),
                    (
                        "generated_job_count".to_owned(),
                        AuditValue::Integer(i64::try_from(record.generated_job_count).map_err(
                            |_| ControlPlaneError::IntegerRange {
                                field: "generated job count",
                            },
                        )?),
                    ),
                ]),
            },
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Atomically persist one signed expansion and create its scheduler jobs.
    ///
    /// The active producer lease is checked before expansion metadata is
    /// looked up, so a caller from another tenant or a stale attempt/fence
    /// cannot use this method as an existence oracle. Exact replay verifies
    /// every immutable job projection and inserts nothing.
    pub fn materialize_expanded_job_set(
        &self,
        request: &MaterializeExpandedJobSet,
        verifying_key: &CapsuleVerifyingKey,
    ) -> Result<ExpandedJobMaterialization, ControlPlaneError> {
        validate_text("expansion execution lease", &request.execution_lease_id)?;
        validate_text("expansion runner", &request.runner_id)?;
        if request.fencing_generation == 0
            || request.installation_fencing_epoch == 0
            || request.producer_job_attempt == 0
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let job_set = validate_expanded_job_set_record(&request.record, verifying_key)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM leases l
                 JOIN jobs j ON j.id = l.job_id
                 JOIN runs r ON r.id = j.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 WHERE l.id = ?1 AND repo.tenant_id = ?2
                   AND r.repository_id = ?3 AND r.id = ?4
                   AND j.job_key = ?5 AND j.attempt = ?6
             )",
            params![
                request.execution_lease_id,
                request.record.tenant_id,
                request.record.repository_id,
                request.record.run_id,
                request.record.producer_job_id,
                i64::from(request.producer_job_attempt),
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(not_found("run", &request.record.run_id));
        }
        let lease = validate_lease_fence_tx(
            &transaction,
            &request.execution_lease_id,
            &request.runner_id,
            request.fencing_generation,
            request.installation_fencing_epoch,
        )?;
        if lease.state != LeaseState::Active
            || request.record.created_unix_ms < lease.issued_unix_ms
            || request.record.created_unix_ms >= lease.expires_unix_ms
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }

        let (parent_capsule, template) =
            authorize_expanded_job_set_tx(&transaction, &request.record, &job_set)?;
        let record_replayed = persist_expanded_job_set_tx(&transaction, &request.record)?;
        if !record_replayed {
            append_expanded_job_set_audit_tx(&transaction, &self.installation_id, &request.record)?;
        }
        let jobs_inserted = materialize_expanded_jobs_tx(
            &transaction,
            &request.record,
            &job_set,
            &parent_capsule,
            &template,
        )?;
        if jobs_inserted != 0 {
            append_audit_event_tx(
                &transaction,
                &self.installation_id,
                AuditEventData {
                    observed_unix_ms: request.record.created_unix_ms,
                    tenant_id: request.record.tenant_id.clone(),
                    actor: AuditPrincipal {
                        kind: "runner".to_owned(),
                        id: request.runner_id.clone(),
                    },
                    action: "workflow.expand.materialize".to_owned(),
                    resource: AuditResource {
                        kind: "expanded-job-set".to_owned(),
                        id: request.record.id.clone(),
                    },
                    result: "persisted".to_owned(),
                    request_id: request.execution_lease_id.clone(),
                    decision_id: Some(request.record.job_set_digest.to_string()),
                    metadata: BTreeMap::from([
                        (
                            "fencing_generation".to_owned(),
                            AuditValue::Integer(to_i64(request.fencing_generation)?),
                        ),
                        (
                            "jobs_inserted".to_owned(),
                            AuditValue::Integer(to_i64(jobs_inserted)?),
                        ),
                    ]),
                },
            )?;
        }
        transaction.commit()?;
        Ok(ExpandedJobMaterialization {
            record_replayed,
            jobs_inserted,
        })
    }
}
