use super::*;
use rusqlite::params;
use serde::Serialize;

pub(in crate::store) fn approval_id_for_kind(
    approvals: &[ApprovalRequest],
    kind: runtrue_policy::ApprovalKind,
) -> Option<&str> {
    approvals
        .iter()
        .find(|approval| approval.kind == kind)
        .map(|approval| approval.id.as_str())
}

pub(in crate::store) fn insert_signed_capsule_tx(
    transaction: &Transaction<'_>,
    capsule: &SignedCapsuleRecord,
    signature_json: &str,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO capsules
         (id, repository_id, digest, canonical_capsule, signature_json, key_id, created_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            capsule.id,
            capsule.repository_id,
            capsule.digest.as_str(),
            capsule.canonical_capsule,
            signature_json,
            capsule.signature.key_id.as_str(),
            to_i64(capsule.created_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn insert_capsule_metadata_tx(
    transaction: &Transaction<'_>,
    metadata: &CapsuleApiMetadata,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO capsule_api_metadata(capsule_id, approval_subject_digest, risk_score)
         VALUES (?1, ?2, ?3)",
        params![
            metadata.capsule_id,
            metadata.approval_subject_digest.as_str(),
            metadata.risk_score,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn insert_capsule_approval_tx(
    transaction: &Transaction<'_>,
    repository_id: &str,
    capsule_id: &str,
    approval: &ApprovalRequest,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO approval_requests
         (id, repository_id, capsule_id, subject_digest, status, request_json,
          created_unix_ms, expires_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            approval.id,
            repository_id,
            capsule_id,
            approval.subject_digest.as_str(),
            approval_status_name(approval.status),
            serde_json::to_string(approval)?,
            to_i64(approval.created_unix_ms)?,
            to_i64(approval.expires_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn insert_or_reuse_scm_approval_tx(
    transaction: &Transaction<'_>,
    repository_id: &str,
    capsule_id: &str,
    approval: &ApprovalRequest,
    now_unix_ms: u64,
) -> Result<ApprovalRequest, ControlPlaneError> {
    if approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution && !approval.rule.one_shot
    {
        let mut statement = transaction.prepare(
            "SELECT request_json FROM approval_requests
             WHERE repository_id = ?1 AND subject_digest = ?2
               AND status IN ('pending', 'approved') AND expires_unix_ms > ?3
             ORDER BY created_unix_ms, id",
        )?;
        let encoded = statement
            .query_map(
                params![
                    repository_id,
                    approval.subject_digest.as_str(),
                    to_i64(now_unix_ms)?,
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for encoded in encoded {
            let candidate: ApprovalRequest = serde_json::from_str(&encoded)?;
            if candidate.kind == approval.kind
                && candidate.subject_digest == approval.subject_digest
                && candidate.risk_score == approval.risk_score
                && candidate.rule == approval.rule
                && matches!(
                    candidate.status,
                    runtrue_policy::ApprovalStatus::Pending
                        | runtrue_policy::ApprovalStatus::Approved
                )
            {
                return Ok(candidate);
            }
        }
    }
    insert_capsule_approval_tx(transaction, repository_id, capsule_id, approval)?;
    Ok(approval.clone())
}

pub(in crate::store) fn insert_run_tx(
    transaction: &Transaction<'_>,
    request: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO runs
         (id, repository_id, capsule_id, status, priority, remote, created_unix_ms)
         VALUES (?1, ?2, ?3, 'created', ?4, ?5, ?6)",
        params![
            request.id,
            request.repository_id,
            request.capsule_id,
            request.priority,
            request.remote,
            to_i64(request.created_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn insert_jobs_tx(
    transaction: &Transaction<'_>,
    request: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    for job in &request.jobs {
        transaction.execute(
            "INSERT INTO jobs
             (id, run_id, job_key, attempt, status, requirements_json, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, 'created', ?5, ?6)",
            params![
                job.id,
                request.id,
                job.job_key,
                i64::from(job.attempt),
                serde_json::to_string(&job.requirements)?,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO job_fencing(job_id, last_generation) VALUES (?1, 0)",
            [&job.id],
        )?;
    }
    Ok(())
}

pub(in crate::store) fn validate_capsule_dag(
    capsule: &ExecutionCapsule,
) -> Result<(), ControlPlaneError> {
    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for job in &capsule.jobs {
        if indegree.insert(job.id.as_str(), job.needs.len()).is_some() {
            return Err(ControlPlaneError::InvalidInput(
                "signed capsule contains duplicate job identifiers",
            ));
        }
    }
    for job in &capsule.jobs {
        for need in &job.needs {
            if !indegree.contains_key(need.as_str()) || need == &job.id {
                return Err(ControlPlaneError::InvalidInput(
                    "signed capsule contains an invalid job dependency",
                ));
            }
            dependents
                .entry(need.as_str())
                .or_default()
                .push(job.id.as_str());
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect::<Vec<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop() {
        visited = visited.saturating_add(1);
        if let Some(children) = dependents.get(id) {
            for child in children {
                let count = indegree
                    .get_mut(child)
                    .ok_or(ControlPlaneError::CorruptState(
                        "validated job dependency disappeared".to_owned(),
                    ))?;
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push(child);
                }
            }
        }
    }
    if visited != capsule.jobs.len() {
        return Err(ControlPlaneError::InvalidInput(
            "signed capsule job dependency graph is cyclic",
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_planned_job_dag(
    jobs: &BTreeMap<String, runtrue_workflow_ir::PlannedJob>,
) -> Result<(), ControlPlaneError> {
    let mut indegree = jobs
        .iter()
        .map(|(id, job)| (id.as_str(), job.needs.len()))
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, job) in jobs {
        for need in &job.needs {
            if !indegree.contains_key(need.as_str()) || need == id {
                return Err(ControlPlaneError::CorruptState(
                    "materialized capsule contains an invalid job dependency".to_owned(),
                ));
            }
            dependents.entry(need).or_default().push(id);
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect::<Vec<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop() {
        visited = visited.saturating_add(1);
        if let Some(children) = dependents.get(id) {
            for child in children {
                let count = indegree.get_mut(child).ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "materialized capsule dependency disappeared".to_owned(),
                    )
                })?;
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push(child);
                }
            }
        }
    }
    if visited != jobs.len() {
        return Err(ControlPlaneError::CorruptState(
            "materialized capsule job dependency graph is cyclic".to_owned(),
        ));
    }
    Ok(())
}

pub(in crate::store) fn materialized_planned_jobs_conn(
    connection: &Connection,
    run_id: &str,
    capsule: &ExecutionCapsule,
) -> Result<BTreeMap<String, runtrue_workflow_ir::PlannedJob>, ControlPlaneError> {
    let mut jobs = capsule
        .jobs
        .iter()
        .cloned()
        .map(|job| (job.id.clone(), job))
        .collect::<BTreeMap<_, _>>();
    if jobs.len() != capsule.jobs.len() {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let parent_digest = capsule.digest()?;
    let mut statement = connection.prepare(
        "SELECT template_id, parent_capsule_digest, canonical_job_set,
                job_set_digest, generated_job_count
         FROM expanded_job_sets WHERE run_id = ?1 ORDER BY template_id",
    )?;
    let records = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (template_id, stored_parent, canonical, stored_digest, generated_count) in records {
        if canonical.is_empty() || canonical.len() > MAX_EXPANDED_JOB_SET_BYTES {
            return Err(ControlPlaneError::CorruptState(
                "expanded job set exceeds its durable byte bound".to_owned(),
            ));
        }
        let expanded: runtrue_workflow_ir::ExpandedJobSet = serde_json::from_slice(&canonical)?;
        if expanded.canonical_bytes()? != canonical
            || stored_parent != parent_digest.as_str()
            || expanded.parent_capsule_digest != parent_digest
            || ContentDigest::sha256(&canonical).as_str() != stored_digest
            || usize::try_from(generated_count).ok() != Some(expanded.jobs.len())
        {
            return Err(ControlPlaneError::CorruptState(
                "expanded job set no longer matches its signed parent".to_owned(),
            ));
        }
        let template = capsule
            .dynamic_jobs
            .iter()
            .find(|candidate| candidate.id == template_id)
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "expanded job set template is absent from its parent".to_owned(),
                )
            })?;
        let materialized_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM jobs
             WHERE run_id = ?1 AND job_key IN (
                 SELECT value FROM json_each(?2)
             )",
            params![run_id, serde_json::to_string(&expanded.generated_job_ids)?],
            |row| row.get(0),
        )?;
        let materialized_count = usize::try_from(materialized_count).map_err(|_| {
            ControlPlaneError::CorruptState("materialized job count is negative".to_owned())
        })?;
        if materialized_count == 0 {
            continue;
        }
        if materialized_count != expanded.jobs.len() {
            return Err(ControlPlaneError::CorruptState(
                "expanded scheduler job materialization is partial".to_owned(),
            ));
        }
        for expanded_job in expanded.jobs {
            let mut normalized = expanded_job.clone();
            normalized.id = template.template.id.clone();
            normalized.matrix.clear();
            if normalized != template.template
                || jobs.insert(expanded_job.id.clone(), expanded_job).is_some()
            {
                return Err(ControlPlaneError::CorruptState(
                    "expanded scheduler job changed its signed template".to_owned(),
                ));
            }
        }
    }
    if jobs.len() > MAX_REMOTE_WORKFLOW_JOBS {
        return Err(ControlPlaneError::CorruptState(
            "materialized capsule exceeds the workflow job bound".to_owned(),
        ));
    }
    validate_planned_job_dag(&jobs)?;
    Ok(jobs)
}

pub(in crate::store) fn initial_remote_job_states(
    capsule: &ExecutionCapsule,
    source_ready: bool,
) -> Result<BTreeMap<&str, JobState>, ControlPlaneError> {
    validate_capsule_dag(capsule)?;
    let mut states = capsule
        .jobs
        .iter()
        .map(|job| {
            let state = if !capsule.context.source_trust.satisfies(job.trust) {
                JobState::BlockedPolicy
            } else if source_ready && job.needs.is_empty() {
                JobState::Queued
            } else {
                JobState::Created
            };
            (job.id.as_str(), state)
        })
        .collect::<BTreeMap<_, _>>();
    loop {
        let skipped = capsule
            .jobs
            .iter()
            .filter(|job| states.get(job.id.as_str()) == Some(&JobState::Created))
            .filter(|job| {
                job.needs.iter().any(|need| {
                    matches!(
                        states.get(need.as_str()),
                        Some(JobState::BlockedPolicy | JobState::Skipped)
                    )
                })
            })
            .map(|job| job.id.as_str())
            .collect::<Vec<_>>();
        if skipped.is_empty() {
            break;
        }
        for id in skipped {
            states.insert(id, JobState::Skipped);
        }
    }
    Ok(states)
}

pub(in crate::store) fn insert_jobs_for_capsule_tx(
    transaction: &Transaction<'_>,
    request: &CreateRunRequest,
    capsule: &ExecutionCapsule,
) -> Result<(), ControlPlaneError> {
    validate_run_jobs(capsule, request)?;
    let source_ready = run_source_binding_ready_tx(transaction, &request.id, capsule)?;
    let initial = initial_remote_job_states(capsule, source_ready)?;
    for (job, planned) in request.jobs.iter().zip(&capsule.jobs) {
        let status = *initial
            .get(planned.id.as_str())
            .ok_or(ControlPlaneError::CorruptState(
                "validated capsule job state is missing".to_owned(),
            ))?;
        let completed = matches!(status, JobState::BlockedPolicy | JobState::Skipped)
            .then_some(to_i64(request.created_unix_ms)?);
        transaction.execute(
            "INSERT INTO jobs
             (id, run_id, job_key, attempt, status, requirements_json,
              created_unix_ms, completed_unix_ms, concurrency_group)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                job.id,
                request.id,
                job.job_key,
                i64::from(job.attempt),
                job_state_name(status),
                serde_json::to_string(&job.requirements)?,
                to_i64(request.created_unix_ms)?,
                completed,
                planned.concurrency,
            ],
        )?;
        transaction.execute(
            "INSERT INTO job_fencing(job_id, last_generation) VALUES (?1, 0)",
            [&job.id],
        )?;
    }
    if let Some(first) = request.jobs.first() {
        conclude_run_if_terminal_tx(transaction, &first.id, request.created_unix_ms)?;
    }
    Ok(())
}

pub(in crate::store) fn run_source_binding_ready_tx(
    transaction: &Transaction<'_>,
    run_id: &str,
    capsule: &ExecutionCapsule,
) -> Result<bool, ControlPlaneError> {
    let Some(tree_digest) = &capsule.context.source_tree_digest else {
        return Ok(true);
    };
    let capsule_digest = capsule.digest()?;
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM run_source_snapshots rss
                 JOIN source_snapshots s ON s.id = rss.source_snapshot_id
                 JOIN runs r ON r.id = rss.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 WHERE rss.run_id = ?1 AND rss.capsule_digest = ?2
                   AND s.state = 'ready' AND s.repository_id = r.repository_id
                   AND s.tenant_id = repo.tenant_id AND s.commit_sha = ?3
                   AND s.tree_manifest_digest = ?4
             )",
            params![
                run_id,
                capsule_digest.as_str(),
                capsule.context.source_commit.as_str(),
                tree_digest.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(in crate::store) fn queue_source_ready_roots_tx(
    transaction: &Transaction<'_>,
    run_id: &str,
    capsule: &ExecutionCapsule,
) -> Result<(), ControlPlaneError> {
    let states = initial_remote_job_states(capsule, true)?;
    for (job_key, state) in states {
        if state == JobState::Queued {
            transaction.execute(
                "UPDATE jobs SET status = 'queued'
                 WHERE run_id = ?1 AND job_key = ?2 AND status = 'created'",
                params![run_id, job_key],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::store) fn insert_run_and_jobs_tx(
    transaction: &Transaction<'_>,
    request: &CreateRunRequest,
) -> Result<(), ControlPlaneError> {
    insert_run_tx(transaction, request)?;
    insert_jobs_tx(transaction, request)
}

pub(in crate::store) fn insert_run_and_jobs_for_capsule_tx(
    transaction: &Transaction<'_>,
    request: &CreateRunRequest,
    capsule: &ExecutionCapsule,
) -> Result<(), ControlPlaneError> {
    insert_run_tx(transaction, request)?;
    insert_jobs_for_capsule_tx(transaction, request, capsule)
}

pub(in crate::store) fn bind_run_source_snapshot_tx(
    transaction: &Transaction<'_>,
    run: &CreateRunRequest,
    snapshot: &SourceSnapshotRecord,
    capsule_digest: &ContentDigest,
    capsule: &ExecutionCapsule,
    bound_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if snapshot.state != SourceSnapshotState::Ready
        || snapshot.repository_id != run.repository_id
        || snapshot.commit_sha != capsule.context.source_commit
        || capsule.context.source_tree_digest.as_ref() != Some(&snapshot.tree_manifest_digest)
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let tenant: Option<String> = transaction
        .query_row(
            "SELECT tenant_id FROM repositories WHERE id = ?1 AND tenant_id = ?2",
            params![run.repository_id, snapshot.tenant_id],
            |row| row.get(0),
        )
        .optional()?;
    if tenant.is_none() {
        return Err(ControlPlaneError::NotFound {
            kind: "ready run source snapshot",
            id: snapshot.id.clone(),
        });
    }
    let durable = source_snapshot_tx(transaction, &snapshot.tenant_id, &snapshot.id)?;
    if durable != *snapshot {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    transaction.execute(
        "INSERT INTO run_source_snapshots
         (run_id, source_snapshot_id, capsule_digest, bound_unix_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            run.id,
            snapshot.id,
            capsule_digest.as_str(),
            to_i64(bound_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn signed_capsule_conn(
    connection: &Connection,
    id: &str,
) -> Result<SignedCapsuleRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, repository_id, digest, canonical_capsule, signature_json, created_unix_ms
             FROM capsules WHERE id = ?1",
            [id],
            signed_capsule_row,
        )
        .optional()?
        .ok_or_else(|| not_found("capsule", id))
}

pub(in crate::store) fn signed_capsule_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<SignedCapsuleRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, repository_id, digest, canonical_capsule, signature_json, created_unix_ms
             FROM capsules WHERE id = ?1",
            [id],
            signed_capsule_row,
        )
        .optional()?
        .ok_or_else(|| not_found("capsule", id))
}

pub(in crate::store) fn capsule_api_metadata_tx(
    transaction: &Transaction<'_>,
    capsule_id: &str,
) -> Result<CapsuleApiMetadata, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT capsule_id, approval_subject_digest, risk_score
             FROM capsule_api_metadata WHERE capsule_id = ?1",
            [capsule_id],
            |row| {
                Ok(CapsuleApiMetadata {
                    capsule_id: row.get(0)?,
                    approval_subject_digest: digest_column(row, 1)?,
                    risk_score: row.get(2)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| not_found("capsule API metadata", capsule_id))
}

pub(in crate::store) fn validate_signed_capsule(
    capsule: &SignedCapsuleRecord,
    verifying_key: &CapsuleVerifyingKey,
) -> Result<String, ControlPlaneError> {
    validate_text("capsule.id", &capsule.id)?;
    validate_text("capsule.repository_id", &capsule.repository_id)?;
    let decoded: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule)?;
    if decoded.canonical_bytes()? != capsule.canonical_capsule {
        return Err(ControlPlaneError::NonCanonicalCapsule);
    }
    let actual_digest = ContentDigest::sha256(&capsule.canonical_capsule);
    if actual_digest != capsule.digest || capsule.signature.capsule_digest != capsule.digest {
        return Err(ControlPlaneError::CapsuleDigestMismatch {
            expected: capsule.digest.clone(),
            actual: actual_digest,
        });
    }
    verifying_key.verify_capsule(&decoded, &capsule.signature)?;
    Ok(serde_json::to_string(&capsule.signature)?)
}

impl ControlPlane {
    pub fn store_signed_capsule(
        &self,
        capsule: &SignedCapsuleRecord,
        verifying_key: &CapsuleVerifyingKey,
    ) -> Result<(), ControlPlaneError> {
        let signature_json = validate_signed_capsule(capsule, verifying_key)?;
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO capsules
             (id, repository_id, digest, canonical_capsule, signature_json, key_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                capsule.id,
                capsule.repository_id,
                capsule.digest.as_str(),
                capsule.canonical_capsule,
                signature_json,
                capsule.signature.key_id.as_str(),
                to_i64(capsule.created_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn store_compiled_capsule_idempotent(
        &self,
        idempotency_key: &str,
        capsule: &SignedCapsuleRecord,
        verifying_key: &CapsuleVerifyingKey,
        metadata: &CapsuleApiMetadata,
        approvals: &[ApprovalRequest],
    ) -> Result<IdempotentResult<SignedCapsuleRecord>, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        let signature_json = validate_signed_capsule(capsule, verifying_key)?;
        if metadata.capsule_id != capsule.id || metadata.risk_score > 100 {
            return Err(ControlPlaneError::InvalidInput(
                "capsule API metadata does not match the signed capsule",
            ));
        }
        let decoded_capsule: ExecutionCapsule = serde_json::from_slice(&capsule.canonical_capsule)?;
        let workflow_approvals = approvals
            .iter()
            .filter(|approval| approval.kind == runtrue_policy::ApprovalKind::WorkflowDefinition)
            .count();
        let privileged_approvals = approvals
            .iter()
            .filter(|approval| approval.kind == runtrue_policy::ApprovalKind::PrivilegedExecution)
            .count();
        let expected_count = usize::from(decoded_capsule.approval.workflow_definition)
            + usize::from(decoded_capsule.approval.privileged_execution);
        if workflow_approvals != usize::from(decoded_capsule.approval.workflow_definition)
            || privileged_approvals != usize::from(decoded_capsule.approval.privileged_execution)
            || approvals.len() != expected_count
        {
            return Err(ControlPlaneError::InvalidInput(
                "capsule approval requests do not match its independent gates",
            ));
        }
        for approval in approvals {
            let expected = ApprovalRequest::create(
                approval.id.clone(),
                approval.kind,
                approval.subject_digest.clone(),
                approval.risk_score,
                approval.created_unix_ms,
                approval.expires_unix_ms,
                approval.rule.clone(),
            )?;
            if &expected != approval
                || approval.subject_digest != metadata.approval_subject_digest
                || approval.risk_score != metadata.risk_score
            {
                return Err(ControlPlaneError::InvalidInput(
                    "approval request does not match capsule metadata",
                ));
            }
        }
        #[derive(Serialize)]
        struct Subject<'a> {
            repository_id: &'a str,
            digest: &'a ContentDigest,
            approval_subject_digest: &'a ContentDigest,
            risk_score: u32,
        }
        let request_hash = hash_serializable(&Subject {
            repository_id: &capsule.repository_id,
            digest: &capsule.digest,
            approval_subject_digest: &metadata.approval_subject_digest,
            risk_score: metadata.risk_score,
        })?;
        let operation = format!("capsule.create:{}", capsule.repository_id);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let value = signed_capsule_tx(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok(IdempotentResult {
                value,
                replayed: true,
            });
        }
        transaction.execute(
            "INSERT INTO capsules
             (id, repository_id, digest, canonical_capsule, signature_json, key_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                capsule.id,
                capsule.repository_id,
                capsule.digest.as_str(),
                capsule.canonical_capsule,
                signature_json,
                capsule.signature.key_id.as_str(),
                to_i64(capsule.created_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO capsule_api_metadata(capsule_id, approval_subject_digest, risk_score)
             VALUES (?1, ?2, ?3)",
            params![
                capsule.id,
                metadata.approval_subject_digest.as_str(),
                metadata.risk_score,
            ],
        )?;
        for approval in approvals {
            transaction.execute(
                "INSERT INTO approval_requests
                 (id, repository_id, capsule_id, subject_digest, status, request_json,
                  created_unix_ms, expires_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    approval.id,
                    capsule.repository_id,
                    capsule.id,
                    approval.subject_digest.as_str(),
                    approval_status_name(approval.status),
                    serde_json::to_string(approval)?,
                    to_i64(approval.created_unix_ms)?,
                    to_i64(approval.expires_unix_ms)?,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                capsule.id,
                to_i64(capsule.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: capsule.clone(),
            replayed: false,
        })
    }

    pub fn signed_capsule(&self, id: &str) -> Result<SignedCapsuleRecord, ControlPlaneError> {
        let connection = self.connection()?;
        signed_capsule_conn(&connection, id)
    }
}
