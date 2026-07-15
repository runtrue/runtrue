use super::*;
use rusqlite::params;

pub(in crate::store) fn scm_check_publication_conn(
    connection: &Connection,
    tenant_id: &str,
    id: &str,
) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
    connection
        .query_row(
            &format!(
                "SELECT {SCM_CHECK_COLUMNS}
                 FROM scm_check_publications WHERE id = ?1 AND tenant_id = ?2"
            ),
            params![id, tenant_id],
            scm_check_publication_row,
        )
        .optional()?
        .ok_or_else(|| not_found("SCM check publication", id))
}

pub(in crate::store) fn scm_check_publication_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    id: &str,
) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {SCM_CHECK_COLUMNS}
                 FROM scm_check_publications WHERE id = ?1 AND tenant_id = ?2"
            ),
            params![id, tenant_id],
            scm_check_publication_row,
        )
        .optional()?
        .ok_or_else(|| not_found("SCM check publication", id))
}

pub(in crate::store) fn scm_check_publication_row(
    row: &Row<'_>,
) -> rusqlite::Result<ScmCheckPublicationRecord> {
    let state: String = row.get(14)?;
    let state = match state.as_str() {
        "reserved" => ScmCheckPublicationState::Reserved,
        "reconciling" => ScmCheckPublicationState::Reconciling,
        "published" => ScmCheckPublicationState::Published,
        "failed" => ScmCheckPublicationState::Failed,
        other => {
            return Err(conversion(
                14,
                DecodeError(format!("unknown SCM check state `{other}`")),
            ))
        }
    };
    let annotation_count = u64_column(row, 11, "SCM check annotation count")?;
    let confirmed_annotations = u64_column(row, 13, "SCM check confirmed annotations")?;
    let attempts = u64_column(row, 15, "SCM check attempts")?;
    Ok(ScmCheckPublicationRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        installation_id: row.get(3)?,
        run_id: row.get(4)?,
        task_id: row.get(5)?,
        provider: row.get(6)?,
        commit_sha: row.get(7)?,
        logical_name: row.get(8)?,
        external_id: row.get(9)?,
        request_digest: digest_column(row, 10)?,
        annotation_count: u32::try_from(annotation_count)
            .map_err(|error| conversion(11, DecodeError(error.to_string())))?,
        provider_check_run_id: optional_u64_column(row, 12, "provider check run id")?,
        confirmed_annotations: u32::try_from(confirmed_annotations)
            .map_err(|error| conversion(13, DecodeError(error.to_string())))?,
        state,
        attempts: u32::try_from(attempts)
            .map_err(|error| conversion(15, DecodeError(error.to_string())))?,
        last_error_code: row.get(16)?,
        created_unix_ms: u64_column(row, 17, "SCM check created_unix_ms")?,
        updated_unix_ms: u64_column(row, 18, "SCM check updated_unix_ms")?,
    })
}

impl ControlPlane {
    pub fn reserve_scm_check_publication(
        &self,
        request: &ReserveScmCheckPublication,
    ) -> Result<IdempotentResult<ScmCheckPublicationRecord>, ControlPlaneError> {
        for (field, value) in [
            ("SCM check publication id", request.id.as_str()),
            ("SCM check tenant", request.tenant_id.as_str()),
            ("SCM check repository", request.repository_id.as_str()),
            ("SCM check installation", request.installation_id.as_str()),
            ("SCM check run", request.run_id.as_str()),
            ("SCM check task", request.task_id.as_str()),
            ("SCM check worker", request.worker_id.as_str()),
            ("SCM check commit", request.commit_sha.as_str()),
            ("SCM check logical name", request.logical_name.as_str()),
            ("SCM check external id", request.external_id.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if !matches!(request.commit_sha.len(), 40 | 64)
            || !request
                .commit_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControlPlaneError::InvalidInput("invalid SCM check commit"));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(
            &transaction,
            &request.task_id,
            &request.worker_id,
            request.now_unix_ms,
        )?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM durable_tasks t
                JOIN repositories r ON r.id = ?2 AND r.tenant_id = ?1
                JOIN scm_repository_links l ON l.repository_id = r.id
                    AND l.tenant_id = r.tenant_id AND l.installation_id = ?3
                JOIN scm_installations i ON i.id = l.installation_id
                    AND i.tenant_id = l.tenant_id
                JOIN runs run ON run.id = ?4 AND run.repository_id = r.id
                WHERE t.id = ?5 AND t.kind = 'scm.check.publish'
                    AND i.provider = 'github' AND i.status = 'active'
                    AND l.status = 'active'
             )",
            params![
                request.tenant_id,
                request.repository_id,
                request.installation_id,
                request.run_id,
                request.task_id,
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::NotFound {
                kind: "SCM check authorization",
                id: request.id.clone(),
            });
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO scm_check_publications
             (id, tenant_id, repository_id, installation_id, run_id, task_id,
              provider, commit_sha, logical_name, external_id, request_digest,
              annotation_count, state, attempts, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'github', ?7, ?8, ?9, ?10,
                     ?11, 'reserved', 1, ?12, ?12)",
            params![
                request.id,
                request.tenant_id,
                request.repository_id,
                request.installation_id,
                request.run_id,
                request.task_id,
                request.commit_sha,
                request.logical_name,
                request.external_id,
                request.request_digest.as_str(),
                request.annotation_count,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let mut existing = scm_check_publication_tx(&transaction, &request.tenant_id, &request.id)?;
        if existing.repository_id != request.repository_id
            || existing.installation_id != request.installation_id
            || existing.run_id != request.run_id
            || existing.task_id != request.task_id
            || existing.commit_sha != request.commit_sha
            || existing.logical_name != request.logical_name
            || existing.external_id != request.external_id
            || existing.request_digest != request.request_digest
            || existing.annotation_count != request.annotation_count
            || request.now_unix_ms < existing.updated_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if inserted == 0 {
            transaction.execute(
                "UPDATE scm_check_publications
                 SET attempts = attempts + 1, updated_unix_ms = ?3
                 WHERE id = ?1 AND tenant_id = ?2",
                params![request.id, request.tenant_id, to_i64(request.now_unix_ms)?],
            )?;
            existing = scm_check_publication_tx(&transaction, &request.tenant_id, &request.id)?;
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        })
    }

    pub fn record_scm_check_progress(
        &self,
        request: &RecordScmCheckProgress,
    ) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
        if request.provider_check_run_id == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "invalid provider check run id",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(
            &transaction,
            &request.task_id,
            &request.worker_id,
            request.now_unix_ms,
        )?;
        let current =
            scm_check_publication_tx(&transaction, &request.tenant_id, &request.publication_id)?;
        if current.task_id != request.task_id
            || matches!(current.state, ScmCheckPublicationState::Failed)
            || current
                .provider_check_run_id
                .is_some_and(|id| id != request.provider_check_run_id)
            || request.confirmed_annotations < current.confirmed_annotations
            || request.confirmed_annotations > current.annotation_count
            || request.now_unix_ms < current.updated_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if current.state == ScmCheckPublicationState::Published {
            transaction.commit()?;
            return Ok(current);
        }
        transaction.execute(
            "UPDATE scm_check_publications
             SET provider_check_run_id = ?3, confirmed_annotations = ?4,
                 state = CASE WHEN state = 'published' THEN state ELSE 'reconciling' END,
                 last_error_code = NULL, updated_unix_ms = ?5
             WHERE id = ?1 AND tenant_id = ?2",
            params![
                request.publication_id,
                request.tenant_id,
                to_i64(request.provider_check_run_id)?,
                request.confirmed_annotations,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let record =
            scm_check_publication_tx(&transaction, &request.tenant_id, &request.publication_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn mark_scm_check_published(
        &self,
        tenant_id: &str,
        publication_id: &str,
        task_id: &str,
        worker_id: &str,
        now_unix_ms: u64,
    ) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(&transaction, task_id, worker_id, now_unix_ms)?;
        let current = scm_check_publication_tx(&transaction, tenant_id, publication_id)?;
        if current.task_id != task_id
            || current.provider_check_run_id.is_none()
            || current.confirmed_annotations != current.annotation_count
            || matches!(current.state, ScmCheckPublicationState::Failed)
            || now_unix_ms < current.updated_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if current.state == ScmCheckPublicationState::Published {
            transaction.commit()?;
            return Ok(current);
        }
        transaction.execute(
            "UPDATE scm_check_publications
             SET state = 'published', last_error_code = NULL, updated_unix_ms = ?3
             WHERE id = ?1 AND tenant_id = ?2",
            params![publication_id, tenant_id, to_i64(now_unix_ms)?],
        )?;
        let record = scm_check_publication_tx(&transaction, tenant_id, publication_id)?;
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id: tenant_id.to_owned(),
                actor: AuditPrincipal {
                    kind: "scm-worker".to_owned(),
                    id: "scm-check-reconciler".to_owned(),
                },
                action: "scm.check.publish".to_owned(),
                resource: AuditResource {
                    kind: "scm-check-publication".to_owned(),
                    id: publication_id.to_owned(),
                },
                result: "success".to_owned(),
                request_id: record.task_id.clone(),
                decision_id: None,
                metadata: BTreeMap::from([
                    (
                        "request_digest".to_owned(),
                        AuditValue::Digest(record.request_digest.clone()),
                    ),
                    (
                        "provider_check_run_id".to_owned(),
                        AuditValue::Integer(
                            i64::try_from(record.provider_check_run_id.ok_or_else(|| {
                                ControlPlaneError::CorruptState(
                                    "published SCM check has no provider id".to_owned(),
                                )
                            })?)
                            .map_err(|_| {
                                ControlPlaneError::IntegerRange {
                                    field: "provider check run id",
                                }
                            })?,
                        ),
                    ),
                ]),
            },
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_scm_check_failure(
        &self,
        request: &RecordScmCheckFailure,
    ) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
        validate_text("SCM check failure code", &request.error_code)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(
            &transaction,
            &request.task_id,
            &request.worker_id,
            request.now_unix_ms,
        )?;
        let current =
            scm_check_publication_tx(&transaction, &request.tenant_id, &request.publication_id)?;
        if current.task_id != request.task_id
            || matches!(current.state, ScmCheckPublicationState::Published)
            || request.now_unix_ms < current.updated_unix_ms
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE scm_check_publications
             SET state = CASE WHEN ?4 THEN 'failed' ELSE 'reconciling' END,
                 last_error_code = ?3, updated_unix_ms = ?5
             WHERE id = ?1 AND tenant_id = ?2",
            params![
                request.publication_id,
                request.tenant_id,
                request.error_code,
                request.terminal,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let record =
            scm_check_publication_tx(&transaction, &request.tenant_id, &request.publication_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn scm_check_publication(
        &self,
        tenant_id: &str,
        publication_id: &str,
    ) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
        validate_text("SCM check tenant", tenant_id)?;
        validate_text("SCM check publication", publication_id)?;
        let connection = self.connection()?;
        scm_check_publication_conn(&connection, tenant_id, publication_id)
    }

    pub fn scm_check_publication_by_provider_run(
        &self,
        tenant_id: &str,
        repository_id: &str,
        installation_id: &str,
        provider_check_run_id: u64,
    ) -> Result<ScmCheckPublicationRecord, ControlPlaneError> {
        validate_text("SCM check tenant", tenant_id)?;
        validate_text("SCM check repository", repository_id)?;
        validate_text("SCM check installation", installation_id)?;
        if provider_check_run_id == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "invalid provider check run id",
            ));
        }
        let connection = self.connection()?;
        connection
            .query_row(
                &format!(
                    "SELECT {SCM_CHECK_COLUMNS}
             FROM scm_check_publications
             WHERE tenant_id = ?1 AND repository_id = ?2
               AND installation_id = ?3 AND provider = 'github'
               AND provider_check_run_id = ?4
             ORDER BY created_unix_ms DESC, id DESC LIMIT 1"
                ),
                params![
                    tenant_id,
                    repository_id,
                    installation_id,
                    to_i64(provider_check_run_id)?,
                ],
                scm_check_publication_row,
            )
            .optional()?
            .ok_or_else(|| not_found("SCM provider check run", &provider_check_run_id.to_string()))
    }
}
