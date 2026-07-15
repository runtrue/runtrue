use super::*;
use rusqlite::params;

pub(in crate::store) fn scm_source_fetch_conn(
    connection: &Connection,
    tenant_id: &str,
    id: &str,
) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                    normalized_event_digest, source_commit, base_commit, origin_digest,
                    token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                    source_snapshot_id, state, attempts, last_error_code,
                    created_unix_ms, updated_unix_ms
             FROM scm_source_fetches WHERE id = ?1 AND tenant_id = ?2",
            params![id, tenant_id],
            scm_source_fetch_row,
        )
        .optional()?
        .ok_or_else(|| not_found("SCM source fetch", id))
}

pub(in crate::store) fn scm_source_fetch_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    id: &str,
) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                    normalized_event_digest, source_commit, base_commit, origin_digest,
                    token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                    source_snapshot_id, state, attempts, last_error_code,
                    created_unix_ms, updated_unix_ms
             FROM scm_source_fetches WHERE id = ?1 AND tenant_id = ?2",
            params![id, tenant_id],
            scm_source_fetch_row,
        )
        .optional()?
        .ok_or_else(|| not_found("SCM source fetch", id))
}

pub(in crate::store) fn scm_source_fetch_row(
    row: &Row<'_>,
) -> rusqlite::Result<ScmSourceFetchRecord> {
    let state: String = row.get(13)?;
    let state = match state.as_str() {
        "reserved" => ScmSourceFetchState::Reserved,
        "fetched" => ScmSourceFetchState::Fetched,
        "snapshot-ready" => ScmSourceFetchState::SnapshotReady,
        "committed" => ScmSourceFetchState::Committed,
        "failed" => ScmSourceFetchState::Failed,
        other => {
            return Err(conversion(
                13,
                DecodeError(format!("unknown SCM fetch state `{other}`")),
            ))
        }
    };
    let attempts = u64_column(row, 14, "SCM fetch attempts")?;
    Ok(ScmSourceFetchRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        installation_id: row.get(3)?,
        origin_task_id: row.get(4)?,
        normalized_event_digest: digest_column(row, 5)?,
        source_commit: row.get(6)?,
        base_commit: row.get(7)?,
        origin_digest: digest_column(row, 8)?,
        token_scope_digest: optional_digest_column(row, 9)?,
        mirror_identity_digest: optional_digest_column(row, 10)?,
        tree_manifest_digest: optional_digest_column(row, 11)?,
        source_snapshot_id: row.get(12)?,
        state,
        attempts: u32::try_from(attempts)
            .map_err(|error| conversion(14, DecodeError(error.to_string())))?,
        last_error_code: row.get(15)?,
        created_unix_ms: u64_column(row, 16, "SCM fetch created_unix_ms")?,
        updated_unix_ms: u64_column(row, 17, "SCM fetch updated_unix_ms")?,
    })
}

pub(in crate::store) const SCM_CHECK_COLUMNS: &str =
    "id, tenant_id, repository_id, installation_id, run_id, task_id, provider,
     commit_sha, logical_name, external_id, request_digest, annotation_count,
     provider_check_run_id, confirmed_annotations, state, attempts, last_error_code,
     created_unix_ms, updated_unix_ms";

impl ControlPlane {
    pub fn reserve_scm_source_fetch(
        &self,
        request: &ReserveScmSourceFetch,
    ) -> Result<IdempotentResult<ScmSourceFetchRecord>, ControlPlaneError> {
        for (field, value) in [
            ("SCM fetch id", request.id.as_str()),
            ("SCM fetch tenant", request.tenant_id.as_str()),
            ("SCM fetch repository", request.repository_id.as_str()),
            ("SCM fetch installation", request.installation_id.as_str()),
            ("SCM fetch task", request.origin_task_id.as_str()),
            ("SCM fetch source commit", request.source_commit.as_str()),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM durable_tasks t
                JOIN repositories r ON r.id = ?2 AND r.tenant_id = ?1
                JOIN scm_repository_links l ON l.repository_id = r.id AND l.tenant_id = r.tenant_id
                JOIN scm_installations i ON i.id = l.installation_id AND i.tenant_id = l.tenant_id
                WHERE t.id = ?4 AND t.kind = 'scm.event' AND l.installation_id = ?3
                  AND i.status = 'active' AND l.status = 'active'
             )",
            params![
                request.tenant_id,
                request.repository_id,
                request.installation_id,
                request.origin_task_id
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::NotFound {
                kind: "SCM fetch authorization",
                id: request.id.clone(),
            });
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO scm_source_fetches
             (id, tenant_id, repository_id, installation_id, origin_task_id,
              normalized_event_digest, source_commit, base_commit, origin_digest,
              state, attempts, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'reserved', 1, ?10, ?10)",
            params![
                request.id,
                request.tenant_id,
                request.repository_id,
                request.installation_id,
                request.origin_task_id,
                request.normalized_event_digest.as_str(),
                request.source_commit,
                request.base_commit,
                request.origin_digest.as_str(),
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let mut existing = scm_source_fetch_tx(&transaction, &request.tenant_id, &request.id)?;
        if existing.repository_id != request.repository_id
            || existing.installation_id != request.installation_id
            || existing.normalized_event_digest != request.normalized_event_digest
            || existing.source_commit != request.source_commit
            || existing.base_commit != request.base_commit
            || existing.origin_digest != request.origin_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if inserted == 0 {
            transaction.execute(
                "UPDATE scm_source_fetches SET attempts = attempts + 1, updated_unix_ms = ?3
                 WHERE id = ?1 AND tenant_id = ?2",
                params![request.id, request.tenant_id, to_i64(request.now_unix_ms)?],
            )?;
            existing = scm_source_fetch_tx(&transaction, &request.tenant_id, &request.id)?;
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        })
    }

    pub fn record_scm_fetch_snapshot_ready(
        &self,
        request: &RecordScmFetchSnapshotReady,
    ) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = scm_source_fetch_tx(&transaction, &request.tenant_id, &request.fetch_id)?;
        let changed = current
            .token_scope_digest
            .as_ref()
            .is_some_and(|v| v != &request.token_scope_digest)
            || current
                .mirror_identity_digest
                .as_ref()
                .is_some_and(|v| v != &request.mirror_identity_digest)
            || current
                .tree_manifest_digest
                .as_ref()
                .is_some_and(|v| v != &request.tree_manifest_digest)
            || current
                .source_snapshot_id
                .as_deref()
                .is_some_and(|v| v != request.source_snapshot_id);
        if changed || matches!(current.state, ScmSourceFetchState::Failed) {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE scm_source_fetches
             SET token_scope_digest = ?3, mirror_identity_digest = ?4,
                 tree_manifest_digest = ?5, source_snapshot_id = ?6,
                 state = CASE WHEN state = 'committed' THEN state ELSE 'snapshot-ready' END,
                 updated_unix_ms = ?7
             WHERE id = ?1 AND tenant_id = ?2",
            params![
                request.fetch_id,
                request.tenant_id,
                request.token_scope_digest.as_str(),
                request.mirror_identity_digest.as_str(),
                request.tree_manifest_digest.as_str(),
                request.source_snapshot_id,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let record = scm_source_fetch_tx(&transaction, &request.tenant_id, &request.fetch_id)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn mark_scm_fetch_committed(
        &self,
        tenant_id: &str,
        fetch_id: &str,
        now_unix_ms: u64,
    ) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE scm_source_fetches SET state = 'committed', updated_unix_ms = ?3
             WHERE id = ?1 AND tenant_id = ?2
               AND state IN ('snapshot-ready', 'committed')",
            params![fetch_id, tenant_id, to_i64(now_unix_ms)?],
        )?;
        if changed == 0 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        scm_source_fetch_conn(&connection, tenant_id, fetch_id)
    }

    pub fn scm_source_fetch(
        &self,
        tenant_id: &str,
        fetch_id: &str,
    ) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
        let connection = self.connection()?;
        scm_source_fetch_conn(&connection, tenant_id, fetch_id)
    }

    pub fn scm_source_fetch_for_task(
        &self,
        tenant_id: &str,
        task_id: &str,
    ) -> Result<ScmSourceFetchRecord, ControlPlaneError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, tenant_id, repository_id, installation_id, origin_task_id,
                        normalized_event_digest, source_commit, base_commit, origin_digest,
                        token_scope_digest, mirror_identity_digest, tree_manifest_digest,
                        source_snapshot_id, state, attempts, last_error_code,
                        created_unix_ms, updated_unix_ms
                 FROM scm_source_fetches
                 WHERE origin_task_id = ?1 AND tenant_id = ?2",
                params![task_id, tenant_id],
                scm_source_fetch_row,
            )
            .optional()?
            .ok_or_else(|| not_found("SCM source fetch", task_id))
    }
}
