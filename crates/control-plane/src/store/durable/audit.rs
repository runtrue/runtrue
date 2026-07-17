use super::*;

impl ControlPlane {
    pub fn append_audit_event(
        &self,
        data: AuditEventData,
    ) -> Result<AuditEvent, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = append_audit_event_tx(&transaction, &self.installation_id, data)?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn audit_events(&self) -> Result<Vec<AuditEvent>, ControlPlaneError> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT event_json FROM audit_events ORDER BY sequence")?;
        let events = statement
            .query_map([], |row| json_column(row, 0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        verify_chain(&events)?;
        Ok(events)
    }

    pub fn capsule_api_metadata(
        &self,
        capsule_id: &str,
    ) -> Result<CapsuleApiMetadata, ControlPlaneError> {
        let connection = self.connection()?;
        connection
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

    pub fn list_runs_page(
        &self,
        repository_id: Option<&str>,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RunRecord>, ControlPlaneError> {
        validate_page(limit, after_id)?;
        if let Some(repository_id) = repository_id {
            validate_text("repository id", repository_id)?;
        }
        let connection = self.connection()?;
        let sql = match (repository_id, after_id) {
            (Some(_), Some(_)) => {
                "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                        started_unix_ms, completed_unix_ms, cancel_reason
                 FROM runs
                 WHERE repository_id = ?1
                   AND (created_unix_ms < (SELECT created_unix_ms FROM runs WHERE id = ?2)
                        OR (created_unix_ms = (SELECT created_unix_ms FROM runs WHERE id = ?2)
                            AND id < ?2))
                 ORDER BY created_unix_ms DESC, id DESC LIMIT ?3"
            }
            (Some(_), None) => {
                "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                        started_unix_ms, completed_unix_ms, cancel_reason
                 FROM runs WHERE repository_id = ?1
                 ORDER BY created_unix_ms DESC, id DESC LIMIT ?3"
            }
            (None, Some(_)) => {
                "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                        started_unix_ms, completed_unix_ms, cancel_reason
                 FROM runs
                 WHERE created_unix_ms < (SELECT created_unix_ms FROM runs WHERE id = ?2)
                    OR (created_unix_ms = (SELECT created_unix_ms FROM runs WHERE id = ?2)
                        AND id < ?2)
                 ORDER BY created_unix_ms DESC, id DESC LIMIT ?3"
            }
            (None, None) => {
                "SELECT id, repository_id, capsule_id, status, priority, remote, created_unix_ms,
                        started_unix_ms, completed_unix_ms, cancel_reason
                 FROM runs ORDER BY created_unix_ms DESC, id DESC LIMIT ?3"
            }
        };
        let mut statement = connection.prepare(sql)?;
        let repository = repository_id.unwrap_or("");
        let cursor = after_id.unwrap_or("");
        let values = statement
            .query_map(
                params![
                    repository,
                    cursor,
                    i64::try_from(limit).map_err(|_| {
                        ControlPlaneError::InvalidInput("page limit is out of range")
                    })?
                ],
                run_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
}

impl ControlPlane {
    pub fn list_runs_page_for_tenant(
        &self,
        tenant_id: &str,
        repository_id: Option<&str>,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RunRecord>, ControlPlaneError> {
        validate_text("run tenant", tenant_id)?;
        validate_page(limit, after_id)?;
        if let Some(repository_id) = repository_id {
            validate_text("repository id", repository_id)?;
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT r.id, r.repository_id, r.capsule_id, r.status, r.priority, r.remote,
                    r.created_unix_ms, r.started_unix_ms, r.completed_unix_ms, r.cancel_reason
             FROM runs r JOIN repositories repo ON repo.id = r.repository_id
             WHERE repo.tenant_id = ?1
               AND (?2 = '' OR r.repository_id = ?2)
               AND (?3 = ''
                    OR r.created_unix_ms < (SELECT created_unix_ms FROM runs WHERE id = ?3)
                    OR (r.created_unix_ms = (SELECT created_unix_ms FROM runs WHERE id = ?3)
                        AND r.id < ?3))
             ORDER BY r.created_unix_ms DESC, r.id DESC LIMIT ?4",
        )?;
        let values = statement
            .query_map(
                params![
                    tenant_id,
                    repository_id.unwrap_or(""),
                    after_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?
                ],
                run_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
}

impl ControlPlane {
    pub fn list_approval_requests_page(
        &self,
        status: Option<&str>,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
        validate_page(limit, after_id)?;
        if let Some(status) = status {
            validate_text("approval status", status)?;
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT request_json FROM approval_requests
             WHERE (?1 = '' OR status = ?1)
               AND (?2 = ''
                    OR created_unix_ms < (SELECT created_unix_ms FROM approval_requests WHERE id = ?2)
                    OR (created_unix_ms = (SELECT created_unix_ms FROM approval_requests WHERE id = ?2)
                        AND id < ?2))
             ORDER BY created_unix_ms DESC, id DESC LIMIT ?3",
        )?;
        let values = statement
            .query_map(
                params![
                    status.unwrap_or(""),
                    after_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?
                ],
                |row| json_column(row, 0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
}

impl ControlPlane {
    pub fn list_approval_requests_page_for_tenant(
        &self,
        tenant_id: &str,
        status: Option<&str>,
        after_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApprovalRequest>, ControlPlaneError> {
        validate_text("approval tenant", tenant_id)?;
        validate_page(limit, after_id)?;
        if let Some(status) = status {
            validate_text("approval status", status)?;
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT a.request_json FROM approval_requests a
             JOIN repositories repo ON repo.id = a.repository_id
             WHERE repo.tenant_id = ?1
               AND (?2 = '' OR a.status = ?2)
               AND (?3 = ''
                    OR a.created_unix_ms < (SELECT created_unix_ms FROM approval_requests WHERE id = ?3)
                    OR (a.created_unix_ms = (SELECT created_unix_ms FROM approval_requests WHERE id = ?3)
                        AND a.id < ?3))
             ORDER BY a.created_unix_ms DESC, a.id DESC LIMIT ?4",
        )?;
        let values = statement
            .query_map(
                params![
                    tenant_id,
                    status.unwrap_or(""),
                    after_id.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?
                ],
                |row| json_column(row, 0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    pub fn approval_request_tenant(&self, id: &str) -> Result<String, ControlPlaneError> {
        validate_text("approval id", id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT repo.tenant_id FROM approval_requests a
                 JOIN repositories repo ON repo.id = a.repository_id WHERE a.id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("approval", id))
    }

    pub fn audit_events_page(
        &self,
        action: Option<&str>,
        before_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ControlPlaneError> {
        validate_page(limit, None)?;
        if let Some(action) = action {
            validate_text("audit action", action)?;
        }
        let events = self.audit_events()?;
        Ok(events
            .into_iter()
            .rev()
            .filter(|event| before_sequence.is_none_or(|cursor| event.sequence < cursor))
            .filter(|event| action.is_none_or(|wanted| event.data.action == wanted))
            .take(limit)
            .collect())
    }

    pub fn audit_events_page_for_tenant(
        &self,
        tenant_id: &str,
        action: Option<&str>,
        before_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ControlPlaneError> {
        validate_text("audit tenant", tenant_id)?;
        validate_page(limit, None)?;
        if let Some(action) = action {
            validate_text("audit action", action)?;
        }
        // Verify the complete chain before returning a tenant-filtered view.
        // The externally visible page is selected in SQL and never contains
        // another tenant's event.
        self.audit_events()?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT event_json FROM audit_events
             WHERE json_extract(event_json, '$.data.tenant_id') = ?1
               AND (?2 = 0 OR sequence < ?2)
               AND (?3 = '' OR json_extract(event_json, '$.data.action') = ?3)
             ORDER BY sequence DESC LIMIT ?4",
        )?;
        let values = statement
            .query_map(
                params![
                    tenant_id,
                    to_i64(before_sequence.unwrap_or(0))?,
                    action.unwrap_or(""),
                    i64::try_from(limit).map_err(|_| ControlPlaneError::InvalidInput(
                        "page limit is out of range"
                    ))?
                ],
                |row| json_column(row, 0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
}
