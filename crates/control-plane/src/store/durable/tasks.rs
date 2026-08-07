use super::*;

pub(in crate::store) fn parse_durable_task_status(
    value: &str,
) -> Result<DurableTaskStatus, DecodeError> {
    match value {
        "pending" => Ok(DurableTaskStatus::Pending),
        "claimed" => Ok(DurableTaskStatus::Claimed),
        "completed" => Ok(DurableTaskStatus::Completed),
        "failed" => Ok(DurableTaskStatus::Failed),
        _ => Err(DecodeError(format!("unknown task status `{value}`"))),
    }
}

pub(in crate::store) fn task_conn(
    connection: &Connection,
    id: &str,
) -> Result<DurableTask, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, kind, payload_json, status, available_unix_ms, attempts,
                    lease_owner, lease_expires_unix_ms, last_error, created_unix_ms,
                    completed_unix_ms FROM durable_tasks WHERE id = ?1",
            [id],
            task_row,
        )
        .optional()?
        .ok_or_else(|| not_found("task", id))
}

pub(in crate::store) fn task_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<DurableTask, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id, kind, payload_json, status, available_unix_ms, attempts,
                    lease_owner, lease_expires_unix_ms, last_error, created_unix_ms,
                    completed_unix_ms FROM durable_tasks WHERE id = ?1",
            [id],
            task_row,
        )
        .optional()?
        .ok_or_else(|| not_found("task", id))
}

pub(in crate::store) fn task_row(row: &Row<'_>) -> rusqlite::Result<DurableTask> {
    let status: String = row.get(3)?;
    let attempts: i64 = row.get(5)?;
    Ok(DurableTask {
        id: row.get(0)?,
        kind: row.get(1)?,
        payload: json_column(row, 2)?,
        status: parse_durable_task_status(&status).map_err(|error| conversion(3, error))?,
        available_unix_ms: u64_column(row, 4, "available_unix_ms")?,
        attempts: u32::try_from(attempts).map_err(|error| conversion(5, error))?,
        lease_owner: row.get(6)?,
        lease_expires_unix_ms: optional_u64_column(row, 7, "lease_expires_unix_ms")?,
        last_error: row.get(8)?,
        created_unix_ms: u64_column(row, 9, "created_unix_ms")?,
        completed_unix_ms: optional_u64_column(row, 10, "completed_unix_ms")?,
    })
}

pub(in crate::store) fn require_task_owner_tx(
    transaction: &Transaction<'_>,
    task_id: &str,
    worker: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let task = task_tx(transaction, task_id)?;
    if task.status != DurableTaskStatus::Claimed || task.lease_owner.as_deref() != Some(worker) {
        return Err(ControlPlaneError::TaskNotOwned);
    }
    if task
        .lease_expires_unix_ms
        .is_none_or(|expires| now_unix_ms >= expires)
    {
        return Err(ControlPlaneError::TaskLeaseExpired);
    }
    Ok(())
}

pub(in crate::store) fn mark_task_completed_tx(
    transaction: &Transaction<'_>,
    task_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "UPDATE durable_tasks SET status = 'completed', completed_unix_ms = ?2,
         lease_owner = NULL, lease_expires_unix_ms = NULL WHERE id = ?1",
        params![task_id, to_i64(now_unix_ms)?],
    )?;
    Ok(())
}

impl ControlPlane {
    pub fn enqueue_task(&self, task: &DurableTask) -> Result<(), ControlPlaneError> {
        validate_text("task.id", &task.id)?;
        validate_text("task.kind", &task.kind)?;
        if task.status != DurableTaskStatus::Pending
            || task.attempts != 0
            || task.lease_owner.is_some()
            || task.lease_expires_unix_ms.is_some()
            || task.completed_unix_ms.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "new durable task must be unclaimed and pending",
            ));
        }
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO durable_tasks
             (id, kind, payload_json, status, available_unix_ms, attempts,
              last_error, created_unix_ms)
             VALUES (?1, ?2, ?3, 'pending', ?4, 0, ?5, ?6)",
            params![
                task.id,
                task.kind,
                serde_json::to_string(&canonicalize_json(task.payload.clone()))?,
                to_i64(task.available_unix_ms)?,
                task.last_error,
                to_i64(task.created_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    /// Atomically complete an owned task and enqueue a bounded deterministic
    /// set of follow-up tasks. Existing identical follow-ups are accepted so
    /// replayed deliveries converge without duplicating downstream work.
    pub fn complete_task_with_followups(
        &self,
        task_id: &str,
        worker: &str,
        followups: &[DurableTask],
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        const MAX_FOLLOWUPS: usize = 64;
        validate_text("task.id", task_id)?;
        validate_text("task.worker", worker)?;
        if followups.len() > MAX_FOLLOWUPS {
            return Err(ControlPlaneError::InvalidInput(
                "too many durable task follow-ups",
            ));
        }
        let mut ids = BTreeSet::new();
        for followup in followups {
            validate_text("follow-up task.id", &followup.id)?;
            validate_text("follow-up task.kind", &followup.kind)?;
            if followup.id == task_id
                || !ids.insert(followup.id.as_str())
                || followup.status != DurableTaskStatus::Pending
                || followup.attempts != 0
                || followup.lease_owner.is_some()
                || followup.lease_expires_unix_ms.is_some()
                || followup.completed_unix_ms.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "follow-up tasks must be distinct, new, and pending",
                ));
            }
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(&transaction, task_id, worker, now_unix_ms)?;
        for followup in followups {
            let payload = canonicalize_json(followup.payload.clone());
            let encoded = serde_json::to_string(&payload)?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO durable_tasks
                 (id, kind, payload_json, status, available_unix_ms, attempts,
                  last_error, created_unix_ms)
                 VALUES (?1, ?2, ?3, 'pending', ?4, 0, ?5, ?6)",
                params![
                    followup.id,
                    followup.kind,
                    encoded,
                    to_i64(followup.available_unix_ms)?,
                    followup.last_error,
                    to_i64(followup.created_unix_ms)?,
                ],
            )?;
            if inserted == 0 {
                let existing = task_tx(&transaction, &followup.id)?;
                if existing.kind != followup.kind || existing.payload != payload {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            }
        }
        mark_task_completed_tx(&transaction, task_id, now_unix_ms)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn claim_task(
        &self,
        worker: &str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<DurableTask>, ControlPlaneError> {
        validate_text("task.worker", worker)?;
        if lease_duration_ms == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "task lease duration must be positive",
            ));
        }
        let lease_expires =
            now_unix_ms
                .checked_add(lease_duration_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "task lease expiry",
                })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE durable_tasks SET status = 'pending', lease_owner = NULL,
             lease_expires_unix_ms = NULL
             WHERE status = 'claimed' AND lease_expires_unix_ms <= ?1",
            [to_i64(now_unix_ms)?],
        )?;
        let id: Option<String> = transaction
            .query_row(
                "SELECT id FROM durable_tasks
                 WHERE status = 'pending' AND available_unix_ms <= ?1
                 ORDER BY available_unix_ms, id LIMIT 1",
                [to_i64(now_unix_ms)?],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE durable_tasks SET status = 'claimed', attempts = attempts + 1,
             lease_owner = ?2, lease_expires_unix_ms = ?3 WHERE id = ?1",
            params![id, worker, to_i64(lease_expires)?],
        )?;
        let task = task_tx(&transaction, &id)?;
        transaction.commit()?;
        Ok(Some(task))
    }

    /// Claim only work of the requested durable kind. This prevents a
    /// specialized worker from consuming tasks owned by another subsystem.
    pub fn claim_task_by_kind(
        &self,
        worker: &str,
        kind: &str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<DurableTask>, ControlPlaneError> {
        validate_text("task.worker", worker)?;
        validate_text("task.kind", kind)?;
        if lease_duration_ms == 0 {
            return Err(ControlPlaneError::InvalidInput(
                "task lease duration must be positive",
            ));
        }
        let lease_expires =
            now_unix_ms
                .checked_add(lease_duration_ms)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "task lease expiry",
                })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE durable_tasks SET status = 'pending', lease_owner = NULL,
             lease_expires_unix_ms = NULL
             WHERE kind = ?1 AND status = 'claimed' AND lease_expires_unix_ms <= ?2",
            params![kind, to_i64(now_unix_ms)?],
        )?;
        if kind == crate::SCM_EVENT_TASK_KIND {
            transaction.execute(
                "UPDATE durable_tasks
                 SET recoverable_until_unix_ms = created_unix_ms + 86400000
                 WHERE kind = 'scm.event' AND status = 'failed'
                   AND recoverable_until_unix_ms IS NULL
                   AND created_unix_ms <= 9223372036768375807
                   AND created_unix_ms + 86400000 > ?1
                   AND last_error IN (
                     'repository-action preparation is temporarily unavailable',
                     'GitHub actor permission lookup is unavailable',
                     'Git mirror repository is unavailable or unsafe',
                     'source manifest CAS publication failed',
                     'Git mirror repository changed while planning',
                     'exact Git revision or trusted workflow is unavailable',
                     'exact reusable workflow mirror or object is unavailable',
                     'source snapshot construction is temporarily unavailable',
                     'restore safe mode blocked the SCM event commit'
                   )",
                [to_i64(now_unix_ms)?],
            )?;
        }
        transaction.execute(
            "UPDATE durable_tasks SET status = 'failed', available_unix_ms = ?2,
             completed_unix_ms = ?2, lease_owner = NULL, lease_expires_unix_ms = NULL
             WHERE kind = ?1 AND status = 'pending'
               AND recoverable_until_unix_ms IS NOT NULL
               AND recoverable_until_unix_ms <= ?2",
            params![kind, to_i64(now_unix_ms)?],
        )?;
        let id: Option<String> = transaction
            .query_row(
                "SELECT id FROM durable_tasks
                 WHERE kind = ?1 AND (
                   (status = 'pending' AND available_unix_ms <= ?2)
                   OR (status = 'failed' AND ?1 = 'scm.event'
                       AND recoverable_until_unix_ms > ?2)
                 )
                 ORDER BY available_unix_ms, id LIMIT 1",
                params![kind, to_i64(now_unix_ms)?],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE durable_tasks SET status = 'claimed', attempts = attempts + 1,
             lease_owner = ?2, lease_expires_unix_ms = ?3, completed_unix_ms = NULL
             WHERE id = ?1 AND status IN ('pending', 'failed')",
            params![id, worker, to_i64(lease_expires)?],
        )?;
        let task = task_tx(&transaction, &id)?;
        transaction.commit()?;
        Ok(Some(task))
    }

    pub fn complete_task(
        &self,
        task_id: &str,
        worker: &str,
        now_unix_ms: u64,
    ) -> Result<DurableTask, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(&transaction, task_id, worker, now_unix_ms)?;
        transaction.execute(
            "UPDATE durable_tasks SET status = 'completed', completed_unix_ms = ?2,
             lease_owner = NULL, lease_expires_unix_ms = NULL WHERE id = ?1",
            params![task_id, to_i64(now_unix_ms)?],
        )?;
        let task = task_tx(&transaction, task_id)?;
        transaction.commit()?;
        Ok(task)
    }
    pub fn fail_task(
        &self,
        task_id: &str,
        worker: &str,
        error: &str,
        now_unix_ms: u64,
        retry_at_unix_ms: Option<u64>,
        recoverable_until_unix_ms: Option<u64>,
    ) -> Result<DurableTask, ControlPlaneError> {
        validate_text("task.error", error)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_task_owner_tx(&transaction, task_id, worker, now_unix_ms)?;
        let (status, available, completed) = if let Some(retry_at) = retry_at_unix_ms {
            if retry_at <= now_unix_ms {
                return Err(ControlPlaneError::InvalidInput(
                    "task retry must be scheduled in the future",
                ));
            }
            ("pending", to_i64(retry_at)?, None)
        } else {
            ("failed", to_i64(now_unix_ms)?, Some(to_i64(now_unix_ms)?))
        };
        let recoverable_until = match recoverable_until_unix_ms {
            Some(deadline)
                if retry_at_unix_ms.is_some_and(|retry_at| retry_at <= deadline)
                    && deadline > now_unix_ms =>
            {
                Some(to_i64(deadline)?)
            }
            Some(_) => {
                return Err(ControlPlaneError::InvalidInput(
                    "task recovery deadline must bound a future retry",
                ))
            }
            None => None,
        };
        transaction.execute(
            "UPDATE durable_tasks SET status = ?2, available_unix_ms = ?3,
             last_error = ?4, completed_unix_ms = ?5, lease_owner = NULL,
             lease_expires_unix_ms = NULL, recoverable_until_unix_ms = ?6 WHERE id = ?1",
            params![
                task_id,
                status,
                available,
                error,
                completed,
                recoverable_until
            ],
        )?;
        let task = task_tx(&transaction, task_id)?;
        transaction.commit()?;
        Ok(task)
    }

    pub fn task(&self, id: &str) -> Result<DurableTask, ControlPlaneError> {
        let connection = self.connection()?;
        task_conn(&connection, id)
    }

    pub fn tasks_by_kind_and_creation(
        &self,
        kind: &str,
        created_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<DurableTask>, ControlPlaneError> {
        validate_text("task.kind", kind)?;
        if limit == 0 || limit > 256 {
            return Err(ControlPlaneError::InvalidInput(
                "durable task batch limit must be between 1 and 256",
            ));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, kind, payload_json, status, available_unix_ms, attempts,
                    lease_owner, lease_expires_unix_ms, last_error, created_unix_ms,
                    completed_unix_ms FROM durable_tasks
             WHERE kind = ?1 AND created_unix_ms = ?2 ORDER BY id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                kind,
                to_i64(created_unix_ms)?,
                i64::try_from(limit).map_err(|_| ControlPlaneError::IntegerRange {
                    field: "durable task batch limit",
                })?
            ],
            task_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
