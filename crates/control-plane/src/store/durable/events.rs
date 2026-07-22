use super::super::*;
use crate::{DurableEventRecord, DurableEventSource, EventReplayRecord, ReplayEventRequest};

const MAX_EVENT_PAYLOAD_BYTES: usize = 1024 * 1024;

fn event_source(value: &str) -> Result<DurableEventSource, DecodeError> {
    match value {
        "frontend" => Ok(DurableEventSource::Frontend),
        "backend" => Ok(DurableEventSource::Backend),
        "system" => Ok(DurableEventSource::System),
        _ => Err(DecodeError(format!(
            "unknown durable event source `{value}`"
        ))),
    }
}

fn event_row(row: &Row<'_>) -> rusqlite::Result<DurableEventRecord> {
    let source: String = row.get(2)?;
    Ok(DurableEventRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        source: event_source(&source).map_err(|error| conversion(2, error))?,
        kind: row.get(3)?,
        handler_kind: row.get(4)?,
        payload: json_column(row, 5)?,
        payload_digest: digest_column(row, 6)?,
        idempotency_identity: row.get(7)?,
        actor_identity: row.get(8)?,
        task_id: row.get(9)?,
        created_unix_ms: u64_column(row, 10, "event creation")?,
    })
}

fn event_tx(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<DurableEventRecord, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,
                    idempotency_identity,actor_identity,task_id,created_unix_ms
               FROM durable_events WHERE id=?1",
            [id],
            event_row,
        )
        .optional()?
        .ok_or_else(|| not_found("event", id))
}

fn replay_row(row: &Row<'_>) -> rusqlite::Result<EventReplayRecord> {
    Ok(EventReplayRecord {
        id: row.get(0)?,
        event_id: row.get(1)?,
        task_id: row.get(2)?,
        requested_by: row.get(3)?,
        requested_unix_ms: u64_column(row, 4, "event replay request")?,
    })
}

fn canonical_event_payload(event: &DurableEventRecord) -> Result<String, ControlPlaneError> {
    let canonical = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
        event.payload.clone(),
    ))?;
    if canonical.len() > MAX_EVENT_PAYLOAD_BYTES
        || ContentDigest::sha256(&canonical) != event.payload_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "event payload is oversized or has the wrong digest",
        ));
    }
    String::from_utf8(canonical)
        .map_err(|_| ControlPlaneError::InvalidInput("event payload is not UTF-8"))
}

impl ControlPlane {
    /// Atomically persist an immutable event and enqueue its first delivery.
    pub fn record_event(
        &self,
        event: &DurableEventRecord,
    ) -> Result<IdempotentResult<DurableEventRecord>, ControlPlaneError> {
        for (field, value) in [
            ("event id", event.id.as_str()),
            ("event tenant", event.tenant_id.as_str()),
            ("event kind", event.kind.as_str()),
            ("event handler", event.handler_kind.as_str()),
            (
                "event idempotency identity",
                event.idempotency_identity.as_str(),
            ),
            ("event actor", event.actor_identity.as_str()),
            ("event task", event.task_id.as_str()),
        ] {
            validate_text(field, value)?;
        }
        let payload = canonical_event_payload(event)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task_inserted = transaction.execute(
            "INSERT OR IGNORE INTO durable_tasks
             (id,kind,payload_json,status,available_unix_ms,attempts,created_unix_ms)
             VALUES(?1,?2,?3,'pending',?4,0,?4)",
            params![
                event.task_id,
                event.handler_kind,
                payload,
                to_i64(event.created_unix_ms)?
            ],
        )?;
        if task_inserted == 0 {
            let existing = task_tx(&transaction, &event.task_id)?;
            if existing.kind != event.handler_kind || existing.payload != event.payload {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
        }
        let inserted = transaction.execute(
            "INSERT INTO durable_events
             (id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,
              idempotency_identity,actor_identity,task_id,created_unix_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT DO NOTHING",
            params![
                event.id,
                event.tenant_id,
                event.source.as_str(),
                event.kind,
                event.handler_kind,
                payload,
                event.payload_digest.as_str(),
                event.idempotency_identity,
                event.actor_identity,
                event.task_id,
                to_i64(event.created_unix_ms)?,
            ],
        )?;
        if inserted == 0 {
            let existing = transaction
                .query_row(
                    "SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,
                            idempotency_identity,actor_identity,task_id,created_unix_ms
                       FROM durable_events
                      WHERE tenant_id=?1 AND source=?2 AND kind=?3 AND idempotency_identity=?4",
                    params![
                        event.tenant_id,
                        event.source.as_str(),
                        event.kind,
                        event.idempotency_identity
                    ],
                    event_row,
                )
                .optional()?;
            let existing = match existing {
                Some(existing) => existing,
                None => event_tx(&transaction, &event.id)?,
            };
            if existing != *event {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let task = task_tx(&transaction, &event.task_id)?;
            if task.kind != event.handler_kind || task.payload != event.payload {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: event.created_unix_ms,
                tenant_id: event.tenant_id.clone(),
                actor: AuditPrincipal {
                    kind: event.source.as_str().to_owned(),
                    id: event.actor_identity.clone(),
                },
                action: "event.accept".to_owned(),
                resource: AuditResource {
                    kind: "event".to_owned(),
                    id: event.id.clone(),
                },
                result: "persisted".to_owned(),
                request_id: event.idempotency_identity.clone(),
                decision_id: None,
                metadata: BTreeMap::from([(
                    "payload_digest".to_owned(),
                    AuditValue::Digest(event.payload_digest.clone()),
                )]),
            },
        )?;
        let value = event_tx(&transaction, &event.id)?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }

    pub fn event(&self, id: &str) -> Result<DurableEventRecord, ControlPlaneError> {
        validate_text("event id", id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,
                        idempotency_identity,actor_identity,task_id,created_unix_ms
                   FROM durable_events WHERE id=?1",
                [id],
                event_row,
            )
            .optional()?
            .ok_or_else(|| not_found("event", id))
    }

    /// Queue an exact redelivery. Only failed original events are replayable.
    pub fn replay_event(
        &self,
        tenant_id: &str,
        request: &ReplayEventRequest,
    ) -> Result<IdempotentResult<EventReplayRecord>, ControlPlaneError> {
        for (field, value) in [
            ("event replay tenant", tenant_id),
            ("event replay id", request.id.as_str()),
            ("event replay event", request.event_id.as_str()),
            ("event replay actor", request.requested_by.as_str()),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT id,event_id,task_id,requested_by,requested_unix_ms
                   FROM durable_event_replays WHERE id=?1",
                [&request.id],
                replay_row,
            )
            .optional()?
        {
            let event = event_tx(&transaction, &existing.event_id)?;
            if existing.event_id != request.event_id
                || existing.task_id != event.task_id
                || existing.requested_by != request.requested_by
                || event.tenant_id != tenant_id
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        let event = event_tx(&transaction, &request.event_id)?;
        if event.tenant_id != tenant_id {
            return Err(not_found("event", &request.event_id));
        }
        let task = task_tx(&transaction, &event.task_id)?;
        if task.status != DurableTaskStatus::Failed {
            return Err(ControlPlaneError::InvalidInput(
                "only a failed event can be replayed",
            ));
        }
        canonical_event_payload(&event)?;
        if task.kind != event.handler_kind || task.payload != event.payload {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE durable_tasks SET status='pending',available_unix_ms=?2,
                    completed_unix_ms=NULL,lease_owner=NULL,lease_expires_unix_ms=NULL
              WHERE id=?1 AND status='failed'",
            params![event.task_id, to_i64(request.requested_unix_ms)?],
        )?;
        transaction.execute(
            "INSERT INTO durable_event_replays
             (id,event_id,task_id,requested_by,requested_unix_ms)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                request.id,
                request.event_id,
                event.task_id,
                request.requested_by,
                to_i64(request.requested_unix_ms)?
            ],
        )?;
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: request.requested_unix_ms,
                tenant_id: tenant_id.to_owned(),
                actor: AuditPrincipal {
                    kind: "event-replay-requester".to_owned(),
                    id: request.requested_by.clone(),
                },
                action: "event.replay".to_owned(),
                resource: AuditResource {
                    kind: "event".to_owned(),
                    id: event.id,
                },
                result: "queued".to_owned(),
                request_id: request.id.clone(),
                decision_id: None,
                metadata: BTreeMap::new(),
            },
        )?;
        let value = transaction.query_row(
            "SELECT id,event_id,task_id,requested_by,requested_unix_ms
               FROM durable_event_replays WHERE id=?1",
            [&request.id],
            replay_row,
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value,
            replayed: false,
        })
    }
}
