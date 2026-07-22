//! Backend-neutral durable event inbox and replay boundary.

use super::StoreFuture;
use crate::{
    ControlPlane, DurableEventRecord, EventReplayRecord, IdempotentResult, ReplayEventRequest,
};

pub trait EventStore: Send + Sync {
    fn record_event<'a>(
        &'a self,
        event: &'a DurableEventRecord,
    ) -> StoreFuture<'a, IdempotentResult<DurableEventRecord>>;
    fn event<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableEventRecord>;
    fn replay_event<'a>(
        &'a self,
        tenant_id: &'a str,
        request: &'a ReplayEventRequest,
    ) -> StoreFuture<'a, IdempotentResult<EventReplayRecord>>;
}

impl EventStore for ControlPlane {
    fn record_event<'a>(
        &'a self,
        event: &'a DurableEventRecord,
    ) -> StoreFuture<'a, IdempotentResult<DurableEventRecord>> {
        let result = ControlPlane::record_event(self, event);
        Box::pin(async move { result })
    }

    fn event<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableEventRecord> {
        let result = ControlPlane::event(self, id);
        Box::pin(async move { result })
    }

    fn replay_event<'a>(
        &'a self,
        tenant_id: &'a str,
        request: &'a ReplayEventRequest,
    ) -> StoreFuture<'a, IdempotentResult<EventReplayRecord>> {
        let result = ControlPlane::replay_event(self, tenant_id, request);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::persistence::{postgres_i64, postgres_u64, PostgresInstallationStore};
    use crate::{ControlPlaneError, DurableEventSource};
    use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
    use runtrue_model::ContentDigest;
    use sqlx::{Postgres, Row as _, Transaction};
    use std::collections::BTreeMap;

    const MAX_EVENT_PAYLOAD_BYTES: usize = 1024 * 1024;

    fn validate_text(value: &str) -> Result<(), ControlPlaneError> {
        if value.is_empty() || value.len() > 8 * 1024 || value.bytes().any(|byte| byte == 0) {
            return Err(ControlPlaneError::InvalidInput(
                "event text field is empty or too long",
            ));
        }
        Ok(())
    }

    fn source(value: &str) -> Result<DurableEventSource, ControlPlaneError> {
        match value {
            "frontend" => Ok(DurableEventSource::Frontend),
            "backend" => Ok(DurableEventSource::Backend),
            "system" => Ok(DurableEventSource::System),
            _ => Err(ControlPlaneError::CorruptState(
                "invalid durable event source".to_owned(),
            )),
        }
    }

    fn canonical_payload(event: &DurableEventRecord) -> Result<Vec<u8>, ControlPlaneError> {
        let payload = serde_json::to_vec(&runtrue_workflow_ir::canonicalize_value(
            event.payload.clone(),
        ))?;
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES
            || ContentDigest::sha256(&payload) != event.payload_digest
        {
            return Err(ControlPlaneError::InvalidInput(
                "event payload is oversized or has the wrong digest",
            ));
        }
        Ok(payload)
    }

    fn event_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<DurableEventRecord, ControlPlaneError> {
        Ok(DurableEventRecord {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            source: source(&row.try_get::<String, _>("source")?)?,
            kind: row.try_get("kind")?,
            handler_kind: row.try_get("handler_kind")?,
            payload: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("payload_json")?)?,
            payload_digest: ContentDigest::parse(row.try_get::<String, _>("payload_digest")?)?,
            idempotency_identity: row.try_get("idempotency_identity")?,
            actor_identity: row.try_get("actor_identity")?,
            task_id: row.try_get("task_id")?,
            created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "event creation")?,
        })
    }

    async fn event_tx(
        transaction: &mut Transaction<'_, Postgres>,
        id: &str,
    ) -> Result<DurableEventRecord, ControlPlaneError> {
        sqlx::query(
            "SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,
                    idempotency_identity,actor_identity,task_id,created_unix_ms
               FROM durable_events WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
        .as_ref()
        .map(event_from_row)
        .transpose()?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "event",
            id: id.to_owned(),
        })
    }

    fn replay_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<EventReplayRecord, ControlPlaneError> {
        Ok(EventReplayRecord {
            id: row.try_get("id")?,
            event_id: row.try_get("event_id")?,
            task_id: row.try_get("task_id")?,
            requested_by: row.try_get("requested_by")?,
            requested_unix_ms: postgres_u64(
                row.try_get("requested_unix_ms")?,
                "event replay request",
            )?,
        })
    }

    impl EventStore for PostgresInstallationStore {
        fn record_event<'a>(
            &'a self,
            event: &'a DurableEventRecord,
        ) -> StoreFuture<'a, IdempotentResult<DurableEventRecord>> {
            Box::pin(async move {
                for value in [
                    event.id.as_str(),
                    event.tenant_id.as_str(),
                    event.kind.as_str(),
                    event.handler_kind.as_str(),
                    event.idempotency_identity.as_str(),
                    event.actor_identity.as_str(),
                    event.task_id.as_str(),
                ] {
                    validate_text(value)?;
                }
                let payload = canonical_payload(event)?;
                let mut transaction = self.pool().begin().await?;
                let task_inserted = sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,created_unix_ms) VALUES($1,$2,$3,'pending',$4,0,$4) ON CONFLICT(id) DO NOTHING")
                    .bind(&event.task_id)
                    .bind(&event.handler_kind)
                    .bind(&payload)
                    .bind(postgres_i64(event.created_unix_ms, "event creation")?)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                if task_inserted == 0 {
                    let task =
                        sqlx::query("SELECT kind,payload_json FROM durable_tasks WHERE id=$1")
                            .bind(&event.task_id)
                            .fetch_one(&mut *transaction)
                            .await?;
                    if task.try_get::<String, _>("kind")? != event.handler_kind
                        || serde_json::from_slice::<serde_json::Value>(
                            &task.try_get::<Vec<u8>, _>("payload_json")?,
                        )? != event.payload
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                }
                let inserted = sqlx::query("INSERT INTO durable_events(id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,idempotency_identity,actor_identity,task_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING")
                    .bind(&event.id)
                    .bind(&event.tenant_id)
                    .bind(event.source.as_str())
                    .bind(&event.kind)
                    .bind(&event.handler_kind)
                    .bind(&payload)
                    .bind(event.payload_digest.as_str())
                    .bind(&event.idempotency_identity)
                    .bind(&event.actor_identity)
                    .bind(&event.task_id)
                    .bind(postgres_i64(event.created_unix_ms, "event creation")?)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                if inserted == 0 {
                    let existing_row = sqlx::query("SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,idempotency_identity,actor_identity,task_id,created_unix_ms FROM durable_events WHERE tenant_id=$1 AND source=$2 AND kind=$3 AND idempotency_identity=$4")
                        .bind(&event.tenant_id)
                        .bind(event.source.as_str())
                        .bind(&event.kind)
                        .bind(&event.idempotency_identity)
                        .fetch_optional(&mut *transaction)
                        .await?;
                    let existing = match existing_row.as_ref().map(event_from_row).transpose()? {
                        Some(existing) => existing,
                        None => event_tx(&mut transaction, &event.id).await?,
                    };
                    let task =
                        sqlx::query("SELECT kind,payload_json FROM durable_tasks WHERE id=$1")
                            .bind(&event.task_id)
                            .fetch_one(&mut *transaction)
                            .await?;
                    if existing != *event
                        || task.try_get::<String, _>("kind")? != event.handler_kind
                        || serde_json::from_slice::<serde_json::Value>(
                            &task.try_get::<Vec<u8>, _>("payload_json")?,
                        )? != event.payload
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                    transaction.commit().await?;
                    return Ok(IdempotentResult {
                        value: existing,
                        replayed: true,
                    });
                }
                super::super::api_tokens::append(
                    &mut transaction,
                    self.installation_id(),
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
                )
                .await?;
                let value = event_tx(&mut transaction, &event.id).await?;
                transaction.commit().await?;
                Ok(IdempotentResult {
                    value,
                    replayed: false,
                })
            })
        }

        fn event<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableEventRecord> {
            Box::pin(async move {
                validate_text(id)?;
                let row = sqlx::query("SELECT id,tenant_id,source,kind,handler_kind,payload_json,payload_digest,idempotency_identity,actor_identity,task_id,created_unix_ms FROM durable_events WHERE id=$1")
                    .bind(id)
                    .fetch_optional(self.pool())
                    .await?;
                row.as_ref()
                    .map(event_from_row)
                    .transpose()?
                    .ok_or_else(|| ControlPlaneError::NotFound {
                        kind: "event",
                        id: id.to_owned(),
                    })
            })
        }

        fn replay_event<'a>(
            &'a self,
            tenant_id: &'a str,
            request: &'a ReplayEventRequest,
        ) -> StoreFuture<'a, IdempotentResult<EventReplayRecord>> {
            Box::pin(async move {
                for value in [
                    tenant_id,
                    &request.id,
                    &request.event_id,
                    &request.requested_by,
                ] {
                    validate_text(value)?;
                }
                let mut transaction = self.pool().begin().await?;
                if let Some(row) = sqlx::query("SELECT id,event_id,task_id,requested_by,requested_unix_ms FROM durable_event_replays WHERE id=$1")
                    .bind(&request.id)
                    .fetch_optional(&mut *transaction)
                    .await?
                {
                    let existing = replay_from_row(&row)?;
                    let event = event_tx(&mut transaction, &existing.event_id).await?;
                    if existing.event_id != request.event_id
                        || existing.task_id != event.task_id
                        || existing.requested_by != request.requested_by
                        || event.tenant_id != tenant_id
                    {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                    transaction.commit().await?;
                    return Ok(IdempotentResult { value: existing, replayed: true });
                }
                let event = event_tx(&mut transaction, &request.event_id).await?;
                if event.tenant_id != tenant_id {
                    return Err(ControlPlaneError::NotFound {
                        kind: "event",
                        id: request.event_id.clone(),
                    });
                }
                let task = sqlx::query(
                    "SELECT kind,payload_json,status FROM durable_tasks WHERE id=$1 FOR UPDATE",
                )
                .bind(&event.task_id)
                .fetch_one(&mut *transaction)
                .await?;
                let status: String = task.try_get("status")?;
                if status != "failed" {
                    return Err(ControlPlaneError::InvalidInput(
                        "only a failed event can be replayed",
                    ));
                }
                canonical_payload(&event)?;
                if task.try_get::<String, _>("kind")? != event.handler_kind
                    || serde_json::from_slice::<serde_json::Value>(
                        &task.try_get::<Vec<u8>, _>("payload_json")?,
                    )? != event.payload
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                sqlx::query("UPDATE durable_tasks SET status='pending',available_unix_ms=$2,completed_unix_ms=NULL,lease_owner=NULL,lease_expires_unix_ms=NULL WHERE id=$1 AND status='failed'")
                    .bind(&event.task_id)
                    .bind(postgres_i64(request.requested_unix_ms, "event replay request")?)
                    .execute(&mut *transaction).await?;
                sqlx::query("INSERT INTO durable_event_replays(id,event_id,task_id,requested_by,requested_unix_ms) VALUES($1,$2,$3,$4,$5)")
                    .bind(&request.id).bind(&request.event_id).bind(&event.task_id).bind(&request.requested_by)
                    .bind(postgres_i64(request.requested_unix_ms, "event replay request")?)
                    .execute(&mut *transaction).await?;
                super::super::api_tokens::append(
                    &mut transaction,
                    self.installation_id(),
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
                )
                .await?;
                let value = EventReplayRecord {
                    id: request.id.clone(),
                    event_id: request.event_id.clone(),
                    task_id: event.task_id,
                    requested_by: request.requested_by.clone(),
                    requested_unix_ms: request.requested_unix_ms,
                };
                transaction.commit().await?;
                Ok(IdempotentResult {
                    value,
                    replayed: false,
                })
            })
        }
    }
}
