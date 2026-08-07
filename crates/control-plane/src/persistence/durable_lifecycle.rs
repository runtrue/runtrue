//! PostgreSQL durable-task and object-lifecycle transaction boundaries.

use super::StoreFuture;
#[cfg(feature = "postgres")]
use super::{postgres_i64, postgres_u64, PostgresInstallationStore};
#[cfg(feature = "postgres")]
use crate::ControlPlaneError;
#[cfg(any(feature = "postgres", test))]
use crate::DurableTaskStatus;
use crate::{
    BackupPinRecord, ControlPlane, DurableTask, IdempotentResult, LifecycleGcLease,
    LifecycleGcMetrics, LifecycleGcRoot, LifecyclePruneSummary, PromotionRequestRecord,
};
#[cfg(feature = "postgres")]
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};
#[cfg(feature = "postgres")]
use std::collections::{BTreeMap, BTreeSet};

pub trait DurableTaskStore: Send + Sync {
    fn create_promotion_request<'a>(
        &'a self,
        idempotency_key: &'a str,
        request: &'a PromotionRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<PromotionRequestRecord>>;
    fn enqueue_task<'a>(&'a self, task: &'a DurableTask) -> StoreFuture<'a, ()>;
    fn complete_task_with_followups<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        followups: &'a [DurableTask],
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;
    fn claim_task<'a>(
        &'a self,
        worker: &'a str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> StoreFuture<'a, Option<DurableTask>>;
    fn claim_task_by_kind<'a>(
        &'a self,
        worker: &'a str,
        kind: &'a str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> StoreFuture<'a, Option<DurableTask>>;
    fn complete_task<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, DurableTask>;
    fn fail_task<'a>(
        &'a self,
        task_id: &'a str,
        worker: &'a str,
        error: &'a str,
        now_unix_ms: u64,
        retry_at_unix_ms: Option<u64>,
        recoverable_until_unix_ms: Option<u64>,
    ) -> StoreFuture<'a, DurableTask>;
    fn task<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableTask>;
    fn tasks_by_kind_and_creation<'a>(
        &'a self,
        kind: &'a str,
        created_unix_ms: u64,
        limit: usize,
    ) -> StoreFuture<'a, Vec<DurableTask>>;
}

pub trait LifecycleGcStore: Send + Sync {
    fn create_backup_pin<'a>(&'a self, pin: &'a BackupPinRecord) -> StoreFuture<'a, bool>;
    fn acquire_lifecycle_gc<'a>(
        &'a self,
        worker_id: &'a str,
        lease_token: &'a str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> StoreFuture<'a, LifecycleGcLease>;
    fn retire_expired_artifacts(
        &self,
        now_unix_ms: u64,
        maximum_artifacts: usize,
    ) -> StoreFuture<'_, usize>;
    fn prune_lifecycle_ledgers(
        &self,
        now_unix_ms: u64,
        retention_ms: u64,
        maximum_rows_per_table: usize,
    ) -> StoreFuture<'_, LifecyclePruneSummary>;
    fn lifecycle_gc_roots<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        now_unix_ms: u64,
        maximum_roots: usize,
    ) -> StoreFuture<'a, Vec<LifecycleGcRoot>>;
    fn record_lifecycle_gc_marks<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        roots: &'a [LifecycleGcRoot],
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ()>;
    fn observe_lifecycle_gc_inventory<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        objects: &'a [(ContentDigest, u64, u64)],
        now_unix_ms: u64,
        safety_horizon_ms: u64,
    ) -> StoreFuture<'a, Vec<ContentDigest>>;
    fn complete_lifecycle_gc<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        swept: &'a [(ContentDigest, u64)],
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn lifecycle_gc_sweep_candidates<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        now_unix_ms: u64,
        safety_horizon_ms: u64,
        maximum_candidates: usize,
    ) -> StoreFuture<'a, Vec<(ContentDigest, u64)>>;
    fn lifecycle_metrics(&self) -> StoreFuture<'_, LifecycleGcMetrics>;
}

impl DurableTaskStore for ControlPlane {
    fn create_promotion_request<'a>(
        &'a self,
        key: &'a str,
        request: &'a PromotionRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<PromotionRequestRecord>> {
        let r = ControlPlane::create_promotion_request_idempotent(self, key, request);
        Box::pin(async move { r })
    }
    fn enqueue_task<'a>(&'a self, task: &'a DurableTask) -> StoreFuture<'a, ()> {
        let r = ControlPlane::enqueue_task(self, task);
        Box::pin(async move { r })
    }
    fn complete_task_with_followups<'a>(
        &'a self,
        id: &'a str,
        worker: &'a str,
        followups: &'a [DurableTask],
        now: u64,
    ) -> StoreFuture<'a, ()> {
        let r = ControlPlane::complete_task_with_followups(self, id, worker, followups, now);
        Box::pin(async move { r })
    }
    fn claim_task<'a>(
        &'a self,
        worker: &'a str,
        now: u64,
        duration: u64,
    ) -> StoreFuture<'a, Option<DurableTask>> {
        let r = ControlPlane::claim_task(self, worker, now, duration);
        Box::pin(async move { r })
    }
    fn claim_task_by_kind<'a>(
        &'a self,
        worker: &'a str,
        kind: &'a str,
        now: u64,
        duration: u64,
    ) -> StoreFuture<'a, Option<DurableTask>> {
        let r = ControlPlane::claim_task_by_kind(self, worker, kind, now, duration);
        Box::pin(async move { r })
    }
    fn complete_task<'a>(
        &'a self,
        id: &'a str,
        worker: &'a str,
        now: u64,
    ) -> StoreFuture<'a, DurableTask> {
        let r = ControlPlane::complete_task(self, id, worker, now);
        Box::pin(async move { r })
    }
    fn fail_task<'a>(
        &'a self,
        id: &'a str,
        worker: &'a str,
        error: &'a str,
        now: u64,
        retry: Option<u64>,
        recoverable_until: Option<u64>,
    ) -> StoreFuture<'a, DurableTask> {
        let r = ControlPlane::fail_task(self, id, worker, error, now, retry, recoverable_until);
        Box::pin(async move { r })
    }
    fn task<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableTask> {
        let r = ControlPlane::task(self, id);
        Box::pin(async move { r })
    }
    fn tasks_by_kind_and_creation<'a>(
        &'a self,
        kind: &'a str,
        created_unix_ms: u64,
        limit: usize,
    ) -> StoreFuture<'a, Vec<DurableTask>> {
        let r = ControlPlane::tasks_by_kind_and_creation(self, kind, created_unix_ms, limit);
        Box::pin(async move { r })
    }
}

impl LifecycleGcStore for ControlPlane {
    fn create_backup_pin<'a>(&'a self, p: &'a BackupPinRecord) -> StoreFuture<'a, bool> {
        let r = ControlPlane::create_backup_pin(self, p);
        Box::pin(async move { r })
    }
    fn acquire_lifecycle_gc<'a>(
        &'a self,
        w: &'a str,
        t: &'a str,
        n: u64,
        d: u64,
    ) -> StoreFuture<'a, LifecycleGcLease> {
        let r = ControlPlane::acquire_lifecycle_gc(self, w, t, n, d);
        Box::pin(async move { r })
    }
    fn retire_expired_artifacts(&self, n: u64, m: usize) -> StoreFuture<'_, usize> {
        let r = ControlPlane::retire_expired_artifacts(self, n, m);
        Box::pin(async move { r })
    }
    fn prune_lifecycle_ledgers(
        &self,
        n: u64,
        rn: u64,
        m: usize,
    ) -> StoreFuture<'_, LifecyclePruneSummary> {
        let r = ControlPlane::prune_lifecycle_ledgers(self, n, rn, m);
        Box::pin(async move { r })
    }
    fn lifecycle_gc_roots<'a>(
        &'a self,
        l: &'a LifecycleGcLease,
        n: u64,
        m: usize,
    ) -> StoreFuture<'a, Vec<LifecycleGcRoot>> {
        let r = ControlPlane::lifecycle_gc_roots(self, l, n, m);
        Box::pin(async move { r })
    }
    fn record_lifecycle_gc_marks<'a>(
        &'a self,
        l: &'a LifecycleGcLease,
        r: &'a [LifecycleGcRoot],
        n: u64,
    ) -> StoreFuture<'a, ()> {
        let v = ControlPlane::record_lifecycle_gc_marks(self, l, r, n);
        Box::pin(async move { v })
    }
    fn observe_lifecycle_gc_inventory<'a>(
        &'a self,
        l: &'a LifecycleGcLease,
        o: &'a [(ContentDigest, u64, u64)],
        n: u64,
        h: u64,
    ) -> StoreFuture<'a, Vec<ContentDigest>> {
        let r = ControlPlane::observe_lifecycle_gc_inventory(self, l, o, n, h);
        Box::pin(async move { r })
    }
    fn complete_lifecycle_gc<'a>(
        &'a self,
        l: &'a LifecycleGcLease,
        s: &'a [(ContentDigest, u64)],
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let r = ControlPlane::complete_lifecycle_gc(self, l, s, n);
        Box::pin(async move { r })
    }
    fn lifecycle_gc_sweep_candidates<'a>(
        &'a self,
        l: &'a LifecycleGcLease,
        n: u64,
        h: u64,
        m: usize,
    ) -> StoreFuture<'a, Vec<(ContentDigest, u64)>> {
        let r = ControlPlane::lifecycle_gc_sweep_candidates(self, l, n, h, m);
        Box::pin(async move { r })
    }
    fn lifecycle_metrics(&self) -> StoreFuture<'_, LifecycleGcMetrics> {
        let r = ControlPlane::lifecycle_metrics(self);
        Box::pin(async move { r })
    }
}

#[cfg(feature = "postgres")]
impl DurableTaskStore for PostgresInstallationStore {
    fn create_promotion_request<'a>(
        &'a self,
        key: &'a str,
        r: &'a PromotionRequestRecord,
    ) -> StoreFuture<'a, IdempotentResult<PromotionRequestRecord>> {
        Box::pin(async move {
            validate_text("idempotency key", key)?;
            validate_text("promotion id", &r.id)?;
            validate_text("promotion kind", &r.kind)?;
            validate_text("promotion source", &r.source_id)?;
            if !matches!(r.kind.as_str(), "cache" | "artifact") || r.status != "pending" {
                return Err(ControlPlaneError::InvalidInput(
                    "new promotion must be pending cache or artifact work",
                ));
            }
            let target = canonicalize(r.target.clone());
            let evidence = canonicalize(r.evidence.clone());
            let target_text = serde_json::to_string(&target)?;
            let evidence_text = serde_json::to_string(&evidence)?;
            let digest = ContentDigest::sha256(serde_json::to_vec(&(
                r.kind.as_str(),
                r.source_id.as_str(),
                &target_text,
                &evidence_text,
            ))?);
            let operation = format!("promotion.create:{}", r.kind);
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,771007))")
                .bind(format!("{operation}:{}", key))
                .execute(&mut *tx)
                .await?;
            if let Some(row)=sqlx::query("SELECT request_hash,resource_id FROM idempotency_records WHERE operation=$1 AND idempotency_key=$2").bind(&operation).bind(key).fetch_optional(&mut*tx).await?{let stored:String=row.try_get("request_hash")?;if stored!=digest.as_str(){return Err(ControlPlaneError::IdempotencyConflict)}let id:String=row.try_get("resource_id")?;let value=promotion_request_tx(&mut tx,&id).await?.ok_or_else(||not_found("promotion request",&id))?;tx.commit().await?;return Ok(IdempotentResult{value,replayed:true})}
            sqlx::query("INSERT INTO promotion_requests(id,kind,source_id,target_json,evidence_json,status,created_unix_ms) VALUES($1,$2,$3,$4,$5,'pending',$6)").bind(&r.id).bind(&r.kind).bind(&r.source_id).bind(json_bytes(&target)?).bind(json_bytes(&evidence)?).bind(postgres_i64(r.created_unix_ms,"promotion creation")?).execute(&mut*tx).await?;
            let task = DurableTask {
                id: format!("promotion-task:{}", r.id),
                kind: format!("{}.promotion", r.kind),
                payload: serde_json::to_value(r)?,
                status: DurableTaskStatus::Pending,
                available_unix_ms: r.created_unix_ms,
                attempts: 0,
                lease_owner: None,
                lease_expires_unix_ms: None,
                last_error: None,
                created_unix_ms: r.created_unix_ms,
                completed_unix_ms: None,
            };
            sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,created_unix_ms) VALUES($1,$2,$3,'pending',$4,0,$4)").bind(&task.id).bind(&task.kind).bind(json_bytes(&task.payload)?).bind(postgres_i64(task.created_unix_ms,"promotion task creation")?).execute(&mut*tx).await?;
            sqlx::query("INSERT INTO idempotency_records(operation,idempotency_key,request_hash,resource_id,created_unix_ms) VALUES($1,$2,$3,$4,$5)").bind(&operation).bind(key).bind(digest.as_str()).bind(&r.id).bind(postgres_i64(r.created_unix_ms,"promotion creation")?).execute(&mut*tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: r.clone(),
                replayed: false,
            })
        })
    }
    fn enqueue_task<'a>(&'a self, task: &'a DurableTask) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_new_task(task)?;
            sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,last_error,created_unix_ms) VALUES($1,$2,$3,'pending',$4,0,$5,$6)")
                .bind(&task.id).bind(&task.kind).bind(json_bytes(&canonicalize(task.payload.clone()))?)
                .bind(postgres_i64(task.available_unix_ms,"task availability")?).bind(&task.last_error)
                .bind(postgres_i64(task.created_unix_ms,"task creation")?).execute(self.pool()).await?;
            Ok(())
        })
    }
    fn complete_task_with_followups<'a>(
        &'a self,
        id: &'a str,
        worker: &'a str,
        followups: &'a [DurableTask],
        now: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_text("task.id", id)?;
            validate_text("task.worker", worker)?;
            if followups.len() > 64 {
                return Err(ControlPlaneError::InvalidInput(
                    "too many durable task follow-ups",
                ));
            }
            let mut ids = BTreeSet::new();
            for f in followups {
                validate_new_task(f)?;
                if f.id == id || !ids.insert(f.id.as_str()) {
                    return Err(ControlPlaneError::InvalidInput(
                        "follow-up tasks must be distinct, new, and pending",
                    ));
                }
            }
            let mut tx = self.pool().begin().await?;
            require_task_owner(&mut tx, id, worker, now).await?;
            for f in followups {
                let payload = canonicalize(f.payload.clone());
                let inserted=sqlx::query("INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,last_error,created_unix_ms) VALUES($1,$2,$3,'pending',$4,0,$5,$6) ON CONFLICT(id) DO NOTHING")
                .bind(&f.id).bind(&f.kind).bind(json_bytes(&payload)?).bind(postgres_i64(f.available_unix_ms,"task availability")?).bind(&f.last_error).bind(postgres_i64(f.created_unix_ms,"task creation")?).execute(&mut*tx).await?.rows_affected();
                if inserted == 0 {
                    let e = task_tx(&mut tx, &f.id, false)
                        .await?
                        .ok_or_else(|| not_found("task", &f.id))?;
                    if e.kind != f.kind || e.payload != payload {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                }
            }
            mark_task_completed(&mut tx, id, now).await?;
            tx.commit().await?;
            Ok(())
        })
    }
    fn claim_task<'a>(
        &'a self,
        w: &'a str,
        n: u64,
        d: u64,
    ) -> StoreFuture<'a, Option<DurableTask>> {
        Box::pin(async move { claim_task_pg(self, w, None, n, d).await })
    }
    fn claim_task_by_kind<'a>(
        &'a self,
        w: &'a str,
        k: &'a str,
        n: u64,
        d: u64,
    ) -> StoreFuture<'a, Option<DurableTask>> {
        Box::pin(async move {
            validate_text("task.kind", k)?;
            claim_task_pg(self, w, Some(k), n, d).await
        })
    }
    fn complete_task<'a>(
        &'a self,
        id: &'a str,
        w: &'a str,
        n: u64,
    ) -> StoreFuture<'a, DurableTask> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            require_task_owner(&mut tx, id, w, n).await?;
            mark_task_completed(&mut tx, id, n).await?;
            let task = task_tx(&mut tx, id, false)
                .await?
                .ok_or_else(|| not_found("task", id))?;
            tx.commit().await?;
            Ok(task)
        })
    }
    fn fail_task<'a>(
        &'a self,
        id: &'a str,
        w: &'a str,
        error: &'a str,
        n: u64,
        retry: Option<u64>,
        recoverable_until: Option<u64>,
    ) -> StoreFuture<'a, DurableTask> {
        Box::pin(async move {
            validate_text("task.error", error)?;
            let mut tx = self.pool().begin().await?;
            require_task_owner(&mut tx, id, w, n).await?;
            let (status, available, completed) = if let Some(r) = retry {
                if r <= n {
                    return Err(ControlPlaneError::InvalidInput(
                        "task retry must be scheduled in the future",
                    ));
                }
                ("pending", postgres_i64(r, "task retry")?, None)
            } else {
                let n = postgres_i64(n, "task failure")?;
                ("failed", n, Some(n))
            };
            let recoverable_until = match recoverable_until {
                Some(deadline)
                    if retry.is_some_and(|retry_at| retry_at <= deadline) && deadline > n =>
                {
                    Some(postgres_i64(deadline, "task recovery deadline")?)
                }
                Some(_) => {
                    return Err(ControlPlaneError::InvalidInput(
                        "task recovery deadline must bound a future retry",
                    ))
                }
                None => None,
            };
            sqlx::query("UPDATE durable_tasks SET status=$2,available_unix_ms=$3,last_error=$4,completed_unix_ms=$5,lease_owner=NULL,lease_expires_unix_ms=NULL,recoverable_until_unix_ms=$6 WHERE id=$1").bind(id).bind(status).bind(available).bind(error).bind(completed).bind(recoverable_until).execute(&mut*tx).await?;
            let task = task_tx(&mut tx, id, false)
                .await?
                .ok_or_else(|| not_found("task", id))?;
            tx.commit().await?;
            Ok(task)
        })
    }
    fn task<'a>(&'a self, id: &'a str) -> StoreFuture<'a, DurableTask> {
        Box::pin(async move {
            validate_text("task.id", id)?;
            let mut tx = self.pool().begin().await?;
            let task = task_tx(&mut tx, id, false)
                .await?
                .ok_or_else(|| not_found("task", id))?;
            tx.commit().await?;
            Ok(task)
        })
    }
    fn tasks_by_kind_and_creation<'a>(
        &'a self,
        kind: &'a str,
        created_unix_ms: u64,
        limit: usize,
    ) -> StoreFuture<'a, Vec<DurableTask>> {
        Box::pin(async move {
            validate_text("task.kind", kind)?;
            if limit == 0 || limit > 256 {
                return Err(ControlPlaneError::InvalidInput(
                    "durable task batch limit must be between 1 and 256",
                ));
            }
            let rows = sqlx::query("SELECT id,kind,payload_json,status,available_unix_ms,attempts,lease_owner,lease_expires_unix_ms,last_error,created_unix_ms,completed_unix_ms FROM durable_tasks WHERE kind=$1 AND created_unix_ms=$2 ORDER BY id LIMIT $3")
                .bind(kind)
                .bind(postgres_i64(created_unix_ms, "task creation")?)
                .bind(i64::try_from(limit).map_err(|_| ControlPlaneError::IntegerRange { field: "durable task batch limit" })?)
                .fetch_all(self.pool())
                .await?;
            rows.into_iter().map(task_row).collect()
        })
    }
}

#[cfg(feature = "postgres")]
impl LifecycleGcStore for PostgresInstallationStore {
    fn create_backup_pin<'a>(&'a self, pin: &'a BackupPinRecord) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_backup_pin(pin)?;
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,771006))")
                .bind(&pin.id)
                .execute(&mut *tx)
                .await?;
            let row=sqlx::query("SELECT id,tenant_id,root_kind,root_id,object_digest,created_unix_ms,expires_unix_ms,released_unix_ms FROM backup_pins WHERE id=$1").bind(&pin.id).fetch_optional(&mut*tx).await?;
            if let Some(r) = row {
                let existing = backup_pin_row(r)?;
                if existing == *pin {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO backup_pins(id,tenant_id,root_kind,root_id,object_digest,created_unix_ms,expires_unix_ms,released_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,NULL)").bind(&pin.id).bind(&pin.tenant_id).bind(&pin.root_kind).bind(&pin.root_id).bind(pin.object_digest.as_str()).bind(postgres_i64(pin.created_unix_ms,"backup pin creation")?).bind(pin.expires_unix_ms.map(|v|postgres_i64(v,"backup pin expiry")).transpose()?).execute(&mut*tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }
    fn acquire_lifecycle_gc<'a>(
        &'a self,
        w: &'a str,
        token: &'a str,
        now: u64,
        duration: u64,
    ) -> StoreFuture<'a, LifecycleGcLease> {
        Box::pin(async move {
            validate_text("GC worker", w)?;
            validate_text("GC lease token", token)?;
            if duration == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "GC lease duration must be positive",
                ));
            }
            let expires = now
                .checked_add(duration)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "GC lease expiry",
                })?;
            let mut tx = self.pool().begin().await?;
            let r=sqlx::query("SELECT current_generation,phase,lease_owner,lease_token,lease_expires_unix_ms FROM lifecycle_gc_control WHERE singleton=TRUE FOR UPDATE").fetch_one(&mut*tx).await?;
            let generation = postgres_u64(r.try_get("current_generation")?, "GC generation")?;
            let phase: String = r.try_get("phase")?;
            let owner: Option<String> = r.try_get("lease_owner")?;
            let current_token: Option<String> = r.try_get("lease_token")?;
            let current_expiry = r
                .try_get::<Option<i64>, _>("lease_expires_unix_ms")?
                .map(|v| postgres_u64(v, "GC lease expiry"))
                .transpose()?;
            if phase != "idle" {
                if owner.as_deref() == Some(w)
                    && current_token.as_deref() == Some(token)
                    && current_expiry.is_some_and(|e| e > now)
                {
                    sqlx::query("UPDATE lifecycle_gc_control SET lease_expires_unix_ms=$2,updated_unix_ms=$3 WHERE singleton=TRUE AND lease_token=$1").bind(token).bind(postgres_i64(expires,"GC lease expiry")?).bind(postgres_i64(now,"GC lease update")?).execute(&mut*tx).await?;
                    tx.commit().await?;
                    return Ok(LifecycleGcLease {
                        generation,
                        phase,
                        lease_owner: w.to_owned(),
                        lease_token: token.to_owned(),
                        expires_unix_ms: expires,
                    });
                }
                if current_expiry.is_some_and(|e| e > now) {
                    return Err(ControlPlaneError::LifecycleGcLeaseBusy);
                }
                sqlx::query("UPDATE lifecycle_gc_cycles SET state='failed',completed_unix_ms=$2 WHERE generation=$1 AND state IN('marking','sweeping')").bind(postgres_i64(generation,"GC generation")?).bind(postgres_i64(now,"GC failure")?).execute(&mut*tx).await?;
            }
            let next = generation
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "GC generation",
                })?;
            sqlx::query("UPDATE lifecycle_gc_control SET current_generation=$1,phase='marking',lease_owner=$2,lease_token=$3,lease_expires_unix_ms=$4,updated_unix_ms=$5 WHERE singleton=TRUE").bind(postgres_i64(next,"GC generation")?).bind(w).bind(token).bind(postgres_i64(expires,"GC lease expiry")?).bind(postgres_i64(now,"GC lease update")?).execute(&mut*tx).await?;
            sqlx::query("INSERT INTO lifecycle_gc_cycles(generation,lease_token,started_unix_ms,state) VALUES($1,$2,$3,'marking')").bind(postgres_i64(next,"GC generation")?).bind(token).bind(postgres_i64(now,"GC cycle start")?).execute(&mut*tx).await?;
            tx.commit().await?;
            Ok(LifecycleGcLease {
                generation: next,
                phase: "marking".to_owned(),
                lease_owner: w.to_owned(),
                lease_token: token.to_owned(),
                expires_unix_ms: expires,
            })
        })
    }
    fn retire_expired_artifacts(&self, now: u64, maximum: usize) -> StoreFuture<'_, usize> {
        Box::pin(async move {
            if maximum == 0 || maximum > 100_000 {
                return Err(ControlPlaneError::InvalidInput(
                    "artifact retirement bound is invalid",
                ));
            }
            let mut tx = self.pool().begin().await?;
            let ids:Vec<String>=sqlx::query_scalar("SELECT artifact_id FROM artifacts_catalog WHERE state<>'retired' AND legal_hold=FALSE AND retention_until_unix_seconds <= $1 ORDER BY retention_until_unix_seconds,artifact_id FOR UPDATE SKIP LOCKED LIMIT $2").bind(postgres_i64(now/1000,"artifact retention clock")?).bind(i64::try_from(maximum).map_err(|_|ControlPlaneError::IntegerRange{field:"artifact retirement bound"})?).fetch_all(&mut*tx).await?;
            for id in &ids {
                sqlx::query("UPDATE artifacts_catalog SET state='retired' WHERE artifact_id=$1 AND legal_hold=FALSE AND retention_until_unix_seconds <= $2 AND state<>'retired'").bind(id).bind(postgres_i64(now/1000,"artifact retention clock")?).execute(&mut*tx).await?;
                sqlx::query("UPDATE tenant_storage_objects SET state='retired',retired_unix_ms=$2 WHERE object_kind='artifact' AND object_id=$1 AND state='active'").bind(id).bind(postgres_i64(now,"artifact retirement")?).execute(&mut*tx).await?;
            }
            if !ids.is_empty() {
                let metadata = BTreeMap::from([(
                    "retired_artifacts".to_owned(),
                    AuditValue::Integer(i64::try_from(ids.len()).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "retired artifacts",
                        }
                    })?),
                )]);
                super::api_tokens::append(
                    &mut tx,
                    self.installation_id(),
                    AuditEventData {
                        observed_unix_ms: now,
                        tenant_id: "installation".to_owned(),
                        actor: AuditPrincipal {
                            kind: "worker".to_owned(),
                            id: "output-lifecycle".to_owned(),
                        },
                        action: "artifact.retire".to_owned(),
                        resource: AuditResource {
                            kind: "artifact-catalog".to_owned(),
                            id: "retention-batch".to_owned(),
                        },
                        result: "completed".to_owned(),
                        request_id: format!("artifact-retention-{now}"),
                        decision_id: None,
                        metadata,
                    },
                )
                .await?;
            }
            tx.commit().await?;
            Ok(ids.len())
        })
    }
    fn prune_lifecycle_ledgers(
        &self,
        now: u64,
        retention: u64,
        maximum: usize,
    ) -> StoreFuture<'_, LifecyclePruneSummary> {
        Box::pin(async move {
            if retention == 0 || maximum == 0 || maximum > 100_000 {
                return Err(ControlPlaneError::InvalidInput(
                    "lifecycle ledger retention bound is invalid",
                ));
            }
            let cutoff = now.saturating_sub(retention);
            let limit = i64::try_from(maximum).map_err(|_| ControlPlaneError::IntegerRange {
                field: "lifecycle prune bound",
            })?;
            let mut tx = self.pool().begin().await?;
            let reservations=sqlx::query("WITH selected AS(SELECT id FROM tenant_storage_reservations WHERE state='reserved' AND expires_unix_ms <= $1 ORDER BY expires_unix_ms LIMIT $2 FOR UPDATE SKIP LOCKED) UPDATE tenant_storage_reservations r SET state='expired',completed_unix_ms=$1 FROM selected s WHERE r.id=s.id").bind(postgres_i64(now,"lifecycle prune clock")?).bind(limit).execute(&mut*tx).await?.rows_affected();
            sqlx::query("UPDATE tenant_storage_ticket_bindings SET state='released',updated_unix_ms=$1,completed_unix_ms=$1 WHERE reservation_id IN(SELECT id FROM tenant_storage_reservations WHERE state='expired') AND state='issued'").bind(postgres_i64(now,"lifecycle prune clock")?).execute(&mut*tx).await?;
            let tickets = delete_bounded(
                &mut tx,
                "artifact_download_tickets",
                "token_hash",
                "expires_unix_ms <= $1 AND (used_unix_ms IS NULL OR used_unix_ms <= $1)",
                "expires_unix_ms",
                cutoff,
                limit,
            )
            .await?;
            let transfers = delete_bounded(
                &mut tx,
                "runner_object_transfers",
                "ctid",
                "state IN('committed','abandoned') AND updated_unix_ms <= $1",
                "updated_unix_ms",
                cutoff,
                limit,
            )
            .await?;
            let observations = delete_bounded(
                &mut tx,
                "cache_access_observations",
                "id",
                "created_unix_ms <= $1",
                "created_unix_ms",
                cutoff,
                limit,
            )
            .await?;
            let logs=sqlx::query("WITH selected AS(SELECT f.ctid FROM runner_log_frames f JOIN leases l ON l.id=f.execution_lease_id WHERE l.state IN('completed','rejected','expired') AND f.wall_time_unix_ms <= $1 ORDER BY f.wall_time_unix_ms LIMIT $2) DELETE FROM runner_log_frames f USING selected s WHERE f.ctid=s.ctid").bind(postgres_i64(cutoff,"lifecycle cutoff")?).bind(limit).execute(&mut*tx).await?.rows_affected();
            tx.commit().await?;
            Ok(LifecyclePruneSummary {
                storage_reservations: reservations,
                download_tickets: tickets,
                object_transfers: transfers,
                cache_observations: observations,
                log_frames: logs,
            })
        })
    }
    fn lifecycle_gc_roots<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        now: u64,
        maximum: usize,
    ) -> StoreFuture<'a, Vec<LifecycleGcRoot>> {
        Box::pin(async move {
            if maximum == 0 || maximum > 1_000_000 {
                return Err(ControlPlaneError::InvalidInput("GC root bound is invalid"));
            }
            let mut tx = self.pool().begin().await?;
            verify_gc_lease(&mut tx, lease, now, "marking", false).await?;
            let rows = sqlx::query(GC_ROOTS_SQL)
                .bind(postgres_i64(now / 1000, "GC root clock")?)
                .bind(postgres_i64(now, "GC root clock")?)
                .fetch_all(&mut *tx)
                .await?;
            let mut roots = BTreeSet::new();
            for r in rows {
                if roots.len() >= maximum {
                    return Err(ControlPlaneError::GcRootLimitExceeded);
                }
                roots.insert(LifecycleGcRoot {
                    digest: ContentDigest::parse(r.try_get::<String, _>("digest")?)?,
                    root_kind: r.try_get("root_kind")?,
                    root_id: r.try_get("root_id")?,
                });
            }
            tx.commit().await?;
            Ok(roots.into_iter().collect())
        })
    }
    fn record_lifecycle_gc_marks<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        roots: &'a [LifecycleGcRoot],
        now: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if roots.len() > 1_000_000 {
                return Err(ControlPlaneError::GcRootLimitExceeded);
            }
            let mut tx = self.pool().begin().await?;
            verify_gc_lease(&mut tx, lease, now, "marking", true).await?;
            for r in roots {
                validate_text("GC root kind", &r.root_kind)?;
                validate_text("GC root id", &r.root_id)?;
                sqlx::query("INSERT INTO lifecycle_gc_marks(generation,object_digest,root_kind,root_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(postgres_i64(lease.generation,"GC generation")?).bind(r.digest.as_str()).bind(&r.root_kind).bind(&r.root_id).execute(&mut*tx).await?;
            }
            let marked: i64 = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT object_digest) FROM lifecycle_gc_marks WHERE generation=$1",
            )
            .bind(postgres_i64(lease.generation, "GC generation")?)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("UPDATE lifecycle_gc_cycles SET marked_objects=$2,state='sweeping' WHERE generation=$1 AND state='marking'").bind(postgres_i64(lease.generation,"GC generation")?).bind(marked).execute(&mut*tx).await?;
            sqlx::query("UPDATE lifecycle_gc_control SET phase='sweeping',updated_unix_ms=$2 WHERE singleton=TRUE AND lease_token=$1 AND phase='marking'").bind(&lease.lease_token).bind(postgres_i64(now,"GC mark completion")?).execute(&mut*tx).await?;
            tx.commit().await?;
            Ok(())
        })
    }
    fn observe_lifecycle_gc_inventory<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        objects: &'a [(ContentDigest, u64, u64)],
        now: u64,
        horizon: u64,
    ) -> StoreFuture<'a, Vec<ContentDigest>> {
        Box::pin(async move {
            if objects.len() > 100_000 || horizon == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "GC inventory bound is invalid",
                ));
            }
            let oldest = now.saturating_sub(horizon);
            let mut tx = self.pool().begin().await?;
            verify_gc_lease(&mut tx, lease, now, "sweeping", true).await?;
            let mut eligible = Vec::new();
            for (d, size, created) in objects {
                let marked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM lifecycle_gc_marks WHERE generation=$1 AND object_digest=$2)").bind(postgres_i64(lease.generation,"GC generation")?).bind(d.as_str()).fetch_one(&mut*tx).await?;
                if marked {
                    sqlx::query("DELETE FROM lifecycle_gc_candidates WHERE object_digest=$1")
                        .bind(d.as_str())
                        .execute(&mut *tx)
                        .await?;
                    continue;
                }
                let row=sqlx::query("SELECT first_absent_generation,last_absent_generation,swept_unix_ms FROM lifecycle_gc_candidates WHERE object_digest=$1 FOR UPDATE").bind(d.as_str()).fetch_optional(&mut*tx).await?;
                if let Some(r) = row {
                    let first = postgres_u64(
                        r.try_get("first_absent_generation")?,
                        "first absent generation",
                    )?;
                    let last = postgres_u64(
                        r.try_get("last_absent_generation")?,
                        "last absent generation",
                    )?;
                    let swept: Option<i64> = r.try_get("swept_unix_ms")?;
                    if swept.is_none() && last.saturating_add(1) == lease.generation {
                        sqlx::query("UPDATE lifecycle_gc_candidates SET last_absent_generation=$2,size_bytes=$3 WHERE object_digest=$1").bind(d.as_str()).bind(postgres_i64(lease.generation,"GC generation")?).bind(postgres_i64(*size,"GC candidate bytes")?).execute(&mut*tx).await?;
                        if first < lease.generation && *created <= oldest {
                            eligible.push(d.clone())
                        }
                    }
                } else {
                    sqlx::query("INSERT INTO lifecycle_gc_candidates(object_digest,first_absent_generation,last_absent_generation,observed_unix_ms,size_bytes) VALUES($1,$2,$2,$3,$4)").bind(d.as_str()).bind(postgres_i64(lease.generation,"GC generation")?).bind(postgres_i64(*created,"GC object creation")?).bind(postgres_i64(*size,"GC candidate bytes")?).execute(&mut*tx).await?;
                }
            }
            sqlx::query("UPDATE lifecycle_gc_cycles SET candidate_objects=(SELECT COUNT(*) FROM lifecycle_gc_candidates WHERE swept_unix_ms IS NULL) WHERE generation=$1").bind(postgres_i64(lease.generation,"GC generation")?).execute(&mut*tx).await?;
            tx.commit().await?;
            Ok(eligible)
        })
    }
    fn complete_lifecycle_gc<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        swept: &'a [(ContentDigest, u64)],
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            if swept.len() > 100_000 {
                return Err(ControlPlaneError::InvalidInput("GC sweep bound is invalid"));
            }
            let mut tx = self.pool().begin().await?;
            let state:Option<String>=sqlx::query_scalar("SELECT state FROM lifecycle_gc_cycles WHERE generation=$1 AND lease_token=$2 FOR UPDATE").bind(postgres_i64(lease.generation,"GC generation")?).bind(&lease.lease_token).fetch_optional(&mut*tx).await?;
            if state.as_deref() == Some("completed") {
                tx.commit().await?;
                return Ok(true);
            }
            verify_gc_lease(&mut tx, lease, now, "sweeping", true).await?;
            let mut bytes = 0u64;
            for (d, size) in swept {
                let changed=sqlx::query("UPDATE lifecycle_gc_candidates SET swept_unix_ms=$2 WHERE object_digest=$1 AND last_absent_generation=$3 AND swept_unix_ms IS NULL").bind(d.as_str()).bind(postgres_i64(now,"GC sweep")?).bind(postgres_i64(lease.generation,"GC generation")?).execute(&mut*tx).await?.rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                bytes = bytes
                    .checked_add(*size)
                    .ok_or(ControlPlaneError::IntegerRange {
                        field: "GC swept bytes",
                    })?;
            }
            sqlx::query("UPDATE lifecycle_gc_cycles SET state='completed',swept_objects=$2,swept_bytes=$3,completed_unix_ms=$4 WHERE generation=$1 AND state='sweeping'").bind(postgres_i64(lease.generation,"GC generation")?).bind(i64::try_from(swept.len()).map_err(|_|ControlPlaneError::IntegerRange{field:"GC swept objects"})?).bind(postgres_i64(bytes,"GC swept bytes")?).bind(postgres_i64(now,"GC completion")?).execute(&mut*tx).await?;
            sqlx::query("UPDATE lifecycle_gc_control SET phase='idle',lease_owner=NULL,lease_token=NULL,lease_expires_unix_ms=NULL,updated_unix_ms=$2 WHERE singleton=TRUE AND lease_token=$1").bind(&lease.lease_token).bind(postgres_i64(now,"GC completion")?).execute(&mut*tx).await?;
            sqlx::query("DELETE FROM lifecycle_gc_marks WHERE generation + 2 < $1")
                .bind(postgres_i64(lease.generation, "GC generation")?)
                .execute(&mut *tx)
                .await?;
            let metadata = BTreeMap::from([
                (
                    "generation".to_owned(),
                    AuditValue::Integer(postgres_i64(lease.generation, "GC generation")?),
                ),
                (
                    "swept_objects".to_owned(),
                    AuditValue::Integer(i64::try_from(swept.len()).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "GC swept objects",
                        }
                    })?),
                ),
                (
                    "swept_bytes".to_owned(),
                    AuditValue::Integer(postgres_i64(bytes, "GC swept bytes")?),
                ),
            ]);
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: now,
                    tenant_id: "installation".to_owned(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: lease.lease_owner.clone(),
                    },
                    action: "storage.gc".to_owned(),
                    resource: AuditResource {
                        kind: "gc-cycle".to_owned(),
                        id: lease.generation.to_string(),
                    },
                    result: "completed".to_owned(),
                    request_id: lease.lease_token.clone(),
                    decision_id: None,
                    metadata,
                },
            )
            .await?;
            tx.commit().await?;
            Ok(false)
        })
    }
    fn lifecycle_gc_sweep_candidates<'a>(
        &'a self,
        lease: &'a LifecycleGcLease,
        now: u64,
        horizon: u64,
        maximum: usize,
    ) -> StoreFuture<'a, Vec<(ContentDigest, u64)>> {
        Box::pin(async move {
            if horizon == 0 || maximum == 0 || maximum > 100_000 {
                return Err(ControlPlaneError::InvalidInput(
                    "GC candidate bound is invalid",
                ));
            }
            let mut tx = self.pool().begin().await?;
            verify_gc_lease(&mut tx, lease, now, "sweeping", false).await?;
            let rows=sqlx::query("SELECT object_digest,size_bytes FROM lifecycle_gc_candidates WHERE first_absent_generation < $1 AND last_absent_generation=$1 AND observed_unix_ms <= $2 AND swept_unix_ms IS NULL ORDER BY object_digest LIMIT $3").bind(postgres_i64(lease.generation,"GC generation")?).bind(postgres_i64(now.saturating_sub(horizon),"GC safety horizon")?).bind(i64::try_from(maximum).map_err(|_|ControlPlaneError::IntegerRange{field:"GC candidate bound"})?).fetch_all(&mut*tx).await?;
            let out = rows
                .into_iter()
                .map(|r| {
                    Ok((
                        ContentDigest::parse(r.try_get::<String, _>("object_digest")?)?,
                        postgres_u64(r.try_get("size_bytes")?, "GC candidate bytes")?,
                    ))
                })
                .collect::<Result<_, ControlPlaneError>>()?;
            tx.commit().await?;
            Ok(out)
        })
    }
    fn lifecycle_metrics(&self) -> StoreFuture<'_, LifecycleGcMetrics> {
        Box::pin(async move {
            let r=sqlx::query("SELECT c.current_generation,COALESCE(y.marked_objects,0) marked_objects,COALESCE(y.candidate_objects,0) candidate_objects,COALESCE(y.swept_objects,0) swept_objects,COALESCE(y.swept_bytes,0) swept_bytes,(SELECT COUNT(*) FROM tenant_storage_reservations WHERE state IN('reserved','committed')) active_storage_reservations,(SELECT COUNT(*) FROM artifact_scan_journal WHERE state IN('pending','claimed')) scan_pending,(SELECT COUNT(*) FROM artifact_scan_journal WHERE state IN('failed','error')) scan_failed FROM lifecycle_gc_control c LEFT JOIN lifecycle_gc_cycles y ON y.generation=c.current_generation WHERE c.singleton=TRUE").fetch_one(self.pool()).await?;
            Ok(LifecycleGcMetrics {
                generation: pg_count(&r, "current_generation", "GC generation")?,
                marked_objects: pg_count(&r, "marked_objects", "GC marked objects")?,
                candidate_objects: pg_count(&r, "candidate_objects", "GC candidate objects")?,
                swept_objects: pg_count(&r, "swept_objects", "GC swept objects")?,
                swept_bytes: pg_count(&r, "swept_bytes", "GC swept bytes")?,
                active_storage_reservations: pg_count(
                    &r,
                    "active_storage_reservations",
                    "active reservations",
                )?,
                scan_pending: pg_count(&r, "scan_pending", "pending scans")?,
                scan_failed_or_error: pg_count(&r, "scan_failed", "failed scans")?,
            })
        })
    }
}

#[cfg(feature = "postgres")]
async fn claim_task_pg(
    store: &PostgresInstallationStore,
    worker: &str,
    kind: Option<&str>,
    now: u64,
    duration: u64,
) -> Result<Option<DurableTask>, ControlPlaneError> {
    validate_text("task.worker", worker)?;
    if duration == 0 {
        return Err(ControlPlaneError::InvalidInput(
            "task lease duration must be positive",
        ));
    }
    let expiry = now
        .checked_add(duration)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "task lease expiry",
        })?;
    let mut tx = store.pool().begin().await?;
    let n = postgres_i64(now, "task claim clock")?;
    if let Some(k) = kind {
        sqlx::query("UPDATE durable_tasks SET status='pending',lease_owner=NULL,lease_expires_unix_ms=NULL WHERE kind=$1 AND status='claimed' AND lease_expires_unix_ms <= $2").bind(k).bind(n).execute(&mut*tx).await?;
        if k == crate::SCM_EVENT_TASK_KIND {
            sqlx::query("UPDATE durable_tasks SET recoverable_until_unix_ms=created_unix_ms+86400000 WHERE kind='scm.event' AND status='failed' AND recoverable_until_unix_ms IS NULL AND created_unix_ms <= 9223372036768375807 AND created_unix_ms+86400000 > $1 AND last_error IN ('repository-action preparation is temporarily unavailable','GitHub actor permission lookup is unavailable','Git mirror repository is unavailable or unsafe','source manifest CAS publication failed','Git mirror repository changed while planning','exact Git revision or trusted workflow is unavailable','exact reusable workflow mirror or object is unavailable','source snapshot construction is temporarily unavailable','restore safe mode blocked the SCM event commit')").bind(n).execute(&mut*tx).await?;
        }
        sqlx::query("UPDATE durable_tasks SET status='failed',available_unix_ms=$2,completed_unix_ms=$2,lease_owner=NULL,lease_expires_unix_ms=NULL WHERE kind=$1 AND status='pending' AND recoverable_until_unix_ms IS NOT NULL AND recoverable_until_unix_ms <= $2").bind(k).bind(n).execute(&mut*tx).await?;
    } else {
        sqlx::query("UPDATE durable_tasks SET status='pending',lease_owner=NULL,lease_expires_unix_ms=NULL WHERE status='claimed' AND lease_expires_unix_ms <= $1").bind(n).execute(&mut*tx).await?;
    }
    let id: Option<String> = if let Some(k) = kind {
        sqlx::query_scalar("SELECT id FROM durable_tasks WHERE kind=$1 AND ((status='pending' AND available_unix_ms <= $2) OR (status='failed' AND $1='scm.event' AND recoverable_until_unix_ms > $2)) ORDER BY available_unix_ms,id FOR UPDATE SKIP LOCKED LIMIT 1").bind(k).bind(n).fetch_optional(&mut*tx).await?
    } else {
        sqlx::query_scalar("SELECT id FROM durable_tasks WHERE status='pending' AND available_unix_ms <= $1 ORDER BY available_unix_ms,id FOR UPDATE SKIP LOCKED LIMIT 1").bind(n).fetch_optional(&mut*tx).await?
    };
    let Some(id) = id else {
        tx.commit().await?;
        return Ok(None);
    };
    sqlx::query("UPDATE durable_tasks SET status='claimed',attempts=attempts+1,lease_owner=$2,lease_expires_unix_ms=$3,completed_unix_ms=NULL WHERE id=$1 AND status IN ('pending','failed')").bind(&id).bind(worker).bind(postgres_i64(expiry,"task lease expiry")?).execute(&mut*tx).await?;
    let task = task_tx(&mut tx, &id, false)
        .await?
        .ok_or_else(|| not_found("task", &id))?;
    tx.commit().await?;
    Ok(Some(task))
}

#[cfg(feature = "postgres")]
async fn promotion_request_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<PromotionRequestRecord>, ControlPlaneError> {
    sqlx::query("SELECT id,kind,source_id,target_json,evidence_json,status,created_unix_ms FROM promotion_requests WHERE id=$1").bind(id).fetch_optional(&mut**tx).await?.map(|r|Ok(PromotionRequestRecord{id:r.try_get("id")?,kind:r.try_get("kind")?,source_id:r.try_get("source_id")?,target:serde_json::from_slice(&r.try_get::<Vec<u8>,_>("target_json")?)?,evidence:serde_json::from_slice(&r.try_get::<Vec<u8>,_>("evidence_json")?)?,status:r.try_get("status")?,created_unix_ms:postgres_u64(r.try_get("created_unix_ms")?,"promotion creation")?})).transpose()
}

#[cfg(feature = "postgres")]
async fn require_task_owner(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    worker: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    let task = task_tx(tx, id, true)
        .await?
        .ok_or_else(|| not_found("task", id))?;
    if task.status != DurableTaskStatus::Claimed || task.lease_owner.as_deref() != Some(worker) {
        return Err(ControlPlaneError::TaskNotOwned);
    }
    if task.lease_expires_unix_ms.is_none_or(|e| now >= e) {
        return Err(ControlPlaneError::TaskLeaseExpired);
    }
    Ok(())
}
#[cfg(feature = "postgres")]
async fn mark_task_completed(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    now: u64,
) -> Result<(), ControlPlaneError> {
    sqlx::query("UPDATE durable_tasks SET status='completed',completed_unix_ms=$2,lease_owner=NULL,lease_expires_unix_ms=NULL WHERE id=$1").bind(id).bind(postgres_i64(now,"task completion")?).execute(&mut**tx).await?;
    Ok(())
}
#[cfg(feature = "postgres")]
async fn task_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    lock: bool,
) -> Result<Option<DurableTask>, ControlPlaneError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    sqlx::query(&format!("SELECT id,kind,payload_json,status,available_unix_ms,attempts,lease_owner,lease_expires_unix_ms,last_error,created_unix_ms,completed_unix_ms FROM durable_tasks WHERE id=$1{suffix}")).bind(id).fetch_optional(&mut**tx).await?.map(task_row).transpose()
}
#[cfg(feature = "postgres")]
fn task_row(r: sqlx::postgres::PgRow) -> Result<DurableTask, ControlPlaneError> {
    let status = match r.try_get::<String, _>("status")?.as_str() {
        "pending" => DurableTaskStatus::Pending,
        "claimed" => DurableTaskStatus::Claimed,
        "completed" => DurableTaskStatus::Completed,
        "failed" => DurableTaskStatus::Failed,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid durable task status".to_owned(),
            ))
        }
    };
    let attempts: i32 = r.try_get("attempts")?;
    Ok(DurableTask {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        payload: serde_json::from_slice(&r.try_get::<Vec<u8>, _>("payload_json")?)?,
        status,
        available_unix_ms: postgres_u64(r.try_get("available_unix_ms")?, "task availability")?,
        attempts: u32::try_from(attempts)
            .map_err(|_| ControlPlaneError::CorruptState("invalid task attempts".to_owned()))?,
        lease_owner: r.try_get("lease_owner")?,
        lease_expires_unix_ms: r
            .try_get::<Option<i64>, _>("lease_expires_unix_ms")?
            .map(|v| postgres_u64(v, "task lease expiry"))
            .transpose()?,
        last_error: r.try_get("last_error")?,
        created_unix_ms: postgres_u64(r.try_get("created_unix_ms")?, "task creation")?,
        completed_unix_ms: r
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|v| postgres_u64(v, "task completion"))
            .transpose()?,
    })
}
#[cfg(feature = "postgres")]
fn validate_new_task(t: &DurableTask) -> Result<(), ControlPlaneError> {
    validate_text("task.id", &t.id)?;
    validate_text("task.kind", &t.kind)?;
    if t.status != DurableTaskStatus::Pending
        || t.attempts != 0
        || t.lease_owner.is_some()
        || t.lease_expires_unix_ms.is_some()
        || t.completed_unix_ms.is_some()
    {
        return Err(ControlPlaneError::InvalidInput(
            "new durable task must be unclaimed and pending",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn canonicalize(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(canonicalize).collect())
        }
        serde_json::Value::Object(o) => serde_json::Value::Object(
            o.into_iter()
                .map(|(k, v)| (k, canonicalize(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        v => v,
    }
}
#[cfg(feature = "postgres")]
fn json_bytes(v: &serde_json::Value) -> Result<Vec<u8>, ControlPlaneError> {
    Ok(serde_json::to_vec(v)?)
}
#[cfg(feature = "postgres")]
fn validate_text(_field: &'static str, v: &str) -> Result<(), ControlPlaneError> {
    if v.is_empty() || v.len() > 1024 {
        return Err(ControlPlaneError::InvalidInput(
            "text field is empty or too long",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(feature = "postgres")]
fn validate_backup_pin(p: &BackupPinRecord) -> Result<(), ControlPlaneError> {
    validate_text("backup pin id", &p.id)?;
    validate_text("backup root id", &p.root_id)?;
    if let Some(t) = &p.tenant_id {
        validate_text("backup pin tenant", t)?
    }
    if !matches!(
        p.root_kind.as_str(),
        "artifact" | "cache" | "source" | "evidence" | "object"
    ) || p.released_unix_ms.is_some()
        || p.expires_unix_ms.is_some_and(|e| e <= p.created_unix_ms)
    {
        return Err(ControlPlaneError::InvalidInput(
            "backup pin metadata is invalid",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn backup_pin_row(r: sqlx::postgres::PgRow) -> Result<BackupPinRecord, ControlPlaneError> {
    Ok(BackupPinRecord {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        root_kind: r.try_get("root_kind")?,
        root_id: r.try_get("root_id")?,
        object_digest: ContentDigest::parse(r.try_get::<String, _>("object_digest")?)?,
        created_unix_ms: postgres_u64(r.try_get("created_unix_ms")?, "backup pin creation")?,
        expires_unix_ms: r
            .try_get::<Option<i64>, _>("expires_unix_ms")?
            .map(|v| postgres_u64(v, "backup pin expiry"))
            .transpose()?,
        released_unix_ms: r
            .try_get::<Option<i64>, _>("released_unix_ms")?
            .map(|v| postgres_u64(v, "backup pin release"))
            .transpose()?,
    })
}
#[cfg(feature = "postgres")]
async fn verify_gc_lease(
    tx: &mut Transaction<'_, Postgres>,
    l: &LifecycleGcLease,
    now: u64,
    phase: &str,
    lock: bool,
) -> Result<(), ControlPlaneError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let valid:bool=sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM lifecycle_gc_control WHERE singleton=TRUE AND current_generation=$1 AND phase=$2 AND lease_owner=$3 AND lease_token=$4 AND lease_expires_unix_ms > $5{suffix})")).bind(postgres_i64(l.generation,"GC generation")?).bind(phase).bind(&l.lease_owner).bind(&l.lease_token).bind(postgres_i64(now,"GC lease clock")?).fetch_one(&mut**tx).await?;
    if valid {
        Ok(())
    } else {
        Err(ControlPlaneError::LifecycleGcLeaseLost)
    }
}
#[cfg(feature = "postgres")]
async fn delete_bounded(
    tx: &mut Transaction<'_, Postgres>,
    table: &str,
    key: &str,
    predicate: &str,
    order: &str,
    cutoff: u64,
    limit: i64,
) -> Result<u64, ControlPlaneError> {
    for v in [table, key, order] {
        if !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ControlPlaneError::InvalidInput(
                "invalid lifecycle table identifier",
            ));
        }
    }
    let sql = if key == "ctid" {
        format!("WITH selected AS(SELECT ctid FROM {table} WHERE {predicate} ORDER BY {order} LIMIT $2) DELETE FROM {table} t USING selected s WHERE t.ctid=s.ctid")
    } else {
        format!("WITH selected AS(SELECT {key} FROM {table} WHERE {predicate} ORDER BY {order} LIMIT $2) DELETE FROM {table} t USING selected s WHERE t.{key}=s.{key}")
    };
    Ok(sqlx::query(&sql)
        .bind(postgres_i64(cutoff, "lifecycle cutoff")?)
        .bind(limit)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}
#[cfg(feature = "postgres")]
fn pg_count(
    r: &sqlx::postgres::PgRow,
    column: &str,
    field: &'static str,
) -> Result<u64, ControlPlaneError> {
    postgres_u64(r.try_get(column)?, field)
}

#[cfg(feature = "postgres")]
const GC_ROOTS_SQL: &str = r#"
SELECT g.manifest_digest AS digest,'cache-manifest' AS root_kind,g.cache_entry_id AS root_id FROM cache_trust_current_heads h JOIN cache_trust_generations g ON g.cache_entry_id=h.cache_entry_id
UNION ALL SELECT g.tree_manifest_digest,'cache-tree',g.cache_entry_id FROM cache_trust_current_heads h JOIN cache_trust_generations g ON g.cache_entry_id=h.cache_entry_id
UNION ALL SELECT a.artifact_id,'artifact-record',a.artifact_id FROM artifacts_catalog a WHERE a.state<>'retired' AND(a.legal_hold=TRUE OR a.retention_until_unix_seconds>$1)
UNION ALL SELECT t.object_digest,'pending-transfer',t.ticket_id FROM runner_object_transfers t WHERE t.state IN('reserved','transferring','verified') AND t.object_digest IS NOT NULL
UNION ALL SELECT c.object_id,'artifact-pending-commit',c.ticket_id FROM runner_data_commits c LEFT JOIN job_result_objects o ON o.kind=c.kind AND o.object_id=c.object_id WHERE o.object_id IS NULL AND c.kind='artifact'
UNION ALL SELECT g.manifest_digest,'cache-manifest',c.ticket_id FROM runner_data_commits c JOIN cache_trust_generations g ON g.cache_entry_id=c.object_id LEFT JOIN job_result_objects o ON o.kind=c.kind AND o.object_id=c.object_id WHERE o.object_id IS NULL AND c.kind='cache'
UNION ALL SELECT p.evidence_digest,'cache-promotion-evidence',p.id FROM cache_promotion_journal p WHERE p.state='pending'
UNION ALL SELECT g.tree_manifest_digest,'cache-promotion-source',p.id FROM cache_promotion_journal p JOIN cache_trust_generations g ON g.cache_entry_id=p.source_cache_entry_id WHERE p.state='pending'
UNION ALL SELECT a.artifact_id,'artifact-promotion-source',p.id FROM artifact_promotions p JOIN artifacts_catalog a ON a.artifact_id=p.source_artifact_id WHERE p.status='pending'
UNION ALL SELECT p.evidence_digest,'artifact-promotion-evidence',p.id FROM artifact_promotions p JOIN artifacts_catalog a ON a.artifact_id=p.source_artifact_id WHERE a.state<>'retired' AND(a.legal_hold=TRUE OR a.retention_until_unix_seconds>$1)
UNION ALL SELECT p.promoted_artifact_id,'artifact-promoted-record',p.id FROM artifact_promotions p JOIN artifacts_catalog a ON a.artifact_id=p.source_artifact_id WHERE p.status='succeeded' AND p.promoted_artifact_id IS NOT NULL AND a.state<>'retired' AND(a.legal_hold=TRUE OR a.retention_until_unix_seconds>$1)
UNION ALL SELECT s.tree_manifest_digest,'source-snapshot',s.id FROM source_snapshots s WHERE s.state='ready' AND EXISTS(SELECT 1 FROM run_source_snapshots r WHERE r.source_snapshot_id=s.id)
UNION ALL SELECT b.object_digest,CASE b.root_kind WHEN'artifact'THEN'artifact-record' WHEN'cache'THEN'cache-manifest' WHEN'source'THEN'source-snapshot' ELSE'opaque-object'END,b.id FROM backup_pins b WHERE b.released_unix_ms IS NULL AND(b.expires_unix_ms IS NULL OR b.expires_unix_ms>$2)
UNION ALL SELECT r.result_digest,'scan-evidence',r.artifact_id||':'||r.scanner FROM artifact_scan_results r
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiTokenAuditStore, ControlPlaneError};

    fn pending(id: &str, kind: &str, available: u64) -> DurableTask {
        DurableTask {
            id: id.to_owned(),
            kind: kind.to_owned(),
            payload: serde_json::json!({"id":id}),
            status: DurableTaskStatus::Pending,
            available_unix_ms: available,
            attempts: 0,
            lease_owner: None,
            lease_expires_unix_ms: None,
            last_error: None,
            created_unix_ms: 1,
            completed_unix_ms: None,
        }
    }

    async fn contract<S: DurableTaskStore + LifecycleGcStore + ApiTokenAuditStore>(
        store: &S,
        suffix: &str,
    ) {
        let promotion = PromotionRequestRecord {
            id: format!("generic-promotion-{suffix}"),
            kind: "cache".to_owned(),
            source_id: format!("source-{suffix}"),
            target: serde_json::json!({"scope":"main"}),
            evidence: serde_json::json!({"approved":true}),
            status: "pending".to_owned(),
            created_unix_ms: 1,
        };
        assert!(
            !store
                .create_promotion_request("promotion-key", &promotion)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            store
                .create_promotion_request("promotion-key", &promotion)
                .await
                .unwrap()
                .replayed
        );
        let promotion_task = store
            .claim_task_by_kind("worker", "cache.promotion", 1, 10)
            .await
            .unwrap()
            .unwrap();
        store
            .complete_task(&promotion_task.id, "worker", 2)
            .await
            .unwrap();
        let first = pending(&format!("task-first-{suffix}"), "build", 1);
        store.enqueue_task(&first).await.unwrap();
        assert!(store
            .claim_task_by_kind("wrong", "other", 2, 10)
            .await
            .unwrap()
            .is_none());
        let claimed = store
            .claim_task_by_kind("worker", "build", 2, 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.attempts, 1);
        assert!(matches!(
            store.complete_task(&first.id, "other", 3).await,
            Err(ControlPlaneError::TaskNotOwned)
        ));
        assert_eq!(
            store
                .fail_task(&first.id, "worker", "retry", 3, Some(5), None)
                .await
                .unwrap()
                .status,
            DurableTaskStatus::Pending
        );
        assert!(store.claim_task("worker", 4, 10).await.unwrap().is_none());
        assert_eq!(
            store
                .claim_task("worker", 5, 10)
                .await
                .unwrap()
                .unwrap()
                .attempts,
            2
        );
        let follow = pending(&format!("task-follow-{suffix}"), "follow", 6);
        store
            .complete_task_with_followups(&first.id, "worker", std::slice::from_ref(&follow), 6)
            .await
            .unwrap();
        assert_eq!(
            store.task(&first.id).await.unwrap().status,
            DurableTaskStatus::Completed
        );
        assert_eq!(
            store.claim_task("worker", 6, 10).await.unwrap().unwrap().id,
            follow.id
        );
        assert_eq!(
            store
                .complete_task(&follow.id, "worker", 7)
                .await
                .unwrap()
                .status,
            DurableTaskStatus::Completed
        );
        let failed = pending(&format!("task-failed-{suffix}"), "fail", 8);
        store.enqueue_task(&failed).await.unwrap();
        store.claim_task("worker", 8, 10).await.unwrap();
        assert_eq!(
            store
                .fail_task(&failed.id, "worker", "terminal", 9, None, None)
                .await
                .unwrap()
                .status,
            DurableTaskStatus::Failed
        );
        let pin = BackupPinRecord {
            id: format!("pin-{suffix}"),
            tenant_id: None,
            root_kind: "object".to_owned(),
            root_id: format!("backup-{suffix}"),
            object_digest: ContentDigest::sha256(format!("pin-object-{suffix}")),
            created_unix_ms: 10,
            expires_unix_ms: None,
            released_unix_ms: None,
        };
        assert!(!store.create_backup_pin(&pin).await.unwrap());
        assert!(store.create_backup_pin(&pin).await.unwrap());
        let lease1 = store
            .acquire_lifecycle_gc("gc-worker", &format!("lease-1-{suffix}"), 11, 100)
            .await
            .unwrap();
        assert!(matches!(
            store.acquire_lifecycle_gc("other", "busy", 12, 100).await,
            Err(ControlPlaneError::LifecycleGcLeaseBusy)
        ));
        let roots = store.lifecycle_gc_roots(&lease1, 12, 100).await.unwrap();
        assert!(roots.iter().any(|r| r.digest == pin.object_digest));
        store
            .record_lifecycle_gc_marks(&lease1, &roots, 13)
            .await
            .unwrap();
        let orphan = ContentDigest::sha256(format!("orphan-{suffix}"));
        assert!(store
            .observe_lifecycle_gc_inventory(&lease1, &[(orphan.clone(), 9, 1)], 14, 1)
            .await
            .unwrap()
            .is_empty());
        assert!(!store.complete_lifecycle_gc(&lease1, &[], 15).await.unwrap());
        assert!(store.complete_lifecycle_gc(&lease1, &[], 16).await.unwrap());
        let lease2 = store
            .acquire_lifecycle_gc("gc-worker", &format!("lease-2-{suffix}"), 20, 100)
            .await
            .unwrap();
        let roots = store.lifecycle_gc_roots(&lease2, 21, 100).await.unwrap();
        store
            .record_lifecycle_gc_marks(&lease2, &roots, 22)
            .await
            .unwrap();
        assert_eq!(
            store
                .observe_lifecycle_gc_inventory(&lease2, &[(orphan.clone(), 9, 1)], 23, 1)
                .await
                .unwrap(),
            vec![orphan.clone()]
        );
        assert_eq!(
            store
                .lifecycle_gc_sweep_candidates(&lease2, 23, 1, 100)
                .await
                .unwrap(),
            vec![(orphan.clone(), 9)]
        );
        assert!(!store
            .complete_lifecycle_gc(&lease2, &[(orphan, 9)], 24)
            .await
            .unwrap());
        let metrics = store.lifecycle_metrics().await.unwrap();
        assert_eq!(
            (
                metrics.generation,
                metrics.swept_objects,
                metrics.swept_bytes
            ),
            (2, 1, 9)
        );
        assert_eq!(store.retire_expired_artifacts(25, 10).await.unwrap(), 0);
        assert_eq!(
            store.prune_lifecycle_ledgers(25, 1, 10).await.unwrap(),
            LifecyclePruneSummary {
                storage_reservations: 0,
                download_tickets: 0,
                object_transfers: 0,
                cache_observations: 0,
                log_frames: 0
            }
        );
        assert_eq!(
            store
                .events()
                .await
                .unwrap()
                .iter()
                .filter(|e| e.data.action == "storage.gc")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn sqlite_durable_lifecycle_contract() {
        let store = ControlPlane::open_in_memory("sqlite-durable-lifecycle", 1).unwrap();
        contract(&store, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_durable_lifecycle_contract() {
        use crate::PostgresInstallationStore;
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "durable-lifecycle").await;
        let store =
            PostgresInstallationStore::connect(fixture.config(), "postgres-durable-lifecycle", 1)
                .await
                .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        contract(&store, &suffix).await;
        store.close().await;
        fixture.cleanup().await;
    }
}
