//! PostgreSQL artifact, cache, storage-accounting, and lifecycle boundary.

use super::StoreFuture;
#[cfg(feature = "postgres")]
use super::{postgres_i64, postgres_u64, PostgresInstallationStore};
#[cfg(any(feature = "postgres", test))]
use crate::CachePromotionState;
use crate::{
    ArtifactCatalogRecord, ArtifactDownloadTicketRecord, ArtifactMetrics, ArtifactPromotionIntent,
    ArtifactScanJournalRecord, ArtifactScanState, CacheAccessObservation, CachePromotionRecord,
    CacheTrustGenerationRecord, CacheTrustMetrics, ControlPlane, IdempotentResult,
    StorageReservationState, StorageTicketBinding, TenantStorageQuota, TenantStorageReservation,
    TenantStorageUsage,
};
#[cfg(feature = "postgres")]
use crate::{ControlPlaneError, StorageTicketBindingState};
#[cfg(feature = "postgres")]
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource, AuditValue};
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use serde_json::Value;
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};
#[cfg(feature = "postgres")]
use std::collections::BTreeMap;

#[cfg(feature = "postgres")]
pub(super) const POSTGRES_MIGRATION: &str =
    include_str!("../../migrations/postgres/0010_artifacts_cache_lifecycle.sql");

#[cfg(feature = "postgres")]
const DEFAULT_MAXIMUM_STORED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
#[cfg(feature = "postgres")]
const DEFAULT_MAXIMUM_OBJECT_COUNT: u64 = 100_000;

/// Durable storage quota and ticket-accounting operations shared by both
/// database backends.
pub trait ArtifactStorageStore: Send + Sync {
    fn set_tenant_storage_quota<'a>(&'a self, quota: &'a TenantStorageQuota)
        -> StoreFuture<'a, ()>;
    fn reserve_tenant_storage<'a>(
        &'a self,
        reservation: &'a TenantStorageReservation,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn tenant_storage_reservation<'a>(
        &'a self,
        tenant_id: &'a str,
        reservation_id: &'a str,
    ) -> StoreFuture<'a, Option<TenantStorageReservation>>;
    fn finish_tenant_storage_reservation<'a>(
        &'a self,
        tenant_id: &'a str,
        reservation_id: &'a str,
        target: StorageReservationState,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn bind_tenant_storage_ticket<'a>(
        &'a self,
        binding: &'a StorageTicketBinding,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn storage_ticket_binding_for_reservation<'a>(
        &'a self,
        tenant_id: &'a str,
        reservation_id: &'a str,
    ) -> StoreFuture<'a, Option<StorageTicketBinding>>;
    fn commit_tenant_storage_ticket<'a>(
        &'a self,
        tenant_id: &'a str,
        ticket_id: &'a str,
        object_id: &'a str,
        actual_bytes: u64,
        actual_objects: u64,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn account_tenant_storage_ticket<'a>(
        &'a self,
        tenant_id: &'a str,
        ticket_id: &'a str,
        object_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn tenant_storage_usage<'a>(
        &'a self,
        tenant_id: &'a str,
    ) -> StoreFuture<'a, TenantStorageUsage>;
}

pub trait ArtifactCatalogStore: Send + Sync {
    fn catalog_artifact<'a>(
        &'a self,
        record: &'a ArtifactCatalogRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactCatalogRecord>>;
    fn artifact_for_tenant<'a>(
        &'a self,
        tenant_id: &'a str,
        artifact_id: &'a str,
    ) -> StoreFuture<'a, ArtifactCatalogRecord>;
    fn artifact<'a>(&'a self, artifact_id: &'a str) -> StoreFuture<'a, ArtifactCatalogRecord>;
    fn issue_artifact_download_ticket<'a>(
        &'a self,
        ticket: &'a ArtifactDownloadTicketRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactDownloadTicketRecord>>;
    fn consume_artifact_download_ticket<'a>(
        &'a self,
        token_hash: &'a ContentDigest,
        tenant_id: Option<&'a str>,
        principal_id: &'a str,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, ArtifactDownloadTicketRecord>;
    fn artifact_metrics<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, ArtifactMetrics>;
}

/// Cache trust generations, current heads, promotion journals, access
/// observations, and their bounded metrics. Implementations preserve exact
/// replay and tenant-scoped lookup semantics across database backends.
pub trait CacheTrustStore: Send + Sync {
    fn record_cache_trust_generation<'a>(
        &'a self,
        record: &'a CacheTrustGenerationRecord,
        expected_store_generation: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn create_cache_promotion_idempotent<'a>(
        &'a self,
        record: &'a CachePromotionRecord,
    ) -> StoreFuture<'a, bool>;
    fn complete_cache_promotion<'a>(
        &'a self,
        tenant_id: &'a str,
        promotion_id: &'a str,
        promoted: &'a CacheTrustGenerationRecord,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn cache_promotion<'a>(
        &'a self,
        tenant_id: &'a str,
        promotion_id: &'a str,
    ) -> StoreFuture<'a, CachePromotionRecord>;
    fn cache_trust_generation<'a>(
        &'a self,
        tenant_id: &'a str,
        cache_entry_id: &'a str,
    ) -> StoreFuture<'a, CacheTrustGenerationRecord>;
    fn record_cache_access_observation<'a>(
        &'a self,
        observation: &'a CacheAccessObservation,
    ) -> StoreFuture<'a, bool>;
    fn cache_trust_metrics<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, CacheTrustMetrics>;
}

/// Artifact scan work and evidence-bearing promotion journals. Claims,
/// completions, catalog state, evidence rows, and audit events are committed
/// as one transaction.
pub trait ArtifactScanPromotionStore: Send + Sync {
    fn enqueue_artifact_scan<'a>(
        &'a self,
        record: &'a ArtifactScanJournalRecord,
    ) -> StoreFuture<'a, bool>;
    fn claim_artifact_scan<'a>(
        &'a self,
        worker_id: &'a str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> StoreFuture<'a, Option<ArtifactScanJournalRecord>>;
    #[allow(clippy::too_many_arguments)]
    fn finish_artifact_scan<'a>(
        &'a self,
        tenant_id: &'a str,
        scan_id: &'a str,
        worker_id: &'a str,
        state: ArtifactScanState,
        result_digest: Option<&'a ContentDigest>,
        error_code: Option<&'a str>,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
    fn create_artifact_promotion<'a>(
        &'a self,
        intent: &'a ArtifactPromotionIntent,
    ) -> StoreFuture<'a, bool>;
    fn artifact_promotion<'a>(
        &'a self,
        tenant_id: &'a str,
        promotion_id: &'a str,
    ) -> StoreFuture<'a, ArtifactPromotionIntent>;
    fn complete_artifact_promotion<'a>(
        &'a self,
        tenant_id: &'a str,
        promotion_id: &'a str,
        promoted_artifact_id: &'a str,
        promoted_manifest_digest: &'a ContentDigest,
        now_unix_ms: u64,
    ) -> StoreFuture<'a, bool>;
}

impl ArtifactScanPromotionStore for ControlPlane {
    fn enqueue_artifact_scan<'a>(
        &'a self,
        record: &'a ArtifactScanJournalRecord,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::enqueue_artifact_scan(self, record);
        Box::pin(async move { result })
    }

    fn claim_artifact_scan<'a>(
        &'a self,
        worker: &'a str,
        now: u64,
        duration: u64,
    ) -> StoreFuture<'a, Option<ArtifactScanJournalRecord>> {
        let result = ControlPlane::claim_artifact_scan(self, worker, now, duration);
        Box::pin(async move { result })
    }

    fn finish_artifact_scan<'a>(
        &'a self,
        tenant: &'a str,
        scan: &'a str,
        worker: &'a str,
        state: ArtifactScanState,
        digest: Option<&'a ContentDigest>,
        error: Option<&'a str>,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::finish_artifact_scan(
            self, tenant, scan, worker, state, digest, error, now,
        );
        Box::pin(async move { result })
    }

    fn create_artifact_promotion<'a>(
        &'a self,
        intent: &'a ArtifactPromotionIntent,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::create_artifact_promotion(self, intent);
        Box::pin(async move { result })
    }

    fn artifact_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
    ) -> StoreFuture<'a, ArtifactPromotionIntent> {
        let result = ControlPlane::artifact_promotion(self, tenant, promotion);
        Box::pin(async move { result })
    }

    fn complete_artifact_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
        promoted: &'a str,
        manifest: &'a ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::complete_artifact_promotion(
            self, tenant, promotion, promoted, manifest, now,
        );
        Box::pin(async move { result })
    }
}

impl CacheTrustStore for ControlPlane {
    fn record_cache_trust_generation<'a>(
        &'a self,
        record: &'a CacheTrustGenerationRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::record_cache_trust_generation(self, record, expected);
        Box::pin(async move { result })
    }

    fn create_cache_promotion_idempotent<'a>(
        &'a self,
        record: &'a CachePromotionRecord,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::create_cache_promotion_idempotent(self, record);
        Box::pin(async move { result })
    }

    fn complete_cache_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
        promoted: &'a CacheTrustGenerationRecord,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::complete_cache_promotion(self, tenant, promotion, promoted, now);
        Box::pin(async move { result })
    }

    fn cache_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
    ) -> StoreFuture<'a, CachePromotionRecord> {
        let result = ControlPlane::cache_promotion(self, tenant, promotion);
        Box::pin(async move { result })
    }

    fn cache_trust_generation<'a>(
        &'a self,
        tenant: &'a str,
        cache_entry: &'a str,
    ) -> StoreFuture<'a, CacheTrustGenerationRecord> {
        let result = ControlPlane::cache_trust_generation(self, tenant, cache_entry);
        Box::pin(async move { result })
    }

    fn record_cache_access_observation<'a>(
        &'a self,
        observation: &'a CacheAccessObservation,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::record_cache_access_observation(self, observation);
        Box::pin(async move { result })
    }

    fn cache_trust_metrics<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, CacheTrustMetrics> {
        let result = ControlPlane::cache_trust_metrics(self, tenant);
        Box::pin(async move { result })
    }
}

impl ArtifactCatalogStore for ControlPlane {
    fn catalog_artifact<'a>(
        &'a self,
        r: &'a ArtifactCatalogRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactCatalogRecord>> {
        let v = ControlPlane::catalog_artifact(self, r);
        Box::pin(async move { v })
    }
    fn artifact_for_tenant<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
    ) -> StoreFuture<'a, ArtifactCatalogRecord> {
        let v = ControlPlane::artifact_for_tenant(self, t, i);
        Box::pin(async move { v })
    }
    fn artifact<'a>(&'a self, i: &'a str) -> StoreFuture<'a, ArtifactCatalogRecord> {
        let v = ControlPlane::artifact(self, i);
        Box::pin(async move { v })
    }
    fn issue_artifact_download_ticket<'a>(
        &'a self,
        t: &'a ArtifactDownloadTicketRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactDownloadTicketRecord>> {
        let v = ControlPlane::issue_artifact_download_ticket(self, t);
        Box::pin(async move { v })
    }
    fn consume_artifact_download_ticket<'a>(
        &'a self,
        h: &'a ContentDigest,
        t: Option<&'a str>,
        p: &'a str,
        n: u64,
    ) -> StoreFuture<'a, ArtifactDownloadTicketRecord> {
        let v = ControlPlane::consume_artifact_download_ticket(self, h, t, p, n);
        Box::pin(async move { v })
    }
    fn artifact_metrics<'a>(&'a self, t: &'a str) -> StoreFuture<'a, ArtifactMetrics> {
        let v = ControlPlane::artifact_metrics(self, t);
        Box::pin(async move { v })
    }
}

impl ArtifactStorageStore for ControlPlane {
    fn set_tenant_storage_quota<'a>(&'a self, q: &'a TenantStorageQuota) -> StoreFuture<'a, ()> {
        let result = ControlPlane::set_tenant_storage_quota(self, q);
        Box::pin(async move { result })
    }
    fn reserve_tenant_storage<'a>(
        &'a self,
        r: &'a TenantStorageReservation,
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::reserve_tenant_storage(self, r, n);
        Box::pin(async move { result })
    }
    fn tenant_storage_reservation<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
    ) -> StoreFuture<'a, Option<TenantStorageReservation>> {
        let result = ControlPlane::tenant_storage_reservation(self, t, r);
        Box::pin(async move { result })
    }
    fn finish_tenant_storage_reservation<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
        s: StorageReservationState,
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::finish_tenant_storage_reservation(self, t, r, s, n);
        Box::pin(async move { result })
    }
    fn bind_tenant_storage_ticket<'a>(
        &'a self,
        b: &'a StorageTicketBinding,
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::bind_tenant_storage_ticket(self, b, n);
        Box::pin(async move { result })
    }
    fn storage_ticket_binding_for_reservation<'a>(
        &'a self,
        t: &'a str,
        r: &'a str,
    ) -> StoreFuture<'a, Option<StorageTicketBinding>> {
        let result = ControlPlane::storage_ticket_binding_for_reservation(self, t, r);
        Box::pin(async move { result })
    }
    fn commit_tenant_storage_ticket<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        o: &'a str,
        b: u64,
        c: u64,
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::commit_tenant_storage_ticket(self, t, i, o, b, c, n);
        Box::pin(async move { result })
    }
    fn account_tenant_storage_ticket<'a>(
        &'a self,
        t: &'a str,
        i: &'a str,
        o: &'a str,
        n: u64,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::account_tenant_storage_ticket(self, t, i, o, n);
        Box::pin(async move { result })
    }
    fn tenant_storage_usage<'a>(&'a self, t: &'a str) -> StoreFuture<'a, TenantStorageUsage> {
        let result = ControlPlane::tenant_storage_usage(self, t);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
impl ArtifactStorageStore for PostgresInstallationStore {
    fn set_tenant_storage_quota<'a>(
        &'a self,
        quota: &'a TenantStorageQuota,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            validate_quota(quota)?;
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
                    .bind(&quota.tenant_id)
                    .fetch_one(self.pool())
                    .await?;
            if !exists {
                return Err(not_found("tenant", &quota.tenant_id));
            }
            sqlx::query("INSERT INTO tenant_storage_quotas(tenant_id,maximum_stored_bytes,maximum_object_count,updated_unix_ms) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET maximum_stored_bytes=excluded.maximum_stored_bytes,maximum_object_count=excluded.maximum_object_count,updated_unix_ms=excluded.updated_unix_ms")
                .bind(&quota.tenant_id)
                .bind(postgres_i64(quota.maximum_stored_bytes, "maximum stored bytes")?)
                .bind(postgres_i64(quota.maximum_object_count, "maximum object count")?)
                .bind(postgres_i64(quota.updated_unix_ms, "storage quota update")?)
                .execute(self.pool()).await?;
            Ok(())
        })
    }

    fn reserve_tenant_storage<'a>(
        &'a self,
        reservation: &'a TenantStorageReservation,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_reservation(reservation, now)?;
            let now_i64 = postgres_i64(now, "storage reservation clock")?;
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, &reservation.tenant_id).await?;
            if let Some(existing) = reservation_by_id(&mut tx, &reservation.id).await? {
                if existing == *reservation {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
                    .bind(&reservation.tenant_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(not_found("tenant storage quota", &reservation.tenant_id));
            }
            sqlx::query("INSERT INTO tenant_storage_quotas(tenant_id,maximum_stored_bytes,maximum_object_count,updated_unix_ms) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(&reservation.tenant_id)
                .bind(postgres_i64(DEFAULT_MAXIMUM_STORED_BYTES, "default maximum stored bytes")?)
                .bind(postgres_i64(DEFAULT_MAXIMUM_OBJECT_COUNT, "default maximum object count")?)
                .bind(now_i64).execute(&mut *tx).await?;
            sqlx::query("UPDATE tenant_storage_reservations SET state='expired',completed_unix_ms=$2 WHERE tenant_id=$1 AND state='reserved' AND expires_unix_ms <= $2")
                .bind(&reservation.tenant_id).bind(now_i64).execute(&mut *tx).await?;
            let quota = sqlx::query("SELECT maximum_stored_bytes,maximum_object_count FROM tenant_storage_quotas WHERE tenant_id=$1 FOR UPDATE")
                .bind(&reservation.tenant_id).fetch_one(&mut *tx).await?;
            let active = sqlx::query("SELECT COALESCE(SUM(billed_bytes),0)::BIGINT AS bytes,COALESCE(SUM(billed_objects),0)::BIGINT AS objects FROM tenant_storage_objects WHERE tenant_id=$1 AND state='active'")
                .bind(&reservation.tenant_id).fetch_one(&mut *tx).await?;
            let held = sqlx::query("SELECT COALESCE(SUM(reserved_bytes),0)::BIGINT AS bytes,COALESCE(SUM(reserved_objects),0)::BIGINT AS objects FROM tenant_storage_reservations WHERE tenant_id=$1 AND state IN ('reserved','committed')")
                .bind(&reservation.tenant_id).fetch_one(&mut *tx).await?;
            let bytes = checked_sum(
                active.try_get("bytes")?,
                held.try_get("bytes")?,
                reservation.reserved_bytes,
                "tenant stored bytes",
            )?;
            let objects = checked_sum(
                active.try_get("objects")?,
                held.try_get("objects")?,
                reservation.reserved_objects,
                "tenant stored objects",
            )?;
            if bytes
                > postgres_u64(
                    quota.try_get("maximum_stored_bytes")?,
                    "maximum stored bytes",
                )?
                || objects
                    > postgres_u64(
                        quota.try_get("maximum_object_count")?,
                        "maximum object count",
                    )?
            {
                return Err(ControlPlaneError::StorageQuotaExceeded);
            }
            sqlx::query("INSERT INTO tenant_storage_reservations(id,tenant_id,ticket_kind,object_digest,reserved_bytes,reserved_objects,state,created_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,'reserved',$7,$8)")
                .bind(&reservation.id).bind(&reservation.tenant_id).bind(&reservation.ticket_kind)
                .bind(reservation.object_digest.as_ref().map(ContentDigest::as_str))
                .bind(postgres_i64(reservation.reserved_bytes, "reserved bytes")?)
                .bind(postgres_i64(reservation.reserved_objects, "reserved objects")?)
                .bind(postgres_i64(reservation.created_unix_ms, "storage reservation creation")?)
                .bind(postgres_i64(reservation.expires_unix_ms, "storage reservation expiry")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn tenant_storage_reservation<'a>(
        &'a self,
        tenant: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, Option<TenantStorageReservation>> {
        Box::pin(async move {
            validate_text("storage reservation tenant", tenant)?;
            validate_text("storage reservation id", id)?;
            let row = sqlx::query(RESERVATION_SELECT)
                .bind(id)
                .bind(tenant)
                .fetch_optional(self.pool())
                .await?;
            row.map(reservation_row).transpose()
        })
    }

    fn finish_tenant_storage_reservation<'a>(
        &'a self,
        tenant: &'a str,
        id: &'a str,
        target: StorageReservationState,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("storage reservation tenant", tenant)?;
            validate_text("storage reservation id", id)?;
            if !matches!(
                target,
                StorageReservationState::Committed | StorageReservationState::Released
            ) {
                return Err(ControlPlaneError::InvalidInput(
                    "storage reservation finish state is invalid",
                ));
            }
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, tenant).await?;
            let row = sqlx::query(&format!(
                "{RESERVATION_COLUMNS} WHERE id=$1 AND tenant_id=$2 FOR UPDATE"
            ))
            .bind(id)
            .bind(tenant)
            .fetch_optional(&mut *tx)
            .await?;
            let current = row
                .map(reservation_row)
                .transpose()?
                .ok_or_else(|| not_found("storage reservation", id))?;
            if current.state == target {
                tx.commit().await?;
                return Ok(true);
            }
            if current.state != StorageReservationState::Reserved || now >= current.expires_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("UPDATE tenant_storage_reservations SET state=$3,completed_unix_ms=$4 WHERE id=$1 AND tenant_id=$2 AND state='reserved'")
                .bind(id).bind(tenant).bind(reservation_state(&target)).bind(postgres_i64(now, "storage reservation completion")?)
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn bind_tenant_storage_ticket<'a>(
        &'a self,
        binding: &'a StorageTicketBinding,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_new_binding(binding, now)?;
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, &binding.tenant_id).await?;
            if let Some(existing) =
                binding_by_reservation(&mut tx, &binding.tenant_id, &binding.reservation_id).await?
            {
                if existing == *binding {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let reservation = sqlx::query(&format!(
                "{RESERVATION_COLUMNS} WHERE id=$1 AND tenant_id=$2 FOR UPDATE"
            ))
            .bind(&binding.reservation_id)
            .bind(&binding.tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .map(reservation_row)
            .transpose()?
            .ok_or_else(|| not_found("storage reservation", &binding.reservation_id))?;
            if reservation.ticket_kind != binding.ticket_kind
                || reservation.state != StorageReservationState::Reserved
                || now >= reservation.expires_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO tenant_storage_ticket_bindings(reservation_id,tenant_id,ticket_kind,ticket_id,state,created_unix_ms,updated_unix_ms) VALUES($1,$2,$3,$4,'issued',$5,$5)")
                .bind(&binding.reservation_id).bind(&binding.tenant_id).bind(&binding.ticket_kind).bind(&binding.ticket_id)
                .bind(postgres_i64(binding.created_unix_ms, "storage ticket creation")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn storage_ticket_binding_for_reservation<'a>(
        &'a self,
        tenant: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, Option<StorageTicketBinding>> {
        Box::pin(async move {
            validate_text("storage ticket tenant", tenant)?;
            validate_text("storage reservation id", id)?;
            let row = sqlx::query(&format!(
                "{BINDING_COLUMNS} WHERE tenant_id=$1 AND reservation_id=$2"
            ))
            .bind(tenant)
            .bind(id)
            .fetch_optional(self.pool())
            .await?;
            row.map(binding_row).transpose()
        })
    }

    fn commit_tenant_storage_ticket<'a>(
        &'a self,
        tenant: &'a str,
        ticket: &'a str,
        object: &'a str,
        actual_bytes: u64,
        actual_objects: u64,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("storage ticket tenant", tenant)?;
            validate_text("storage ticket id", ticket)?;
            validate_text("storage ticket object", object)?;
            if actual_objects == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "storage ticket object count is zero",
                ));
            }
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, tenant).await?;
            let binding = binding_by_ticket(&mut tx, tenant, ticket)
                .await?
                .ok_or_else(|| not_found("storage ticket", ticket))?;
            if matches!(
                binding.state,
                StorageTicketBindingState::Committed | StorageTicketBindingState::Accounted
            ) {
                if binding.object_id.as_deref() == Some(object)
                    && binding.actual_bytes == Some(actual_bytes)
                    && binding.actual_objects == Some(actual_objects)
                {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if binding.state != StorageTicketBindingState::Issued {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let reservation = sqlx::query(&format!(
                "{RESERVATION_COLUMNS} WHERE id=$1 AND tenant_id=$2 FOR UPDATE"
            ))
            .bind(&binding.reservation_id)
            .bind(tenant)
            .fetch_optional(&mut *tx)
            .await?
            .map(reservation_row)
            .transpose()?
            .ok_or_else(|| not_found("storage reservation", &binding.reservation_id))?;
            if reservation.state != StorageReservationState::Reserved
                || now >= reservation.expires_unix_ms
                || actual_bytes > reservation.reserved_bytes
                || actual_objects > reservation.reserved_objects
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let now_i64 = postgres_i64(now, "storage ticket update")?;
            sqlx::query("UPDATE tenant_storage_ticket_bindings SET object_id=$3,actual_bytes=$4,actual_objects=$5,state='committed',updated_unix_ms=$6 WHERE tenant_id=$1 AND ticket_id=$2 AND state='issued'")
                .bind(tenant).bind(ticket).bind(object)
                .bind(postgres_i64(actual_bytes, "storage ticket actual bytes")?).bind(postgres_i64(actual_objects, "storage ticket actual objects")?).bind(now_i64)
                .execute(&mut *tx).await?;
            sqlx::query("UPDATE tenant_storage_reservations SET state='committed',completed_unix_ms=$3 WHERE id=$1 AND tenant_id=$2 AND state='reserved'")
                .bind(&binding.reservation_id).bind(tenant).bind(now_i64).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn account_tenant_storage_ticket<'a>(
        &'a self,
        tenant: &'a str,
        ticket: &'a str,
        object: &'a str,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("storage ticket tenant", tenant)?;
            validate_text("storage ticket id", ticket)?;
            validate_text("storage ticket object", object)?;
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, tenant).await?;
            let replay = account_ticket(&mut tx, tenant, ticket, object, now).await?;
            tx.commit().await?;
            Ok(replay)
        })
    }

    fn tenant_storage_usage<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, TenantStorageUsage> {
        Box::pin(async move {
            validate_text("storage usage tenant", tenant)?;
            let active = sqlx::query("SELECT COALESCE(SUM(billed_bytes),0)::BIGINT AS bytes,COALESCE(SUM(billed_objects),0)::BIGINT AS objects FROM tenant_storage_objects WHERE tenant_id=$1 AND state='active'")
                .bind(tenant).fetch_one(self.pool()).await?;
            let held = sqlx::query("SELECT COALESCE(SUM(reserved_bytes),0)::BIGINT AS bytes,COALESCE(SUM(reserved_objects),0)::BIGINT AS objects FROM tenant_storage_reservations WHERE tenant_id=$1 AND state IN ('reserved','committed')")
                .bind(tenant).fetch_one(self.pool()).await?;
            Ok(TenantStorageUsage {
                tenant_id: tenant.to_owned(),
                active_bytes: postgres_u64(active.try_get("bytes")?, "active storage bytes")?,
                active_objects: postgres_u64(active.try_get("objects")?, "active storage objects")?,
                reserved_bytes: postgres_u64(held.try_get("bytes")?, "reserved storage bytes")?,
                reserved_objects: postgres_u64(
                    held.try_get("objects")?,
                    "reserved storage objects",
                )?,
            })
        })
    }
}

#[cfg(feature = "postgres")]
impl ArtifactCatalogStore for PostgresInstallationStore {
    fn catalog_artifact<'a>(
        &'a self,
        record: &'a ArtifactCatalogRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactCatalogRecord>> {
        Box::pin(async move {
            validate_artifact(record)?;
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, &record.tenant_id).await?;
            let authorized:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM job_result_objects o JOIN jobs j ON j.id=o.job_id AND j.attempt=o.job_attempt JOIN runs r ON r.id=j.run_id JOIN repositories repo ON repo.id=r.repository_id WHERE o.job_id=$1 AND o.job_attempt=$2 AND o.kind='artifact' AND o.object_id=$3 AND j.run_id=$4 AND r.repository_id=$5 AND repo.tenant_id=$6)")
                .bind(&record.job_id).bind(i32::try_from(record.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"artifact job attempt"})?).bind(&record.artifact_id).bind(&record.run_id).bind(&record.repository_id).bind(&record.tenant_id).fetch_one(&mut *tx).await?;
            if !authorized {
                return Err(not_found("artifact", &record.artifact_id));
            }
            if let Some(existing) =
                artifact_by_tenant_tx(&mut tx, &record.tenant_id, &record.artifact_id).await?
            {
                if existing != *record {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                account_artifact_ticket_if_present(&mut tx, record).await?;
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            sqlx::query("INSERT INTO artifacts_catalog(artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,result_kind,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms) VALUES($1,$2,$3,$4,$5,$6,'artifact',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
                .bind(&record.artifact_id).bind(&record.tenant_id).bind(&record.repository_id).bind(&record.run_id).bind(&record.job_id).bind(i32::try_from(record.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"artifact job attempt"})?)
                .bind(&record.step_id).bind(&record.output_name).bind(record.content_digest.as_str()).bind(record.manifest_digest.as_str()).bind(record.provenance_digest.as_str()).bind(postgres_i64(record.size_bytes,"artifact size")?)
                .bind(&record.media_type).bind(&record.classification).bind(&record.scan_state).bind(postgres_i64(record.retention_until_unix_seconds,"artifact retention")?).bind(record.legal_hold).bind(&record.state).bind(postgres_i64(record.created_unix_ms,"artifact creation")?).execute(&mut *tx).await?;
            account_artifact_ticket_if_present(&mut tx, record).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: record.clone(),
                replayed: false,
            })
        })
    }
    fn artifact_for_tenant<'a>(
        &'a self,
        tenant: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, ArtifactCatalogRecord> {
        Box::pin(async move {
            validate_text("tenant id", tenant)?;
            validate_text("artifact id", id)?;
            let mut tx = self.pool().begin().await?;
            let value = artifact_by_tenant_tx(&mut tx, tenant, id)
                .await?
                .ok_or_else(|| not_found("artifact", id))?;
            tx.commit().await?;
            Ok(value)
        })
    }
    fn artifact<'a>(&'a self, id: &'a str) -> StoreFuture<'a, ArtifactCatalogRecord> {
        Box::pin(async move {
            validate_text("artifact id", id)?;
            sqlx::query(ARTIFACT_SELECT)
                .bind(id)
                .fetch_optional(self.pool())
                .await?
                .map(artifact_row)
                .transpose()?
                .ok_or_else(|| not_found("artifact", id))
        })
    }
    fn issue_artifact_download_ticket<'a>(
        &'a self,
        ticket: &'a ArtifactDownloadTicketRecord,
    ) -> StoreFuture<'a, IdempotentResult<ArtifactDownloadTicketRecord>> {
        Box::pin(async move {
            if ticket.expires_unix_ms <= ticket.issued_unix_ms
                || ticket.used_unix_ms.is_some()
                || ticket.expires_unix_ms.saturating_sub(ticket.issued_unix_ms) > 15 * 60 * 1000
            {
                return Err(ControlPlaneError::InvalidInput(
                    "artifact download ticket lifetime is invalid",
                ));
            }
            let mut tx = self.pool().begin().await?;
            lock_tenant(&mut tx, &ticket.tenant_id).await?;
            let artifact = artifact_by_tenant_tx(&mut tx, &ticket.tenant_id, &ticket.artifact_id)
                .await?
                .ok_or_else(|| not_found("artifact", &ticket.artifact_id))?;
            if artifact.classification != ticket.classification
                || artifact.manifest_digest != ticket.manifest_digest
                || artifact.state == "retired"
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if let Some(existing) = download_ticket_tx(&mut tx, &ticket.token_hash).await? {
                if existing != *ticket {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(IdempotentResult {
                    value: existing,
                    replayed: true,
                });
            }
            sqlx::query("INSERT INTO artifact_download_tickets(token_hash,artifact_id,tenant_id,principal_id,classification,manifest_digest,issued_unix_ms,expires_unix_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(ticket.token_hash.as_str()).bind(&ticket.artifact_id).bind(&ticket.tenant_id).bind(&ticket.principal_id).bind(&ticket.classification).bind(ticket.manifest_digest.as_str()).bind(postgres_i64(ticket.issued_unix_ms,"download ticket issue")?).bind(postgres_i64(ticket.expires_unix_ms,"download ticket expiry")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(IdempotentResult {
                value: ticket.clone(),
                replayed: false,
            })
        })
    }
    fn consume_artifact_download_ticket<'a>(
        &'a self,
        hash: &'a ContentDigest,
        tenant: Option<&'a str>,
        principal: &'a str,
        now: u64,
    ) -> StoreFuture<'a, ArtifactDownloadTicketRecord> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let ticket = download_ticket_tx(&mut tx, hash)
                .await?
                .ok_or_else(|| not_found("artifact download", "redacted"))?;
            if tenant.is_some_and(|t| ticket.tenant_id != t)
                || ticket.principal_id != principal
                || ticket.used_unix_ms.is_some()
                || now >= ticket.expires_unix_ms
            {
                return Err(not_found("artifact download", "redacted"));
            }
            let changed=sqlx::query("UPDATE artifact_download_tickets SET used_unix_ms=$2 WHERE token_hash=$1 AND used_unix_ms IS NULL AND expires_unix_ms>$2").bind(hash.as_str()).bind(postgres_i64(now,"download use")?).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            tx.commit().await?;
            Ok(ArtifactDownloadTicketRecord {
                used_unix_ms: Some(now),
                ..ticket
            })
        })
    }
    fn artifact_metrics<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, ArtifactMetrics> {
        Box::pin(async move {
            validate_text("artifact metrics tenant", tenant)?;
            let row=sqlx::query("SELECT (SELECT COUNT(*) FROM artifacts_catalog WHERE tenant_id=$1)::BIGINT AS cataloged,(SELECT COUNT(*) FROM artifacts_catalog WHERE tenant_id=$1 AND state='quarantined')::BIGINT AS quarantined,(SELECT COUNT(*) FROM artifact_download_tickets WHERE tenant_id=$1)::BIGINT AS issued,(SELECT COUNT(*) FROM artifact_download_tickets WHERE tenant_id=$1 AND used_unix_ms IS NOT NULL)::BIGINT AS consumed").bind(tenant).fetch_one(self.pool()).await?;
            Ok(ArtifactMetrics {
                cataloged: postgres_u64(row.try_get("cataloged")?, "artifact metric")?,
                quarantined: postgres_u64(row.try_get("quarantined")?, "artifact metric")?,
                download_tickets_issued: postgres_u64(row.try_get("issued")?, "artifact metric")?,
                download_tickets_consumed: postgres_u64(
                    row.try_get("consumed")?,
                    "artifact metric",
                )?,
            })
        })
    }
}

#[cfg(feature = "postgres")]
impl ArtifactScanPromotionStore for PostgresInstallationStore {
    fn enqueue_artifact_scan<'a>(
        &'a self,
        record: &'a ArtifactScanJournalRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_artifact_scan(record)?;
            if record.state != ArtifactScanState::Pending
                || record.attempts != 0
                || record.result_digest.is_some()
                || record.lease_owner.is_some()
                || record.lease_expires_unix_ms.is_some()
                || record.completed_unix_ms.is_some()
                || record.last_error_code.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "new artifact scan must be pending",
                ));
            }
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771004))")
                .bind(format!("{}\u{1f}{}", record.artifact_id, record.scanner))
                .execute(&mut *tx)
                .await?;
            let artifact = artifact_by_tenant_tx(&mut tx, &record.tenant_id, &record.artifact_id)
                .await?
                .ok_or_else(|| not_found("artifact", &record.artifact_id))?;
            if crate::artifact_scan_subject_digest(&artifact, &record.scanner)?
                != record.subject_digest
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if let Some(existing) = artifact_scan_pg(&mut tx, &record.id, None, false).await? {
                if existing == *record {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let duplicate: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM artifact_scan_journal
                 WHERE artifact_id=$1 AND scanner=$2)",
            )
            .bind(&record.artifact_id)
            .bind(&record.scanner)
            .fetch_one(&mut *tx)
            .await?;
            if duplicate {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO artifact_scan_journal
                 (id,tenant_id,artifact_id,scanner,subject_digest,state,attempts,created_unix_ms)
                 VALUES($1,$2,$3,$4,$5,'pending',0,$6)",
            )
            .bind(&record.id)
            .bind(&record.tenant_id)
            .bind(&record.artifact_id)
            .bind(&record.scanner)
            .bind(record.subject_digest.as_str())
            .bind(postgres_i64(
                record.created_unix_ms,
                "artifact scan creation",
            )?)
            .execute(&mut *tx)
            .await?;
            let changed = sqlx::query(
                "UPDATE artifacts_catalog SET scan_state='pending',state='quarantined'
                 WHERE artifact_id=$1 AND tenant_id=$2",
            )
            .bind(&record.artifact_id)
            .bind(&record.tenant_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(not_found("artifact", &record.artifact_id));
            }
            tx.commit().await?;
            Ok(false)
        })
    }

    fn claim_artifact_scan<'a>(
        &'a self,
        worker: &'a str,
        now: u64,
        duration: u64,
    ) -> StoreFuture<'a, Option<ArtifactScanJournalRecord>> {
        Box::pin(async move {
            validate_text("scanner worker id", worker)?;
            if duration == 0 {
                return Err(ControlPlaneError::InvalidInput(
                    "scanner lease duration must be positive",
                ));
            }
            let expires = now
                .checked_add(duration)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "scanner lease expiry",
                })?;
            let now_i64 = postgres_i64(now, "artifact scan claim clock")?;
            let mut tx = self.pool().begin().await?;
            sqlx::query(
                "UPDATE artifact_scan_journal
                 SET state='pending',lease_owner=NULL,lease_expires_unix_ms=NULL,
                     last_error_code='lease-expired'
                 WHERE state='claimed' AND lease_expires_unix_ms <= $1",
            )
            .bind(now_i64)
            .execute(&mut *tx)
            .await?;
            let id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM artifact_scan_journal
                 WHERE state='pending' ORDER BY created_unix_ms,id
                 FOR UPDATE SKIP LOCKED LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await?;
            let Some(id) = id else {
                tx.commit().await?;
                return Ok(None);
            };
            let changed = sqlx::query(
                "UPDATE artifact_scan_journal
                 SET state='claimed',lease_owner=$2,lease_expires_unix_ms=$3,
                     attempts=attempts+1
                 WHERE id=$1 AND state='pending'",
            )
            .bind(&id)
            .bind(worker)
            .bind(postgres_i64(expires, "artifact scan lease expiry")?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::TaskNotOwned);
            }
            let claimed = artifact_scan_pg(&mut tx, &id, None, false)
                .await?
                .ok_or_else(|| not_found("artifact scan", &id))?;
            tx.commit().await?;
            Ok(Some(claimed))
        })
    }

    fn finish_artifact_scan<'a>(
        &'a self,
        tenant: &'a str,
        scan_id: &'a str,
        worker: &'a str,
        state: ArtifactScanState,
        result: Option<&'a ContentDigest>,
        error: Option<&'a str>,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("artifact scan tenant", tenant)?;
            validate_text("artifact scan id", scan_id)?;
            validate_text("scanner worker id", worker)?;
            if !matches!(
                state,
                ArtifactScanState::Passed | ArtifactScanState::Failed | ArtifactScanState::Error
            ) || matches!(state, ArtifactScanState::Passed | ArtifactScanState::Failed)
                != result.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "artifact scan result is invalid",
                ));
            }
            if let Some(value) = error {
                validate_text("scanner error code", value)?;
            }
            let mut tx = self.pool().begin().await?;
            let scan = artifact_scan_pg(&mut tx, scan_id, Some(tenant), true)
                .await?
                .ok_or_else(|| not_found("artifact scan", scan_id))?;
            if scan.state == state && scan.result_digest.as_ref() == result {
                tx.commit().await?;
                return Ok(true);
            }
            if scan.state != ArtifactScanState::Claimed
                || scan.lease_owner.as_deref() != Some(worker)
                || scan
                    .lease_expires_unix_ms
                    .is_none_or(|expiry| expiry <= now)
            {
                return Err(ControlPlaneError::TaskNotOwned);
            }
            let state_text = artifact_scan_state(&state);
            if let Some(digest) = result {
                let inserted = sqlx::query(
                    "INSERT INTO artifact_scan_results
                     (artifact_id,scanner,result_digest,status,created_unix_ms)
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
                )
                .bind(&scan.artifact_id)
                .bind(&scan.scanner)
                .bind(digest.as_str())
                .bind(state_text)
                .bind(postgres_i64(now, "artifact scan result creation")?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if inserted == 0 {
                    let stored: Option<String> = sqlx::query_scalar(
                        "SELECT status FROM artifact_scan_results
                         WHERE artifact_id=$1 AND scanner=$2 AND result_digest=$3",
                    )
                    .bind(&scan.artifact_id)
                    .bind(&scan.scanner)
                    .bind(digest.as_str())
                    .fetch_optional(&mut *tx)
                    .await?;
                    if stored.as_deref() != Some(state_text) {
                        return Err(ControlPlaneError::IdempotencyConflict);
                    }
                }
            }
            let changed = sqlx::query(
                "UPDATE artifact_scan_journal
                 SET state=$3,result_digest=$4,lease_owner=NULL,lease_expires_unix_ms=NULL,
                     completed_unix_ms=$5,last_error_code=$6
                 WHERE id=$1 AND tenant_id=$2 AND state='claimed'",
            )
            .bind(scan_id)
            .bind(tenant)
            .bind(state_text)
            .bind(result.map(ContentDigest::as_str))
            .bind(postgres_i64(now, "artifact scan completion")?)
            .bind(error)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::TaskNotOwned);
            }
            let passed = state == ArtifactScanState::Passed;
            let changed = sqlx::query(
                "UPDATE artifacts_catalog
                 SET scan_state=$3,state=CASE WHEN $4 THEN 'available' ELSE 'quarantined' END
                 WHERE artifact_id=$1 AND tenant_id=$2",
            )
            .bind(&scan.artifact_id)
            .bind(tenant)
            .bind(if passed { "passed" } else { "failed" })
            .bind(passed)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(not_found("artifact", &scan.artifact_id));
            }
            let mut metadata = BTreeMap::from([
                (
                    "scanner".to_owned(),
                    AuditValue::String(scan.scanner.clone()),
                ),
                (
                    "artifact_id".to_owned(),
                    AuditValue::String(scan.artifact_id.clone()),
                ),
            ]);
            if let Some(digest) = result {
                metadata.insert(
                    "result_digest".to_owned(),
                    AuditValue::Digest(digest.clone()),
                );
            }
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: now,
                    tenant_id: tenant.to_owned(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: worker.to_owned(),
                    },
                    action: "artifact.scan".to_owned(),
                    resource: AuditResource {
                        kind: "artifact-scan".to_owned(),
                        id: scan_id.to_owned(),
                    },
                    result: state_text.to_owned(),
                    request_id: scan_id.to_owned(),
                    decision_id: Some(scan.subject_digest.to_string()),
                    metadata,
                },
            )
            .await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn create_artifact_promotion<'a>(
        &'a self,
        intent: &'a ArtifactPromotionIntent,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_artifact_promotion(intent)?;
            if intent.status != "pending"
                || intent.promoted_artifact_id.is_some()
                || intent.promoted_manifest_digest.is_some()
                || intent.completed_unix_ms.is_some()
                || intent.last_error_code.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "new artifact promotion must be pending",
                ));
            }
            if crate::artifact_promotion_subject_digest(intent)? != intent.subject_digest {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771005))")
                .bind(&intent.id)
                .execute(&mut *tx)
                .await?;
            let source = artifact_by_tenant_tx_locked(
                &mut tx,
                &intent.tenant_id,
                &intent.source_artifact_id,
            )
            .await?
            .ok_or_else(|| not_found("artifact promotion source", &intent.source_artifact_id))?;
            if source.manifest_digest != intent.source_manifest_digest
                || source.provenance_digest != intent.source_provenance_digest
                || source.classification != intent.source_classification
                || source.state == "retired"
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if intent.target_classification != "quarantined" {
                let scan_ok = if let Some(digest) = &intent.scan_evidence_digest {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM artifact_scan_results
                         WHERE artifact_id=$1 AND result_digest=$2 AND status='passed')",
                    )
                    .bind(&intent.source_artifact_id)
                    .bind(digest.as_str())
                    .fetch_one(&mut *tx)
                    .await?
                } else {
                    false
                };
                let waived =
                    source.scan_state == "waived" && intent.approval_evidence_digest.is_some();
                if !scan_ok && !waived {
                    return Err(ControlPlaneError::ArtifactPromotionEvidenceRequired);
                }
            }
            if let Some(existing) = artifact_promotion_pg(&mut tx, &intent.id, None, false).await? {
                if existing == *intent {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO artifact_promotions
                 (id,source_artifact_id,tenant_id,target_classification,evidence_digest,status,created_unix_ms)
                 VALUES($1,$2,$3,$4,$5,'pending',$6)",
            )
            .bind(&intent.id)
            .bind(&intent.source_artifact_id)
            .bind(&intent.tenant_id)
            .bind(&intent.target_classification)
            .bind(intent.evidence_digest.as_str())
            .bind(postgres_i64(
                intent.created_unix_ms,
                "artifact promotion creation",
            )?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO artifact_promotion_bindings
                 (promotion_id,subject_digest,source_manifest_digest,source_provenance_digest,
                  source_classification,evidence_json,scan_evidence_digest,approval_evidence_digest)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(&intent.id)
            .bind(intent.subject_digest.as_str())
            .bind(intent.source_manifest_digest.as_str())
            .bind(intent.source_provenance_digest.as_str())
            .bind(&intent.source_classification)
            .bind(json_bytes(&canonicalize_json(intent.evidence.clone()))?)
            .bind(
                intent
                    .scan_evidence_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .bind(
                intent
                    .approval_evidence_digest
                    .as_ref()
                    .map(ContentDigest::as_str),
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn artifact_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
    ) -> StoreFuture<'a, ArtifactPromotionIntent> {
        Box::pin(async move {
            validate_text("artifact promotion tenant", tenant)?;
            validate_text("artifact promotion id", promotion)?;
            let mut tx = self.pool().begin().await?;
            let value = artifact_promotion_pg(&mut tx, promotion, Some(tenant), false)
                .await?
                .ok_or_else(|| not_found("artifact promotion", promotion))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn complete_artifact_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
        promoted: &'a str,
        manifest: &'a ContentDigest,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("artifact promotion tenant", tenant)?;
            validate_text("artifact promotion id", promotion)?;
            validate_text("promoted artifact id", promoted)?;
            let mut tx = self.pool().begin().await?;
            let current = artifact_promotion_pg(&mut tx, promotion, Some(tenant), true)
                .await?
                .ok_or_else(|| not_found("artifact promotion", promotion))?;
            if current.status == "succeeded" {
                if current.promoted_artifact_id.as_deref() == Some(promoted)
                    && current.promoted_manifest_digest.as_ref() == Some(manifest)
                {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if current.status != "pending" {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = sqlx::query(
                "UPDATE artifact_promotions
                 SET status='succeeded',promoted_artifact_id=$2,completed_unix_ms=$3
                 WHERE id=$1 AND tenant_id=$4 AND status='pending'",
            )
            .bind(promotion)
            .bind(promoted)
            .bind(postgres_i64(now, "artifact promotion completion")?)
            .bind(tenant)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let changed = sqlx::query(
                "UPDATE artifact_promotion_bindings SET promoted_manifest_digest=$2
                 WHERE promotion_id=$1 AND promoted_manifest_digest IS NULL",
            )
            .bind(promotion)
            .bind(manifest.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let metadata = BTreeMap::from([
                (
                    "source_artifact_id".to_owned(),
                    AuditValue::String(current.source_artifact_id.clone()),
                ),
                (
                    "promoted_artifact_id".to_owned(),
                    AuditValue::String(promoted.to_owned()),
                ),
                (
                    "evidence_digest".to_owned(),
                    AuditValue::Digest(current.evidence_digest.clone()),
                ),
            ]);
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: now,
                    tenant_id: tenant.to_owned(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "artifact-promotion".to_owned(),
                    },
                    action: "artifact.promote".to_owned(),
                    resource: AuditResource {
                        kind: "artifact-promotion".to_owned(),
                        id: promotion.to_owned(),
                    },
                    result: "completed".to_owned(),
                    request_id: promotion.to_owned(),
                    decision_id: Some(current.subject_digest.to_string()),
                    metadata,
                },
            )
            .await?;
            tx.commit().await?;
            Ok(false)
        })
    }
}

#[cfg(feature = "postgres")]
impl CacheTrustStore for PostgresInstallationStore {
    fn record_cache_trust_generation<'a>(
        &'a self,
        record: &'a CacheTrustGenerationRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_cache_generation(record)?;
            let mut tx = self.pool().begin().await?;
            let replayed = record_cache_generation_pg(&mut tx, record, expected, None).await?;
            tx.commit().await?;
            Ok(replayed)
        })
    }

    fn create_cache_promotion_idempotent<'a>(
        &'a self,
        record: &'a CachePromotionRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_cache_promotion(record)?;
            if record.state != CachePromotionState::Pending
                || record.promoted_cache_entry_id.is_some()
                || record.completed_unix_ms.is_some()
                || record.last_error.is_some()
            {
                return Err(ControlPlaneError::InvalidInput(
                    "new cache promotion must be pending",
                ));
            }
            if crate::cache_promotion_subject_digest(record)? != record.subject_digest {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let mut tx = self.pool().begin().await?;
            // Promotion IDs and subject digests are independently unique. A
            // boundary-wide lock makes concurrent changed replays deterministic
            // instead of leaking a backend-specific unique-constraint error.
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(CACHE_PROMOTION_CREATE_LOCK)
                .execute(&mut *tx)
                .await?;
            let source: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM cache_trust_generations
                 WHERE cache_entry_id=$1 AND tenant_id=$2 AND repository_id=$3)",
            )
            .bind(&record.source_cache_entry_id)
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .fetch_one(&mut *tx)
            .await?;
            if !source {
                return Err(not_found(
                    "cache promotion source",
                    &record.source_cache_entry_id,
                ));
            }
            if let Some(existing) = cache_promotion_pg(&mut tx, &record.id, None, false).await? {
                if existing == *record {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO cache_promotion_journal
                 (id,subject_digest,tenant_id,repository_id,source_cache_entry_id,
                  target_identity_digest,target_trust_domain_json,
                  expected_target_cache_entry_id,evidence_digest,evidence_json,state,
                  created_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11)",
            )
            .bind(&record.id)
            .bind(record.subject_digest.as_str())
            .bind(&record.tenant_id)
            .bind(&record.repository_id)
            .bind(&record.source_cache_entry_id)
            .bind(record.target_identity_digest.as_str())
            .bind(json_bytes(&canonicalize_json(
                record.target_trust_domain.clone(),
            ))?)
            .bind(&record.expected_target_cache_entry_id)
            .bind(record.evidence_digest.as_str())
            .bind(json_bytes(&canonicalize_json(record.evidence.clone()))?)
            .bind(postgres_i64(
                record.created_unix_ms,
                "cache promotion creation",
            )?)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(false)
        })
    }

    fn complete_cache_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
        promoted: &'a CacheTrustGenerationRecord,
        now: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_text("cache promotion tenant", tenant)?;
            validate_text("cache promotion id", promotion)?;
            validate_cache_generation(promoted)?;
            let mut tx = self.pool().begin().await?;
            let journal = cache_promotion_pg(&mut tx, promotion, Some(tenant), true)
                .await?
                .ok_or_else(|| not_found("cache promotion", promotion))?;
            if journal.state == CachePromotionState::Completed {
                let exact = cache_generation_pg(&mut tx, tenant, &promoted.cache_entry_id, false)
                    .await?
                    .as_ref()
                    == Some(promoted);
                if journal.promoted_cache_entry_id.as_deref()
                    == Some(promoted.cache_entry_id.as_str())
                    && exact
                {
                    tx.commit().await?;
                    return Ok(true);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            if journal.state != CachePromotionState::Pending
                || promoted.tenant_id != journal.tenant_id
                || promoted.repository_id != journal.repository_id
                || promoted.identity_digest != journal.target_identity_digest
                || promoted.source_cache_entry_id.as_deref()
                    != Some(journal.source_cache_entry_id.as_str())
                || promoted.promotion_evidence_digest.as_ref() != Some(&journal.evidence_digest)
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let replayed = record_cache_generation_pg(
                &mut tx,
                promoted,
                journal
                    .expected_target_cache_entry_id
                    .as_ref()
                    .map(|_| promoted.generation.saturating_sub(1)),
                journal.expected_target_cache_entry_id.as_deref(),
            )
            .await?;
            let changed = sqlx::query(
                "UPDATE cache_promotion_journal
                 SET state='completed',promoted_cache_entry_id=$2,completed_unix_ms=$3
                 WHERE id=$1 AND tenant_id=$4 AND state='pending'",
            )
            .bind(promotion)
            .bind(&promoted.cache_entry_id)
            .bind(postgres_i64(now, "cache promotion completion")?)
            .bind(tenant)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let metadata = BTreeMap::from([
                (
                    "source_cache_entry_id".to_owned(),
                    AuditValue::String(journal.source_cache_entry_id),
                ),
                (
                    "promoted_cache_entry_id".to_owned(),
                    AuditValue::String(promoted.cache_entry_id.clone()),
                ),
                (
                    "evidence_digest".to_owned(),
                    AuditValue::Digest(journal.evidence_digest),
                ),
            ]);
            super::api_tokens::append(
                &mut tx,
                self.installation_id(),
                AuditEventData {
                    observed_unix_ms: now,
                    tenant_id: tenant.to_owned(),
                    actor: AuditPrincipal {
                        kind: "worker".to_owned(),
                        id: "cache-promotion".to_owned(),
                    },
                    action: "cache.promote".to_owned(),
                    resource: AuditResource {
                        kind: "cache-promotion".to_owned(),
                        id: promotion.to_owned(),
                    },
                    result: "completed".to_owned(),
                    request_id: promotion.to_owned(),
                    decision_id: Some(journal.subject_digest.to_string()),
                    metadata,
                },
            )
            .await?;
            tx.commit().await?;
            Ok(replayed)
        })
    }

    fn cache_promotion<'a>(
        &'a self,
        tenant: &'a str,
        promotion: &'a str,
    ) -> StoreFuture<'a, CachePromotionRecord> {
        Box::pin(async move {
            validate_text("cache promotion tenant", tenant)?;
            validate_text("cache promotion id", promotion)?;
            let mut tx = self.pool().begin().await?;
            let value = cache_promotion_pg(&mut tx, promotion, Some(tenant), false)
                .await?
                .ok_or_else(|| not_found("cache promotion", promotion))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn cache_trust_generation<'a>(
        &'a self,
        tenant: &'a str,
        cache_entry: &'a str,
    ) -> StoreFuture<'a, CacheTrustGenerationRecord> {
        Box::pin(async move {
            validate_text("cache generation tenant", tenant)?;
            validate_text("cache entry id", cache_entry)?;
            let mut tx = self.pool().begin().await?;
            let value = cache_generation_pg(&mut tx, tenant, cache_entry, false)
                .await?
                .ok_or_else(|| not_found("cache generation", cache_entry))?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn record_cache_access_observation<'a>(
        &'a self,
        observation: &'a CacheAccessObservation,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            validate_cache_observation(observation)?;
            let mut tx = self.pool().begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771003))")
                .bind(&observation.id)
                .execute(&mut *tx)
                .await?;
            let authorized: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                   SELECT 1 FROM jobs j
                   JOIN runs r ON r.id=j.run_id
                   JOIN repositories repo ON repo.id=r.repository_id
                   WHERE j.id=$1 AND j.attempt=$2 AND j.run_id=$3
                     AND r.repository_id=$4 AND repo.tenant_id=$5)",
            )
            .bind(&observation.job_id)
            .bind(i32::try_from(observation.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "cache observation job attempt",
                }
            })?)
            .bind(&observation.run_id)
            .bind(&observation.repository_id)
            .bind(&observation.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            if !authorized {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let inserted = sqlx::query(
                "INSERT INTO cache_access_observations
                 (id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,
                  operation,key_material_digest,candidates_json,outcome,
                  selected_trust_domain_json,selected_generation,transferred_bytes,
                  latency_ms,breaker_state,created_unix_ms)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(&observation.id)
            .bind(&observation.tenant_id)
            .bind(&observation.repository_id)
            .bind(&observation.run_id)
            .bind(&observation.job_id)
            .bind(i32::try_from(observation.job_attempt).map_err(|_| {
                ControlPlaneError::IntegerRange {
                    field: "cache observation job attempt",
                }
            })?)
            .bind(&observation.step_id)
            .bind(&observation.operation)
            .bind(observation.key_material_digest.as_str())
            .bind(json_bytes(&Value::Array(observation.candidates.clone()))?)
            .bind(&observation.outcome)
            .bind(
                observation
                    .selected_trust_domain
                    .as_ref()
                    .map(json_bytes)
                    .transpose()?,
            )
            .bind(
                observation
                    .selected_generation
                    .map(|v| postgres_i64(v, "cache selected generation"))
                    .transpose()?,
            )
            .bind(postgres_i64(
                observation.transferred_bytes,
                "cache transferred bytes",
            )?)
            .bind(postgres_i64(observation.latency_ms, "cache latency")?)
            .bind(&observation.breaker_state)
            .bind(postgres_i64(
                observation.created_unix_ms,
                "cache observation creation",
            )?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            let stored = cache_observation_pg(&mut tx, &observation.id)
                .await?
                .ok_or_else(|| not_found("cache observation", &observation.id))?;
            if stored != *observation {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            tx.commit().await?;
            Ok(inserted == 0)
        })
    }

    fn cache_trust_metrics<'a>(&'a self, tenant: &'a str) -> StoreFuture<'a, CacheTrustMetrics> {
        Box::pin(async move {
            validate_text("cache metrics tenant", tenant)?;
            let row = sqlx::query(
                "SELECT
                   COUNT(*) FILTER (WHERE outcome='hit')::BIGINT AS hits,
                   COUNT(*) FILTER (WHERE outcome='miss')::BIGINT AS misses,
                   COUNT(*) FILTER (WHERE outcome='bypassed-health')::BIGINT AS bypassed_health,
                   COUNT(*) FILTER (WHERE outcome='saved')::BIGINT AS saves,
                   COUNT(*) FILTER (WHERE outcome='save-failed')::BIGINT AS save_failures,
                   COUNT(*) FILTER (WHERE outcome='denied')::BIGINT AS denied
                 FROM cache_access_observations WHERE tenant_id=$1",
            )
            .bind(tenant)
            .fetch_one(self.pool())
            .await?;
            let promotions = sqlx::query(
                "SELECT
                   COUNT(*) FILTER (WHERE state='pending')::BIGINT AS pending,
                   COUNT(*) FILTER (WHERE state='completed')::BIGINT AS completed,
                   COUNT(*) FILTER (WHERE state='failed')::BIGINT AS failed
                 FROM cache_promotion_journal WHERE tenant_id=$1",
            )
            .bind(tenant)
            .fetch_one(self.pool())
            .await?;
            Ok(CacheTrustMetrics {
                hits: postgres_u64(row.try_get("hits")?, "cache hits")?,
                misses: postgres_u64(row.try_get("misses")?, "cache misses")?,
                bypassed_health: postgres_u64(
                    row.try_get("bypassed_health")?,
                    "cache health bypasses",
                )?,
                saves: postgres_u64(row.try_get("saves")?, "cache saves")?,
                save_failures: postgres_u64(row.try_get("save_failures")?, "cache save failures")?,
                denied: postgres_u64(row.try_get("denied")?, "cache denials")?,
                promotions_pending: postgres_u64(
                    promotions.try_get("pending")?,
                    "pending cache promotions",
                )?,
                promotions_completed: postgres_u64(
                    promotions.try_get("completed")?,
                    "completed cache promotions",
                )?,
                promotions_failed: postgres_u64(
                    promotions.try_get("failed")?,
                    "failed cache promotions",
                )?,
            })
        })
    }
}

#[cfg(feature = "postgres")]
const CACHE_PROMOTION_CREATE_LOCK: i64 = 0x5275_6e54_6361_6301;
#[cfg(feature = "postgres")]
const CACHE_GENERATION_COLUMNS: &str = "SELECT cache_entry_id,tenant_id,repository_id,identity_digest,key_material_digest,key_material_json,trust_domain_json,generation,manifest_digest,tree_manifest_digest,fencing_generation,source_cache_entry_id,promotion_evidence_digest,created_unix_ms FROM cache_trust_generations";
#[cfg(feature = "postgres")]
const CACHE_PROMOTION_COLUMNS: &str = "SELECT id,subject_digest,tenant_id,repository_id,source_cache_entry_id,target_identity_digest,target_trust_domain_json,expected_target_cache_entry_id,evidence_digest,evidence_json,state,promoted_cache_entry_id,created_unix_ms,completed_unix_ms,last_error FROM cache_promotion_journal";
#[cfg(feature = "postgres")]
const CACHE_OBSERVATION_COLUMNS: &str = "SELECT id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,operation,key_material_digest,candidates_json,outcome,selected_trust_domain_json,selected_generation,transferred_bytes,latency_ms,breaker_state,created_unix_ms FROM cache_access_observations";
#[cfg(feature = "postgres")]
const ARTIFACT_SCAN_COLUMNS: &str = "SELECT id,tenant_id,artifact_id,scanner,subject_digest,state,result_digest,lease_owner,lease_expires_unix_ms,attempts,created_unix_ms,completed_unix_ms,last_error_code FROM artifact_scan_journal";
#[cfg(feature = "postgres")]
const ARTIFACT_PROMOTION_COLUMNS: &str = "SELECT p.id,b.subject_digest,p.tenant_id,p.source_artifact_id,b.source_manifest_digest,b.source_provenance_digest,b.source_classification,p.target_classification,p.evidence_digest,b.evidence_json,b.scan_evidence_digest,b.approval_evidence_digest,p.status,p.promoted_artifact_id,b.promoted_manifest_digest,p.created_unix_ms,p.completed_unix_ms,b.last_error_code FROM artifact_promotions p JOIN artifact_promotion_bindings b ON b.promotion_id=p.id";
#[cfg(feature = "postgres")]
const RESERVATION_COLUMNS: &str = "SELECT id,tenant_id,ticket_kind,object_digest,reserved_bytes,reserved_objects,state,created_unix_ms,expires_unix_ms,completed_unix_ms FROM tenant_storage_reservations";
#[cfg(feature = "postgres")]
const RESERVATION_SELECT: &str = "SELECT id,tenant_id,ticket_kind,object_digest,reserved_bytes,reserved_objects,state,created_unix_ms,expires_unix_ms,completed_unix_ms FROM tenant_storage_reservations WHERE id=$1 AND tenant_id=$2";
#[cfg(feature = "postgres")]
const BINDING_COLUMNS: &str = "SELECT reservation_id,tenant_id,ticket_kind,ticket_id,object_id,actual_bytes,actual_objects,state,created_unix_ms,updated_unix_ms,completed_unix_ms FROM tenant_storage_ticket_bindings";
#[cfg(feature = "postgres")]
const ARTIFACT_COLUMNS:&str="SELECT artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms FROM artifacts_catalog";
#[cfg(feature = "postgres")]
const ARTIFACT_SELECT:&str="SELECT artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms FROM artifacts_catalog WHERE artifact_id=$1";

#[cfg(feature = "postgres")]
fn validate_text(field: &'static str, value: &str) -> Result<(), ControlPlaneError> {
    if value.is_empty() || value.len() > 1024 {
        return Err(ControlPlaneError::InvalidInput(field));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_cache_generation(record: &CacheTrustGenerationRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("cache entry id", record.cache_entry_id.as_str()),
        ("cache tenant", record.tenant_id.as_str()),
        ("cache repository", record.repository_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if record.generation == 0
        || record.fencing_generation == 0
        || !record.key_material.is_object()
        || !record.trust_domain.is_object()
        || record.source_cache_entry_id.is_some() != record.promotion_evidence_digest.is_some()
    {
        return Err(ControlPlaneError::InvalidInput(
            "cache generation metadata is invalid",
        ));
    }
    if let Some(source) = &record.source_cache_entry_id {
        validate_text("cache promotion source", source)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_cache_promotion(record: &CachePromotionRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("cache promotion id", record.id.as_str()),
        ("cache promotion tenant", record.tenant_id.as_str()),
        ("cache promotion repository", record.repository_id.as_str()),
        (
            "cache promotion source",
            record.source_cache_entry_id.as_str(),
        ),
    ] {
        validate_text(field, value)?;
    }
    if !record.target_trust_domain.is_object() || !record.evidence.is_object() {
        return Err(ControlPlaneError::InvalidInput(
            "cache promotion evidence and trust domain must be objects",
        ));
    }
    if let Some(expected) = &record.expected_target_cache_entry_id {
        validate_text("expected cache promotion head", expected)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_cache_observation(value: &CacheAccessObservation) -> Result<(), ControlPlaneError> {
    for (field, text) in [
        ("cache observation id", value.id.as_str()),
        ("cache observation tenant", value.tenant_id.as_str()),
        ("cache observation repository", value.repository_id.as_str()),
        ("cache observation run", value.run_id.as_str()),
        ("cache observation job", value.job_id.as_str()),
        ("cache observation step", value.step_id.as_str()),
    ] {
        validate_text(field, text)?;
    }
    if value.job_attempt == 0
        || !matches!(value.operation.as_str(), "restore" | "save")
        || !matches!(
            value.outcome.as_str(),
            "hit" | "miss" | "bypassed-health" | "saved" | "save-failed" | "denied"
        )
        || !matches!(
            value.breaker_state.as_str(),
            "closed" | "open" | "half-open"
        )
        || value.candidates.len() > 16
        || value
            .candidates
            .iter()
            .any(|candidate| !candidate.is_object())
        || value
            .selected_trust_domain
            .as_ref()
            .is_some_and(|scope| !scope.is_object())
    {
        return Err(ControlPlaneError::InvalidInput(
            "cache observation metadata is invalid",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        other => other,
    }
}

#[cfg(feature = "postgres")]
fn json_bytes(value: &Value) -> Result<Vec<u8>, ControlPlaneError> {
    Ok(serde_json::to_vec(value)?)
}
#[cfg(feature = "postgres")]
fn validate_quota(q: &TenantStorageQuota) -> Result<(), ControlPlaneError> {
    validate_text("storage quota tenant", &q.tenant_id)?;
    if q.maximum_stored_bytes == 0 || q.maximum_object_count == 0 {
        return Err(ControlPlaneError::InvalidInput(
            "storage quota bounds must be greater than zero",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn validate_artifact(r: &ArtifactCatalogRecord) -> Result<(), ControlPlaneError> {
    for (f, v) in [
        ("artifact id", r.artifact_id.as_str()),
        ("tenant id", r.tenant_id.as_str()),
        ("repository id", r.repository_id.as_str()),
        ("run id", r.run_id.as_str()),
        ("job id", r.job_id.as_str()),
        ("step id", r.step_id.as_str()),
        ("output name", r.output_name.as_str()),
        ("media type", r.media_type.as_str()),
        ("classification", r.classification.as_str()),
    ] {
        validate_text(f, v)?;
    }
    if r.job_attempt == 0
        || !matches!(
            r.scan_state.as_str(),
            "pending" | "passed" | "failed" | "waived"
        )
        || !matches!(r.state.as_str(), "available" | "quarantined" | "retired")
    {
        return Err(ControlPlaneError::InvalidInput(
            "artifact catalog metadata is invalid",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn validate_artifact_scan(scan: &ArtifactScanJournalRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("artifact scan id", scan.id.as_str()),
        ("artifact scan tenant", scan.tenant_id.as_str()),
        ("artifact scan artifact", scan.artifact_id.as_str()),
        ("artifact scan scanner", scan.scanner.as_str()),
    ] {
        validate_text(field, value)?;
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn artifact_scan_state(state: &ArtifactScanState) -> &'static str {
    match state {
        ArtifactScanState::Pending => "pending",
        ArtifactScanState::Claimed => "claimed",
        ArtifactScanState::Passed => "passed",
        ArtifactScanState::Failed => "failed",
        ArtifactScanState::Error => "error",
    }
}

#[cfg(feature = "postgres")]
fn validate_artifact_promotion(intent: &ArtifactPromotionIntent) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("artifact promotion id", intent.id.as_str()),
        ("artifact promotion tenant", intent.tenant_id.as_str()),
        (
            "artifact promotion source",
            intent.source_artifact_id.as_str(),
        ),
    ] {
        validate_text(field, value)?;
    }
    let edge = (
        intent.source_classification.as_str(),
        intent.target_classification.as_str(),
    );
    if !matches!(
        edge,
        ("untrusted-build", "quarantined")
            | ("quarantined", "verified-test-output")
            | ("verified-test-output", "release-candidate")
            | ("release-candidate", "promoted-release")
            | ("promoted-release", "public")
    ) || !intent.evidence.is_object()
        || ContentDigest::sha256(json_bytes(&canonicalize_json(intent.evidence.clone()))?)
            != intent.evidence_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "artifact promotion metadata is invalid",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn validate_reservation(r: &TenantStorageReservation, now: u64) -> Result<(), ControlPlaneError> {
    validate_text("storage reservation id", &r.id)?;
    validate_text("storage reservation tenant", &r.tenant_id)?;
    if !matches!(
        r.ticket_kind.as_str(),
        "cache" | "artifact" | "report" | "source"
    ) || r.reserved_objects == 0
        || r.expires_unix_ms <= r.created_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "storage reservation metadata is invalid",
        ));
    }
    if r.state != StorageReservationState::Reserved
        || r.completed_unix_ms.is_some()
        || now < r.created_unix_ms
        || now >= r.expires_unix_ms
    {
        return Err(ControlPlaneError::InvalidInput(
            "new storage reservation is not active",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn validate_new_binding(b: &StorageTicketBinding, now: u64) -> Result<(), ControlPlaneError> {
    validate_text("storage reservation id", &b.reservation_id)?;
    validate_text("storage ticket tenant", &b.tenant_id)?;
    validate_text("storage ticket id", &b.ticket_id)?;
    if !matches!(
        b.ticket_kind.as_str(),
        "cache" | "artifact" | "report" | "source"
    ) || b.updated_unix_ms < b.created_unix_ms
        || b.actual_objects == Some(0)
    {
        return Err(ControlPlaneError::InvalidInput(
            "storage ticket binding metadata is invalid",
        ));
    }
    if b.state != StorageTicketBindingState::Issued
        || b.object_id.is_some()
        || b.actual_bytes.is_some()
        || b.actual_objects.is_some()
        || b.completed_unix_ms.is_some()
        || b.created_unix_ms != b.updated_unix_ms
        || b.created_unix_ms > now
    {
        return Err(ControlPlaneError::InvalidInput(
            "new storage ticket binding is not issued",
        ));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
fn reservation_state(s: &StorageReservationState) -> &'static str {
    match s {
        StorageReservationState::Reserved => "reserved",
        StorageReservationState::Committed => "committed",
        StorageReservationState::Released => "released",
        StorageReservationState::Expired => "expired",
    }
}
#[cfg(feature = "postgres")]
fn reservation_row(
    row: sqlx::postgres::PgRow,
) -> Result<TenantStorageReservation, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "reserved" => StorageReservationState::Reserved,
        "committed" => StorageReservationState::Committed,
        "released" => StorageReservationState::Released,
        "expired" => StorageReservationState::Expired,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "invalid storage reservation state {other}"
            )))
        }
    };
    let digest = row
        .try_get::<Option<String>, _>("object_digest")?
        .map(ContentDigest::parse)
        .transpose()?;
    Ok(TenantStorageReservation {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        ticket_kind: row.try_get("ticket_kind")?,
        object_digest: digest,
        reserved_bytes: postgres_u64(row.try_get("reserved_bytes")?, "reserved bytes")?,
        reserved_objects: postgres_u64(row.try_get("reserved_objects")?, "reserved objects")?,
        state,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "storage reservation creation",
        )?,
        expires_unix_ms: postgres_u64(
            row.try_get("expires_unix_ms")?,
            "storage reservation expiry",
        )?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|v| postgres_u64(v, "storage reservation completion"))
            .transpose()?,
    })
}
#[cfg(feature = "postgres")]
fn binding_row(row: sqlx::postgres::PgRow) -> Result<StorageTicketBinding, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "issued" => StorageTicketBindingState::Issued,
        "committed" => StorageTicketBindingState::Committed,
        "accounted" => StorageTicketBindingState::Accounted,
        "released" => StorageTicketBindingState::Released,
        other => {
            return Err(ControlPlaneError::CorruptState(format!(
                "invalid storage ticket binding state {other}"
            )))
        }
    };
    Ok(StorageTicketBinding {
        reservation_id: row.try_get("reservation_id")?,
        tenant_id: row.try_get("tenant_id")?,
        ticket_kind: row.try_get("ticket_kind")?,
        ticket_id: row.try_get("ticket_id")?,
        object_id: row.try_get("object_id")?,
        actual_bytes: row
            .try_get::<Option<i64>, _>("actual_bytes")?
            .map(|v| postgres_u64(v, "storage ticket actual bytes"))
            .transpose()?,
        actual_objects: row
            .try_get::<Option<i64>, _>("actual_objects")?
            .map(|v| postgres_u64(v, "storage ticket actual objects"))
            .transpose()?,
        state,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "storage ticket creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "storage ticket update")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|v| postgres_u64(v, "storage ticket completion"))
            .transpose()?,
    })
}
#[cfg(feature = "postgres")]
async fn record_cache_generation_pg(
    tx: &mut Transaction<'_, Postgres>,
    record: &CacheTrustGenerationRecord,
    expected_store_generation: Option<u64>,
    expected_head_cache_entry_id: Option<&str>,
) -> Result<bool, ControlPlaneError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771001))")
        .bind(&record.cache_entry_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 771002))")
        .bind(record.identity_digest.as_str())
        .execute(&mut **tx)
        .await?;
    let repository: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1 AND tenant_id=$2)",
    )
    .bind(&record.repository_id)
    .bind(&record.tenant_id)
    .fetch_one(&mut **tx)
    .await?;
    if !repository {
        return Err(not_found("cache repository", &record.repository_id));
    }
    if let Some(existing) =
        cache_generation_pg(tx, &record.tenant_id, &record.cache_entry_id, false).await?
    {
        if existing == *record {
            return Ok(true);
        }
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let current: Option<(String, i64)> = sqlx::query_as(
        "SELECT cache_entry_id,generation FROM cache_trust_current_heads
         WHERE identity_digest=$1 FOR UPDATE",
    )
    .bind(record.identity_digest.as_str())
    .fetch_optional(&mut **tx)
    .await?;
    let current_generation = current
        .as_ref()
        .map(|(_, value)| postgres_u64(*value, "cache head generation"))
        .transpose()?;
    let expected_next = expected_store_generation.map_or(1, |value| value.saturating_add(1));
    if current_generation.is_some() && current_generation != expected_store_generation
        || expected_head_cache_entry_id.is_some()
            && current.as_ref().map(|(value, _)| value.as_str()) != expected_head_cache_entry_id
        || record.generation != expected_next
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    if let Some(source_id) = &record.source_cache_entry_id {
        let source = cache_generation_pg(tx, &record.tenant_id, source_id, false)
            .await?
            .ok_or_else(|| not_found("cache promotion source", source_id))?;
        if source.repository_id != record.repository_id
            || source.key_material_digest != record.key_material_digest
            || source.tree_manifest_digest != record.tree_manifest_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    sqlx::query(
        "INSERT INTO cache_trust_generations
         (cache_entry_id,tenant_id,repository_id,identity_digest,key_material_digest,
          key_material_json,trust_domain_json,generation,manifest_digest,
          tree_manifest_digest,fencing_generation,source_cache_entry_id,
          promotion_evidence_digest,created_unix_ms)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&record.cache_entry_id)
    .bind(&record.tenant_id)
    .bind(&record.repository_id)
    .bind(record.identity_digest.as_str())
    .bind(record.key_material_digest.as_str())
    .bind(json_bytes(&canonicalize_json(record.key_material.clone()))?)
    .bind(json_bytes(&canonicalize_json(record.trust_domain.clone()))?)
    .bind(postgres_i64(record.generation, "cache generation")?)
    .bind(record.manifest_digest.as_str())
    .bind(record.tree_manifest_digest.as_str())
    .bind(postgres_i64(
        record.fencing_generation,
        "cache fencing generation",
    )?)
    .bind(&record.source_cache_entry_id)
    .bind(
        record
            .promotion_evidence_digest
            .as_ref()
            .map(ContentDigest::as_str),
    )
    .bind(postgres_i64(
        record.created_unix_ms,
        "cache generation creation",
    )?)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO cache_trust_current_heads
         (identity_digest,cache_entry_id,generation,updated_unix_ms)
         VALUES($1,$2,$3,$4)
         ON CONFLICT(identity_digest) DO UPDATE SET
           cache_entry_id=excluded.cache_entry_id,
           generation=excluded.generation,
           updated_unix_ms=excluded.updated_unix_ms",
    )
    .bind(record.identity_digest.as_str())
    .bind(&record.cache_entry_id)
    .bind(postgres_i64(record.generation, "cache generation")?)
    .bind(postgres_i64(
        record.created_unix_ms,
        "cache generation creation",
    )?)
    .execute(&mut **tx)
    .await?;
    Ok(false)
}

#[cfg(feature = "postgres")]
async fn cache_generation_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    cache_entry: &str,
    lock: bool,
) -> Result<Option<CacheTrustGenerationRecord>, ControlPlaneError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let row = sqlx::query(&format!(
        "{CACHE_GENERATION_COLUMNS} WHERE cache_entry_id=$1 AND tenant_id=$2{suffix}"
    ))
    .bind(cache_entry)
    .bind(tenant)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(cache_generation_row_pg).transpose()
}

#[cfg(feature = "postgres")]
fn cache_generation_row_pg(
    row: sqlx::postgres::PgRow,
) -> Result<CacheTrustGenerationRecord, ControlPlaneError> {
    Ok(CacheTrustGenerationRecord {
        cache_entry_id: row.try_get("cache_entry_id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        identity_digest: ContentDigest::parse(row.try_get::<String, _>("identity_digest")?)?,
        key_material_digest: ContentDigest::parse(
            row.try_get::<String, _>("key_material_digest")?,
        )?,
        key_material: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("key_material_json")?)?,
        trust_domain: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("trust_domain_json")?)?,
        generation: postgres_u64(row.try_get("generation")?, "cache generation")?,
        manifest_digest: ContentDigest::parse(row.try_get::<String, _>("manifest_digest")?)?,
        tree_manifest_digest: ContentDigest::parse(
            row.try_get::<String, _>("tree_manifest_digest")?,
        )?,
        fencing_generation: postgres_u64(
            row.try_get("fencing_generation")?,
            "cache fencing generation",
        )?,
        source_cache_entry_id: row.try_get("source_cache_entry_id")?,
        promotion_evidence_digest: row
            .try_get::<Option<String>, _>("promotion_evidence_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "cache generation creation",
        )?,
    })
}

#[cfg(feature = "postgres")]
async fn cache_promotion_pg(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    tenant: Option<&str>,
    lock: bool,
) -> Result<Option<CachePromotionRecord>, ControlPlaneError> {
    let tenant_predicate = if tenant.is_some() {
        " AND tenant_id=$2"
    } else {
        ""
    };
    let lock_suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!("{CACHE_PROMOTION_COLUMNS} WHERE id=$1{tenant_predicate}{lock_suffix}");
    let mut query = sqlx::query(&sql).bind(id);
    if let Some(tenant) = tenant {
        query = query.bind(tenant);
    }
    query
        .fetch_optional(&mut **tx)
        .await?
        .map(cache_promotion_row_pg)
        .transpose()
}

#[cfg(feature = "postgres")]
fn cache_promotion_row_pg(
    row: sqlx::postgres::PgRow,
) -> Result<CachePromotionRecord, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "pending" => CachePromotionState::Pending,
        "completed" => CachePromotionState::Completed,
        "failed" => CachePromotionState::Failed,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid cache promotion state".to_owned(),
            ))
        }
    };
    Ok(CachePromotionRecord {
        id: row.try_get("id")?,
        subject_digest: ContentDigest::parse(row.try_get::<String, _>("subject_digest")?)?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        source_cache_entry_id: row.try_get("source_cache_entry_id")?,
        target_identity_digest: ContentDigest::parse(
            row.try_get::<String, _>("target_identity_digest")?,
        )?,
        target_trust_domain: serde_json::from_slice(
            &row.try_get::<Vec<u8>, _>("target_trust_domain_json")?,
        )?,
        expected_target_cache_entry_id: row.try_get("expected_target_cache_entry_id")?,
        evidence_digest: ContentDigest::parse(row.try_get::<String, _>("evidence_digest")?)?,
        evidence: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("evidence_json")?)?,
        state,
        promoted_cache_entry_id: row.try_get("promoted_cache_entry_id")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "cache promotion creation")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|value| postgres_u64(value, "cache promotion completion"))
            .transpose()?,
        last_error: row.try_get("last_error")?,
    })
}

#[cfg(feature = "postgres")]
async fn cache_observation_pg(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<CacheAccessObservation>, ControlPlaneError> {
    sqlx::query(&format!("{CACHE_OBSERVATION_COLUMNS} WHERE id=$1"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(cache_observation_row_pg)
        .transpose()
}

#[cfg(feature = "postgres")]
fn cache_observation_row_pg(
    row: sqlx::postgres::PgRow,
) -> Result<CacheAccessObservation, ControlPlaneError> {
    let attempt: i32 = row.try_get("job_attempt")?;
    let candidates: Value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("candidates_json")?)?;
    let candidates = candidates.as_array().cloned().ok_or_else(|| {
        ControlPlaneError::CorruptState("cache candidates are not an array".to_owned())
    })?;
    Ok(CacheAccessObservation {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        run_id: row.try_get("run_id")?,
        job_id: row.try_get("job_id")?,
        job_attempt: u32::try_from(attempt).map_err(|_| {
            ControlPlaneError::CorruptState("invalid cache observation job attempt".to_owned())
        })?,
        step_id: row.try_get("step_id")?,
        operation: row.try_get("operation")?,
        key_material_digest: ContentDigest::parse(
            row.try_get::<String, _>("key_material_digest")?,
        )?,
        candidates,
        outcome: row.try_get("outcome")?,
        selected_trust_domain: row
            .try_get::<Option<Vec<u8>>, _>("selected_trust_domain_json")?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?,
        selected_generation: row
            .try_get::<Option<i64>, _>("selected_generation")?
            .map(|value| postgres_u64(value, "cache selected generation"))
            .transpose()?,
        transferred_bytes: postgres_u64(
            row.try_get("transferred_bytes")?,
            "cache transferred bytes",
        )?,
        latency_ms: postgres_u64(row.try_get("latency_ms")?, "cache latency")?,
        breaker_state: row.try_get("breaker_state")?,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "cache observation creation",
        )?,
    })
}

#[cfg(feature = "postgres")]
async fn lock_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
) -> Result<(), ControlPlaneError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1096040772))")
        .bind(tenant)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
#[cfg(feature = "postgres")]
async fn reservation_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<TenantStorageReservation>, ControlPlaneError> {
    sqlx::query(&format!("{RESERVATION_COLUMNS} WHERE id=$1 FOR UPDATE"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(reservation_row)
        .transpose()
}
#[cfg(feature = "postgres")]
async fn binding_by_reservation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<StorageTicketBinding>, ControlPlaneError> {
    sqlx::query(&format!(
        "{BINDING_COLUMNS} WHERE tenant_id=$1 AND reservation_id=$2 FOR UPDATE"
    ))
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .map(binding_row)
    .transpose()
}
#[cfg(feature = "postgres")]
async fn binding_by_ticket(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<StorageTicketBinding>, ControlPlaneError> {
    sqlx::query(&format!(
        "{BINDING_COLUMNS} WHERE tenant_id=$1 AND ticket_id=$2 FOR UPDATE"
    ))
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .map(binding_row)
    .transpose()
}
#[cfg(feature = "postgres")]
fn checked_sum(a: i64, b: i64, c: u64, field: &'static str) -> Result<u64, ControlPlaneError> {
    postgres_u64(a, field)?
        .checked_add(postgres_u64(b, field)?)
        .and_then(|v| v.checked_add(c))
        .ok_or(ControlPlaneError::IntegerRange { field })
}
#[cfg(feature = "postgres")]
async fn account_ticket(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    ticket: &str,
    object: &str,
    now: u64,
) -> Result<bool, ControlPlaneError> {
    let binding = binding_by_ticket(tx, tenant, ticket)
        .await?
        .ok_or_else(|| not_found("storage ticket", ticket))?;
    if binding.object_id.as_deref() != Some(object) {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let bytes = binding
        .actual_bytes
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    let objects = binding
        .actual_objects
        .ok_or(ControlPlaneError::IdempotencyConflict)?;
    let existing=sqlx::query("SELECT billed_bytes,billed_objects,state,retired_unix_ms FROM tenant_storage_objects WHERE tenant_id=$1 AND object_kind=$2 AND object_id=$3 FOR UPDATE")
        .bind(tenant).bind(&binding.ticket_kind).bind(object).fetch_optional(&mut **tx).await?;
    let exact = match existing.as_ref() {
        Some(r) => {
            postgres_u64(r.try_get("billed_bytes")?, "storage object bytes")? == bytes
                && postgres_u64(r.try_get("billed_objects")?, "storage object count")? == objects
                && r.try_get::<String, _>("state")? == "active"
                && r.try_get::<Option<i64>, _>("retired_unix_ms")?.is_none()
        }
        None => false,
    };
    if binding.state == StorageTicketBindingState::Accounted {
        return if exact {
            Ok(true)
        } else {
            Err(ControlPlaneError::IdempotencyConflict)
        };
    }
    if binding.state != StorageTicketBindingState::Committed {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    if existing.is_some() && !exact {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let now_i64 = postgres_i64(now, "storage object creation")?;
    if existing.is_none() {
        sqlx::query("INSERT INTO tenant_storage_objects(tenant_id,object_kind,object_id,billed_bytes,billed_objects,state,created_unix_ms) VALUES($1,$2,$3,$4,$5,'active',$6)")
        .bind(tenant).bind(&binding.ticket_kind).bind(object).bind(postgres_i64(bytes,"storage object bytes")?).bind(postgres_i64(objects,"storage object count")?).bind(now_i64).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE tenant_storage_ticket_bindings SET state='accounted',updated_unix_ms=$3,completed_unix_ms=$3 WHERE tenant_id=$1 AND ticket_id=$2 AND state='committed'").bind(tenant).bind(ticket).bind(now_i64).execute(&mut **tx).await?;
    sqlx::query("UPDATE tenant_storage_reservations SET state='released',completed_unix_ms=$3 WHERE id=$1 AND tenant_id=$2 AND state='committed'").bind(&binding.reservation_id).bind(tenant).bind(now_i64).execute(&mut **tx).await?;
    Ok(false)
}
#[cfg(feature = "postgres")]
fn artifact_row(row: sqlx::postgres::PgRow) -> Result<ArtifactCatalogRecord, ControlPlaneError> {
    let attempt: i32 = row.try_get("job_attempt")?;
    Ok(ArtifactCatalogRecord {
        artifact_id: row.try_get("artifact_id")?,
        tenant_id: row.try_get("tenant_id")?,
        repository_id: row.try_get("repository_id")?,
        run_id: row.try_get("run_id")?,
        job_id: row.try_get("job_id")?,
        job_attempt: u32::try_from(attempt).map_err(|_| {
            ControlPlaneError::CorruptState("invalid artifact job attempt".to_owned())
        })?,
        step_id: row.try_get("step_id")?,
        output_name: row.try_get("output_name")?,
        content_digest: ContentDigest::parse(row.try_get::<String, _>("content_digest")?)?,
        manifest_digest: ContentDigest::parse(row.try_get::<String, _>("manifest_digest")?)?,
        provenance_digest: ContentDigest::parse(row.try_get::<String, _>("provenance_digest")?)?,
        size_bytes: postgres_u64(row.try_get("size_bytes")?, "artifact size")?,
        media_type: row.try_get("media_type")?,
        classification: row.try_get("classification")?,
        scan_state: row.try_get("scan_state")?,
        retention_until_unix_seconds: postgres_u64(
            row.try_get("retention_until_unix_seconds")?,
            "artifact retention",
        )?,
        legal_hold: row.try_get("legal_hold")?,
        state: row.try_get("state")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "artifact creation")?,
    })
}
#[cfg(feature = "postgres")]
async fn artifact_scan_pg(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    tenant: Option<&str>,
    lock: bool,
) -> Result<Option<ArtifactScanJournalRecord>, ControlPlaneError> {
    let tenant_predicate = if tenant.is_some() {
        " AND tenant_id=$2"
    } else {
        ""
    };
    let lock_suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!("{ARTIFACT_SCAN_COLUMNS} WHERE id=$1{tenant_predicate}{lock_suffix}");
    let mut query = sqlx::query(&sql).bind(id);
    if let Some(tenant) = tenant {
        query = query.bind(tenant);
    }
    query
        .fetch_optional(&mut **tx)
        .await?
        .map(artifact_scan_row_pg)
        .transpose()
}

#[cfg(feature = "postgres")]
fn artifact_scan_row_pg(
    row: sqlx::postgres::PgRow,
) -> Result<ArtifactScanJournalRecord, ControlPlaneError> {
    let state = match row.try_get::<String, _>("state")?.as_str() {
        "pending" => ArtifactScanState::Pending,
        "claimed" => ArtifactScanState::Claimed,
        "passed" => ArtifactScanState::Passed,
        "failed" => ArtifactScanState::Failed,
        "error" => ArtifactScanState::Error,
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid artifact scan state".to_owned(),
            ))
        }
    };
    let attempts: i32 = row.try_get("attempts")?;
    Ok(ArtifactScanJournalRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        artifact_id: row.try_get("artifact_id")?,
        scanner: row.try_get("scanner")?,
        subject_digest: ContentDigest::parse(row.try_get::<String, _>("subject_digest")?)?,
        state,
        result_digest: row
            .try_get::<Option<String>, _>("result_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        lease_owner: row.try_get("lease_owner")?,
        lease_expires_unix_ms: row
            .try_get::<Option<i64>, _>("lease_expires_unix_ms")?
            .map(|value| postgres_u64(value, "artifact scan lease expiry"))
            .transpose()?,
        attempts: u32::try_from(attempts).map_err(|_| {
            ControlPlaneError::CorruptState("invalid artifact scan attempts".to_owned())
        })?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "artifact scan creation")?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|value| postgres_u64(value, "artifact scan completion"))
            .transpose()?,
        last_error_code: row.try_get("last_error_code")?,
    })
}

#[cfg(feature = "postgres")]
async fn artifact_promotion_pg(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    tenant: Option<&str>,
    lock: bool,
) -> Result<Option<ArtifactPromotionIntent>, ControlPlaneError> {
    let tenant_predicate = if tenant.is_some() {
        " AND p.tenant_id=$2"
    } else {
        ""
    };
    let lock_suffix = if lock { " FOR UPDATE OF p,b" } else { "" };
    let sql = format!("{ARTIFACT_PROMOTION_COLUMNS} WHERE p.id=$1{tenant_predicate}{lock_suffix}");
    let mut query = sqlx::query(&sql).bind(id);
    if let Some(tenant) = tenant {
        query = query.bind(tenant);
    }
    query
        .fetch_optional(&mut **tx)
        .await?
        .map(artifact_promotion_row_pg)
        .transpose()
}

#[cfg(feature = "postgres")]
fn artifact_promotion_row_pg(
    row: sqlx::postgres::PgRow,
) -> Result<ArtifactPromotionIntent, ControlPlaneError> {
    Ok(ArtifactPromotionIntent {
        id: row.try_get("id")?,
        subject_digest: ContentDigest::parse(row.try_get::<String, _>("subject_digest")?)?,
        tenant_id: row.try_get("tenant_id")?,
        source_artifact_id: row.try_get("source_artifact_id")?,
        source_manifest_digest: ContentDigest::parse(
            row.try_get::<String, _>("source_manifest_digest")?,
        )?,
        source_provenance_digest: ContentDigest::parse(
            row.try_get::<String, _>("source_provenance_digest")?,
        )?,
        source_classification: row.try_get("source_classification")?,
        target_classification: row.try_get("target_classification")?,
        evidence_digest: ContentDigest::parse(row.try_get::<String, _>("evidence_digest")?)?,
        evidence: serde_json::from_slice(&row.try_get::<Vec<u8>, _>("evidence_json")?)?,
        scan_evidence_digest: row
            .try_get::<Option<String>, _>("scan_evidence_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        approval_evidence_digest: row
            .try_get::<Option<String>, _>("approval_evidence_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        status: row.try_get("status")?,
        promoted_artifact_id: row.try_get("promoted_artifact_id")?,
        promoted_manifest_digest: row
            .try_get::<Option<String>, _>("promoted_manifest_digest")?
            .map(ContentDigest::parse)
            .transpose()?,
        created_unix_ms: postgres_u64(
            row.try_get("created_unix_ms")?,
            "artifact promotion creation",
        )?,
        completed_unix_ms: row
            .try_get::<Option<i64>, _>("completed_unix_ms")?
            .map(|value| postgres_u64(value, "artifact promotion completion"))
            .transpose()?,
        last_error_code: row.try_get("last_error_code")?,
    })
}

#[cfg(feature = "postgres")]
async fn artifact_by_tenant_tx_locked(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<ArtifactCatalogRecord>, ControlPlaneError> {
    sqlx::query(&format!(
        "{ARTIFACT_COLUMNS} WHERE tenant_id=$1 AND artifact_id=$2 FOR UPDATE"
    ))
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .map(artifact_row)
    .transpose()
}

#[cfg(feature = "postgres")]
async fn artifact_by_tenant_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: &str,
) -> Result<Option<ArtifactCatalogRecord>, ControlPlaneError> {
    sqlx::query(&format!(
        "{ARTIFACT_COLUMNS} WHERE tenant_id=$1 AND artifact_id=$2"
    ))
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .map(artifact_row)
    .transpose()
}
#[cfg(feature = "postgres")]
async fn account_artifact_ticket_if_present(
    tx: &mut Transaction<'_, Postgres>,
    artifact: &ArtifactCatalogRecord,
) -> Result<(), ControlPlaneError> {
    let binding:Option<(String,i64)>=sqlx::query_as("SELECT b.ticket_id,b.updated_unix_ms FROM runner_data_commits c JOIN tenant_storage_ticket_bindings b ON b.ticket_id=c.ticket_id AND b.tenant_id=c.tenant_id WHERE c.kind='artifact' AND c.object_id=$1 AND c.tenant_id=$2 AND c.job_id=$3 AND c.job_attempt=$4")
        .bind(&artifact.artifact_id).bind(&artifact.tenant_id).bind(&artifact.job_id).bind(i32::try_from(artifact.job_attempt).map_err(|_|ControlPlaneError::IntegerRange{field:"artifact job attempt"})?).fetch_optional(&mut **tx).await?;
    if let Some((ticket, updated)) = binding {
        account_ticket(
            tx,
            &artifact.tenant_id,
            &ticket,
            &artifact.artifact_id,
            artifact
                .created_unix_ms
                .max(postgres_u64(updated, "storage ticket update")?),
        )
        .await?;
    }
    Ok(())
}
#[cfg(feature = "postgres")]
async fn download_ticket_tx(
    tx: &mut Transaction<'_, Postgres>,
    hash: &ContentDigest,
) -> Result<Option<ArtifactDownloadTicketRecord>, ControlPlaneError> {
    let row=sqlx::query("SELECT token_hash,artifact_id,tenant_id,principal_id,classification,manifest_digest,issued_unix_ms,expires_unix_ms,used_unix_ms FROM artifact_download_tickets WHERE token_hash=$1 FOR UPDATE").bind(hash.as_str()).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        Ok(ArtifactDownloadTicketRecord {
            token_hash: ContentDigest::parse(r.try_get::<String, _>("token_hash")?)?,
            artifact_id: r.try_get("artifact_id")?,
            tenant_id: r.try_get("tenant_id")?,
            principal_id: r.try_get("principal_id")?,
            classification: r.try_get("classification")?,
            manifest_digest: ContentDigest::parse(r.try_get::<String, _>("manifest_digest")?)?,
            issued_unix_ms: postgres_u64(r.try_get("issued_unix_ms")?, "download issue")?,
            expires_unix_ms: postgres_u64(r.try_get("expires_unix_ms")?, "download expiry")?,
            used_unix_ms: r
                .try_get::<Option<i64>, _>("used_unix_ms")?
                .map(|v| postgres_u64(v, "download use"))
                .transpose()?,
        })
    })
    .transpose()
}
#[cfg(feature = "postgres")]
fn not_found(kind: &'static str, id: &str) -> ControlPlaneError {
    ControlPlaneError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(test)]
mod cache_contract_tests {
    use super::*;
    #[cfg(feature = "postgres")]
    use crate::TenantIdentityStore;
    use crate::{
        artifact_promotion_subject_digest, artifact_scan_subject_digest,
        cache_promotion_subject_digest, ApiTokenAuditStore, ControlPlaneError, RepositoryRecord,
        TenantIdentityRecord,
    };
    use serde_json::Value;
    use std::collections::BTreeMap;

    async fn cache_contract(
        store: &dyn CacheTrustStore,
        tenant: &str,
        repository: &str,
        run: &str,
        job: &str,
        suffix: &str,
    ) {
        let source = CacheTrustGenerationRecord {
            cache_entry_id: format!("cache-source-{suffix}"),
            tenant_id: tenant.to_owned(),
            repository_id: repository.to_owned(),
            identity_digest: ContentDigest::sha256(format!("source-identity-{suffix}")),
            key_material_digest: ContentDigest::sha256(format!("key-material-{suffix}")),
            key_material: serde_json::json!({"purpose":"build","suffix":suffix}),
            trust_domain: serde_json::json!({"kind":"pull_request_quarantine","change_id":"7"}),
            generation: 1,
            manifest_digest: ContentDigest::sha256(format!("source-manifest-{suffix}")),
            tree_manifest_digest: ContentDigest::sha256(format!("tree-{suffix}")),
            fencing_generation: 7,
            source_cache_entry_id: None,
            promotion_evidence_digest: None,
            created_unix_ms: 10,
        };
        assert!(!store
            .record_cache_trust_generation(&source, None)
            .await
            .unwrap());
        assert!(store
            .record_cache_trust_generation(&source, None)
            .await
            .unwrap());
        assert_eq!(
            store
                .cache_trust_generation(tenant, &source.cache_entry_id)
                .await
                .unwrap(),
            source
        );
        assert!(matches!(
            store
                .cache_trust_generation("other-tenant", &source.cache_entry_id)
                .await,
            Err(ControlPlaneError::NotFound { .. })
        ));
        let mut substituted = source.clone();
        substituted.tree_manifest_digest = ContentDigest::sha256(b"substitution");
        assert!(matches!(
            store
                .record_cache_trust_generation(&substituted, None)
                .await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));

        let mut promotion = CachePromotionRecord {
            id: format!("promotion-{suffix}"),
            subject_digest: ContentDigest::sha256([]),
            tenant_id: tenant.to_owned(),
            repository_id: repository.to_owned(),
            source_cache_entry_id: source.cache_entry_id.clone(),
            target_identity_digest: ContentDigest::sha256(format!("target-identity-{suffix}")),
            target_trust_domain: serde_json::json!({"kind":"repository_main_verified"}),
            expected_target_cache_entry_id: None,
            evidence_digest: ContentDigest::sha256(format!("evidence-{suffix}")),
            evidence: serde_json::json!({"kind":"verified_attestation","scan":"passed"}),
            state: CachePromotionState::Pending,
            promoted_cache_entry_id: None,
            created_unix_ms: 11,
            completed_unix_ms: None,
            last_error: None,
        };
        promotion.subject_digest = cache_promotion_subject_digest(&promotion).unwrap();
        assert!(!store
            .create_cache_promotion_idempotent(&promotion)
            .await
            .unwrap());
        assert!(store
            .create_cache_promotion_idempotent(&promotion)
            .await
            .unwrap());
        let mut changed_promotion = promotion.clone();
        changed_promotion.evidence = serde_json::json!({"kind":"different"});
        changed_promotion.subject_digest =
            cache_promotion_subject_digest(&changed_promotion).unwrap();
        assert!(matches!(
            store
                .create_cache_promotion_idempotent(&changed_promotion)
                .await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let mut cross_tenant = promotion.clone();
        cross_tenant.id = format!("cross-tenant-{suffix}");
        cross_tenant.tenant_id = "other-tenant".to_owned();
        cross_tenant.subject_digest = cache_promotion_subject_digest(&cross_tenant).unwrap();
        assert!(matches!(
            store.create_cache_promotion_idempotent(&cross_tenant).await,
            Err(ControlPlaneError::NotFound { .. })
        ));

        let promoted = CacheTrustGenerationRecord {
            cache_entry_id: format!("cache-promoted-{suffix}"),
            tenant_id: tenant.to_owned(),
            repository_id: repository.to_owned(),
            identity_digest: promotion.target_identity_digest.clone(),
            key_material_digest: source.key_material_digest.clone(),
            key_material: source.key_material.clone(),
            trust_domain: promotion.target_trust_domain.clone(),
            generation: 1,
            manifest_digest: ContentDigest::sha256(format!("promoted-manifest-{suffix}")),
            tree_manifest_digest: source.tree_manifest_digest.clone(),
            fencing_generation: 8,
            source_cache_entry_id: Some(source.cache_entry_id.clone()),
            promotion_evidence_digest: Some(promotion.evidence_digest.clone()),
            created_unix_ms: 12,
        };
        assert!(!store
            .complete_cache_promotion(tenant, &promotion.id, &promoted, 12)
            .await
            .unwrap());
        assert!(store
            .complete_cache_promotion(tenant, &promotion.id, &promoted, 13)
            .await
            .unwrap());
        assert_eq!(
            store
                .cache_promotion(tenant, &promotion.id)
                .await
                .unwrap()
                .promoted_cache_entry_id
                .as_deref(),
            Some(promoted.cache_entry_id.as_str())
        );
        assert!(matches!(
            store.cache_promotion("other-tenant", &promotion.id).await,
            Err(ControlPlaneError::NotFound { .. })
        ));

        let observation = CacheAccessObservation {
            id: format!("observation-{suffix}"),
            tenant_id: tenant.to_owned(),
            repository_id: repository.to_owned(),
            run_id: run.to_owned(),
            job_id: job.to_owned(),
            job_attempt: 1,
            step_id: "build".to_owned(),
            operation: "restore".to_owned(),
            key_material_digest: source.key_material_digest,
            candidates: vec![serde_json::json!({"kind":"repository_main_verified"})],
            outcome: "hit".to_owned(),
            selected_trust_domain: Some(promoted.trust_domain),
            selected_generation: Some(1),
            transferred_bytes: 4096,
            latency_ms: 12,
            breaker_state: "closed".to_owned(),
            created_unix_ms: 13,
        };
        assert!(!store
            .record_cache_access_observation(&observation)
            .await
            .unwrap());
        assert!(store
            .record_cache_access_observation(&observation)
            .await
            .unwrap());
        let mut changed_observation = observation.clone();
        changed_observation.latency_ms += 1;
        assert!(matches!(
            store
                .record_cache_access_observation(&changed_observation)
                .await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        assert_eq!(
            store.cache_trust_metrics(tenant).await.unwrap(),
            CacheTrustMetrics {
                hits: 1,
                promotions_completed: 1,
                ..CacheTrustMetrics::default()
            }
        );
        assert_eq!(
            store.cache_trust_metrics("other-tenant").await.unwrap(),
            CacheTrustMetrics::default()
        );
    }

    async fn artifact_scan_promotion_contract<S>(
        store: &S,
        source: &ArtifactCatalogRecord,
        suffix: &str,
    ) where
        S: ArtifactScanPromotionStore + ApiTokenAuditStore,
    {
        let scanner = format!("scanner-{suffix}");
        let scan = ArtifactScanJournalRecord {
            id: format!("artifact-scan-{suffix}"),
            tenant_id: source.tenant_id.clone(),
            artifact_id: source.artifact_id.clone(),
            scanner: scanner.clone(),
            subject_digest: artifact_scan_subject_digest(source, &scanner).unwrap(),
            state: ArtifactScanState::Pending,
            result_digest: None,
            lease_owner: None,
            lease_expires_unix_ms: None,
            attempts: 0,
            created_unix_ms: 30,
            completed_unix_ms: None,
            last_error_code: None,
        };
        assert!(!store.enqueue_artifact_scan(&scan).await.unwrap());
        assert!(store.enqueue_artifact_scan(&scan).await.unwrap());
        let mut changed_scan = scan.clone();
        changed_scan.subject_digest = ContentDigest::sha256(b"changed scan");
        assert!(matches!(
            store.enqueue_artifact_scan(&changed_scan).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let mut cross_tenant = scan.clone();
        cross_tenant.id = format!("cross-tenant-scan-{suffix}");
        cross_tenant.tenant_id = "other-tenant".to_owned();
        assert!(matches!(
            store.enqueue_artifact_scan(&cross_tenant).await,
            Err(ControlPlaneError::NotFound { .. })
        ));
        let first_claim = store
            .claim_artifact_scan("expired-scanner", 31, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_claim.id, scan.id);
        assert_eq!(first_claim.attempts, 1);
        let claimed = store
            .claim_artifact_scan("scanner-worker", 32, 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.id, scan.id);
        assert_eq!(claimed.attempts, 2);
        assert_eq!(claimed.last_error_code.as_deref(), Some("lease-expired"));
        let result = ContentDigest::sha256(format!("scan-result-{suffix}"));
        assert!(matches!(
            store
                .finish_artifact_scan(
                    &source.tenant_id,
                    &scan.id,
                    "expired-scanner",
                    ArtifactScanState::Passed,
                    Some(&result),
                    None,
                    33,
                )
                .await,
            Err(ControlPlaneError::TaskNotOwned)
        ));
        assert!(!store
            .finish_artifact_scan(
                &source.tenant_id,
                &scan.id,
                "scanner-worker",
                ArtifactScanState::Passed,
                Some(&result),
                None,
                33,
            )
            .await
            .unwrap());
        assert!(store
            .finish_artifact_scan(
                &source.tenant_id,
                &scan.id,
                "scanner-worker",
                ArtifactScanState::Passed,
                Some(&result),
                None,
                34,
            )
            .await
            .unwrap());

        let evidence = serde_json::json!({"approval":"yes","kind":"scan"});
        let evidence = canonicalize_contract_json(evidence);
        let mut promotion = ArtifactPromotionIntent {
            id: format!("artifact-promotion-{suffix}"),
            subject_digest: ContentDigest::sha256([]),
            tenant_id: source.tenant_id.clone(),
            source_artifact_id: source.artifact_id.clone(),
            source_manifest_digest: source.manifest_digest.clone(),
            source_provenance_digest: source.provenance_digest.clone(),
            source_classification: source.classification.clone(),
            target_classification: "verified-test-output".to_owned(),
            evidence_digest: ContentDigest::sha256(serde_json::to_vec(&evidence).unwrap()),
            evidence,
            scan_evidence_digest: Some(result),
            approval_evidence_digest: None,
            status: "pending".to_owned(),
            promoted_artifact_id: None,
            promoted_manifest_digest: None,
            created_unix_ms: 35,
            completed_unix_ms: None,
            last_error_code: None,
        };
        promotion.subject_digest = artifact_promotion_subject_digest(&promotion).unwrap();
        assert!(!store.create_artifact_promotion(&promotion).await.unwrap());
        assert!(store.create_artifact_promotion(&promotion).await.unwrap());
        assert!(matches!(
            store
                .artifact_promotion("other-tenant", &promotion.id)
                .await,
            Err(ControlPlaneError::NotFound { .. })
        ));
        let stored = store
            .artifact_promotion(&source.tenant_id, &promotion.id)
            .await
            .unwrap();
        assert_eq!(stored, promotion);
        let promoted = ContentDigest::sha256(format!("promoted-{suffix}"));
        assert!(!store
            .complete_artifact_promotion(
                &source.tenant_id,
                &promotion.id,
                promoted.as_str(),
                &promoted,
                36,
            )
            .await
            .unwrap());
        assert!(store
            .complete_artifact_promotion(
                &source.tenant_id,
                &promotion.id,
                promoted.as_str(),
                &promoted,
                37,
            )
            .await
            .unwrap());
        assert!(matches!(
            store
                .complete_artifact_promotion(
                    &source.tenant_id,
                    &promotion.id,
                    "substitution",
                    &promoted,
                    38,
                )
                .await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let events = store.events().await.unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.data.action == "artifact.scan")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.data.action == "artifact.promote")
                .count(),
            1
        );
    }

    fn canonicalize_contract_json(value: Value) -> Value {
        match value {
            Value::Array(values) => {
                Value::Array(values.into_iter().map(canonicalize_contract_json).collect())
            }
            Value::Object(values) => Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize_contract_json(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            value => value,
        }
    }

    #[tokio::test]
    async fn sqlite_cache_trust_contract() {
        let store = ControlPlane::open_in_memory("sqlite-cache-contract", 1).unwrap();
        let tenant = "sqlite-cache-tenant";
        let repository = "sqlite-cache-repository";
        let run = "sqlite-cache-run";
        let job = "sqlite-cache-job";
        store
            .put_tenant_identity(
                &TenantIdentityRecord {
                    id: tenant.to_owned(),
                    slug: tenant.to_owned(),
                    name: "SQLite cache contract".to_owned(),
                    status: "active".to_owned(),
                    settings: serde_json::json!({}),
                    created_unix_ms: 1,
                    updated_unix_ms: 1,
                    version: 1,
                },
                None,
            )
            .unwrap();
        store
            .create_repository(&RepositoryRecord {
                id: repository.to_owned(),
                tenant_id: tenant.to_owned(),
                owner: "owner".to_owned(),
                name: "cache-contract".to_owned(),
                default_branch: "main".to_owned(),
                visibility: "private".to_owned(),
                created_unix_ms: 1,
            })
            .unwrap();
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                "INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('sqlite-cache-capsule',?1,?2,X'00','{}','key',1)",
                rusqlite::params![repository, ContentDigest::sha256([]).as_str()],
            )
            .unwrap();
            connection
                .execute(
                "INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES(?1,?2,'sqlite-cache-capsule','completed',0,1,1)",
                rusqlite::params![run, repository],
            )
            .unwrap();
            connection
                .execute(
                "INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES(?1,?2,'build',1,'completed','{}',1)",
                rusqlite::params![job, run],
            )
            .unwrap();
        }
        cache_contract(&store, tenant, repository, run, job, "sqlite").await;
        let source = ArtifactCatalogRecord {
            artifact_id: "sqlite-scan-artifact".to_owned(),
            tenant_id: tenant.to_owned(),
            repository_id: repository.to_owned(),
            run_id: run.to_owned(),
            job_id: job.to_owned(),
            job_attempt: 1,
            step_id: "package".to_owned(),
            output_name: "scan-package".to_owned(),
            content_digest: ContentDigest::sha256(b"sqlite artifact content"),
            manifest_digest: ContentDigest::sha256(b"sqlite artifact manifest"),
            provenance_digest: ContentDigest::sha256(b"sqlite artifact provenance"),
            size_bytes: 7,
            media_type: "application/octet-stream".to_owned(),
            classification: "quarantined".to_owned(),
            scan_state: "pending".to_owned(),
            retention_until_unix_seconds: 100,
            legal_hold: false,
            state: "quarantined".to_owned(),
            created_unix_ms: 29,
        };
        {
            let connection = store.connection().unwrap();
            connection
                .pragma_update(None, "foreign_keys", false)
                .unwrap();
            connection
                .execute(
                    "INSERT INTO artifacts_catalog
             (artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,result_kind,
              step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,
              media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,
              created_unix_ms)
             VALUES(?1,?2,?3,?4,?5,1,'artifact',?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,0,?16,?17)",
                    rusqlite::params![
                        source.artifact_id,
                        source.tenant_id,
                        source.repository_id,
                        source.run_id,
                        source.job_id,
                        source.step_id,
                        source.output_name,
                        source.content_digest.as_str(),
                        source.manifest_digest.as_str(),
                        source.provenance_digest.as_str(),
                        i64::try_from(source.size_bytes).unwrap(),
                        source.media_type,
                        source.classification,
                        source.scan_state,
                        i64::try_from(source.retention_until_unix_seconds).unwrap(),
                        source.state,
                        i64::try_from(source.created_unix_ms).unwrap(),
                    ],
                )
                .unwrap();
            connection
                .pragma_update(None, "foreign_keys", true)
                .unwrap();
        }
        artifact_scan_promotion_contract(&store, &source, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_cache_trust_contract() {
        use crate::PostgresInstallationStore;

        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "cache-trust").await;
        let store =
            PostgresInstallationStore::connect(fixture.config(), "postgres-cache-contract", 1)
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
        let tenant = format!("cache-tenant-{suffix}");
        let repository = format!("cache-repository-{suffix}");
        let capsule = format!("cache-capsule-{suffix}");
        let run = format!("cache-run-{suffix}");
        let job = format!("cache-job-{suffix}");
        store
            .put_tenant_identity(
                &TenantIdentityRecord {
                    id: tenant.clone(),
                    slug: tenant.clone(),
                    name: "PostgreSQL cache contract".to_owned(),
                    status: "active".to_owned(),
                    settings: serde_json::json!({}),
                    created_unix_ms: 1,
                    updated_unix_ms: 1,
                    version: 1,
                },
                None,
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES($1,$2,$3,$4,'main','private',1)")
            .bind(&repository).bind(&tenant).bind(format!("owner-{suffix}")).bind(format!("repo-{suffix}")).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,'key',1)")
            .bind(&capsule).bind(&repository).bind(ContentDigest::sha256([]).as_str()).bind([0_u8].as_slice()).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,$2,$3,'completed',0,TRUE,1)")
            .bind(&run).bind(&repository).bind(&capsule).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES($1,$2,'build',1,'completed',$3,1)")
            .bind(&job).bind(&run).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();

        let pool = format!("cache-pool-{suffix}");
        let runner = format!("cache-runner-{suffix}");
        let lease = format!("cache-lease-{suffix}");
        let artifact_id = format!("scan-artifact-{suffix}");
        let ticket = format!("scan-ticket-{suffix}");
        let zero = ContentDigest::sha256([]);
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES($1,$2,$3,'active',1)")
            .bind(&pool).bind(&tenant).bind(format!("cache-pool-{suffix}")).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES($1,$2,'offline',$3,1,1)")
            .bind(&runner).bind(&pool).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES($1,$2,$3,$4,1,1,$5,'completed',1,2,3,4)")
            .bind(&lease).bind(&job).bind(&tenant).bind(&runner).bind(zero.as_str()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_data_commits(kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms) VALUES('artifact',$1,$2,$3,$4,$5,1,'package','scan-package',$6,1,$7,7)")
            .bind(&artifact_id).bind(&tenant).bind(&repository).bind(&run).bind(&job).bind(&lease).bind(&ticket).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal) VALUES($1,1,'artifact',$2,0)")
            .bind(&job).bind(&artifact_id).execute(store.pool()).await.unwrap();
        let source = ArtifactCatalogRecord {
            artifact_id: artifact_id.clone(),
            tenant_id: tenant.clone(),
            repository_id: repository.clone(),
            run_id: run.clone(),
            job_id: job.clone(),
            job_attempt: 1,
            step_id: "package".to_owned(),
            output_name: "scan-package".to_owned(),
            content_digest: ContentDigest::sha256(format!("content-{suffix}")),
            manifest_digest: ContentDigest::sha256(format!("manifest-{suffix}")),
            provenance_digest: ContentDigest::sha256(format!("provenance-{suffix}")),
            size_bytes: 7,
            media_type: "application/octet-stream".to_owned(),
            classification: "quarantined".to_owned(),
            scan_state: "pending".to_owned(),
            retention_until_unix_seconds: 100,
            legal_hold: false,
            state: "quarantined".to_owned(),
            created_unix_ms: 29,
        };
        sqlx::query("INSERT INTO artifacts_catalog(artifact_id,tenant_id,repository_id,run_id,job_id,job_attempt,result_kind,step_id,output_name,content_digest,manifest_digest,provenance_digest,size_bytes,media_type,classification,scan_state,retention_until_unix_seconds,legal_hold,state,created_unix_ms) VALUES($1,$2,$3,$4,$5,1,'artifact',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,FALSE,$16,$17)")
            .bind(&source.artifact_id).bind(&source.tenant_id).bind(&source.repository_id).bind(&source.run_id).bind(&source.job_id).bind(&source.step_id).bind(&source.output_name)
            .bind(source.content_digest.as_str()).bind(source.manifest_digest.as_str()).bind(source.provenance_digest.as_str()).bind(i64::try_from(source.size_bytes).unwrap())
            .bind(&source.media_type).bind(&source.classification).bind(&source.scan_state).bind(i64::try_from(source.retention_until_unix_seconds).unwrap()).bind(&source.state).bind(i64::try_from(source.created_unix_ms).unwrap())
            .execute(store.pool()).await.unwrap();

        cache_contract(&store, &tenant, &repository, &run, &job, &suffix).await;
        artifact_scan_promotion_contract(&store, &source, &suffix).await;

        let identity = ContentDigest::sha256(format!("race-identity-{suffix}"));
        let base = CacheTrustGenerationRecord {
            cache_entry_id: format!("race-a-{suffix}"),
            tenant_id: tenant.clone(),
            repository_id: repository.clone(),
            identity_digest: identity.clone(),
            key_material_digest: ContentDigest::sha256(format!("race-key-{suffix}")),
            key_material: serde_json::json!({"purpose":"race"}),
            trust_domain: serde_json::json!({"kind":"verified"}),
            generation: 1,
            manifest_digest: ContentDigest::sha256(format!("race-manifest-a-{suffix}")),
            tree_manifest_digest: ContentDigest::sha256(format!("race-tree-{suffix}")),
            fencing_generation: 1,
            source_cache_entry_id: None,
            promotion_evidence_digest: None,
            created_unix_ms: 20,
        };
        let competing = CacheTrustGenerationRecord {
            cache_entry_id: format!("race-b-{suffix}"),
            manifest_digest: ContentDigest::sha256(format!("race-manifest-b-{suffix}")),
            ..base.clone()
        };
        let (first, second) = tokio::join!(
            store.record_cache_trust_generation(&base, None),
            store.record_cache_trust_generation(&competing, None)
        );
        assert!(matches!(
            (&first, &second),
            (Ok(false), Err(ControlPlaneError::IdempotencyConflict))
                | (Err(ControlPlaneError::IdempotencyConflict), Ok(false))
        ));
        let generations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cache_trust_generations WHERE identity_digest=$1",
        )
        .bind(identity.as_str())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(generations, 1);
        store.close().await;
        fixture.cleanup().await;
    }
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;
    use crate::{TenantIdentityRecord, TenantIdentityStore};

    #[tokio::test]
    async fn postgres_storage_accounting_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "storage-accounting").await;
        let store =
            PostgresInstallationStore::connect(fixture.config(), "artifact-storage-contract", 1)
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
        let tenant = format!("storage-{suffix}");
        store
            .put_tenant_identity(
                &TenantIdentityRecord {
                    id: tenant.clone(),
                    slug: tenant.clone(),
                    name: "Storage contract".to_owned(),
                    status: "active".to_owned(),
                    settings: serde_json::json!({}),
                    created_unix_ms: 1,
                    updated_unix_ms: 1,
                    version: 1,
                },
                None,
            )
            .await
            .unwrap();
        let quota = TenantStorageQuota {
            tenant_id: tenant.clone(),
            maximum_stored_bytes: 10,
            maximum_object_count: 1,
            updated_unix_ms: 2,
        };
        ArtifactStorageStore::set_tenant_storage_quota(&store, &quota)
            .await
            .unwrap();
        let reservation = TenantStorageReservation {
            id: format!("reservation-{suffix}"),
            tenant_id: tenant.clone(),
            ticket_kind: "artifact".to_owned(),
            object_digest: None,
            reserved_bytes: 10,
            reserved_objects: 1,
            state: StorageReservationState::Reserved,
            created_unix_ms: 3,
            expires_unix_ms: 100,
            completed_unix_ms: None,
        };
        assert!(
            !ArtifactStorageStore::reserve_tenant_storage(&store, &reservation, 4)
                .await
                .unwrap()
        );
        assert!(
            ArtifactStorageStore::reserve_tenant_storage(&store, &reservation, 4)
                .await
                .unwrap()
        );
        let substitution = TenantStorageReservation {
            reserved_bytes: 9,
            ..reservation.clone()
        };
        assert!(matches!(
            ArtifactStorageStore::reserve_tenant_storage(&store, &substitution, 4).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let overflow = TenantStorageReservation {
            id: format!("overflow-{suffix}"),
            ..reservation.clone()
        };
        assert!(matches!(
            ArtifactStorageStore::reserve_tenant_storage(&store, &overflow, 4).await,
            Err(ControlPlaneError::StorageQuotaExceeded)
        ));

        let binding = StorageTicketBinding {
            reservation_id: reservation.id.clone(),
            tenant_id: tenant.clone(),
            ticket_kind: "artifact".to_owned(),
            ticket_id: format!("ticket-{suffix}"),
            object_id: None,
            actual_bytes: None,
            actual_objects: None,
            state: StorageTicketBindingState::Issued,
            created_unix_ms: 5,
            updated_unix_ms: 5,
            completed_unix_ms: None,
        };
        assert!(
            !ArtifactStorageStore::bind_tenant_storage_ticket(&store, &binding, 5)
                .await
                .unwrap()
        );
        assert!(
            ArtifactStorageStore::bind_tenant_storage_ticket(&store, &binding, 5)
                .await
                .unwrap()
        );
        let object = format!("artifact-{suffix}");
        assert!(!ArtifactStorageStore::commit_tenant_storage_ticket(
            &store,
            &tenant,
            &binding.ticket_id,
            &object,
            8,
            1,
            6,
        )
        .await
        .unwrap());
        assert!(ArtifactStorageStore::commit_tenant_storage_ticket(
            &store,
            &tenant,
            &binding.ticket_id,
            &object,
            8,
            1,
            6,
        )
        .await
        .unwrap());
        assert!(!ArtifactStorageStore::account_tenant_storage_ticket(
            &store,
            &tenant,
            &binding.ticket_id,
            &object,
            7,
        )
        .await
        .unwrap());
        assert!(ArtifactStorageStore::account_tenant_storage_ticket(
            &store,
            &tenant,
            &binding.ticket_id,
            &object,
            7,
        )
        .await
        .unwrap());
        assert_eq!(
            ArtifactStorageStore::tenant_storage_usage(&store, &tenant)
                .await
                .unwrap(),
            TenantStorageUsage {
                tenant_id: tenant.clone(),
                active_bytes: 8,
                active_objects: 1,
                reserved_bytes: 0,
                reserved_objects: 0,
            }
        );

        let repository = format!("repository-{suffix}");
        let capsule = format!("capsule-{suffix}");
        let run = format!("run-{suffix}");
        let job = format!("job-{suffix}");
        let pool = format!("pool-{suffix}");
        let runner = format!("runner-{suffix}");
        let lease = format!("lease-{suffix}");
        let zero = ContentDigest::sha256([]);
        sqlx::query("INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms) VALUES($1,$2,$3,$4,'main','private',1)")
            .bind(&repository).bind(&tenant).bind(format!("owner-{suffix}")).bind(format!("repo-{suffix}")).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES($1,$2,$3,$4,$5,'key',1)")
            .bind(&capsule).bind(&repository).bind(zero.as_str()).bind([0_u8].as_slice()).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES($1,$2,$3,'completed',0,TRUE,1)")
            .bind(&run).bind(&repository).bind(&capsule).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms) VALUES($1,$2,'build',1,'completed',$3,1)")
            .bind(&job).bind(&run).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES($1,$2,$3,'active',1)")
            .bind(&pool).bind(&tenant).bind(format!("pool-{suffix}")).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES($1,$2,'offline',$3,1,1)")
            .bind(&runner).bind(&pool).bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES($1,$2,$3,$4,1,1,$5,'completed',1,2,3,4)")
            .bind(&lease).bind(&job).bind(&tenant).bind(&runner).bind(zero.as_str()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runner_data_commits(kind,object_id,tenant_id,repository_id,run_id,job_id,job_attempt,step_id,output_name,lease_id,fencing_generation,ticket_id,committed_unix_ms) VALUES('artifact',$1,$2,$3,$4,$5,1,'step','output',$6,1,$7,7)")
            .bind(&object).bind(&tenant).bind(&repository).bind(&run).bind(&job).bind(&lease).bind(&binding.ticket_id).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO job_result_objects(job_id,job_attempt,kind,object_id,ordinal) VALUES($1,1,'artifact',$2,0)")
            .bind(&job).bind(&object).execute(store.pool()).await.unwrap();
        let artifact = ArtifactCatalogRecord {
            artifact_id: object.clone(),
            tenant_id: tenant.clone(),
            repository_id: repository,
            run_id: run,
            job_id: job,
            job_attempt: 1,
            step_id: "step".to_owned(),
            output_name: "output".to_owned(),
            content_digest: zero.clone(),
            manifest_digest: zero.clone(),
            provenance_digest: zero.clone(),
            size_bytes: 8,
            media_type: "application/octet-stream".to_owned(),
            classification: "internal".to_owned(),
            scan_state: "passed".to_owned(),
            retention_until_unix_seconds: 100,
            legal_hold: false,
            state: "available".to_owned(),
            created_unix_ms: 7,
        };
        assert!(
            !ArtifactCatalogStore::catalog_artifact(&store, &artifact)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            ArtifactCatalogStore::catalog_artifact(&store, &artifact)
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(
            ArtifactCatalogStore::artifact_for_tenant(&store, &tenant, &object)
                .await
                .unwrap(),
            artifact
        );
        let download = ArtifactDownloadTicketRecord {
            token_hash: ContentDigest::sha256(b"download"),
            artifact_id: object,
            tenant_id: tenant.clone(),
            principal_id: "principal".to_owned(),
            classification: "internal".to_owned(),
            manifest_digest: zero,
            issued_unix_ms: 10,
            expires_unix_ms: 100,
            used_unix_ms: None,
        };
        assert!(
            !ArtifactCatalogStore::issue_artifact_download_ticket(&store, &download)
                .await
                .unwrap()
                .replayed
        );
        assert!(
            ArtifactCatalogStore::issue_artifact_download_ticket(&store, &download)
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(
            ArtifactCatalogStore::consume_artifact_download_ticket(
                &store,
                &download.token_hash,
                Some(&tenant),
                "principal",
                11
            )
            .await
            .unwrap()
            .used_unix_ms,
            Some(11)
        );
        assert_eq!(
            ArtifactCatalogStore::artifact_metrics(&store, &tenant)
                .await
                .unwrap()
                .download_tickets_consumed,
            1
        );
        store.close().await;
        fixture.cleanup().await;
    }
}
