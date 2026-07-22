use super::StoreFuture;
use crate::ControlPlaneError;
#[cfg(feature = "postgres")]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use runtrue_secrets::ExternalSecretReleaseState;
use runtrue_secrets::{
    ExternalSecretBrokerError, ExternalSecretLeaseMetadata, ExternalSecretReleaseJournalEntry,
    ExternalSecretReleaseReservation, ExternalSecretReserveOutcome, ExternalSecretRevokeOutcome,
};

/// Plaintext-free external-secret release journal boundary. Authorization
/// creates the exact reservation; this store atomically verifies its durable
/// provider, secret, repository, run/job, runner, and lease lineage.
pub trait ExternalSecretReleaseStore: Send + Sync {
    fn reserve_external_release<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretReserveOutcome>;
    fn mark_external_release_delivered<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        metadata: &'a ExternalSecretLeaseMetadata,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry>;
    fn mark_external_release_indeterminate<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        metadata: Option<&'a ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry>;
    fn external_release<'a>(
        &'a self,
        release_id: &'a str,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry>;
    fn begin_external_release_revoke<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretRevokeOutcome>;
    fn mark_external_release_revoked<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        revoked_unix_ms: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry>;
}

fn embedded_error(error: ExternalSecretBrokerError) -> ControlPlaneError {
    match error {
        ExternalSecretBrokerError::SubjectConflict => ControlPlaneError::IdempotencyConflict,
        ExternalSecretBrokerError::IndeterminateRecoveryRequired => {
            ControlPlaneError::InvalidTransition {
                entity: "external release",
                from: "indeterminate",
                to: "automatic recovery",
            }
        }
        _ => ControlPlaneError::CorruptState(format!(
            "external secret release journal rejected operation: {error}"
        )),
    }
}

impl ExternalSecretReleaseStore for crate::ControlPlane {
    fn reserve_external_release<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretReserveOutcome> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::reserve(self, reservation)
            .map_err(embedded_error);
        Box::pin(async move { result })
    }

    fn mark_external_release_delivered<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        metadata: &'a ExternalSecretLeaseMetadata,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::mark_delivered(
            self,
            reservation,
            metadata,
        )
        .and_then(|()| {
            runtrue_secrets::ExternalSecretReleaseJournal::load(self, &reservation.release_id)
        })
        .map_err(embedded_error);
        Box::pin(async move { result })
    }

    fn mark_external_release_indeterminate<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        metadata: Option<&'a ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::mark_indeterminate(
            self,
            reservation,
            metadata,
            observed_unix_ms,
        )
        .and_then(|()| {
            runtrue_secrets::ExternalSecretReleaseJournal::load(self, &reservation.release_id)
        })
        .map_err(embedded_error);
        Box::pin(async move { result })
    }

    fn external_release<'a>(
        &'a self,
        release_id: &'a str,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::load(self, release_id)
            .map_err(embedded_error);
        Box::pin(async move { result })
    }

    fn begin_external_release_revoke<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretRevokeOutcome> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::begin_revoke(self, reservation)
            .map_err(embedded_error);
        Box::pin(async move { result })
    }

    fn mark_external_release_revoked<'a>(
        &'a self,
        reservation: &'a ExternalSecretReleaseReservation,
        revoked_unix_ms: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        let result = runtrue_secrets::ExternalSecretReleaseJournal::mark_revoked(
            self,
            reservation,
            revoked_unix_ms,
        )
        .and_then(|()| {
            runtrue_secrets::ExternalSecretReleaseJournal::load(self, &reservation.release_id)
        })
        .map_err(embedded_error);
        Box::pin(async move { result })
    }
}

#[cfg(feature = "postgres")]
use super::PostgresInstallationStore;
#[cfg(feature = "postgres")]
use sqlx::{Postgres, Row as _, Transaction};

#[cfg(feature = "postgres")]
const COLUMNS: &str = "release_id,release_subject_digest,provider_configuration_id,
     provider_configuration_digest,provider_configuration_version,
     provider_reference_digest,tenant_id,repository_id,run_id,runner_id,
     execution_lease_id,fencing_generation,installation_fencing_epoch,
     job_id,job_attempt,step_id,secret_metadata_id,purpose,reservation_json,
     state,provider_metadata_json,provider_metadata_digest,transition_attempts,
     expires_unix_ms,created_unix_ms,updated_unix_ms,revoked_unix_ms,reservation_digest";

#[cfg(feature = "postgres")]
fn i64v(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

#[cfg(feature = "postgres")]
fn u64v(value: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(value).map_err(|_| ControlPlaneError::CorruptState(format!("negative {field}")))
}

#[cfg(feature = "postgres")]
fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ControlPlaneError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 256 * 1024 {
        return Err(ControlPlaneError::InvalidInput(
            "external release journal value exceeds its bound",
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "postgres")]
fn reservation_digest(bytes: &[u8]) -> ContentDigest {
    let mut material = b"runtrue.external-release-reservation.v1\0".to_vec();
    material.extend_from_slice(bytes);
    ContentDigest::sha256(material)
}

#[cfg(feature = "postgres")]
fn metadata_matches(
    metadata: &ExternalSecretLeaseMetadata,
    reservation: &ExternalSecretReleaseReservation,
) -> bool {
    metadata.release_id == reservation.release_id
        && metadata.release_subject_digest == reservation.release_subject_digest
        && metadata.provider == reservation.provider_id
        && metadata.tenant_id == reservation.tenant_id
        && metadata.repository_id == reservation.repository_id
        && metadata.run_id == reservation.run_id
        && metadata.runner_id == reservation.runner_id
        && metadata.secret_metadata_id == reservation.secret_metadata_id
        && metadata.execution_lease_id == reservation.execution_lease_id
        && metadata.fencing_generation == reservation.fencing_generation
        && metadata.installation_fencing_epoch == reservation.installation_fencing_epoch
        && metadata.job_id == reservation.job_id
        && metadata.job_attempt == reservation.job_attempt
        && metadata.step_id == reservation.step_id
        && metadata.purpose == reservation.purpose
        && metadata.expires_unix_ms <= reservation.expires_unix_ms
}

#[cfg(feature = "postgres")]
fn decode_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ExternalSecretReleaseJournalEntry, ControlPlaneError> {
    let reservation_bytes: Vec<u8> = row.try_get("reservation_json")?;
    let reservation: ExternalSecretReleaseReservation = serde_json::from_slice(&reservation_bytes)?;
    if canonical(&reservation)? != reservation_bytes
        || reservation_digest(&reservation_bytes).as_str()
            != row.try_get::<String, _>("reservation_digest")?
    {
        return Err(ControlPlaneError::CorruptState(
            "external release reservation digest changed".to_owned(),
        ));
    }
    let state_name: String = row.try_get("state")?;
    let state_bytes: Option<Vec<u8>> = row.try_get("provider_metadata_json")?;
    let state = match (state_name.as_str(), state_bytes) {
        ("reserved", None) => ExternalSecretReleaseState::Reserved,
        (name, Some(bytes)) => {
            let state: ExternalSecretReleaseState = serde_json::from_slice(&bytes)?;
            let digest = ContentDigest::sha256(&bytes);
            if canonical(&state)? != bytes
                || row
                    .try_get::<Option<String>, _>("provider_metadata_digest")?
                    .as_deref()
                    != Some(digest.as_str())
                || !matches!(
                    (name, &state),
                    ("delivered", ExternalSecretReleaseState::Delivered { .. })
                        | ("revoking", ExternalSecretReleaseState::Revoking { .. })
                        | ("revoked", ExternalSecretReleaseState::Revoked { .. })
                        | (
                            "indeterminate",
                            ExternalSecretReleaseState::Indeterminate { .. }
                        )
                )
            {
                return Err(ControlPlaneError::CorruptState(
                    "external release state digest changed".to_owned(),
                ));
            }
            state
        }
        _ => {
            return Err(ControlPlaneError::CorruptState(
                "invalid external release state".to_owned(),
            ))
        }
    };
    let exact = reservation.release_id == row.try_get::<String, _>("release_id")?
        && reservation.release_subject_digest.as_str()
            == row.try_get::<String, _>("release_subject_digest")?
        && reservation.provider_id == row.try_get::<String, _>("provider_configuration_id")?
        && reservation.provider_reference_digest.as_str()
            == row.try_get::<String, _>("provider_reference_digest")?
        && reservation.tenant_id == row.try_get::<String, _>("tenant_id")?
        && reservation.repository_id == row.try_get::<String, _>("repository_id")?
        && reservation.run_id == row.try_get::<String, _>("run_id")?
        && reservation.runner_id == row.try_get::<String, _>("runner_id")?
        && reservation.execution_lease_id == row.try_get::<String, _>("execution_lease_id")?
        && reservation.fencing_generation
            == u64v(row.try_get("fencing_generation")?, "external release fence")?
        && reservation.installation_fencing_epoch
            == u64v(
                row.try_get("installation_fencing_epoch")?,
                "external release epoch",
            )?
        && reservation.job_id == row.try_get::<String, _>("job_id")?
        && reservation.job_attempt
            == u32::try_from(row.try_get::<i32, _>("job_attempt")?).map_err(|_| {
                ControlPlaneError::CorruptState("negative external release attempt".to_owned())
            })?
        && reservation.step_id == row.try_get::<String, _>("step_id")?
        && reservation.secret_metadata_id == row.try_get::<String, _>("secret_metadata_id")?
        && reservation.purpose == row.try_get::<String, _>("purpose")?
        && reservation.expires_unix_ms
            == u64v(row.try_get("expires_unix_ms")?, "external release expiry")?;
    let revoked = row
        .try_get::<Option<i64>, _>("revoked_unix_ms")?
        .map(|v| u64v(v, "external release revocation"))
        .transpose()?;
    if !exact
        || row.try_get::<i32, _>("transition_attempts")? > 8
        || match &state {
            ExternalSecretReleaseState::Revoked {
                revoked_unix_ms, ..
            } => Some(*revoked_unix_ms) != revoked,
            _ => revoked.is_some(),
        }
    {
        return Err(ControlPlaneError::CorruptState(
            "external release durable columns changed".to_owned(),
        ));
    }
    Ok(ExternalSecretReleaseJournalEntry { reservation, state })
}

#[cfg(feature = "postgres")]
async fn load_tx(
    tx: &mut Transaction<'_, Postgres>,
    release_id: &str,
    lock: bool,
) -> Result<Option<ExternalSecretReleaseJournalEntry>, ControlPlaneError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM external_secret_release_journal WHERE release_id=$1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = sqlx::query(&sql)
        .bind(release_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let entry = decode_row(&row)?;
    let snapshot: Option<(String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT j.provider_configuration_digest,j.provider_configuration_version,v.snapshot_json
         FROM external_secret_release_journal j
         JOIN tenant_provider_configuration_versions v
           ON v.tenant_id=j.tenant_id
          AND v.provider_configuration_id=j.provider_configuration_id
          AND v.version=j.provider_configuration_version
         WHERE j.release_id=$1",
    )
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((stored_digest, stored_version, bytes)) = snapshot else {
        return Err(ControlPlaneError::CorruptState(
            "external release provider snapshot disappeared".to_owned(),
        ));
    };
    let provider: crate::TenantProviderConfiguration = serde_json::from_slice(&bytes)?;
    crate::store::validate_provider_configuration(&provider)?;
    if provider.tenant_id != entry.reservation.tenant_id
        || provider.id != entry.reservation.provider_id
        || provider.configuration_digest.as_str() != stored_digest
        || i64v(provider.version, "provider version")? != stored_version
    {
        return Err(ControlPlaneError::CorruptState(
            "external release provider version binding changed".to_owned(),
        ));
    }
    Ok(Some(entry))
}

#[cfg(feature = "postgres")]
type ExternalReleaseStateParts = (&'static str, Option<Vec<u8>>, Option<String>);

#[cfg(feature = "postgres")]
fn state_parts(
    state: &ExternalSecretReleaseState,
) -> Result<ExternalReleaseStateParts, ControlPlaneError> {
    if matches!(state, ExternalSecretReleaseState::Reserved) {
        return Ok(("reserved", None, None));
    }
    let name = match state {
        ExternalSecretReleaseState::Delivered { .. } => "delivered",
        ExternalSecretReleaseState::Revoking { .. } => "revoking",
        ExternalSecretReleaseState::Revoked { .. } => "revoked",
        ExternalSecretReleaseState::Indeterminate { .. } => "indeterminate",
        ExternalSecretReleaseState::Reserved => unreachable!(),
    };
    let bytes = canonical(state)?;
    let digest = ContentDigest::sha256(&bytes).to_string();
    Ok((name, Some(bytes), Some(digest)))
}

#[cfg(feature = "postgres")]
async fn transition(
    store: &PostgresInstallationStore,
    reservation: &ExternalSecretReleaseReservation,
    next: &ExternalSecretReleaseState,
    expected: &str,
    observed_unix_ms: u64,
) -> Result<ExternalSecretReleaseJournalEntry, ControlPlaneError> {
    let (name, bytes, digest) = state_parts(next)?;
    let mut tx = store.pool().begin().await?;
    let old = load_tx(&mut tx, &reservation.release_id, true)
        .await?
        .ok_or_else(|| ControlPlaneError::NotFound {
            kind: "external release",
            id: reservation.release_id.clone(),
        })?;
    if old.reservation != *reservation {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    if old.state == *next {
        tx.commit().await?;
        return Ok(old);
    }
    let changed = sqlx::query(
        "UPDATE external_secret_release_journal
         SET state=$2,provider_metadata_json=$3,provider_metadata_digest=$4,
             transition_attempts=transition_attempts+1,
             updated_unix_ms=GREATEST(updated_unix_ms,$5),
             revoked_unix_ms=CASE WHEN $2='revoked' THEN $5 ELSE revoked_unix_ms END
         WHERE release_id=$1 AND state=$6 AND transition_attempts<8",
    )
    .bind(&reservation.release_id)
    .bind(name)
    .bind(bytes)
    .bind(digest)
    .bind(i64v(observed_unix_ms, "external release observation")?)
    .bind(expected)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let value = load_tx(&mut tx, &reservation.release_id, false)
        .await?
        .ok_or_else(|| {
            ControlPlaneError::CorruptState("external release disappeared".to_owned())
        })?;
    tx.commit().await?;
    Ok(value)
}

#[cfg(feature = "postgres")]
impl ExternalSecretReleaseStore for PostgresInstallationStore {
    fn reserve_external_release<'a>(
        &'a self,
        r: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretReserveOutcome> {
        Box::pin(async move {
            let bytes = canonical(r)?;
            let digest = reservation_digest(&bytes);
            let mut tx = self.pool().begin().await?;
            if let Some(old) = load_tx(&mut tx, &r.release_id, true).await? {
                if old.reservation == *r {
                    tx.commit().await?;
                    return Ok(ExternalSecretReserveOutcome {
                        created: false,
                        entry: old,
                    });
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            // Lock the current provider row, then bind its immutable snapshot.
            let provider = sqlx::query(
                "SELECT configuration_digest,version FROM tenant_provider_configurations
                 WHERE tenant_id=$1 AND id=$2 AND capability='external-secret' AND status='active'
                 FOR SHARE",
            )
            .bind(&r.tenant_id)
            .bind(&r.provider_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
            let provider_version = u64v(provider.try_get("version")?, "provider version")?;
            let (provider_digest, exact_version) =
                validate_lineage_current(&mut tx, r, provider_version).await?;
            if exact_version != provider_version
                || provider_digest != provider.try_get::<String, _>("configuration_digest")?
            {
                return Err(ControlPlaneError::EnvironmentGateNotReady);
            }
            let created: i64 = sqlx::query_scalar("SELECT issued_unix_ms FROM leases WHERE id=$1")
                .bind(&r.execution_lease_id)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO external_secret_release_journal
                 (release_id,release_subject_digest,provider_configuration_id,
                  provider_configuration_digest,provider_configuration_version,
                  provider_reference_digest,tenant_id,repository_id,run_id,runner_id,
                  execution_lease_id,fencing_generation,installation_fencing_epoch,
                  job_id,job_attempt,step_id,secret_metadata_id,purpose,reservation_json,
                  state,transition_attempts,expires_unix_ms,created_unix_ms,updated_unix_ms,
                  reservation_digest)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                        $19,'reserved',0,$20,$21,$21,$22)",
            )
            .bind(&r.release_id)
            .bind(r.release_subject_digest.as_str())
            .bind(&r.provider_id)
            .bind(&provider_digest)
            .bind(i64v(provider_version, "provider version")?)
            .bind(r.provider_reference_digest.as_str())
            .bind(&r.tenant_id)
            .bind(&r.repository_id)
            .bind(&r.run_id)
            .bind(&r.runner_id)
            .bind(&r.execution_lease_id)
            .bind(i64v(r.fencing_generation, "lease fence")?)
            .bind(i64v(r.installation_fencing_epoch, "installation epoch")?)
            .bind(&r.job_id)
            .bind(
                i32::try_from(r.job_attempt).map_err(|_| ControlPlaneError::IntegerRange {
                    field: "job attempt",
                })?,
            )
            .bind(&r.step_id)
            .bind(&r.secret_metadata_id)
            .bind(&r.purpose)
            .bind(bytes)
            .bind(i64v(r.expires_unix_ms, "release expiry")?)
            .bind(created)
            .bind(digest.as_str())
            .execute(&mut *tx)
            .await?;
            let entry = load_tx(&mut tx, &r.release_id, false)
                .await?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState("external release disappeared".to_owned())
                })?;
            tx.commit().await?;
            Ok(ExternalSecretReserveOutcome {
                created: true,
                entry,
            })
        })
    }

    fn mark_external_release_delivered<'a>(
        &'a self,
        r: &'a ExternalSecretReleaseReservation,
        m: &'a ExternalSecretLeaseMetadata,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        Box::pin(async move {
            if !metadata_matches(m, r) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transition(
                self,
                r,
                &ExternalSecretReleaseState::Delivered {
                    provider_metadata: m.clone(),
                },
                "reserved",
                0,
            )
            .await
        })
    }

    fn mark_external_release_indeterminate<'a>(
        &'a self,
        r: &'a ExternalSecretReleaseReservation,
        m: Option<&'a ExternalSecretLeaseMetadata>,
        observed: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        Box::pin(async move {
            if m.is_some_and(|v| !metadata_matches(v, r)) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transition(
                self,
                r,
                &ExternalSecretReleaseState::Indeterminate {
                    provider_metadata: m.cloned(),
                    observed_unix_ms: observed,
                },
                "reserved",
                observed,
            )
            .await
        })
    }

    fn external_release<'a>(
        &'a self,
        id: &'a str,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        Box::pin(async move {
            let mut tx = self.pool().begin().await?;
            let value =
                load_tx(&mut tx, id, false)
                    .await?
                    .ok_or_else(|| ControlPlaneError::NotFound {
                        kind: "external release",
                        id: id.to_owned(),
                    })?;
            tx.commit().await?;
            Ok(value)
        })
    }

    fn begin_external_release_revoke<'a>(
        &'a self,
        r: &'a ExternalSecretReleaseReservation,
    ) -> StoreFuture<'a, ExternalSecretRevokeOutcome> {
        Box::pin(async move {
            let current = self.external_release(&r.release_id).await?;
            if current.reservation != *r {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            match current.state {
                ExternalSecretReleaseState::Revoking { .. } => Ok(ExternalSecretRevokeOutcome {
                    started: false,
                    entry: current,
                }),
                ExternalSecretReleaseState::Delivered {
                    ref provider_metadata,
                } => {
                    let entry = transition(
                        self,
                        r,
                        &ExternalSecretReleaseState::Revoking {
                            provider_metadata: provider_metadata.clone(),
                        },
                        "delivered",
                        0,
                    )
                    .await?;
                    Ok(ExternalSecretRevokeOutcome {
                        started: true,
                        entry,
                    })
                }
                _ => Err(ControlPlaneError::InvalidTransition {
                    entity: "external release",
                    from: "not-delivered",
                    to: "revoking",
                }),
            }
        })
    }

    fn mark_external_release_revoked<'a>(
        &'a self,
        r: &'a ExternalSecretReleaseReservation,
        revoked: u64,
    ) -> StoreFuture<'a, ExternalSecretReleaseJournalEntry> {
        Box::pin(async move {
            let current = self.external_release(&r.release_id).await?;
            if current.reservation != *r {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            match current.state {
                ExternalSecretReleaseState::Revoked {
                    revoked_unix_ms, ..
                } if revoked_unix_ms == revoked => Ok(current),
                ExternalSecretReleaseState::Revoking { provider_metadata } => {
                    transition(
                        self,
                        r,
                        &ExternalSecretReleaseState::Revoked {
                            provider_metadata,
                            revoked_unix_ms: revoked,
                        },
                        "revoking",
                        revoked,
                    )
                    .await
                }
                _ => Err(ControlPlaneError::InvalidTransition {
                    entity: "external release",
                    from: "not-revoking",
                    to: "revoked",
                }),
            }
        })
    }
}

#[cfg(feature = "postgres")]
async fn validate_lineage_current(
    tx: &mut Transaction<'_, Postgres>,
    reservation: &ExternalSecretReleaseReservation,
    provider_version: u64,
) -> Result<(String, u64), ControlPlaneError> {
    // Same exact validation as validate_lineage, with the locked current
    // provider version supplied by reserve rather than caller-controlled data.
    let state = sqlx::query(
        "SELECT fencing_epoch,safe_mode FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut **tx)
    .await?;
    if state.try_get::<bool, _>("safe_mode")? {
        return Err(ControlPlaneError::InstallationSafeMode);
    }
    if u64v(state.try_get("fencing_epoch")?, "installation epoch")?
        != reservation.installation_fencing_epoch
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    let row = sqlx::query(
        "SELECT p.version,p.snapshot_json,s.provider,s.provider_reference,s.status,
                l.runner_id,l.fencing_generation,l.installation_fencing_epoch,l.state,l.issued_unix_ms,
                l.expires_unix_ms,l.hard_deadline_unix_ms,j.id AS durable_job,j.run_id,j.attempt,
                r.repository_id,repo.tenant_id,pool.tenant_id AS runner_tenant
         FROM tenant_provider_configuration_versions p
         JOIN secret_metadata s ON s.tenant_id=p.tenant_id AND s.id=$3
         JOIN leases l ON l.tenant_id=p.tenant_id AND l.id=$4
         JOIN jobs j ON j.id=l.job_id JOIN runs r ON r.id=j.run_id
         JOIN repositories repo ON repo.id=r.repository_id JOIN runners rr ON rr.id=l.runner_id
         JOIN runner_pools pool ON pool.id=rr.pool_id
         WHERE p.tenant_id=$1 AND p.provider_configuration_id=$2 AND p.version=$5 FOR SHARE OF p,s,l,j,r,repo,rr,pool",
    ).bind(&reservation.tenant_id).bind(&reservation.provider_id).bind(&reservation.secret_metadata_id)
      .bind(&reservation.execution_lease_id).bind(i64v(provider_version,"provider version")?)
      .fetch_optional(&mut **tx).await?.ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    let snapshot: Vec<u8> = row.try_get("snapshot_json")?;
    let provider: crate::TenantProviderConfiguration = serde_json::from_slice(&snapshot)?;
    crate::store::validate_provider_configuration(&provider)?;
    let reference: Option<String> = row.try_get("provider_reference")?;
    if provider.tenant_id != reservation.tenant_id
        || provider.id != reservation.provider_id
        || provider.capability != "external-secret"
        || provider.status != "active"
        || provider.version != provider_version
        || row.try_get::<String, _>("provider")? != reservation.provider_id
        || row.try_get::<String, _>("status")? != "active"
        || reference
            .as_ref()
            .map(|v| ContentDigest::sha256(v.as_bytes()))
            != Some(reservation.provider_reference_digest.clone())
        || row.try_get::<String, _>("runner_id")? != reservation.runner_id
        || u64v(row.try_get("fencing_generation")?, "lease fence")?
            != reservation.fencing_generation
        || u64v(row.try_get("installation_fencing_epoch")?, "lease epoch")?
            != reservation.installation_fencing_epoch
        || row.try_get::<String, _>("state")? != "active"
        || row.try_get::<String, _>("durable_job")? != reservation.job_id
        || row.try_get::<String, _>("run_id")? != reservation.run_id
        || row.try_get::<i32, _>("attempt")? != i32::try_from(reservation.job_attempt).unwrap_or(-1)
        || row.try_get::<String, _>("repository_id")? != reservation.repository_id
        || row.try_get::<String, _>("tenant_id")? != reservation.tenant_id
        || row.try_get::<String, _>("runner_tenant")? != reservation.tenant_id
        || reservation.expires_unix_ms <= u64v(row.try_get("issued_unix_ms")?, "lease issue")?
        || reservation.expires_unix_ms > u64v(row.try_get("expires_unix_ms")?, "lease expiry")?
        || reservation.expires_unix_ms
            > u64v(row.try_get("hard_deadline_unix_ms")?, "lease deadline")?
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok((provider.configuration_digest.to_string(), provider.version))
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;
    use crate::{DeploymentProviderStore, TenantProviderConfiguration};

    #[tokio::test]
    async fn postgres_external_release_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = super::super::PostgresTestSchema::create(&url, "external-release").await;
        let store = PostgresInstallationStore::connect(fixture.config(), "external-release", 1)
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO tenants(id,slug,name,status,settings_json,created_unix_ms,updated_unix_ms,version)
             VALUES('external-tenant','external-tenant','External','active','{}',1,1,1);
             INSERT INTO repositories(id,tenant_id,owner,name,default_branch,visibility,created_unix_ms)
             VALUES('external-repo','external-tenant','owner','repo','main','private',2);
             INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms)
             VALUES('external-pool','external-tenant','pool','active',3);
             INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms)
             VALUES('external-runner','external-pool','online','{}',4,4);
             INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms)
             VALUES('external-capsule','external-repo','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}','{}','key',5);
             INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms)
             VALUES('external-run','external-repo','external-capsule','running',0,TRUE,6);
             INSERT INTO jobs(id,run_id,job_key,attempt,status,requirements_json,created_unix_ms)
             VALUES('external-job','external-run','job',1,'running','{}',7);
             INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,
                installation_fencing_epoch,capsule_digest,state,issued_unix_ms,
                accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms)
             VALUES('external-lease','external-job','external-tenant','external-runner',1,1,
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'active',10,20,1000,1000);",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let mut provider = TenantProviderConfiguration {
            id: "external-provider".into(),
            tenant_id: "external-tenant".into(),
            capability: "external-secret".into(),
            provider_kind: "vault".into(),
            endpoint_origin: "https://vault.example.test".into(),
            credential_reference: "secret-metadata://credential".into(),
            trust_bundle_digest: ContentDigest::sha256(b"trust"),
            public_key_digest: None,
            configuration_digest: ContentDigest::sha256([]),
            status: "active".into(),
            created_unix_ms: 8,
            updated_unix_ms: 8,
            version: 1,
        };
        provider.configuration_digest = provider.expected_configuration_digest().unwrap();
        assert!(store.put_provider(&provider, None).await.unwrap());
        sqlx::query(
            "INSERT INTO secret_metadata
             (id,tenant_id,scope,name,provider,provider_reference,secret_type,status,
              current_version,created_unix_ms,updated_unix_ms)
             VALUES('external-secret','external-tenant','repository:external-repo','TOKEN',
                    'external-provider','secret/path','string','active',1,9,9)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let reservation = ExternalSecretReleaseReservation {
            release_id: "external-release".into(),
            release_subject_digest: ContentDigest::sha256(b"subject"),
            provider_id: provider.id.clone(),
            provider_reference_digest: ContentDigest::sha256(b"secret/path"),
            tenant_id: "external-tenant".into(),
            repository_id: "external-repo".into(),
            run_id: "external-run".into(),
            runner_id: "external-runner".into(),
            execution_lease_id: "external-lease".into(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            job_id: "external-job".into(),
            job_attempt: 1,
            step_id: "step".into(),
            secret_metadata_id: "external-secret".into(),
            purpose: "deploy".into(),
            expires_unix_ms: 900,
        };
        let created = store.reserve_external_release(&reservation).await.unwrap();
        assert!(created.created);
        assert!(
            !store
                .reserve_external_release(&reservation)
                .await
                .unwrap()
                .created
        );
        let mut indeterminate_reservation = reservation.clone();
        indeterminate_reservation.release_id = "external-release-indeterminate".into();
        indeterminate_reservation.release_subject_digest = ContentDigest::sha256(b"subject-2");
        store
            .reserve_external_release(&indeterminate_reservation)
            .await
            .unwrap();
        let indeterminate = store
            .mark_external_release_indeterminate(&indeterminate_reservation, None, 50)
            .await
            .unwrap();
        assert!(matches!(
            indeterminate.state,
            ExternalSecretReleaseState::Indeterminate {
                observed_unix_ms: 50,
                ..
            }
        ));
        let mut metadata = ExternalSecretLeaseMetadata {
            release_id: reservation.release_id.clone(),
            release_subject_digest: reservation.release_subject_digest.clone(),
            provider: reservation.provider_id.clone(),
            tenant_id: reservation.tenant_id.clone(),
            repository_id: reservation.repository_id.clone(),
            run_id: reservation.run_id.clone(),
            runner_id: reservation.runner_id.clone(),
            secret_metadata_id: reservation.secret_metadata_id.clone(),
            execution_lease_id: reservation.execution_lease_id.clone(),
            fencing_generation: 1,
            installation_fencing_epoch: 1,
            job_id: reservation.job_id.clone(),
            job_attempt: 1,
            step_id: reservation.step_id.clone(),
            purpose: reservation.purpose.clone(),
            provider_lease_id: Some("provider-lease".into()),
            provider_version: Some(1),
            renewable: false,
            expires_unix_ms: 800,
        };
        let delivered = store
            .mark_external_release_delivered(&reservation, &metadata)
            .await
            .unwrap();
        assert!(matches!(
            delivered.state,
            ExternalSecretReleaseState::Delivered { .. }
        ));
        metadata.purpose = "wrong".into();
        assert!(matches!(
            store
                .mark_external_release_delivered(&reservation, &metadata)
                .await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        let revoking = store
            .begin_external_release_revoke(&reservation)
            .await
            .unwrap();
        assert!(revoking.started);
        assert!(
            !store
                .begin_external_release_revoke(&reservation)
                .await
                .unwrap()
                .started
        );
        let revoked = store
            .mark_external_release_revoked(&reservation, 850)
            .await
            .unwrap();
        assert!(matches!(
            revoked.state,
            ExternalSecretReleaseState::Revoked {
                revoked_unix_ms: 850,
                ..
            }
        ));
        assert_eq!(
            store
                .external_release(&reservation.release_id)
                .await
                .unwrap(),
            revoked
        );
        assert!(sqlx::query(
            "UPDATE external_secret_release_journal SET reservation_digest='tampered'
             WHERE release_id='external-release'",
        )
        .execute(store.pool())
        .await
        .is_err());
        assert!(sqlx::query(
            "DELETE FROM external_secret_release_journal WHERE release_id='external-release'",
        )
        .execute(store.pool())
        .await
        .is_err());
        store.close().await;
        fixture.cleanup().await;
    }
}
