//! Offline, exact-value SQLite to PostgreSQL transfer support.
//!
//! This module deliberately operates below the domain stores.  The PostgreSQL
//! migrations remain the authority for shape and constraints; transfer only
//! proceeds when the source and destination table/column inventories match.

use crate::{
    migration::{materialize_catalog, MigrationBackend, SQLITE_RETIRED_USER_VERSION},
    postgres_transfer_ready, ControlPlaneError, DatabaseReadiness, InstallationRecoveryState,
    InstallationStateStore, PostgresInstallationStore,
};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use sqlx::{Acquire as _, Postgres, QueryBuilder, Row as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

const COPY_BATCH_ROWS: i64 = 256;
const INTERNAL_SQLITE_TABLES: &[&str] = &[
    "installation_state",
    "schema_migrations",
    "runtrue_schema_migrations",
];
const INTERNAL_POSTGRES_TABLES: &[&str] = &[
    "installation_state",
    "postgres_transfer_state",
    "runtrue_legacy_schema_migrations",
    "runtrue_schema_migrations",
];
const DERIVED_POSTGRES_TABLES: &[&str] = &["runner_enrollment_idempotency", "runner_oidc_grants"];
const SEEDED_POSTGRES_TABLES: &[&str] = &["lifecycle_gc_control"];

#[derive(Debug, Error)]
pub enum PostgresTransferError {
    #[error("PostgreSQL parity is incomplete; transfer remains disabled")]
    ParityIncomplete,
    #[error("SQLite transfer source failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("SQLite transfer source path failed: {0}")]
    SourcePath(#[from] std::io::Error),
    #[error("PostgreSQL transfer destination failed: {0}")]
    Postgres(#[from] sqlx::Error),
    #[error("control-plane recovery operation failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
    #[error("transfer inventory is incompatible: {0}")]
    Incompatible(String),
    #[error("transfer destination is not empty: table `{table}` contains {rows} rows")]
    DestinationNotEmpty { table: String, rows: i64 },
    #[error("transfer requires both databases to be in restore safe mode")]
    SafeModeRequired,
    #[error("transfer verification failed for table `{table}`")]
    VerificationFailed { table: String },
    #[error("SQLite transfer source is unsafe: {0}")]
    UnsafeSource(String),
    #[error("SQLite transfer source changed while it was being copied")]
    SourceChanged,
    #[error("PostgreSQL transfer lifecycle state conflicts with this operation")]
    TransferStateConflict,
    #[error("PostgreSQL transfer has not completed durable verification")]
    TransferNotVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PostgresTransferTableReport {
    pub table: String,
    pub rows: u64,
    pub canonical_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PostgresTransferReport {
    pub installation_id: String,
    pub source_fencing_epoch: u64,
    pub destination_fencing_epoch: u64,
    pub activation_permitted: bool,
    pub verification_digest: String,
    pub tables: Vec<PostgresTransferTableReport>,
}

/// One securely identified SQLite source held under a write-excluding SQLite
/// transaction for the complete PostgreSQL copy. The connection is never
/// reopened by pathname, so readiness and copied rows come from one snapshot.
pub struct SqliteTransferSource {
    connection: Connection,
    path: PathBuf,
    installation_id: String,
    fencing_epoch: u64,
    data_version: i64,
    metadata: SourceFileIdentity,
}

#[derive(Clone, Copy)]
struct SourceFileIdentity {
    length: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
}

impl SqliteTransferSource {
    pub fn open(path: &Path) -> Result<Self, PostgresTransferError> {
        let path = secure_sqlite_source_path(path)?;
        let before = fs::symlink_metadata(&path)?;
        validate_sqlite_source_metadata(&path, &before)?;
        let identity = source_file_identity(&before);
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let opened = fs::symlink_metadata(&path)?;
        validate_sqlite_source_metadata(&path, &opened)?;
        if !same_source_file(identity, source_file_identity(&opened)) {
            return Err(PostgresTransferError::SourceChanged);
        }
        connection.execute_batch(
            "PRAGMA busy_timeout=0;
             PRAGMA foreign_keys=ON;
             BEGIN IMMEDIATE;
             PRAGMA query_only=ON;",
        )?;
        verify_sqlite_unified_migration_state(&connection)?;
        let (installation_id, fencing_epoch, safe_mode) = connection.query_row(
            "SELECT installation_id,fencing_epoch,safe_mode
             FROM installation_state WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )?;
        if !safe_mode {
            return Err(PostgresTransferError::SafeModeRequired);
        }
        let fencing_epoch = u64::try_from(fencing_epoch).map_err(|_| {
            PostgresTransferError::Incompatible("source fencing epoch is negative".to_owned())
        })?;
        let data_version = connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        Ok(Self {
            connection,
            path,
            installation_id,
            fencing_epoch,
            data_version,
            metadata: identity,
        })
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    fn verify_unchanged(&self) -> Result<(), PostgresTransferError> {
        let data_version: i64 = self
            .connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        let metadata = fs::symlink_metadata(&self.path)?;
        validate_sqlite_source_metadata(&self.path, &metadata)?;
        if data_version != self.data_version
            || !same_source_file(self.metadata, source_file_identity(&metadata))
        {
            return Err(PostgresTransferError::SourceChanged);
        }
        Ok(())
    }
}

fn verify_sqlite_unified_migration_state(
    connection: &Connection,
) -> Result<(), PostgresTransferError> {
    let marker: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if marker != SQLITE_RETIRED_USER_VERSION {
        return Err(PostgresTransferError::Incompatible(
            "SQLite source has not crossed the unified migration boundary".to_owned(),
        ));
    }
    let (expected, _) = materialize_catalog(
        MigrationBackend::Sqlite,
        &crate::store::database::SQLITE_LEGACY_MIGRATIONS,
    )
    .map_err(|_| {
        PostgresTransferError::Incompatible(
            "embedded SQLite migration catalog is invalid".to_owned(),
        )
    })?;
    let rows = connection
        .prepare(
            "SELECT sequence,migration_id,definition_sha256,implementation_sha256
         FROM runtrue_schema_migrations ORDER BY sequence",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() != expected.len()
        || rows.iter().zip(expected).any(|(row, migration)| {
            row.0 != migration.sequence
                || row.1 != migration.migration_id
                || row.2 != migration.definition_sha256
                || row.3 != migration.implementation_sha256
        })
    {
        return Err(PostgresTransferError::Incompatible(
            "SQLite source migration ledger does not match the unified catalog".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnKind {
    Boolean,
    SmallInteger,
    Integer,
    BigInteger,
    Real,
    Double,
    Text,
    Bytes,
    Json,
}

#[derive(Debug, Clone, PartialEq)]
enum TransferValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    Text(String),
    Bytes(Vec<u8>),
    Json(serde_json::Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferColumn {
    name: String,
    kind: ColumnKind,
}

fn secure_sqlite_source_path(path: &Path) -> Result<PathBuf, PostgresTransferError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => checked.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(value) => {
                checked.push(value);
                let metadata = fs::symlink_metadata(&checked)?;
                if metadata.file_type().is_symlink() {
                    return Err(PostgresTransferError::UnsafeSource(
                        "path contains a symbolic-link component".to_owned(),
                    ));
                }
            }
            Component::ParentDir => {
                return Err(PostgresTransferError::UnsafeSource(
                    "path must not contain parent-directory traversal".to_owned(),
                ));
            }
        }
    }
    let parent = checked.parent().ok_or_else(|| {
        PostgresTransferError::UnsafeSource("source path has no parent directory".to_owned())
    })?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() {
        return Err(PostgresTransferError::UnsafeSource(
            "source parent is not a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        let effective_uid = nix::unistd::geteuid().as_raw();
        if parent_metadata.uid() != effective_uid
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(PostgresTransferError::UnsafeSource(
                "source parent must be owned by the current user and not group/world writable"
                    .to_owned(),
            ));
        }
    }
    Ok(checked)
}

fn validate_sqlite_source_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), PostgresTransferError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PostgresTransferError::UnsafeSource(
            "source must be a regular non-symlink file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        let effective_uid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != effective_uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(PostgresTransferError::UnsafeSource(
                "source must be owner-only mode 0600, singly linked, and owned by the current user"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn source_file_identity(metadata: &fs::Metadata) -> SourceFileIdentity {
    SourceFileIdentity {
        length: metadata.len(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        modified_seconds: metadata.mtime(),
        #[cfg(unix)]
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

fn same_source_file(left: SourceFileIdentity, right: SourceFileIdentity) -> bool {
    left.length == right.length && {
        #[cfg(unix)]
        {
            left.device == right.device
                && left.inode == right.inode
                && left.modified_seconds == right.modified_seconds
                && left.modified_nanoseconds == right.modified_nanoseconds
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

/// Atomically prove a PostgreSQL destination is empty before placing it in
/// restore safe mode. This avoids fencing a live installation merely because
/// its URL was passed to the transfer CLI by mistake.
pub async fn prepare_empty_postgres_destination(
    destination: &PostgresInstallationStore,
    prepared_unix_ms: u64,
) -> Result<InstallationRecoveryState, PostgresTransferError> {
    if !postgres_transfer_ready() {
        return Err(PostgresTransferError::ParityIncomplete);
    }
    prepare_empty_postgres_destination_inner(destination, prepared_unix_ms).await
}

async fn prepare_empty_postgres_destination_inner(
    destination: &PostgresInstallationStore,
    prepared_unix_ms: u64,
) -> Result<InstallationRecoveryState, PostgresTransferError> {
    let prepared_unix_ms = i64::try_from(prepared_unix_ms).map_err(|_| {
        PostgresTransferError::Incompatible(
            "destination preparation timestamp is out of range".to_owned(),
        )
    })?;
    let mut connection = destination.pool().acquire().await?;
    let target_columns = postgres_columns(&mut connection).await?;
    let target_tables = target_columns.keys().cloned().collect::<BTreeSet<_>>();
    let mut transaction = connection.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    lock_transfer_tables(&mut transaction, &target_tables).await?;
    require_destination_seed_rows(&mut transaction).await?;
    ensure_destination_empty(&mut transaction, &target_tables).await?;
    let row = sqlx::query(
        "SELECT installation_id,fencing_epoch,safe_mode,last_restore_unix_ms
         FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let installation_id: String = row.try_get("installation_id")?;
    if installation_id != destination.installation_id() {
        return Err(PostgresTransferError::Incompatible(format!(
            "destination installation identity changed before preparation: expected `{}`, found `{installation_id}`",
            destination.installation_id()
        )));
    }
    let current_epoch: i64 = row.try_get("fencing_epoch")?;
    let safe_mode: bool = row.try_get("safe_mode")?;
    let last_restore_unix_ms: Option<i64> = row.try_get("last_restore_unix_ms")?;
    let (fencing_epoch, last_restore_unix_ms) = if safe_mode {
        (current_epoch, last_restore_unix_ms)
    } else {
        let next_epoch = current_epoch.checked_add(1).ok_or_else(|| {
            PostgresTransferError::Incompatible(
                "destination fencing epoch overflow during preparation".to_owned(),
            )
        })?;
        sqlx::query(
            "UPDATE installation_state
             SET fencing_epoch=$1,safe_mode=TRUE,last_restore_unix_ms=$2
             WHERE singleton=TRUE",
        )
        .bind(next_epoch)
        .bind(prepared_unix_ms)
        .execute(&mut *transaction)
        .await?;
        (next_epoch, Some(prepared_unix_ms))
    };
    let transfer = sqlx::query(
        "SELECT installation_id,phase,prepared_fencing_epoch
         FROM postgres_transfer_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(transfer) = transfer {
        let transfer_installation: String = transfer.try_get("installation_id")?;
        let phase: String = transfer.try_get("phase")?;
        let prepared_epoch: i64 = transfer.try_get("prepared_fencing_epoch")?;
        if transfer_installation != installation_id
            || phase != "prepared"
            || prepared_epoch != fencing_epoch
        {
            return Err(PostgresTransferError::TransferStateConflict);
        }
    } else {
        sqlx::query(
            "INSERT INTO postgres_transfer_state
             (singleton,installation_id,phase,prepared_fencing_epoch,prepared_unix_ms)
             VALUES(TRUE,$1,'prepared',$2,$3)",
        )
        .bind(&installation_id)
        .bind(fencing_epoch)
        .bind(prepared_unix_ms)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(InstallationRecoveryState {
        fencing_epoch: u64::try_from(fencing_epoch).map_err(|_| {
            PostgresTransferError::Incompatible("destination fencing epoch is negative".to_owned())
        })?,
        safe_mode: true,
        last_restore_unix_ms: last_restore_unix_ms
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    PostgresTransferError::Incompatible(
                        "destination restore timestamp is negative".to_owned(),
                    )
                })
            })
            .transpose()?,
    })
}

/// Copy every authoritative row into an empty, migrated PostgreSQL database.
///
/// Both source and destination must already be in restore safe mode. The
/// destination remains in safe mode and receives a fresh installation fence;
/// a separate activation operation must leave safe mode explicitly.
pub async fn copy_sqlite_to_postgres(
    source: &SqliteTransferSource,
    destination: &PostgresInstallationStore,
    completed_unix_ms: u64,
) -> Result<PostgresTransferReport, PostgresTransferError> {
    if !postgres_transfer_ready() {
        return Err(PostgresTransferError::ParityIncomplete);
    }

    let source_installation_id = source.installation_id.clone();
    let source_epoch = source.fencing_epoch;
    let destination_readiness = destination.load_database_readiness().await?;
    require_compatible_installations(&source_installation_id, true, &destination_readiness)?;

    let source_tables = sqlite_tables(&source.connection)?;
    let mut connection = destination.pool().acquire().await?;
    let target_columns = postgres_columns(&mut connection).await?;
    let target_tables = target_columns.keys().cloned().collect::<BTreeSet<_>>();
    let transferable_tables = target_tables
        .iter()
        .filter(|table| !DERIVED_POSTGRES_TABLES.contains(&table.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    if source_tables != transferable_tables {
        return Err(PostgresTransferError::Incompatible(format!(
            "table sets differ; source-only={:?}, destination-only={:?}",
            source_tables
                .difference(&transferable_tables)
                .collect::<Vec<_>>(),
            transferable_tables
                .difference(&source_tables)
                .collect::<Vec<_>>()
        )));
    }

    let order = postgres_table_order(&mut connection, &transferable_tables).await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    lock_transfer_tables(&mut transaction, &target_tables).await?;
    require_locked_destination_state(
        &mut transaction,
        &source_installation_id,
        &destination_readiness,
    )
    .await?;
    require_destination_seed_rows(&mut transaction).await?;
    ensure_destination_empty(&mut transaction, &target_tables).await?;
    delete_destination_seed_rows(&mut transaction).await?;

    let mut reports = Vec::with_capacity(order.len());
    for table in order {
        let columns = target_columns.get(&table).ok_or_else(|| {
            PostgresTransferError::Incompatible(format!("missing columns for `{table}`"))
        })?;
        let report = copy_table(&source.connection, &mut transaction, &table, columns).await?;
        reports.push(report);
    }
    reports.extend(backfill_derived_tables(&mut transaction, &target_columns).await?);

    let destination_epoch = source_epoch
        .max(destination_readiness.recovery.fencing_epoch)
        .checked_add(1)
        .ok_or_else(|| {
            PostgresTransferError::Incompatible("installation fencing epoch overflow".to_owned())
        })?;
    source.verify_unchanged()?;
    let mut report = PostgresTransferReport {
        installation_id: source_installation_id,
        source_fencing_epoch: source_epoch,
        destination_fencing_epoch: destination_epoch,
        activation_permitted: true,
        verification_digest: String::new(),
        tables: reports,
    };
    let verification_digest = transfer_report_digest(&report);
    report.verification_digest = hex::encode(verification_digest);
    fence_transferred_state(&mut transaction, destination_epoch, completed_unix_ms).await?;
    let transitioned = sqlx::query(
        "UPDATE postgres_transfer_state
         SET phase='verified',source_fencing_epoch=$1,verified_fencing_epoch=$2,
             verified_report_digest=$3,verified_unix_ms=$4
         WHERE singleton=TRUE AND installation_id=$5 AND phase='prepared'
           AND prepared_fencing_epoch=$6",
    )
    .bind(i64::try_from(source_epoch).map_err(|_| {
        PostgresTransferError::Incompatible("source fencing epoch is out of range".to_owned())
    })?)
    .bind(i64::try_from(destination_epoch).map_err(|_| {
        PostgresTransferError::Incompatible("destination fencing epoch is out of range".to_owned())
    })?)
    .bind(verification_digest.to_vec())
    .bind(i64::try_from(completed_unix_ms).map_err(|_| {
        PostgresTransferError::Incompatible("transfer timestamp is out of range".to_owned())
    })?)
    .bind(&report.installation_id)
    .bind(
        i64::try_from(destination_readiness.recovery.fencing_epoch).map_err(|_| {
            PostgresTransferError::Incompatible(
                "prepared destination fencing epoch is out of range".to_owned(),
            )
        })?,
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if transitioned != 1 {
        return Err(PostgresTransferError::TransferStateConflict);
    }
    transaction.commit().await?;
    Ok(report)
}

/// Atomically consume a successfully verified transfer at its exact fence.
/// Generic restore-safe-mode state is insufficient: preparation, failed
/// copies, and partial copies never reach the durable `verified` phase and
/// therefore cannot be activated through this operation.
pub async fn activate_verified_postgres_transfer(
    destination: &PostgresInstallationStore,
    expected_fencing_epoch: u64,
    activated_unix_ms: u64,
) -> Result<InstallationRecoveryState, PostgresTransferError> {
    let expected_fencing_epoch = i64::try_from(expected_fencing_epoch).map_err(|_| {
        PostgresTransferError::Incompatible("activation fencing epoch is out of range".to_owned())
    })?;
    let activated_unix_ms = i64::try_from(activated_unix_ms).map_err(|_| {
        PostgresTransferError::Incompatible("activation timestamp is out of range".to_owned())
    })?;
    let mut connection = destination.pool().acquire().await?;
    let mut transaction = connection.begin().await?;
    let transfer = sqlx::query(
        "SELECT installation_id,phase,verified_fencing_epoch,verified_report_digest,
                verified_unix_ms
         FROM postgres_transfer_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(PostgresTransferError::TransferNotVerified)?;
    let installation_id: String = transfer.try_get("installation_id")?;
    let phase: String = transfer.try_get("phase")?;
    let verified_epoch: Option<i64> = transfer.try_get("verified_fencing_epoch")?;
    let report_digest: Option<Vec<u8>> = transfer.try_get("verified_report_digest")?;
    let verified_unix_ms: Option<i64> = transfer.try_get("verified_unix_ms")?;
    if installation_id != destination.installation_id()
        || phase != "verified"
        || verified_epoch != Some(expected_fencing_epoch)
        || report_digest
            .as_deref()
            .is_none_or(|digest| digest.len() != 32)
        || verified_unix_ms.is_none_or(|verified| activated_unix_ms < verified)
    {
        return Err(PostgresTransferError::TransferNotVerified);
    }
    let installation = sqlx::query(
        "SELECT fencing_epoch,safe_mode,last_restore_unix_ms
         FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let fencing_epoch: i64 = installation.try_get("fencing_epoch")?;
    let safe_mode: bool = installation.try_get("safe_mode")?;
    let last_restore_unix_ms: Option<i64> = installation.try_get("last_restore_unix_ms")?;
    if !safe_mode || fencing_epoch != expected_fencing_epoch {
        return Err(PostgresTransferError::TransferStateConflict);
    }
    let open_leases: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM leases
         WHERE state IN ('offered','active','cancel_requested'))",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if open_leases {
        return Err(ControlPlaneError::RestoreHasOpenLeases.into());
    }
    sqlx::query("UPDATE installation_state SET safe_mode=FALSE WHERE singleton=TRUE")
        .execute(&mut *transaction)
        .await?;
    let transitioned = sqlx::query(
        "UPDATE postgres_transfer_state SET phase='activated',activated_unix_ms=$1
         WHERE singleton=TRUE AND phase='verified' AND verified_fencing_epoch=$2",
    )
    .bind(activated_unix_ms)
    .bind(expected_fencing_epoch)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if transitioned != 1 {
        return Err(PostgresTransferError::TransferStateConflict);
    }
    transaction.commit().await?;
    Ok(InstallationRecoveryState {
        fencing_epoch: u64::try_from(fencing_epoch).map_err(|_| {
            PostgresTransferError::Incompatible("activation fence is negative".to_owned())
        })?,
        safe_mode: false,
        last_restore_unix_ms: last_restore_unix_ms
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    PostgresTransferError::Incompatible(
                        "activation restore timestamp is negative".to_owned(),
                    )
                })
            })
            .transpose()?,
    })
}

fn require_compatible_installations(
    source_installation_id: &str,
    source_safe_mode: bool,
    destination: &DatabaseReadiness,
) -> Result<(), PostgresTransferError> {
    if source_installation_id != destination.installation_id {
        return Err(PostgresTransferError::Incompatible(format!(
            "installation IDs differ: source `{source_installation_id}`, destination `{}`",
            destination.installation_id
        )));
    }
    if !source_safe_mode || !destination.recovery.safe_mode {
        return Err(PostgresTransferError::SafeModeRequired);
    }
    Ok(())
}

fn sqlite_tables(connection: &Connection) -> Result<BTreeSet<String>, PostgresTransferError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let mut tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    for internal in INTERNAL_SQLITE_TABLES {
        tables.remove(*internal);
    }
    Ok(tables)
}

async fn postgres_columns(
    connection: &mut sqlx::PgConnection,
) -> Result<BTreeMap<String, Vec<TransferColumn>>, PostgresTransferError> {
    let rows = sqlx::query(
        "SELECT table_name, column_name, udt_name
         FROM information_schema.columns
         WHERE table_schema = current_schema()
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    let mut tables = BTreeMap::<String, Vec<TransferColumn>>::new();
    for row in rows {
        let table: String = row.try_get("table_name")?;
        if INTERNAL_POSTGRES_TABLES.contains(&table.as_str()) {
            continue;
        }
        let name: String = row.try_get("column_name")?;
        let encoded_kind: String = row.try_get("udt_name")?;
        let kind = match encoded_kind.as_str() {
            "bool" => ColumnKind::Boolean,
            "int2" => ColumnKind::SmallInteger,
            "int4" => ColumnKind::Integer,
            "int8" => ColumnKind::BigInteger,
            "float4" => ColumnKind::Real,
            "float8" => ColumnKind::Double,
            "text" | "varchar" | "bpchar" => ColumnKind::Text,
            "bytea" => ColumnKind::Bytes,
            "jsonb" => ColumnKind::Json,
            other => {
                return Err(PostgresTransferError::Incompatible(format!(
                    "unsupported PostgreSQL type `{other}` for `{table}.{name}`"
                )))
            }
        };
        tables
            .entry(table)
            .or_default()
            .push(TransferColumn { name, kind });
    }
    Ok(tables)
}

async fn ensure_destination_empty(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    tables: &BTreeSet<String>,
) -> Result<(), PostgresTransferError> {
    for table in tables {
        if SEEDED_POSTGRES_TABLES.contains(&table.as_str()) {
            continue;
        }
        let sql = format!("SELECT COUNT(*) FROM {}", quoted_identifier(table)?);
        let rows: i64 = sqlx::query_scalar(&sql)
            .fetch_one(&mut **transaction)
            .await?;
        if rows != 0 {
            return Err(PostgresTransferError::DestinationNotEmpty {
                table: table.clone(),
                rows,
            });
        }
    }
    Ok(())
}

async fn require_destination_seed_rows(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), PostgresTransferError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT COUNT(*)=1 AND COALESCE(BOOL_AND(
             singleton=TRUE AND current_generation=0 AND phase='idle'
             AND lease_owner IS NULL AND lease_token IS NULL
             AND lease_expires_unix_ms IS NULL AND updated_unix_ms=0
         ),FALSE)
         FROM lifecycle_gc_control",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !valid {
        return Err(PostgresTransferError::Incompatible(
            "destination bootstrap row `lifecycle_gc_control` is not pristine".to_owned(),
        ));
    }
    Ok(())
}

async fn delete_destination_seed_rows(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), PostgresTransferError> {
    sqlx::query("DELETE FROM lifecycle_gc_control")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_transfer_tables(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    tables: &BTreeSet<String>,
) -> Result<(), PostgresTransferError> {
    if tables.is_empty() {
        return Ok(());
    }
    let names = tables
        .iter()
        .map(|table| quoted_identifier(table))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    sqlx::query(&format!("LOCK TABLE {names} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn require_locked_destination_state(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    source_installation_id: &str,
    expected: &DatabaseReadiness,
) -> Result<(), PostgresTransferError> {
    let row = sqlx::query(
        "SELECT installation_id,fencing_epoch,safe_mode
         FROM installation_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let installation_id: String = row.try_get("installation_id")?;
    let fencing_epoch: i64 = row.try_get("fencing_epoch")?;
    let safe_mode: bool = row.try_get("safe_mode")?;
    let fencing_epoch = u64::try_from(fencing_epoch).map_err(|_| {
        PostgresTransferError::Incompatible("destination fencing epoch is negative".to_owned())
    })?;
    if installation_id != source_installation_id || installation_id != expected.installation_id {
        return Err(PostgresTransferError::Incompatible(format!(
            "destination installation identity changed before transfer: expected `{}`, found `{installation_id}`",
            expected.installation_id
        )));
    }
    if !safe_mode {
        return Err(PostgresTransferError::SafeModeRequired);
    }
    if fencing_epoch != expected.recovery.fencing_epoch {
        return Err(PostgresTransferError::Incompatible(format!(
            "destination fencing epoch changed before transfer: expected {}, found {fencing_epoch}",
            expected.recovery.fencing_epoch
        )));
    }
    Ok(())
}

async fn backfill_derived_tables(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    columns: &BTreeMap<String, Vec<TransferColumn>>,
) -> Result<Vec<PostgresTransferTableReport>, PostgresTransferError> {
    sqlx::query(
        "INSERT INTO runner_enrollment_idempotency
         (operation,idempotency_key,request_hash,enrollment_token_id,created_unix_ms)
         SELECT operation,idempotency_key,request_hash,resource_id,created_unix_ms
         FROM idempotency_records
         WHERE operation LIKE 'runner-pool.enrollment-token.create:%'",
    )
    .execute(&mut **transaction)
    .await?;
    // SQLite stores the runner grant binding in canonical grant_json but has
    // no separate authorization timestamp. The lease issue time is a stable,
    // conservative lower bound; every reconstructed grant is fenced below
    // before the destination can be activated.
    sqlx::query(
        "INSERT INTO runner_oidc_grants
         (grant_id,execution_lease_id,fencing_generation,installation_fencing_epoch,
          runner_id,job_attempt,step_id,runner_posture_digest,state,
          authorized_unix_ms,revoked_unix_ms)
         SELECT g.id,l.id,l.fencing_generation,l.installation_fencing_epoch,
                l.runner_id,j.attempt,parsed_grant.value->>'step_id',
                parsed_grant.value->>'runner_posture_digest',
                CASE WHEN g.revoked_unix_ms IS NULL THEN 'authorized' ELSE 'revoked' END,
                l.issued_unix_ms,g.revoked_unix_ms
         FROM oidc_grants g
         CROSS JOIN LATERAL (
             SELECT convert_from(g.grant_json,'UTF8')::jsonb AS value
         ) parsed_grant
         JOIN leases l ON l.id=parsed_grant.value->>'execution_lease_id'
         JOIN jobs j ON j.id=l.job_id
         WHERE parsed_grant.value->>'grant_id'=g.id
           AND (parsed_grant.value->>'fencing_generation')::BIGINT=l.fencing_generation
           AND parsed_grant.value->>'job_id'=l.job_id
           AND parsed_grant.value->>'runner_posture_digest' IS NOT NULL",
    )
    .execute(&mut **transaction)
    .await?;
    let mut reports = Vec::with_capacity(DERIVED_POSTGRES_TABLES.len());
    for table in DERIVED_POSTGRES_TABLES {
        let table_columns = columns.get(*table).ok_or_else(|| {
            PostgresTransferError::Incompatible(format!(
                "derived PostgreSQL table `{table}` is missing"
            ))
        })?;
        let mut hashes = postgres_row_hashes(transaction, table, table_columns).await?;
        hashes.sort_unstable();
        reports.push(PostgresTransferTableReport {
            table: (*table).to_owned(),
            rows: u64::try_from(hashes.len()).map_err(|_| {
                PostgresTransferError::Incompatible("derived row count overflow".to_owned())
            })?,
            canonical_digest: hex::encode(table_digest(&hashes)),
        });
    }
    Ok(reports)
}

async fn postgres_table_order(
    connection: &mut sqlx::PgConnection,
    tables: &BTreeSet<String>,
) -> Result<Vec<String>, PostgresTransferError> {
    let rows = sqlx::query(
        "SELECT tc.table_name, ccu.table_name AS referenced_table
         FROM information_schema.table_constraints tc
         JOIN information_schema.constraint_column_usage ccu
           ON ccu.constraint_schema = tc.constraint_schema
          AND ccu.constraint_name = tc.constraint_name
         WHERE tc.table_schema = current_schema()
           AND tc.constraint_type = 'FOREIGN KEY'",
    )
    .fetch_all(&mut *connection)
    .await?;
    let mut dependencies = tables
        .iter()
        .map(|table| (table.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for row in rows {
        let table: String = row.try_get("table_name")?;
        let referenced: String = row.try_get("referenced_table")?;
        if table != referenced && tables.contains(&table) && tables.contains(&referenced) {
            dependencies.entry(table).or_default().insert(referenced);
        }
    }
    let mut order = Vec::with_capacity(tables.len());
    while !dependencies.is_empty() {
        let ready = dependencies
            .iter()
            .filter(|(_, required)| required.is_empty())
            .map(|(table, _)| table.clone())
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(PostgresTransferError::Incompatible(format!(
                "foreign-key cycle prevents ordered transfer: {:?}",
                dependencies.keys().collect::<Vec<_>>()
            )));
        }
        for table in ready {
            dependencies.remove(&table);
            for required in dependencies.values_mut() {
                required.remove(&table);
            }
            order.push(table);
        }
    }
    Ok(order)
}

async fn copy_table(
    source: &Connection,
    destination: &mut sqlx::Transaction<'_, Postgres>,
    table: &str,
    columns: &[TransferColumn],
) -> Result<PostgresTransferTableReport, PostgresTransferError> {
    require_source_columns(source, table, columns)?;
    require_source_rowid(source, table)?;
    let mut source_hashes = Vec::<[u8; 32]>::new();
    let mut last_rowid = None;
    loop {
        let rows = sqlite_page(source, table, columns, last_rowid, COPY_BATCH_ROWS)?;
        if rows.is_empty() {
            break;
        }
        for (rowid, values) in rows {
            insert_postgres_row(destination, table, columns, &values).await?;
            source_hashes.push(row_digest(&values));
            last_rowid = Some(rowid);
        }
    }

    let target_hashes = postgres_row_hashes(destination, table, columns).await?;
    source_hashes.sort_unstable();
    let mut target_hashes = target_hashes;
    target_hashes.sort_unstable();
    if source_hashes != target_hashes {
        return Err(PostgresTransferError::VerificationFailed {
            table: table.to_owned(),
        });
    }
    let digest = table_digest(&source_hashes);
    Ok(PostgresTransferTableReport {
        table: table.to_owned(),
        rows: u64::try_from(source_hashes.len()).map_err(|_| {
            PostgresTransferError::Incompatible("table row count overflow".to_owned())
        })?,
        canonical_digest: hex::encode(digest),
    })
}

fn sqlite_page(
    source: &Connection,
    table: &str,
    columns: &[TransferColumn],
    after_rowid: Option<i64>,
    limit: i64,
) -> Result<Vec<(i64, Vec<TransferValue>)>, PostgresTransferError> {
    let select = match after_rowid {
        Some(_) => format!(
            "SELECT rowid, {} FROM {} WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
            quoted_column_list(columns)?,
            quoted_identifier(table)?
        ),
        None => format!(
            "SELECT rowid, {} FROM {} ORDER BY rowid LIMIT ?1",
            quoted_column_list(columns)?,
            quoted_identifier(table)?
        ),
    };
    let mut statement = source.prepare(&select)?;
    let collect_row = |row: &rusqlite::Row<'_>| {
        let rowid = row.get::<_, i64>(0)?;
        let values = columns
            .iter()
            .enumerate()
            .map(|(index, column)| sqlite_value(row.get_ref(index + 1)?, column.kind))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rowid, values))
    };
    match after_rowid {
        Some(rowid) => Ok(statement
            .query_map((rowid, limit), collect_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?),
        None => Ok(statement
            .query_map([limit], collect_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?),
    }
}

fn require_source_columns(
    source: &Connection,
    table: &str,
    target: &[TransferColumn],
) -> Result<(), PostgresTransferError> {
    let sql = format!("PRAGMA table_info({})", quoted_identifier(table)?);
    let mut statement = source.prepare(&sql)?;
    let source_columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    let target_columns = target
        .iter()
        .map(|column| column.name.clone())
        .collect::<BTreeSet<_>>();
    if source_columns != target_columns {
        return Err(PostgresTransferError::Incompatible(format!(
            "column sets differ for `{table}`: source={source_columns:?}, destination={target_columns:?}"
        )));
    }
    Ok(())
}

fn require_source_rowid(source: &Connection, table: &str) -> Result<(), PostgresTransferError> {
    let schema: String = source.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;
    if schema.to_ascii_uppercase().contains("WITHOUT ROWID") {
        return Err(PostgresTransferError::Incompatible(format!(
            "SQLite table `{table}` has no rowid and cannot be paginated safely"
        )));
    }
    Ok(())
}

fn sqlite_value(value: ValueRef<'_>, kind: ColumnKind) -> rusqlite::Result<TransferValue> {
    match (value, kind) {
        (ValueRef::Null, _) => Ok(TransferValue::Null),
        (ValueRef::Integer(value), ColumnKind::Boolean) if value == 0 || value == 1 => {
            Ok(TransferValue::Boolean(value == 1))
        }
        (
            ValueRef::Integer(value),
            ColumnKind::SmallInteger | ColumnKind::Integer | ColumnKind::BigInteger,
        ) => Ok(TransferValue::Integer(value)),
        (ValueRef::Real(value), ColumnKind::Real | ColumnKind::Double) => {
            Ok(TransferValue::Real(value))
        }
        (ValueRef::Integer(value), ColumnKind::Real | ColumnKind::Double) => {
            Ok(TransferValue::Real(value as f64))
        }
        (ValueRef::Text(value), ColumnKind::Text) => String::from_utf8(value.to_vec())
            .map(TransferValue::Text)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    value.len(),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            }),
        (ValueRef::Text(value), ColumnKind::Json) => serde_json::from_slice(value)
            .map(TransferValue::Json)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    value.len(),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            }),
        (ValueRef::Blob(value), ColumnKind::Bytes) => Ok(TransferValue::Bytes(value.to_vec())),
        // Historical SQLite JSON columns were declared TEXT. PostgreSQL uses
        // BYTEA so canonical JSON bytes are preserved without re-encoding.
        (ValueRef::Text(value), ColumnKind::Bytes) => Ok(TransferValue::Bytes(value.to_vec())),
        (value, _) => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            value.data_type(),
            "SQLite value type does not match PostgreSQL transfer column".into(),
        )),
    }
}

async fn insert_postgres_row(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    table: &str,
    columns: &[TransferColumn],
    values: &[TransferValue],
) -> Result<(), PostgresTransferError> {
    let mut query = QueryBuilder::<Postgres>::new("INSERT INTO ");
    query.push(quoted_identifier(table)?);
    query.push(" (");
    {
        let mut separated = query.separated(", ");
        for column in columns {
            separated.push(quoted_identifier(&column.name)?);
        }
    }
    query.push(") VALUES (");
    {
        let mut separated = query.separated(", ");
        for (column, value) in columns.iter().zip(values) {
            push_bind(&mut separated, column.kind, value)?;
        }
    }
    query.push(")");
    query.build().execute(&mut **transaction).await?;
    Ok(())
}

fn push_bind<'a>(
    query: &mut sqlx::query_builder::Separated<'_, 'a, Postgres, &'static str>,
    kind: ColumnKind,
    value: &TransferValue,
) -> Result<(), PostgresTransferError> {
    match (kind, value) {
        (ColumnKind::Boolean, TransferValue::Null) => query.push_bind(Option::<bool>::None),
        (ColumnKind::Boolean, TransferValue::Boolean(value)) => query.push_bind(*value),
        (ColumnKind::SmallInteger, TransferValue::Null) => query.push_bind(Option::<i16>::None),
        (ColumnKind::SmallInteger, TransferValue::Integer(value)) => {
            query.push_bind(i16::try_from(*value).map_err(|_| {
                PostgresTransferError::Incompatible("SMALLINT value is out of range".to_owned())
            })?)
        }
        (ColumnKind::Integer, TransferValue::Null) => query.push_bind(Option::<i32>::None),
        (ColumnKind::Integer, TransferValue::Integer(value)) => {
            query.push_bind(i32::try_from(*value).map_err(|_| {
                PostgresTransferError::Incompatible("INTEGER value is out of range".to_owned())
            })?)
        }
        (ColumnKind::BigInteger, TransferValue::Null) => query.push_bind(Option::<i64>::None),
        (ColumnKind::BigInteger, TransferValue::Integer(value)) => query.push_bind(*value),
        (ColumnKind::Real, TransferValue::Null) => query.push_bind(Option::<f32>::None),
        (ColumnKind::Real, TransferValue::Real(value)) => query.push_bind(*value as f32),
        (ColumnKind::Double, TransferValue::Null) => query.push_bind(Option::<f64>::None),
        (ColumnKind::Double, TransferValue::Real(value)) => query.push_bind(*value),
        (ColumnKind::Text, TransferValue::Null) => query.push_bind(Option::<String>::None),
        (ColumnKind::Text, TransferValue::Text(value)) => query.push_bind(value.clone()),
        (ColumnKind::Bytes, TransferValue::Null) => query.push_bind(Option::<Vec<u8>>::None),
        (ColumnKind::Bytes, TransferValue::Bytes(value)) => query.push_bind(value.clone()),
        (ColumnKind::Json, TransferValue::Null) => query
            .push_bind(Option::<String>::None)
            .push_unseparated("::jsonb"),
        (ColumnKind::Json, TransferValue::Json(value)) => query
            .push_bind(serde_json::to_string(value).map_err(|error| {
                PostgresTransferError::Incompatible(format!(
                    "JSON transfer value could not be encoded: {error}"
                ))
            })?)
            .push_unseparated("::jsonb"),
        _ => {
            return Err(PostgresTransferError::Incompatible(
                "transfer value does not match destination column".to_owned(),
            ))
        }
    };
    Ok(())
}

async fn postgres_row_hashes(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    table: &str,
    columns: &[TransferColumn],
) -> Result<Vec<[u8; 32]>, PostgresTransferError> {
    let sql = format!(
        "SELECT {} FROM {}",
        postgres_select_list(columns)?,
        quoted_identifier(table)?
    );
    let rows = sqlx::query(&sql).fetch_all(&mut **transaction).await?;
    rows.into_iter()
        .map(|row| {
            let values = columns
                .iter()
                .enumerate()
                .map(|(index, column)| postgres_value(&row, index, column.kind))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(row_digest(&values))
        })
        .collect()
}

fn postgres_value(
    row: &sqlx::postgres::PgRow,
    index: usize,
    kind: ColumnKind,
) -> Result<TransferValue, PostgresTransferError> {
    macro_rules! optional {
        ($type:ty, $map:expr) => {
            match row.try_get::<Option<$type>, _>(index)? {
                Some(value) => $map(value),
                None => TransferValue::Null,
            }
        };
    }
    Ok(match kind {
        ColumnKind::Boolean => optional!(bool, TransferValue::Boolean),
        ColumnKind::SmallInteger => {
            optional!(i16, |value| TransferValue::Integer(i64::from(value)))
        }
        ColumnKind::Integer => optional!(i32, |value| TransferValue::Integer(i64::from(value))),
        ColumnKind::BigInteger => optional!(i64, TransferValue::Integer),
        ColumnKind::Real => optional!(f32, |value| TransferValue::Real(f64::from(value))),
        ColumnKind::Double => optional!(f64, TransferValue::Real),
        ColumnKind::Text => optional!(String, TransferValue::Text),
        ColumnKind::Bytes => optional!(Vec<u8>, TransferValue::Bytes),
        ColumnKind::Json => match row.try_get::<Option<String>, _>(index)? {
            Some(value) => TransferValue::Json(serde_json::from_str(&value).map_err(|error| {
                PostgresTransferError::Incompatible(format!(
                    "PostgreSQL JSON value could not be decoded: {error}"
                ))
            })?),
            None => TransferValue::Null,
        },
    })
}

fn row_digest(values: &[TransferValue]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.sqlite-postgres-row.v1\0");
    for value in values {
        match value {
            TransferValue::Null => hash.update([0]),
            TransferValue::Boolean(value) => hash.update([1, u8::from(*value)]),
            TransferValue::Integer(value) => {
                hash.update([2]);
                hash.update(value.to_be_bytes());
            }
            TransferValue::Real(value) => {
                hash.update([3]);
                hash.update(value.to_bits().to_be_bytes());
            }
            TransferValue::Text(value) => hash_sized(&mut hash, 4, value.as_bytes()),
            TransferValue::Bytes(value) => hash_sized(&mut hash, 5, value),
            TransferValue::Json(value) => {
                let encoded = serde_json::to_vec(value)
                    .expect("serde_json::Value always serializes to valid JSON");
                hash_sized(&mut hash, 6, &encoded);
            }
        }
    }
    hash.finalize().into()
}

fn hash_sized(hash: &mut Sha256, tag: u8, value: &[u8]) {
    hash.update([tag]);
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn table_digest(rows: &[[u8; 32]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.sqlite-postgres-table.v1\0");
    hash.update(u64::try_from(rows.len()).unwrap_or(u64::MAX).to_be_bytes());
    for row in rows {
        hash.update(row);
    }
    hash.finalize().into()
}

fn transfer_report_digest(report: &PostgresTransferReport) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.sqlite-postgres-transfer-report.v1\0");
    hash_sized(&mut hash, 1, report.installation_id.as_bytes());
    hash.update(report.source_fencing_epoch.to_be_bytes());
    hash.update(report.destination_fencing_epoch.to_be_bytes());
    let mut tables = report.tables.iter().collect::<Vec<_>>();
    tables.sort_unstable_by(|left, right| left.table.cmp(&right.table));
    hash.update(
        u64::try_from(tables.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for table in tables {
        hash_sized(&mut hash, 2, table.table.as_bytes());
        hash.update(table.rows.to_be_bytes());
        hash_sized(&mut hash, 3, table.canonical_digest.as_bytes());
    }
    hash.finalize().into()
}

async fn fence_transferred_state(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    fencing_epoch: u64,
    completed_unix_ms: u64,
) -> Result<(), PostgresTransferError> {
    let fencing_epoch = i64::try_from(fencing_epoch).map_err(|_| {
        PostgresTransferError::Incompatible("installation fencing epoch is out of range".to_owned())
    })?;
    let completed_unix_ms = i64::try_from(completed_unix_ms).map_err(|_| {
        PostgresTransferError::Incompatible("transfer timestamp is out of range".to_owned())
    })?;
    sqlx::query(
        "UPDATE installation_state
         SET fencing_epoch = $1, safe_mode = TRUE, last_restore_unix_ms = $2
         WHERE singleton = TRUE",
    )
    .bind(fencing_epoch)
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE jobs SET status = 'lost', completed_unix_ms = $1
         WHERE id IN (
             SELECT DISTINCT job_id FROM leases
             WHERE state IN ('offered', 'active', 'cancel_requested')
         ) AND status IN ('queued', 'leased', 'preparing', 'running', 'finalizing')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE leases SET state = 'expired'
         WHERE state IN ('offered', 'active', 'cancel_requested')",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_secret_leases
         SET state = 'expired', revoked_unix_ms = $1 WHERE state = 'delivered'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_issuances
         SET state = 'expired', revoked_unix_ms = $1 WHERE state = 'issued'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_oidc_grants
         SET state = 'expired', revoked_unix_ms = $1 WHERE state = 'authorized'",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("UPDATE oidc_grants SET revoked_unix_ms = $1 WHERE revoked_unix_ms IS NULL")
        .bind(completed_unix_ms)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "UPDATE runner_object_transfers
         SET state = 'abandoned', updated_unix_ms = $1
         WHERE state IN ('reserved', 'transferring')",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE enrollment_tokens SET expires_unix_ms = LEAST(expires_unix_ms, $1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms > $1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_launch_claims SET expires_unix_ms = LEAST(expires_unix_ms, $1)
         WHERE consumed_unix_ms IS NULL AND expires_unix_ms > $1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE runner_autoscaler_leases SET expires_unix_ms = LEAST(expires_unix_ms, $1)
         WHERE expires_unix_ms > $1",
    )
    .bind(completed_unix_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn quoted_column_list(columns: &[TransferColumn]) -> Result<String, PostgresTransferError> {
    columns
        .iter()
        .map(|column| quoted_identifier(&column.name))
        .collect::<Result<Vec<_>, _>>()
        .map(|columns| columns.join(", "))
}

fn postgres_select_list(columns: &[TransferColumn]) -> Result<String, PostgresTransferError> {
    columns
        .iter()
        .map(|column| {
            let identifier = quoted_identifier(&column.name)?;
            Ok(if column.kind == ColumnKind::Json {
                format!("{identifier}::text")
            } else {
                identifier
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|columns| columns.join(", "))
}

fn quoted_identifier(identifier: &str) -> Result<String, PostgresTransferError> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PostgresTransferError::Incompatible(
            "database inventory contains an unsafe identifier".to_owned(),
        ));
    }
    Ok(format!("\"{identifier}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn secure_sqlite(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn identifiers_are_strictly_quoted() {
        assert_eq!(
            quoted_identifier("runner_leases").unwrap(),
            "\"runner_leases\""
        );
        for invalid in ["", "a-b", "a.b", "a\"b", "a b"] {
            assert!(quoted_identifier(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn canonical_hash_distinguishes_types_and_boundaries() {
        assert_ne!(
            row_digest(&[TransferValue::Text("1".to_owned())]),
            row_digest(&[TransferValue::Integer(1)])
        );
        assert_ne!(
            row_digest(&[
                TransferValue::Text("ab".to_owned()),
                TransferValue::Text("c".to_owned()),
            ]),
            row_digest(&[
                TransferValue::Text("a".to_owned()),
                TransferValue::Text("bc".to_owned()),
            ])
        );
    }

    #[test]
    fn transfer_report_digest_is_order_independent_and_identity_bound() {
        let table_a = PostgresTransferTableReport {
            table: "a".to_owned(),
            rows: 1,
            canonical_digest: hex::encode([1_u8; 32]),
        };
        let table_b = PostgresTransferTableReport {
            table: "b".to_owned(),
            rows: 2,
            canonical_digest: hex::encode([2_u8; 32]),
        };
        let report = PostgresTransferReport {
            installation_id: "installation".to_owned(),
            source_fencing_epoch: 2,
            destination_fencing_epoch: 3,
            activation_permitted: true,
            verification_digest: String::new(),
            tables: vec![table_a.clone(), table_b.clone()],
        };
        let mut reordered = report.clone();
        reordered.tables = vec![table_b, table_a];
        assert_eq!(
            transfer_report_digest(&report),
            transfer_report_digest(&reordered)
        );
        reordered.installation_id = "other".to_owned();
        assert_ne!(
            transfer_report_digest(&report),
            transfer_report_digest(&reordered)
        );
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_transfer_source_rejects_links_permissions_and_concurrent_writers() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.sqlite");
        let control = crate::ControlPlane::open(&path, "source-lock", 1).unwrap();
        control.enter_restore_safe_mode(2).unwrap();
        drop(control);
        secure_sqlite(&path);

        let symbolic = directory.path().join("symbolic.sqlite");
        symlink(&path, &symbolic).unwrap();
        assert!(matches!(
            SqliteTransferSource::open(&symbolic),
            Err(PostgresTransferError::UnsafeSource(_))
        ));
        let hard = directory.path().join("hard.sqlite");
        fs::hard_link(&path, &hard).unwrap();
        assert!(matches!(
            SqliteTransferSource::open(&path),
            Err(PostgresTransferError::UnsafeSource(_))
        ));
        fs::remove_file(hard).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            SqliteTransferSource::open(&path),
            Err(PostgresTransferError::UnsafeSource(_))
        ));
        secure_sqlite(&path);

        let source = SqliteTransferSource::open(&path).unwrap();
        assert_eq!(source.installation_id(), "source-lock");
        assert!(matches!(
            SqliteTransferSource::open(&path),
            Err(PostgresTransferError::Sqlite(
                rusqlite::Error::SqliteFailure(_, _)
            ))
        ));
        source.verify_unchanged().unwrap();
    }

    #[test]
    fn installation_identity_and_safe_mode_are_required_before_copy() {
        let ready = DatabaseReadiness {
            backend: crate::DatabaseBackendKind::Postgres,
            schema_version: crate::POSTGRES_SCHEMA_VERSION,
            installation_id: "installation".to_owned(),
            recovery: crate::InstallationRecoveryState {
                fencing_epoch: 4,
                safe_mode: true,
                last_restore_unix_ms: Some(10),
            },
        };
        require_compatible_installations("installation", true, &ready).unwrap();
        assert!(matches!(
            require_compatible_installations("other", true, &ready),
            Err(PostgresTransferError::Incompatible(_))
        ));
        assert!(matches!(
            require_compatible_installations("installation", false, &ready),
            Err(PostgresTransferError::SafeModeRequired)
        ));
        let mut unsafe_destination = ready;
        unsafe_destination.recovery.safe_mode = false;
        assert!(matches!(
            require_compatible_installations("installation", true, &unsafe_destination),
            Err(PostgresTransferError::SafeModeRequired)
        ));
    }

    #[test]
    fn source_columns_match_by_name_not_physical_order() {
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch("CREATE TABLE sample(second TEXT, first TEXT) STRICT;")
            .unwrap();
        let target = vec![
            TransferColumn {
                name: "first".to_owned(),
                kind: ColumnKind::Text,
            },
            TransferColumn {
                name: "second".to_owned(),
                kind: ColumnKind::Text,
            },
        ];
        require_source_columns(&source, "sample", &target).unwrap();
    }

    #[test]
    fn sqlite_text_is_preserved_as_postgres_bytes() {
        assert_eq!(
            sqlite_value(ValueRef::Text(br#"{"key":"value"}"#), ColumnKind::Bytes).unwrap(),
            TransferValue::Bytes(br#"{"key":"value"}"#.to_vec())
        );
    }

    #[test]
    fn sqlite_json_is_parsed_for_postgres_jsonb() {
        let value = sqlite_value(ValueRef::Text(br#"{"b":2,"a":1}"#), ColumnKind::Json).unwrap();
        assert_eq!(
            value,
            TransferValue::Json(serde_json::json!({"a": 1, "b": 2}))
        );
        assert!(sqlite_value(ValueRef::Text(b"not-json"), ColumnKind::Json).is_err());
    }

    #[test]
    fn pagination_includes_minimum_sqlite_rowid() {
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch("CREATE TABLE sample(value TEXT) STRICT;")
            .unwrap();
        source
            .execute(
                "INSERT INTO sample(rowid,value) VALUES(?1,'minimum')",
                [i64::MIN],
            )
            .unwrap();
        source
            .execute("INSERT INTO sample(rowid,value) VALUES(-1,'next')", [])
            .unwrap();
        let columns = [TransferColumn {
            name: "value".to_owned(),
            kind: ColumnKind::Text,
        }];
        let first = sqlite_page(&source, "sample", &columns, None, 1).unwrap();
        assert_eq!(first[0].0, i64::MIN);
        let second = sqlite_page(&source, "sample", &columns, Some(first[0].0), 1).unwrap();
        assert_eq!(second[0].0, -1);
    }

    #[test]
    fn without_rowid_tables_are_rejected_explicitly() {
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch("CREATE TABLE sample(id TEXT PRIMARY KEY) WITHOUT ROWID;")
            .unwrap();
        assert!(matches!(
            require_source_rowid(&source, "sample"),
            Err(PostgresTransferError::Incompatible(_))
        ));
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn transfer_inventory_matches_fully_migrated_sqlite() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transfer.sqlite");
        drop(crate::ControlPlane::open(&path, "transfer-inventory", 1).unwrap());
        let fixture = crate::persistence::PostgresTestSchema::create(&url, "sqlite-transfer").await;
        let store = PostgresInstallationStore::connect_for_transfer(
            fixture.config(),
            "transfer-inventory",
            1,
        )
        .await
        .unwrap();
        let crash_window_state = store.load_database_readiness().await.unwrap();
        assert!(crash_window_state.recovery.safe_mode);
        assert!(matches!(
            activate_verified_postgres_transfer(
                &store,
                crash_window_state.recovery.fencing_epoch,
                2,
            )
            .await,
            Err(PostgresTransferError::TransferNotVerified)
        ));
        let source = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let source_tables = sqlite_tables(&source).unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        let target = postgres_columns(&mut connection).await.unwrap();
        let target_tables = target.keys().cloned().collect::<BTreeSet<_>>();
        let transferable = target_tables
            .iter()
            .filter(|table| !DERIVED_POSTGRES_TABLES.contains(&table.as_str()))
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(source_tables.difference(&transferable).next().is_none());
        assert!(transferable.difference(&source_tables).next().is_none());
        for table in DERIVED_POSTGRES_TABLES {
            assert!(
                target_tables.contains(*table),
                "missing derived table {table}"
            );
        }
        for table in source_tables.intersection(&transferable) {
            require_source_columns(&source, table, &target[table]).unwrap();
            require_source_rowid(&source, table).unwrap();
        }
        let order = postgres_table_order(&mut connection, &transferable)
            .await
            .unwrap();
        assert_eq!(order.into_iter().collect::<BTreeSet<_>>(), transferable);
        let mut transaction = connection.begin().await.unwrap();
        require_destination_seed_rows(&mut transaction)
            .await
            .unwrap();
        delete_destination_seed_rows(&mut transaction)
            .await
            .unwrap();
        let derived = backfill_derived_tables(&mut transaction, &target)
            .await
            .unwrap();
        assert_eq!(
            derived
                .iter()
                .map(|report| report.table.as_str())
                .collect::<BTreeSet<_>>(),
            DERIVED_POSTGRES_TABLES.iter().copied().collect()
        );
        assert!(derived.iter().all(|report| report.rows == 0));
        fence_transferred_state(&mut transaction, 2, 1_000)
            .await
            .unwrap();
        transaction.rollback().await.unwrap();
        drop(connection);
        sqlx::query(
            "INSERT INTO idempotency_records
             (operation,idempotency_key,request_hash,resource_id,created_unix_ms)
             VALUES('transfer-test','key','hash','resource',0)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let before_refusal = store.load_database_readiness().await.unwrap();
        assert!(matches!(
            prepare_empty_postgres_destination_inner(&store, 2_000).await,
            Err(PostgresTransferError::DestinationNotEmpty { .. })
        ));
        assert_eq!(
            store.load_database_readiness().await.unwrap(),
            before_refusal
        );
        sqlx::query("DELETE FROM idempotency_records WHERE operation='transfer-test'")
            .execute(store.pool())
            .await
            .unwrap();
        let prepared = prepare_empty_postgres_destination_inner(&store, 2_000)
            .await
            .unwrap();
        assert!(prepared.safe_mode);
        assert!(matches!(
            activate_verified_postgres_transfer(&store, prepared.fencing_epoch, 2_001).await,
            Err(PostgresTransferError::TransferNotVerified)
        ));
        sqlx::query(
            "INSERT INTO idempotency_records
             (operation,idempotency_key,request_hash,resource_id,created_unix_ms)
             VALUES('partial-transfer-test','key','hash','resource',0)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert!(matches!(
            activate_verified_postgres_transfer(&store, prepared.fencing_epoch, 2_002).await,
            Err(PostgresTransferError::TransferNotVerified)
        ));
        sqlx::query("DELETE FROM idempotency_records WHERE operation='partial-transfer-test'")
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            prepare_empty_postgres_destination_inner(&store, 3_000)
                .await
                .unwrap(),
            prepared
        );

        let control = crate::ControlPlane::open(&path, "transfer-inventory", 2_100).unwrap();
        control.enter_restore_safe_mode(2_101).unwrap();
        drop(control);
        #[cfg(unix)]
        secure_sqlite(&path);
        let source = SqliteTransferSource::open(&path).unwrap();
        let report = copy_sqlite_to_postgres(&source, &store, 2_200)
            .await
            .unwrap();
        assert!(report.activation_permitted);
        assert_eq!(report.verification_digest.len(), 64);
        assert!(report.destination_fencing_epoch > prepared.fencing_epoch);
        assert!(matches!(
            activate_verified_postgres_transfer(
                &store,
                report.destination_fencing_epoch.saturating_sub(1),
                2_300,
            )
            .await,
            Err(PostgresTransferError::TransferNotVerified)
        ));
        let active =
            activate_verified_postgres_transfer(&store, report.destination_fencing_epoch, 2_300)
                .await
                .unwrap();
        assert!(!active.safe_mode);
        let phase: String =
            sqlx::query_scalar("SELECT phase FROM postgres_transfer_state WHERE singleton=TRUE")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(phase, "activated");
        assert!(matches!(
            activate_verified_postgres_transfer(&store, report.destination_fencing_epoch, 2_301,)
                .await,
            Err(PostgresTransferError::TransferNotVerified)
        ));
        store.close().await;
        fixture.cleanup().await;
    }
}
