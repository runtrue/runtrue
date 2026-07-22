use super::{audit::verify_audit_chain, integrity::verify_integrity, schema::verify_schema};
use crate::{
    secure_fs::{open_regular_guard, verify_guard_identity},
    BackupError, BackupLimits,
};
use runtrue_control_plane::LifecycleGcRoot;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _};
use std::{collections::BTreeSet, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatabaseInspection {
    pub(crate) installation_id: String,
    pub(crate) schema_version: u32,
    pub(crate) fencing_epoch: u64,
    pub(crate) safe_mode: bool,
    pub(crate) key_material_required: bool,
    pub(crate) capsule_count: usize,
    pub(crate) secret_snapshot_count: usize,
    pub(crate) oidc_grant_count: usize,
    pub(crate) authoritative_blob_roots: Vec<LifecycleGcRoot>,
}

pub(crate) fn inspect_database(
    path: &Path,
    limits: BackupLimits,
) -> Result<DatabaseInspection, BackupError> {
    let guard = open_regular_guard(path)?;
    let metadata = guard.metadata().map_err(|source| BackupError::Io {
        operation: "inspect SQLite database",
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() == 0 || metadata.len() > limits.max_database_bytes {
        return Err(BackupError::LimitExceeded("database bytes"));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    verify_guard_identity(path, &guard)?;
    verify_integrity(&connection)?;
    let schema_version = verify_schema(&connection)?;
    verify_audit_chain(&connection, limits)?;

    let (installation_id, fencing_epoch, safe_mode): (String, u64, bool) = if schema_version >= 3 {
        connection.query_row(
            "SELECT installation_id, fencing_epoch, safe_mode
                 FROM installation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, u64_column(row, 1)?, row.get(2)?)),
        )?
    } else {
        connection.query_row(
            "SELECT installation_id, fencing_epoch
                 FROM installation_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, u64_column(row, 1)?, false)),
        )?
    };
    if installation_id.is_empty() || installation_id.len() > 8 * 1024 || fencing_epoch == 0 {
        return Err(BackupError::InvalidDatabase(
            "installation identity or fencing epoch is invalid",
        ));
    }

    let capsule_count = bounded_count(&connection, "capsules", limits.max_database_records)?;
    let secret_snapshot_count = if table_exists(&connection, "secret_vault_snapshots")? {
        bounded_count(
            &connection,
            "secret_vault_snapshots",
            limits.max_database_records,
        )?
    } else {
        0
    };
    let oidc_grant_count = if table_exists(&connection, "oidc_grants")? {
        bounded_count(&connection, "oidc_grants", limits.max_database_records)?
    } else {
        0
    };
    let authoritative_blob_roots =
        authoritative_blob_roots(&connection, schema_version, limits.max_database_records)?;
    verify_guard_identity(path, &guard)?;
    Ok(DatabaseInspection {
        installation_id,
        schema_version,
        fencing_epoch,
        safe_mode,
        key_material_required: capsule_count > 0
            || secret_snapshot_count > 0
            || oidc_grant_count > 0,
        capsule_count,
        secret_snapshot_count,
        oidc_grant_count,
        authoritative_blob_roots,
    })
}

fn authoritative_blob_roots(
    connection: &Connection,
    schema_version: u32,
    maximum_roots: usize,
) -> Result<Vec<LifecycleGcRoot>, BackupError> {
    let mut roots = BTreeSet::new();
    let mut collect = |sql: &str| -> Result<(), BackupError> {
        let mut statement = connection.prepare(sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if roots.len() >= maximum_roots {
                return Err(BackupError::LimitExceeded("authoritative blob roots"));
            }
            let encoded: String = row.get(0)?;
            roots.insert(LifecycleGcRoot {
                digest: runtrue_model::ContentDigest::parse(encoded)
                    .map_err(|_| BackupError::InvalidDatabase("invalid blob root digest"))?,
                root_kind: row.get(1)?,
                root_id: row.get(2)?,
            });
        }
        Ok(())
    };
    if schema_version >= 14 {
        collect(
            "SELECT object_digest, 'opaque-object', ticket_id
               FROM runner_object_transfers
              WHERE state IN ('reserved','transferring','verified','committed')
                AND object_digest IS NOT NULL",
        )?;
    }
    if schema_version >= 15 {
        collect(
            "SELECT s.tree_manifest_digest, 'source-snapshot', s.id
               FROM source_snapshots s
             WHERE s.state = 'ready' AND EXISTS(
               SELECT 1 FROM run_source_snapshots r WHERE r.source_snapshot_id = s.id
             )",
        )?;
    }
    if schema_version >= 17 {
        collect(
            "SELECT g.manifest_digest, 'cache-manifest', g.cache_entry_id
               FROM cache_trust_current_heads h
             JOIN cache_trust_generations g ON g.cache_entry_id = h.cache_entry_id",
        )?;
        collect(
            "SELECT g.tree_manifest_digest, 'cache-tree', g.cache_entry_id
               FROM cache_trust_current_heads h
             JOIN cache_trust_generations g ON g.cache_entry_id = h.cache_entry_id",
        )?;
        collect(
            "SELECT evidence_digest, 'cache-promotion-evidence', id
               FROM cache_promotion_journal WHERE state IN ('pending','completed')",
        )?;
        collect(
            "SELECT g.manifest_digest, 'cache-manifest', c.ticket_id
               FROM runner_data_commits c
               JOIN cache_trust_generations g ON g.cache_entry_id = c.object_id
               LEFT JOIN job_result_objects o
                 ON o.kind = c.kind AND o.object_id = c.object_id
              WHERE c.kind = 'cache' AND o.object_id IS NULL",
        )?;
    }
    if schema_version >= 18 {
        collect(
            "SELECT artifact_id, 'artifact-record', artifact_id
               FROM artifacts_catalog WHERE state != 'retired'",
        )?;
        collect(
            "SELECT result_digest, 'scan-evidence', artifact_id || ':' || scanner
               FROM artifact_scan_results",
        )?;
        collect(
            "SELECT p.evidence_digest, 'artifact-promotion-evidence', p.id
               FROM artifact_promotions p
               JOIN artifacts_catalog a ON a.artifact_id = p.source_artifact_id
              WHERE a.state != 'retired'",
        )?;
        collect(
            "SELECT p.promoted_artifact_id, 'artifact-promoted-record', p.id
               FROM artifact_promotions p
               JOIN artifacts_catalog a ON a.artifact_id = p.source_artifact_id
              WHERE p.status = 'succeeded' AND p.promoted_artifact_id IS NOT NULL
                AND a.state != 'retired'",
        )?;
        collect(
            "SELECT c.object_id, 'artifact-pending-commit', c.ticket_id
               FROM runner_data_commits c
               LEFT JOIN job_result_objects o
                 ON o.kind = c.kind AND o.object_id = c.object_id
              WHERE c.kind = 'artifact' AND o.object_id IS NULL",
        )?;
    }
    if schema_version >= 19 {
        collect(
            "SELECT object_digest,
                    CASE root_kind
                      WHEN 'artifact' THEN 'artifact-record'
                      WHEN 'cache' THEN 'cache-manifest'
                      WHEN 'source' THEN 'source-snapshot'
                      ELSE 'opaque-object'
                    END,
                    id
               FROM backup_pins
              WHERE released_unix_ms IS NULL",
        )?;
        collect(
            "SELECT scan_evidence_digest, 'scan-evidence', promotion_id
               FROM artifact_promotion_bindings
              WHERE scan_evidence_digest IS NOT NULL",
        )?;
        collect(
            "SELECT approval_evidence_digest, 'artifact-promotion-evidence', promotion_id
               FROM artifact_promotion_bindings
              WHERE approval_evidence_digest IS NOT NULL",
        )?;
    }
    Ok(roots.into_iter().collect())
}

pub(super) fn bounded_count(
    connection: &Connection,
    table: &str,
    limit: usize,
) -> Result<usize, BackupError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: u64 = connection.query_row(&sql, [], |row| row.get(0))?;
    let count =
        usize::try_from(count).map_err(|_| BackupError::LimitExceeded("database records"))?;
    if count > limit {
        return Err(BackupError::LimitExceeded("database records"));
    }
    Ok(count)
}

pub(super) fn table_exists(connection: &Connection, table: &str) -> Result<bool, BackupError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(true),
        )
        .optional()
        .map(|value| value.unwrap_or(false))
        .map_err(BackupError::from)
}

pub(super) fn u64_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}
