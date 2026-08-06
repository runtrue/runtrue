use super::decode::to_i64;
use super::validation::validate_text;
use super::ControlPlane;
use crate::{
    migration::{
        materialize_catalog, MigrationBackend, MigrationReport, SQLITE_LEGACY_SCHEMA_VERSION,
        SQLITE_RETIRED_USER_VERSION,
    },
    ControlPlaneError,
};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

#[cfg(not(unix))]
use std::fs::{File, OpenOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DatabaseIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

pub(super) const MIGRATION_1: &str = include_str!("../../migrations/0001_control_plane.sql");
pub(super) const MIGRATION_2: &str = include_str!("../../migrations/0002_api_contract.sql");
pub(super) const MIGRATION_3: &str = include_str!("../../migrations/0003_restore_safety.sql");
pub(super) const MIGRATION_4: &str = include_str!("../../migrations/0004_authentication.sql");
pub(super) const MIGRATION_5: &str = include_str!("../../migrations/0005_runner_certificates.sql");
pub(super) const MIGRATION_6: &str = include_str!("../../migrations/0006_runner_brokers.sql");
pub(super) const MIGRATION_7: &str =
    include_str!("../../migrations/0007_scm_approval_continuations.sql");
pub(super) const MIGRATION_8: &str = include_str!("../../migrations/0008_remote_scheduler.sql");
pub(super) const MIGRATION_9: &str =
    include_str!("../../migrations/0009_runner_rotation_replays.sql");
pub(super) const MIGRATION_10: &str =
    include_str!("../../migrations/0010_runner_broker_attempts.sql");
pub(super) const MIGRATION_11: &str = include_str!("../../migrations/0011_runner_logs.sql");
pub(super) const MIGRATION_12: &str = include_str!("../../migrations/0012_runner_blob_uploads.sql");
pub(super) const MIGRATION_13: &str = include_str!("../../migrations/0013_runner_data_commits.sql");
pub(super) const MIGRATION_14: &str =
    include_str!("../../migrations/0014_runner_object_transfers.sql");
pub(super) const MIGRATION_15: &str = include_str!("../../migrations/0015_source_snapshots.sql");
pub(super) const MIGRATION_16: &str =
    include_str!("../../migrations/0016_github_source_fetches.sql");
pub(super) const MIGRATION_17: &str = include_str!("../../migrations/0017_cache_trust.sql");
pub(super) const MIGRATION_18: &str = include_str!("../../migrations/0018_artifact_catalog.sql");
pub(super) const MIGRATION_19: &str = include_str!("../../migrations/0019_output_lifecycle.sql");
pub(super) const MIGRATION_20: &str =
    include_str!("../../migrations/0020_workflow_expansions_and_triggers.sql");
pub(super) const MIGRATION_21: &str =
    include_str!("../../migrations/0021_output_lifecycle_integrity.sql");
pub(super) const MIGRATION_22: &str =
    include_str!("../../migrations/0022_scm_check_publications.sql");
pub(super) const MIGRATION_23: &str =
    include_str!("../../migrations/0023_human_identity_policy_state.sql");
pub(super) const MIGRATION_24: &str =
    include_str!("../../migrations/0024_environments_deployments.sql");
pub(super) const MIGRATION_25: &str =
    include_str!("../../migrations/0025_github_installation_lifecycle.sql");
pub(super) const MIGRATION_26: &str = include_str!("../../migrations/0026_scm_webhook_events.sql");
pub(super) const MIGRATION_27: &str = include_str!("../../migrations/0027_scm_check_revisions.sql");
pub(super) const MIGRATION_28: &str =
    include_str!("../../migrations/0028_scm_check_revision_journal.sql");
pub(super) const MIGRATION_29: &str =
    include_str!("../../migrations/0029_workflow_frontend_reports.sql");
pub(super) const MIGRATION_30: &str =
    include_str!("../../migrations/0030_execution_credential_taint.sql");
pub(super) const MIGRATION_31: &str =
    include_str!("../../migrations/0031_repository_workflow_settings.sql");
pub(super) const MIGRATION_32: &str =
    include_str!("../../migrations/0032_repository_workflow_directories.sql");
pub(super) const MIGRATION_33: &str = include_str!("../../migrations/0033_secret_projects.sql");
pub(super) const MIGRATION_34: &str = include_str!("../../migrations/0034_runner_fleet.sql");
pub(super) const CURRENT_SCHEMA_VERSION: u32 = SQLITE_LEGACY_SCHEMA_VERSION;

pub(crate) const SQLITE_LEGACY_MIGRATIONS: [&str; SQLITE_LEGACY_SCHEMA_VERSION as usize] = [
    MIGRATION_1,
    MIGRATION_2,
    MIGRATION_3,
    MIGRATION_4,
    MIGRATION_5,
    MIGRATION_6,
    MIGRATION_7,
    MIGRATION_8,
    MIGRATION_9,
    MIGRATION_10,
    MIGRATION_11,
    MIGRATION_12,
    MIGRATION_13,
    MIGRATION_14,
    MIGRATION_15,
    MIGRATION_16,
    MIGRATION_17,
    MIGRATION_18,
    MIGRATION_19,
    MIGRATION_20,
    MIGRATION_21,
    MIGRATION_22,
    MIGRATION_23,
    MIGRATION_24,
    MIGRATION_25,
    MIGRATION_26,
    MIGRATION_27,
    MIGRATION_28,
    MIGRATION_29,
    MIGRATION_30,
    MIGRATION_31,
    MIGRATION_32,
    MIGRATION_33,
    MIGRATION_34,
];

const SQLITE_UNIFIED_LEDGER_DDL: &str = "
CREATE TABLE runtrue_schema_migrations (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    migration_id TEXT NOT NULL UNIQUE CHECK (length(migration_id) BETWEEN 1 AND 200),
    definition_sha256 BLOB NOT NULL CHECK (length(definition_sha256) = 32),
    implementation_sha256 BLOB NOT NULL CHECK (length(implementation_sha256) = 32),
    applied_unix_ms INTEGER NOT NULL CHECK (applied_unix_ms >= 0)
) STRICT;";

pub(crate) const SQLITE_LEGACY_TABLES: &[&str] = &[
    "api_tokens",
    "approval_decisions",
    "approval_requests",
    "artifact_download_tickets",
    "artifact_promotion_bindings",
    "artifact_promotions",
    "artifact_scan_journal",
    "artifact_scan_results",
    "artifacts_catalog",
    "audit_events",
    "backup_pins",
    "browser_refresh_family_tokens",
    "browser_session_events",
    "browser_sessions",
    "cache_access_observations",
    "cache_promotion_journal",
    "cache_trust_current_heads",
    "cache_trust_generations",
    "capsule_api_metadata",
    "capsules",
    "configuration_project_targets",
    "configuration_projects",
    "deployment_request_events",
    "deployment_requests",
    "deployments",
    "durable_tasks",
    "emergency_deny_replacements",
    "enrollment_tokens",
    "environment_concurrency_leases",
    "environment_versions",
    "environments",
    "expanded_job_sets",
    "external_secret_release_journal",
    "github_app_setup_transactions",
    "github_installation_profiles",
    "github_lifecycle_deliveries",
    "github_repository_catalog",
    "human_identities",
    "human_user_tenant_bindings",
    "human_users",
    "idempotency_records",
    "installation_state",
    "job_fencing",
    "job_result_objects",
    "jobs",
    "leases",
    "lifecycle_gc_candidates",
    "lifecycle_gc_control",
    "lifecycle_gc_cycles",
    "lifecycle_gc_marks",
    "normalized_trigger_events",
    "oidc_browser_transaction_events",
    "oidc_browser_transactions",
    "oidc_grants",
    "oidc_issuances",
    "policy_activations",
    "policy_bundle_drafts",
    "policy_shadow_reports",
    "policy_simulation_reports",
    "policy_versions",
    "promotion_requests",
    "replay_bundles",
    "report_summaries",
    "repositories",
    "repository_workflow_settings",
    "run_approval_authorizations",
    "run_source_snapshots",
    "runner_autoscaler_leases",
    "runner_blob_uploads",
    "runner_certificate_rotations",
    "runner_certificates",
    "runner_data_commits",
    "runner_enrollment_postures",
    "runner_fleet_requests",
    "runner_job_rejections",
    "runner_launch_claims",
    "runner_log_frames",
    "runner_object_transfers",
    "runner_oidc_issuances",
    "runner_pool_scaling_policies",
    "runner_pool_templates",
    "runner_pools",
    "runner_scheduler_cursors",
    "runner_secret_leases",
    "runner_source_tickets",
    "runners",
    "runs",
    "schedule_trigger_cursors",
    "schema_migrations",
    "scm_check_publications",
    "scm_installations",
    "scm_pending_executions",
    "scm_proposed_analyses",
    "scm_repository_links",
    "scm_source_fetches",
    "scm_task_results",
    "scm_webhook_events",
    "secret_metadata",
    "secret_vault_snapshots",
    "signer_policies",
    "signer_policy_versions",
    "signing_result_journal",
    "source_snapshots",
    "tenant_memberships",
    "tenant_oidc_provider_configs",
    "tenant_policy_states",
    "tenant_provider_configuration_versions",
    "tenant_provider_configurations",
    "tenant_scheduler_quotas",
    "tenant_storage_objects",
    "tenant_storage_quotas",
    "tenant_storage_reservations",
    "tenant_storage_ticket_bindings",
    "tenants",
    "variable_snapshots",
    "variable_versions",
    "variables",
    "workflow_frontend_reports",
];

const RUNNER_UPDATE_TABLES: &[&str] = &[
    "runner_pool_update_policies",
    "runner_replacements",
    "runner_slots",
    "runner_software_update_claims",
    "runner_enrollment_replays",
    "runner_update_releases",
    "runner_update_trust_states",
];

const EVENT_REPLAY_TABLES: &[&str] = &["durable_event_replays", "durable_events"];
const USER_MANAGEMENT_TABLES: &[&str] = &["repository_access_grants", "team_memberships", "teams"];
const REPOSITORY_WRITER_AUTO_APPROVAL_TABLES: &[&str] = &["repository_auto_approval_policies"];

const SQLITE_REQUIRED_TRIGGERS: &[&str] = &[
    "audit_events_no_delete",
    "audit_events_no_update",
    "deployment_request_events_no_delete",
    "deployment_request_events_no_update",
    "environment_versions_no_delete",
    "environment_versions_no_update",
    "signer_policy_versions_no_delete",
    "signer_policy_versions_no_update",
    "tenant_provider_configuration_versions_no_delete",
    "tenant_provider_configuration_versions_no_update",
];

fn open_secure_database_file(path: &Path) -> Result<(File, DatabaseIdentity), ControlPlaneError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|source| database_path_io(parent, source))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(unsafe_database_path(
            parent,
            "the immediate parent must be a real directory",
        ));
    }

    let create_new = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_secure_file_metadata(path, &metadata)?;
            false
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(source) => return Err(database_path_io(path, source)),
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create_new);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| database_path_io(path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| database_path_io(path, source))?;
    validate_secure_file_metadata(path, &metadata)?;
    let identity = database_identity(&metadata);
    verify_database_identity(path, &identity)?;
    Ok((file, identity))
}

fn verify_database_identity(
    path: &Path,
    expected: &DatabaseIdentity,
) -> Result<(), ControlPlaneError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| database_path_io(path, source))?;
    validate_secure_file_metadata(path, &metadata)?;
    if &database_identity(&metadata) != expected {
        return Err(unsafe_database_path(
            path,
            "the database file changed while it was being opened",
        ));
    }
    Ok(())
}

fn validate_sqlite_sidecars(database_path: &Path) -> Result<(), ControlPlaneError> {
    for suffix in ["-wal", "-shm"] {
        let path = sqlite_sidecar_path(database_path, suffix);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(database_path_io(&path, source)),
        };
        validate_secure_file_metadata(&path, &metadata)?;
        let expected = database_identity(&metadata);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(&path)
            .map_err(|source| database_path_io(&path, source))?;
        let opened_metadata = file
            .metadata()
            .map_err(|source| database_path_io(&path, source))?;
        validate_secure_file_metadata(&path, &opened_metadata)?;
        if database_identity(&opened_metadata) != expected {
            return Err(unsafe_database_path(
                &path,
                "the SQLite sidecar changed while it was being opened",
            ));
        }
    }
    Ok(())
}

pub(super) fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = database_path.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

fn validate_secure_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ControlPlaneError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unsafe_database_path(path, "expected a regular file"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(unsafe_database_path(
            path,
            "Unix permissions must be exactly 0600",
        ));
    }
    Ok(())
}

fn database_identity(metadata: &fs::Metadata) -> DatabaseIdentity {
    DatabaseIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

fn unsafe_database_path(path: &Path, reason: &'static str) -> ControlPlaneError {
    ControlPlaneError::UnsafeDatabasePath {
        path: path.to_string_lossy().into_owned(),
        reason,
    }
}

fn database_path_io(path: &Path, source: io::Error) -> ControlPlaneError {
    ControlPlaneError::DatabasePathIo {
        path: path.to_string_lossy().into_owned(),
        source,
    }
}

impl ControlPlane {
    pub fn open(
        path: impl AsRef<Path>,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        Self::open_with_migration_report(path, installation_id, now_unix_ms)
            .map(|(control_plane, _)| control_plane)
    }

    /// Open an embedded database and return the backend-neutral migration
    /// result from the same transaction that binds the installation identity.
    pub fn open_with_migration_report(
        path: impl AsRef<Path>,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<(Self, MigrationReport), ControlPlaneError> {
        let path = path.as_ref();
        validate_sqlite_sidecars(path)?;
        let (database_guard, identity) = open_secure_database_file(path)?;
        let connection = Connection::open(path)?;
        let result = Self::initialize(connection, installation_id.into(), now_unix_ms)?;
        verify_database_identity(path, &identity)?;
        validate_sqlite_sidecars(path)?;
        drop(database_guard);
        Ok(result)
    }

    pub fn open_in_memory(
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        Self::open_in_memory_with_migration_report(installation_id, now_unix_ms)
            .map(|(control_plane, _)| control_plane)
    }

    pub fn open_in_memory_with_migration_report(
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<(Self, MigrationReport), ControlPlaneError> {
        let connection = Connection::open_in_memory()?;
        Self::initialize(connection, installation_id.into(), now_unix_ms)
    }

    fn initialize(
        mut connection: Connection,
        installation_id: String,
        now_unix_ms: u64,
    ) -> Result<(Self, MigrationReport), ControlPlaneError> {
        validate_text("installation_id", &installation_id)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        // The embedded control plane serializes access through one connection.
        // TRUNCATE avoids cross-namespace WAL sidecars that a host process can
        // unlink while the container still has them open.
        connection.pragma_update(None, "journal_mode", "TRUNCATE")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let migration_report = ensure_sqlite_current_schema(&transaction, now_unix_ms)?;
        transaction.execute(
            "INSERT OR IGNORE INTO installation_state(singleton, installation_id, fencing_epoch)
             VALUES (1, ?1, 1)",
            [&installation_id],
        )?;
        let stored: String = transaction.query_row(
            "SELECT installation_id FROM installation_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if stored != installation_id {
            return Err(ControlPlaneError::InstallationMismatch {
                expected: stored,
                actual: installation_id,
            });
        }
        transaction.commit()?;
        Ok((
            Self {
                connection: Mutex::new(connection),
                installation_id: stored,
            },
            migration_report,
        ))
    }
}

fn ensure_sqlite_current_schema(
    transaction: &rusqlite::Transaction<'_>,
    now_unix_ms: u64,
) -> Result<MigrationReport, ControlPlaneError> {
    let (catalog, lineage) =
        materialize_catalog(MigrationBackend::Sqlite, &SQLITE_LEGACY_MIGRATIONS)?;
    let baseline = &catalog[0];
    if table_exists(transaction, "runtrue_schema_migrations")? {
        let applied = verify_sqlite_unified_ledger(transaction, &catalog, true)?;
        verify_sqlite_schema_contract(transaction, false, applied.saturating_sub(1))?;
        let mut applied_ids = Vec::new();
        for migration in catalog.iter().skip(applied) {
            transaction.execute_batch(migration.sql.as_deref().ok_or_else(|| {
                ControlPlaneError::InvalidMigrationHistory(
                    "forward SQLite migration has no SQL payload".to_owned(),
                )
            })?)?;
            transaction.execute(
                "INSERT INTO runtrue_schema_migrations
                 (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    i64::from(migration.sequence),
                    migration.migration_id,
                    migration.definition_sha256.as_slice(),
                    migration.implementation_sha256.as_slice(),
                    to_i64(now_unix_ms)?,
                ],
            )?;
            applied_ids.push(migration.migration_id.to_owned());
        }
        verify_sqlite_unified_ledger(transaction, &catalog, false)?;
        verify_sqlite_schema_contract(transaction, false, catalog.len().saturating_sub(1))?;
        return Ok(MigrationReport {
            backend: MigrationBackend::Sqlite,
            logical_schema_generation: catalog.last().unwrap().logical_schema_generation,
            applied_migration_ids: applied_ids,
            replayed_migration_ids: catalog[..applied]
                .iter()
                .map(|migration| migration.migration_id.to_owned())
                .collect(),
            bridged_legacy_lineage: None,
        });
    }

    let version: u32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SQLITE_LEGACY_SCHEMA_VERSION {
        return Err(ControlPlaneError::UnsupportedSchemaVersion(version));
    }
    let divergent = reconcile_divergent_schema(transaction, version)?;
    for (offset, migration) in SQLITE_LEGACY_MIGRATIONS
        .iter()
        .enumerate()
        .skip(version as usize)
    {
        let target = u32::try_from(offset + 1)
            .map_err(|_| ControlPlaneError::UnsupportedSchemaVersion(version))?;
        if divergent.already_applied(target) {
            transaction.pragma_update(None, "user_version", target)?;
        } else {
            transaction.execute_batch(migration)?;
        }
        transaction.execute(
            "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
            params![i64::from(target), to_i64(now_unix_ms)?],
        )?;
    }

    verify_sqlite_legacy_history(transaction)?;
    verify_sqlite_schema_contract(transaction, true, 0)?;
    transaction.execute_batch(SQLITE_UNIFIED_LEDGER_DDL)?;
    transaction.execute(
        "INSERT INTO runtrue_schema_migrations
         (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
         VALUES (?1,?2,?3,?4,?5)",
        params![
            i64::from(baseline.sequence),
            baseline.migration_id,
            baseline.definition_sha256.as_slice(),
            baseline.implementation_sha256.as_slice(),
            to_i64(now_unix_ms)?,
        ],
    )?;
    transaction.pragma_update(None, "user_version", SQLITE_RETIRED_USER_VERSION)?;
    for migration in catalog.iter().skip(1) {
        transaction.execute_batch(migration.sql.as_deref().ok_or_else(|| {
            ControlPlaneError::InvalidMigrationHistory(
                "forward SQLite migration has no SQL payload".to_owned(),
            )
        })?)?;
        transaction.execute(
            "INSERT INTO runtrue_schema_migrations
             (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                i64::from(migration.sequence),
                migration.migration_id,
                migration.definition_sha256.as_slice(),
                migration.implementation_sha256.as_slice(),
                to_i64(now_unix_ms)?
            ],
        )?;
    }
    verify_sqlite_unified_ledger(transaction, &catalog, false)?;
    verify_sqlite_schema_contract(transaction, true, catalog.len().saturating_sub(1))?;
    Ok(MigrationReport {
        backend: MigrationBackend::Sqlite,
        logical_schema_generation: catalog.last().unwrap().logical_schema_generation,
        applied_migration_ids: catalog
            .iter()
            .map(|migration| migration.migration_id.to_owned())
            .collect(),
        replayed_migration_ids: Vec::new(),
        bridged_legacy_lineage: Some(lineage),
    })
}

fn verify_sqlite_legacy_history(connection: &Connection) -> Result<(), ControlPlaneError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SQLITE_LEGACY_SCHEMA_VERSION {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "SQLite legacy user_version is {version}, expected {SQLITE_LEGACY_SCHEMA_VERSION}"
        )));
    }
    let mut statement =
        connection.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
    let versions = statement
        .query_map([], |row| row.get::<_, u32>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = (1..=SQLITE_LEGACY_SCHEMA_VERSION).collect::<Vec<_>>();
    if versions != expected {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite legacy migration ledger is missing, reordered, duplicated, or from an unsupported lineage"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_sqlite_unified_ledger(
    connection: &Connection,
    expected: &[crate::migration::MaterializedMigration],
    allow_prefix: bool,
) -> Result<usize, ControlPlaneError> {
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='table' AND name='runtrue_schema_migrations'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            ControlPlaneError::InvalidMigrationHistory(
                "SQLite unified migration ledger is missing".to_owned(),
            )
        })?;
    if normalized_sqlite_ddl(&ddl) != normalized_sqlite_ddl(SQLITE_UNIFIED_LEDGER_DDL) {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite unified migration ledger constraints do not match the contract".to_owned(),
        ));
    }
    let strict: i64 = connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name='runtrue_schema_migrations' AND schema='main'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| {
            ControlPlaneError::InvalidMigrationHistory(
                "SQLite unified migration ledger is missing or is not a STRICT table".to_owned(),
            )
        })?;
    if strict != 1 {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite unified migration ledger is not STRICT".to_owned(),
        ));
    }
    let mut columns = connection.prepare(
        "SELECT name,upper(type),pk FROM pragma_table_info('runtrue_schema_migrations') ORDER BY cid",
    )?;
    let columns = columns
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected_columns = vec![
        ("sequence".to_owned(), "INTEGER".to_owned(), 1),
        ("migration_id".to_owned(), "TEXT".to_owned(), 0),
        ("definition_sha256".to_owned(), "BLOB".to_owned(), 0),
        ("implementation_sha256".to_owned(), "BLOB".to_owned(), 0),
        ("applied_unix_ms".to_owned(), "INTEGER".to_owned(), 0),
    ];
    if columns != expected_columns {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite unified migration ledger has incompatible columns".to_owned(),
        ));
    }
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
    if rows.is_empty()
        || rows.len() > expected.len()
        || (!allow_prefix && rows.len() != expected.len())
        || rows.iter().zip(expected).any(|(row, migration)| {
            row.0 != migration.sequence
                || row.1 != migration.migration_id
                || row.2 != migration.definition_sha256
                || row.3 != migration.implementation_sha256
        })
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite unified migration ledger does not match the catalog".to_owned(),
        ));
    }
    Ok(rows.len())
}

fn normalized_sqlite_ddl(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_owned()
}

fn verify_sqlite_schema_contract(
    connection: &Connection,
    verify_data: bool,
    forward_migrations: usize,
) -> Result<(), ControlPlaneError> {
    let actual_tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type='table' AND name NOT LIKE 'sqlite_%'
               AND name <> 'runtrue_schema_migrations'
             ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    let mut expected_tables = SQLITE_LEGACY_TABLES
        .iter()
        .map(|table| (*table).to_owned())
        .collect::<BTreeSet<_>>();
    if forward_migrations >= 1 {
        expected_tables.extend(RUNNER_UPDATE_TABLES.iter().map(|table| (*table).to_owned()));
    }
    if forward_migrations >= 2 {
        expected_tables.extend(
            USER_MANAGEMENT_TABLES
                .iter()
                .map(|table| (*table).to_owned()),
        );
    }
    if forward_migrations >= 3 {
        expected_tables.extend(EVENT_REPLAY_TABLES.iter().map(|table| (*table).to_owned()));
    }
    if forward_migrations >= 6 {
        expected_tables.extend(
            REPOSITORY_WRITER_AUTO_APPROVAL_TABLES
                .iter()
                .map(|table| (*table).to_owned()),
        );
    }
    if actual_tables != expected_tables {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite schema tables do not match the recognized v34 baseline".to_owned(),
        ));
    }
    let actual_triggers = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='trigger' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    let expected_triggers = SQLITE_REQUIRED_TRIGGERS
        .iter()
        .map(|trigger| (*trigger).to_owned())
        .collect::<BTreeSet<_>>();
    if actual_triggers != expected_triggers
        || !column_exists(connection, "installation_state", "safe_mode")?
        || !column_exists(connection, "installation_state", "last_restore_unix_ms")?
        || !column_exists(connection, "leases", "terminal_credential_taint")?
        || !column_exists(
            connection,
            "repository_workflow_settings",
            "workflow_directory",
        )?
        || column_exists(connection, "repository_workflow_settings", "workflow_path")?
        || !column_exists(connection, "configuration_projects", "version")?
        || !column_exists(connection, "runner_fleet_requests", "state")?
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "SQLite schema invariants do not match the recognized v34 baseline".to_owned(),
        ));
    }
    if verify_data {
        let mut foreign_key_failures = connection.prepare("PRAGMA foreign_key_check")?;
        if foreign_key_failures.query([])?.next()?.is_some() {
            return Err(ControlPlaneError::InvalidMigrationHistory(
                "SQLite legacy baseline contains foreign-key violations".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct DivergentSchemaLineage {
    credential_taint: bool,
    repository_settings: bool,
    workflow_directory: bool,
}

impl DivergentSchemaLineage {
    fn already_applied(&self, version: u32) -> bool {
        match version {
            30 => self.credential_taint,
            31 => self.repository_settings,
            32 => self.workflow_directory,
            _ => false,
        }
    }
}

/// Versions 29 through 31 were independently released by the `next` and
/// `main` lineages. Identify those immutable on-disk shapes and add the one
/// common table that the main lineage lacks before continuing through the
/// canonical merged migration sequence.
fn reconcile_divergent_schema(
    connection: &Connection,
    version: u32,
) -> Result<DivergentSchemaLineage, ControlPlaneError> {
    if version < 29 {
        return Ok(DivergentSchemaLineage::default());
    }

    let frontend_reports = table_exists(connection, "workflow_frontend_reports")?;
    let credential_taint = column_exists(connection, "leases", "terminal_credential_taint")?;
    let repository_settings = table_exists(connection, "repository_workflow_settings")?;
    let workflow_path = column_exists(connection, "repository_workflow_settings", "workflow_path")?;
    let workflow_directory = column_exists(
        connection,
        "repository_workflow_settings",
        "workflow_directory",
    )?;

    let known_shape = match version {
        29 => {
            !repository_settings
                && !workflow_path
                && !workflow_directory
                && (frontend_reports || credential_taint)
        }
        30 => {
            credential_taint
                && !workflow_directory
                && ((frontend_reports && !repository_settings && !workflow_path)
                    || (repository_settings && workflow_path))
        }
        31 => {
            credential_taint
                && repository_settings
                && ((workflow_path && !workflow_directory)
                    || (!workflow_path && workflow_directory))
        }
        32 => {
            frontend_reports
                && credential_taint
                && repository_settings
                && !workflow_path
                && workflow_directory
        }
        _ => true,
    };
    if !known_shape {
        return Err(ControlPlaneError::CorruptState(format!(
            "database schema shape does not match declared version {version}"
        )));
    }

    if (29..=31).contains(&version) && !frontend_reports {
        connection.execute_batch(MIGRATION_29)?;
        // MIGRATION_29 declares its canonical version. Restore the divergent
        // lineage's later version in the same transaction so a crash cannot
        // leave user_version behind its already-recorded history.
        connection.pragma_update(None, "user_version", version)?;
    }

    Ok(DivergentSchemaLineage {
        credential_taint,
        repository_settings,
        workflow_directory,
    })
}

pub(super) fn table_exists(connection: &Connection, table: &str) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
}

pub(super) fn column_exists(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        params![table, column],
        |row| row.get(0),
    )
}

#[cfg(test)]
pub(super) fn apply_migration(
    connection: &mut Connection,
    sql: &str,
    version: u32,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(sql)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version, applied_unix_ms) VALUES (?1, ?2)",
        params![i64::from(version), to_i64(now_unix_ms)?],
    )?;
    transaction.commit()?;
    Ok(())
}
