use super::decode::to_i64;
use super::validation::validate_text;
use super::ControlPlane;
use crate::ControlPlaneError;
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
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
    include_str!("../../migrations/0029_execution_credential_taint.sql");
pub(super) const MIGRATION_30: &str =
    include_str!("../../migrations/0030_repository_workflow_settings.sql");
pub(super) const MIGRATION_31: &str =
    include_str!("../../migrations/0031_repository_workflow_directories.sql");
#[cfg(test)]
pub(super) const CURRENT_SCHEMA_VERSION: u32 = 31;

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
        let path = path.as_ref();
        validate_sqlite_sidecars(path)?;
        let (database_guard, identity) = open_secure_database_file(path)?;
        let connection = Connection::open(path)?;
        let control_plane = Self::initialize(connection, installation_id.into(), now_unix_ms)?;
        verify_database_identity(path, &identity)?;
        validate_sqlite_sidecars(path)?;
        drop(database_guard);
        Ok(control_plane)
    }

    pub fn open_in_memory(
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        let connection = Connection::open_in_memory()?;
        Self::initialize(connection, installation_id.into(), now_unix_ms)
    }

    fn initialize(
        mut connection: Connection,
        installation_id: String,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        validate_text("installation_id", &installation_id)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let migrations = [
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
        ];
        if usize::try_from(version).map_or(true, |version| version > migrations.len()) {
            return Err(ControlPlaneError::UnsupportedSchemaVersion(version));
        }
        for (offset, migration) in migrations.iter().enumerate().skip(version as usize) {
            let target = u32::try_from(offset + 1)
                .map_err(|_| ControlPlaneError::UnsupportedSchemaVersion(version))?;
            apply_migration(&mut connection, migration, target, now_unix_ms)?;
        }
        connection.execute(
            "INSERT OR IGNORE INTO installation_state(singleton, installation_id, fencing_epoch)
             VALUES (1, ?1, 1)",
            [&installation_id],
        )?;
        let stored: String = connection.query_row(
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
        Ok(Self {
            connection: Mutex::new(connection),
            installation_id: stored,
        })
    }
}

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
