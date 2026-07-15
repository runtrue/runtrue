//! Bounded, fail-closed single-node backup and restore.
//!
//! The archive is an operator-protected directory, not an encrypted container.
//! SQLite is captured through its online backup API. Every retained file is
//! listed by role, byte length, and SHA-256 digest in a bounded manifest.

mod database;
mod format;
mod secure_fs;

pub use format::{
    BackupLimits, BackupManifest, BackupRole, LocalKeyContinuity, ManifestEntry,
    BACKUP_FORMAT_VERSION, DATABASE_RELATIVE_PATH, MANIFEST_FILE_NAME,
};

use database::{
    force_delete_journal_mode, inspect_database, online_copy_database, verify_local_security_seed,
    DatabaseInspection,
};
use runtrue_control_plane::{ControlPlane, ControlPlaneError};
use runtrue_model::{ContentDigest, ModelError};
use runtrue_output_lifecycle::{verify_authoritative_object_graph, LifecycleLimits};
use runtrue_storage::{CasLimits, FsCas};
use secure_fs::{
    cleanup_directory, collect_relative_files, copy_regular_file, copy_source_tree,
    ensure_parent_directories, hash_regular_file, prepare_empty_directory, read_bounded_file,
    require_backup_directory, require_private_regular_file, sync_directory_tree,
    validate_relative_path, write_new_private_file, CopyState,
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

#[derive(Clone)]
pub struct BackupSourcePaths {
    pub database: PathBuf,
    pub blobs: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub key_ciphertext: Option<PathBuf>,
}

impl fmt::Debug for BackupSourcePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupSourcePaths")
            .field("database", &self.database)
            .field("blobs", &self.blobs)
            .field("config", &self.config)
            .field("key_ciphertext", &self.key_ciphertext)
            .finish()
    }
}

pub struct LocalSecuritySeed(Zeroizing<[u8; 32]>);

impl LocalSecuritySeed {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, BackupError> {
        let path = path.as_ref();
        require_private_regular_file(path)?;
        let mut bytes = read_bounded_file(path, 33)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(BackupError::InvalidSecuritySeed);
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self::from_bytes(seed))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LocalSecuritySeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalSecuritySeed([REDACTED])")
    }
}

pub struct CreateBackupRequest<'a> {
    pub source: BackupSourcePaths,
    pub destination: PathBuf,
    pub local_security_seed: Option<&'a LocalSecuritySeed>,
    pub created_unix_ms: u64,
    pub limits: BackupLimits,
}

pub struct VerifyBackupRequest<'a> {
    pub backup: PathBuf,
    pub local_security_seed: Option<&'a LocalSecuritySeed>,
    pub limits: BackupLimits,
}

pub struct RestoreBackupRequest<'a> {
    pub backup: PathBuf,
    pub target: PathBuf,
    pub local_security_seed: Option<&'a LocalSecuritySeed>,
    pub restored_unix_ms: u64,
    pub limits: BackupLimits,
}

pub struct ActivateRestoreRequest<'a> {
    pub target: PathBuf,
    pub local_security_seed: Option<&'a LocalSecuritySeed>,
    pub expected_fencing_epoch: u64,
    pub verification_acknowledged: bool,
    pub limits: BackupLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReport {
    pub backup: PathBuf,
    pub manifest_digest: ContentDigest,
    pub installation_id: String,
    pub schema_version: u32,
    pub fencing_epoch: u64,
    pub entry_count: usize,
    pub total_bytes: u64,
    pub local_key_continuity_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReport {
    pub target: PathBuf,
    pub manifest_digest: ContentDigest,
    pub installation_id: String,
    pub source_fencing_epoch: u64,
    pub restored_fencing_epoch: u64,
    pub safe_mode: bool,
    pub entry_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReport {
    pub target: PathBuf,
    pub installation_id: String,
    pub fencing_epoch: u64,
    pub safe_mode: bool,
}

#[derive(Debug)]
struct VerifiedArchive {
    manifest: BackupManifest,
    manifest_digest: ContentDigest,
}

pub fn create_backup(request: CreateBackupRequest<'_>) -> Result<BackupReport, BackupError> {
    let limits = validated_limits(request.limits)?;
    let prepared = prepare_empty_directory(&request.destination)?;
    let result = create_backup_inner(&request, limits);
    if result.is_err() {
        cleanup_directory(&request.destination, &prepared);
    }
    result
}

fn create_backup_inner(
    request: &CreateBackupRequest<'_>,
    limits: BackupLimits,
) -> Result<BackupReport, BackupError> {
    ensure_sources_outside_destination(&request.source, &request.destination)?;
    let database_destination = request.destination.join(DATABASE_RELATIVE_PATH);
    online_copy_database(&request.source.database, &database_destination, limits)?;
    let inspection = inspect_database(&database_destination, limits)?;
    let continuity = verify_required_key_state(
        &database_destination,
        &inspection,
        request.local_security_seed,
        None,
        limits,
    )?;

    let mut state = CopyState::new();
    let (database_size, database_digest) =
        hash_regular_file(&database_destination, limits.max_database_bytes)?;
    state.add_entry(
        ManifestEntry {
            path: DATABASE_RELATIVE_PATH.to_owned(),
            role: BackupRole::Database,
            size_bytes: database_size,
            digest: database_digest,
        },
        limits,
    )?;
    for (source, prefix, role) in [
        (request.source.blobs.as_deref(), "blobs", BackupRole::Blob),
        (
            request.source.config.as_deref(),
            "config",
            BackupRole::Config,
        ),
        (
            request.source.key_ciphertext.as_deref(),
            "key-ciphertext",
            BackupRole::KeyCiphertext,
        ),
    ] {
        if let Some(source) = source {
            copy_source_tree(
                source,
                &request.destination,
                prefix,
                role,
                &mut state,
                limits,
            )?;
        }
    }
    state
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = BackupManifest {
        format_version: BACKUP_FORMAT_VERSION,
        created_unix_ms: request.created_unix_ms,
        installation_id: inspection.installation_id.clone(),
        source_schema_version: inspection.schema_version,
        source_fencing_epoch: inspection.fencing_epoch,
        local_key_continuity: continuity,
        entries: state.entries,
        total_bytes: state.total_bytes,
    };
    validate_manifest(&manifest, limits)?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    if manifest_bytes.len() as u64 > limits.max_manifest_bytes {
        return Err(BackupError::LimitExceeded("manifest bytes"));
    }
    let manifest_digest = ContentDigest::sha256(&manifest_bytes);
    write_new_private_file(
        &request.destination.join(MANIFEST_FILE_NAME),
        &manifest_bytes,
    )?;
    sync_directory_tree(&request.destination)?;

    let verified = verify_archive(&request.destination, request.local_security_seed, limits)?;
    if verified.manifest_digest != manifest_digest {
        return Err(BackupError::InvalidManifest(
            "manifest changed after creation".to_owned(),
        ));
    }
    Ok(report_from_verified(request.destination.clone(), &verified))
}

pub fn verify_backup(request: VerifyBackupRequest<'_>) -> Result<BackupReport, BackupError> {
    let limits = validated_limits(request.limits)?;
    let verified = verify_archive(&request.backup, request.local_security_seed, limits)?;
    Ok(report_from_verified(request.backup, &verified))
}

pub fn restore_backup(request: RestoreBackupRequest<'_>) -> Result<RestoreReport, BackupError> {
    let limits = validated_limits(request.limits)?;
    let verified = verify_archive(&request.backup, request.local_security_seed, limits)?;
    let prepared = prepare_empty_directory(&request.target)?;
    let result = ensure_disjoint(&request.backup, &request.target)
        .and_then(|()| restore_backup_inner(&request, &verified, limits));
    if result.is_err() {
        cleanup_directory(&request.target, &prepared);
    }
    result
}

fn restore_backup_inner(
    request: &RestoreBackupRequest<'_>,
    verified: &VerifiedArchive,
    limits: BackupLimits,
) -> Result<RestoreReport, BackupError> {
    for entry in &verified.manifest.entries {
        ensure_parent_directories(&request.target, &entry.path, limits)?;
        let source = request
            .backup
            .join(validate_relative_path(&entry.path, limits)?);
        let destination = request.target.join(&entry.path);
        if entry.role == BackupRole::Database {
            online_copy_database(&source, &destination, limits)?;
        } else {
            let (size, digest) = copy_regular_file(&source, &destination, limits.max_file_bytes)?;
            if size != entry.size_bytes || digest != entry.digest {
                return Err(BackupError::DigestMismatch(entry.path.clone()));
            }
        }
    }
    let manifest_bytes = read_bounded_file(
        &request.backup.join(MANIFEST_FILE_NAME),
        limits.max_manifest_bytes,
    )?;
    write_new_private_file(&request.target.join(MANIFEST_FILE_NAME), &manifest_bytes)?;

    let database = request.target.join(DATABASE_RELATIVE_PATH);
    let before = inspect_database(&database, limits)?;
    if before.installation_id != verified.manifest.installation_id
        || before.fencing_epoch != verified.manifest.source_fencing_epoch
    {
        return Err(BackupError::InvalidDatabase(
            "restored snapshot identity changed before fencing",
        ));
    }
    let control = ControlPlane::open(
        &database,
        verified.manifest.installation_id.clone(),
        request.restored_unix_ms,
    )?;
    let recovery = control.enter_restore_safe_mode(request.restored_unix_ms)?;
    drop(control);
    force_delete_journal_mode(&database)?;
    let expected_epoch = verified
        .manifest
        .source_fencing_epoch
        .checked_add(1)
        .ok_or(BackupError::LimitExceeded("fencing epoch"))?;
    if recovery.fencing_epoch != expected_epoch || !recovery.safe_mode {
        return Err(BackupError::UnexpectedFencingEpoch {
            expected: expected_epoch,
            actual: recovery.fencing_epoch,
        });
    }
    let after = inspect_database(&database, limits)?;
    if after.installation_id != verified.manifest.installation_id
        || after.fencing_epoch != expected_epoch
        || !after.safe_mode
    {
        return Err(BackupError::InvalidDatabase(
            "restored database did not retain safe mode and the new fence",
        ));
    }
    verify_required_key_state(
        &database,
        &after,
        request.local_security_seed,
        verified.manifest.local_key_continuity.as_ref(),
        limits,
    )?;
    verify_restored_files(&request.target, &verified.manifest, limits)?;
    sync_directory_tree(&request.target)?;
    Ok(RestoreReport {
        target: request.target.clone(),
        manifest_digest: verified.manifest_digest.clone(),
        installation_id: after.installation_id,
        source_fencing_epoch: verified.manifest.source_fencing_epoch,
        restored_fencing_epoch: after.fencing_epoch,
        safe_mode: after.safe_mode,
        entry_count: verified.manifest.entries.len(),
        total_bytes: verified.manifest.total_bytes,
    })
}

pub fn activate_restore(
    request: ActivateRestoreRequest<'_>,
) -> Result<ActivationReport, BackupError> {
    if !request.verification_acknowledged {
        return Err(BackupError::ActivationAcknowledgementRequired);
    }
    let limits = validated_limits(request.limits)?;
    require_backup_directory(&request.target)?;
    let manifest_bytes = read_bounded_file(
        &request.target.join(MANIFEST_FILE_NAME),
        limits.max_manifest_bytes,
    )?;
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, limits)?;
    verify_restored_files(&request.target, &manifest, limits)?;
    let database = request.target.join(DATABASE_RELATIVE_PATH);
    let inspection = inspect_database(&database, limits)?;
    if inspection.installation_id != manifest.installation_id
        || !inspection.safe_mode
        || inspection.fencing_epoch != request.expected_fencing_epoch
        || inspection.fencing_epoch != manifest.source_fencing_epoch.saturating_add(1)
    {
        return Err(BackupError::InvalidDatabase(
            "activation target is not at the exact post-restore safe-mode fence",
        ));
    }
    verify_authoritative_blob_roots(&request.target, &manifest, &inspection, limits)?;
    verify_required_key_state(
        &database,
        &inspection,
        request.local_security_seed,
        manifest.local_key_continuity.as_ref(),
        limits,
    )?;
    let control = ControlPlane::open(&database, manifest.installation_id.clone(), unix_ms()?)?;
    let state = control.leave_restore_safe_mode(request.expected_fencing_epoch)?;
    drop(control);
    force_delete_journal_mode(&database)?;
    let final_inspection = inspect_database(&database, limits)?;
    if final_inspection.safe_mode
        || final_inspection.fencing_epoch != request.expected_fencing_epoch
    {
        return Err(BackupError::InvalidDatabase(
            "activation did not durably leave safe mode",
        ));
    }
    Ok(ActivationReport {
        target: request.target,
        installation_id: manifest.installation_id,
        fencing_epoch: state.fencing_epoch,
        safe_mode: state.safe_mode,
    })
}

fn verify_authoritative_blob_roots(
    archive_root: &Path,
    manifest: &BackupManifest,
    inspection: &DatabaseInspection,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    if inspection.authoritative_blob_roots.is_empty() {
        return Ok(());
    }
    if !manifest.entries.iter().any(|entry| {
        entry.role == BackupRole::Blob && entry.path.starts_with("blobs/cas/objects/sha256/")
    }) {
        return Err(BackupError::InvalidManifest(
            "authoritative CAS roots exist but the archive has no CAS objects".to_owned(),
        ));
    }
    let cas = FsCas::open_read_only(archive_root.join("blobs/cas"), CasLimits::default())?;
    let reachable_limit = limits.max_entries.min(limits.max_database_records);
    let mut lifecycle_limits = LifecycleLimits::default();
    lifecycle_limits.maximum_roots = reachable_limit;
    lifecycle_limits.maximum_reachable_objects = reachable_limit;
    lifecycle_limits.maximum_inventory_objects = limits.max_entries;
    lifecycle_limits.maximum_manifest_bytes = lifecycle_limits
        .maximum_manifest_bytes
        .min(limits.max_file_bytes);
    verify_authoritative_object_graph(
        &cas,
        &inspection.authoritative_blob_roots,
        lifecycle_limits,
    )?;
    Ok(())
}

fn verify_archive(
    backup: &Path,
    seed: Option<&LocalSecuritySeed>,
    limits: BackupLimits,
) -> Result<VerifiedArchive, BackupError> {
    require_backup_directory(backup)?;
    let manifest_path = backup.join(MANIFEST_FILE_NAME);
    let manifest_bytes = read_bounded_file(&manifest_path, limits.max_manifest_bytes)?;
    let manifest_digest = ContentDigest::sha256(&manifest_bytes);
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, limits)?;
    let expected_files = manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .chain(std::iter::once(MANIFEST_FILE_NAME.to_owned()))
        .collect::<Vec<_>>();
    let actual_files = collect_relative_files(backup, limits)?;
    if actual_files != expected_files {
        return Err(BackupError::InvalidManifest(format!(
            "archive file set mismatch: expected {expected_files:?}, found {actual_files:?}"
        )));
    }
    for entry in &manifest.entries {
        let path = backup.join(validate_relative_path(&entry.path, limits)?);
        let limit = if entry.role == BackupRole::Database {
            limits.max_database_bytes
        } else {
            limits.max_file_bytes
        };
        let (size, digest) = hash_regular_file(&path, limit)?;
        if size != entry.size_bytes || digest != entry.digest {
            return Err(BackupError::DigestMismatch(entry.path.clone()));
        }
    }
    let database = backup.join(DATABASE_RELATIVE_PATH);
    let inspection = inspect_database(&database, limits)?;
    if inspection.installation_id != manifest.installation_id
        || inspection.schema_version != manifest.source_schema_version
        || inspection.fencing_epoch != manifest.source_fencing_epoch
    {
        return Err(BackupError::InvalidManifest(
            "manifest database identity does not match the snapshot".to_owned(),
        ));
    }
    verify_authoritative_blob_roots(backup, &manifest, &inspection, limits)?;
    verify_required_key_state(
        &database,
        &inspection,
        seed,
        manifest.local_key_continuity.as_ref(),
        limits,
    )?;
    Ok(VerifiedArchive {
        manifest,
        manifest_digest,
    })
}

fn verify_restored_files(
    target: &Path,
    manifest: &BackupManifest,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    let expected_files = manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .chain(std::iter::once(MANIFEST_FILE_NAME.to_owned()))
        .collect::<Vec<_>>();
    let actual_files = collect_relative_files(target, limits)?;
    if actual_files != expected_files {
        return Err(BackupError::InvalidManifest(format!(
            "restore file set mismatch: expected {expected_files:?}, found {actual_files:?}"
        )));
    }
    for entry in manifest
        .entries
        .iter()
        .filter(|entry| entry.role != BackupRole::Database)
    {
        let path = target.join(validate_relative_path(&entry.path, limits)?);
        let (size, digest) = hash_regular_file(&path, limits.max_file_bytes)?;
        if size != entry.size_bytes || digest != entry.digest {
            return Err(BackupError::DigestMismatch(entry.path.clone()));
        }
    }
    Ok(())
}

fn verify_required_key_state(
    database: &Path,
    inspection: &DatabaseInspection,
    seed: Option<&LocalSecuritySeed>,
    expected: Option<&LocalKeyContinuity>,
    limits: BackupLimits,
) -> Result<Option<LocalKeyContinuity>, BackupError> {
    if inspection.key_material_required || expected.is_some() {
        let seed = seed.ok_or(BackupError::KeyVerificationRequired)?;
        let continuity = verify_local_security_seed(database, seed.as_bytes(), expected, limits)?;
        return Ok(Some(continuity));
    }
    Ok(None)
}

fn validate_manifest(manifest: &BackupManifest, limits: BackupLimits) -> Result<(), BackupError> {
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(BackupError::UnsupportedBackupFormat(
            manifest.format_version,
        ));
    }
    if manifest.installation_id.is_empty()
        || manifest.installation_id.len() > 8 * 1024
        || manifest.source_schema_version == 0
        || manifest.source_schema_version > database::CURRENT_SCHEMA_VERSION
        || manifest.source_fencing_epoch == 0
        || manifest.entries.is_empty()
        || manifest.entries.len() > limits.max_entries
    {
        return Err(BackupError::InvalidManifest(
            "manifest identity, schema, fence, or entry count is invalid".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    let mut database_count = 0_usize;
    for entry in &manifest.entries {
        validate_relative_path(&entry.path, limits)?;
        if previous.is_some_and(|previous| previous >= entry.path.as_str())
            || !seen.insert(entry.path.as_str())
        {
            return Err(BackupError::InvalidManifest(
                "manifest paths must be unique and strictly sorted".to_owned(),
            ));
        }
        previous = Some(&entry.path);
        let valid_role_path = match entry.role {
            BackupRole::Database => entry.path == DATABASE_RELATIVE_PATH,
            BackupRole::Blob => entry.path.starts_with("blobs/"),
            BackupRole::Config => entry.path.starts_with("config/"),
            BackupRole::KeyCiphertext => entry.path.starts_with("key-ciphertext/"),
        };
        if !valid_role_path {
            return Err(BackupError::InvalidManifest(
                "manifest role does not match its path".to_owned(),
            ));
        }
        if entry.role == BackupRole::Database {
            database_count += 1;
            if entry.size_bytes == 0 || entry.size_bytes > limits.max_database_bytes {
                return Err(BackupError::LimitExceeded("database bytes"));
            }
        } else if entry.size_bytes > limits.max_file_bytes {
            return Err(BackupError::LimitExceeded("file bytes"));
        }
        total = total
            .checked_add(entry.size_bytes)
            .ok_or(BackupError::LimitExceeded("archive bytes"))?;
    }
    if database_count != 1 || total != manifest.total_bytes || total > limits.max_total_bytes {
        return Err(BackupError::InvalidManifest(
            "manifest database count or total byte count is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn report_from_verified(path: PathBuf, verified: &VerifiedArchive) -> BackupReport {
    BackupReport {
        backup: path,
        manifest_digest: verified.manifest_digest.clone(),
        installation_id: verified.manifest.installation_id.clone(),
        schema_version: verified.manifest.source_schema_version,
        fencing_epoch: verified.manifest.source_fencing_epoch,
        entry_count: verified.manifest.entries.len(),
        total_bytes: verified.manifest.total_bytes,
        local_key_continuity_verified: verified.manifest.local_key_continuity.is_some(),
    }
}

fn validated_limits(limits: BackupLimits) -> Result<BackupLimits, BackupError> {
    limits
        .validate()
        .map_err(|message| BackupError::InvalidConfiguration(message.to_owned()))
}

fn ensure_sources_outside_destination(
    source: &BackupSourcePaths,
    destination: &Path,
) -> Result<(), BackupError> {
    for directory in [
        source.blobs.as_deref(),
        source.config.as_deref(),
        source.key_ciphertext.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_disjoint(directory, destination)?;
    }
    ensure_disjoint(&source.database, destination)
}

fn ensure_disjoint(left: &Path, right: &Path) -> Result<(), BackupError> {
    let left = fs::canonicalize(left).map_err(|source| BackupError::Io {
        operation: "canonicalize path",
        path: left.to_owned(),
        source,
    })?;
    let right = fs::canonicalize(right).map_err(|source| BackupError::Io {
        operation: "canonicalize path",
        path: right.to_owned(),
        source,
    })?;
    if left.starts_with(&right) || right.starts_with(&left) {
        return Err(BackupError::OverlappingPaths { left, right });
    }
    Ok(())
}

pub fn current_unix_ms() -> Result<u64, BackupError> {
    unix_ms()
}

fn unix_ms() -> Result<u64, BackupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(BackupError::InvalidSystemTime)
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("invalid backup configuration: {0}")]
    InvalidConfiguration(String),
    #[error("unsupported backup format version {0}")]
    UnsupportedBackupFormat(u32),
    #[error("unsupported control-plane schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid backup manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid SQLite backup: {0}")]
    InvalidDatabase(&'static str),
    #[error("backup limit exceeded for {0}")]
    LimitExceeded(&'static str),
    #[error("backup source and destination overlap: {left} and {right}")]
    OverlappingPaths { left: PathBuf, right: PathBuf },
    #[error("destination {0} must not exist or must be an empty private directory")]
    DestinationNotEmpty(PathBuf),
    #[error("unsafe backup path: {0}")]
    UnsafePath(String),
    #[error("unsupported symlink or special file {0}")]
    UnsupportedFileType(PathBuf),
    #[error("directory {0} is writable by group or other users")]
    InsecurePermissions(PathBuf),
    #[error("source changed while it was being copied: {0}")]
    SourceChanged(PathBuf),
    #[error("digest or byte length mismatch for {0}")]
    DigestMismatch(String),
    #[error("SQLite online backup remained busy beyond its bounded retry budget")]
    DatabaseBusy,
    #[error("a valid local installation security seed is required to verify key-bound state")]
    KeyVerificationRequired,
    #[error("installation security seed must contain exactly 32 bytes")]
    InvalidSecuritySeed,
    #[error("local capsule/OIDC signing key continuity check failed")]
    KeyContinuityMismatch,
    #[error("restore activation requires an explicit completed-verification acknowledgement")]
    ActivationAcknowledgementRequired,
    #[error("post-restore fencing epoch is {actual}, expected {expected}")]
    UnexpectedFencingEpoch { expected: u64, actual: u64 },
    #[error("system clock cannot be represented as Unix milliseconds")]
    InvalidSystemTime,
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("SQLite backup operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("backup JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("content digest is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("capsule attestation verification failed: {0}")]
    Attest(#[from] runtrue_attest::AttestError),
    #[error("execution capsule verification failed: {0}")]
    Capsule(#[from] runtrue_workflow_ir::CapsuleError),
    #[error("audit chain verification failed: {0}")]
    Audit(#[from] runtrue_audit::AuditError),
    #[error("secret ciphertext verification failed")]
    Secrets(#[from] runtrue_secrets::SecretsError),
    #[error("control-plane recovery-state operation failed: {0}")]
    ControlPlane(#[from] ControlPlaneError),
    #[error("authoritative CAS verification failed: {0}")]
    Storage(#[from] runtrue_storage::StorageError),
    #[error("authoritative object graph verification failed: {0}")]
    Lifecycle(#[from] runtrue_output_lifecycle::LifecycleError),
}
