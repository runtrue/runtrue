use super::inspection::{bounded_count, table_exists, u64_column};
use crate::{
    secure_fs::{open_regular_guard, verify_guard_identity},
    BackupError, BackupLimits, LocalKeyContinuity,
};
use runtrue_attest::{CapsuleSignature, CapsuleSigningKey, CapsuleVerifyingKey};
use runtrue_oidc::OidcSigningKey;
use runtrue_secrets::{MasterKey, SecretVault, SecretVaultSnapshot};
use runtrue_workflow_ir::ExecutionCapsule;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use zeroize::Zeroize as _;

pub(crate) fn verify_local_security_seed(
    database_path: &Path,
    seed: &[u8; 32],
    expected: Option<&LocalKeyContinuity>,
    limits: BackupLimits,
) -> Result<LocalKeyContinuity, BackupError> {
    let guard = open_regular_guard(database_path)?;
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    verify_guard_identity(database_path, &guard)?;
    let mut capsule_seed = derive_security_seed(seed, b"capsule-signing");
    let mut secret_seed = derive_security_seed(seed, b"secret-vault");
    let mut oidc_seed = derive_security_seed(seed, b"oidc-signing");
    let capsule_key = CapsuleSigningKey::from_seed(capsule_seed).verifying_key();
    let master_key = MasterKey::from_bytes(secret_seed);
    let oidc_key = OidcSigningKey::from_seed(oidc_seed).verifying_key();
    capsule_seed.zeroize();
    secret_seed.zeroize();
    oidc_seed.zeroize();
    let continuity = LocalKeyContinuity {
        capsule_signing_key_id: capsule_key.key_id(),
        oidc_signing_key_id: oidc_key.key_id(),
    };
    if expected.is_some_and(|expected| expected != &continuity) {
        return Err(BackupError::KeyContinuityMismatch);
    }
    verify_capsules(&connection, &capsule_key, limits)?;
    verify_secret_snapshots(&connection, &master_key, limits)?;
    verify_guard_identity(database_path, &guard)?;
    Ok(continuity)
}

pub(super) fn verify_integrity(connection: &Connection) -> Result<(), BackupError> {
    let mut statement = connection.prepare("PRAGMA integrity_check")?;
    let mut rows = statement.query([])?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        if results.len() >= 1_024 {
            return Err(BackupError::LimitExceeded("SQLite integrity results"));
        }
        let result: String = row.get(0)?;
        if result.len() > 64 * 1024 {
            return Err(BackupError::LimitExceeded("SQLite integrity result bytes"));
        }
        results.push(result);
    }
    if results.as_slice() != ["ok"] {
        return Err(BackupError::InvalidDatabase(
            "SQLite integrity_check did not return ok",
        ));
    }
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(BackupError::InvalidDatabase(
            "SQLite foreign_key_check reported a violation",
        ));
    }
    Ok(())
}

fn verify_capsules(
    connection: &Connection,
    key: &CapsuleVerifyingKey,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    let count = bounded_count(connection, "capsules", limits.max_database_records)?;
    let mut statement = connection.prepare(
        "SELECT length(canonical_capsule), canonical_capsule, signature_json
         FROM capsules ORDER BY id",
    )?;
    let mut rows = statement.query([])?;
    let mut seen = 0_usize;
    while let Some(row) = rows.next()? {
        let capsule_length = u64_column(row, 0)?;
        if capsule_length > limits.max_database_record_bytes {
            return Err(BackupError::LimitExceeded("canonical capsule bytes"));
        }
        let canonical: Vec<u8> = row.get(1)?;
        let signature_json: String = row.get(2)?;
        if signature_json.len() as u64 > limits.max_database_record_bytes {
            return Err(BackupError::LimitExceeded("capsule signature bytes"));
        }
        let capsule: ExecutionCapsule = serde_json::from_slice(&canonical)?;
        if capsule.canonical_bytes()? != canonical {
            return Err(BackupError::InvalidDatabase("capsule is not canonical"));
        }
        let signature: CapsuleSignature = serde_json::from_str(&signature_json)?;
        key.verify_capsule(&capsule, &signature)?;
        seen += 1;
    }
    if seen != count {
        return Err(BackupError::InvalidDatabase(
            "capsule count changed during verification",
        ));
    }
    Ok(())
}

fn verify_secret_snapshots(
    connection: &Connection,
    master_key: &MasterKey,
    limits: BackupLimits,
) -> Result<(), BackupError> {
    if !table_exists(connection, "secret_vault_snapshots")? {
        return Ok(());
    }
    let count = bounded_count(
        connection,
        "secret_vault_snapshots",
        limits.max_database_records,
    )?;
    let mut statement = connection.prepare(
        "SELECT length(snapshot_json), snapshot_json
         FROM secret_vault_snapshots ORDER BY tenant_id, scope",
    )?;
    let mut rows = statement.query([])?;
    let mut seen = 0_usize;
    while let Some(row) = rows.next()? {
        let length = u64_column(row, 0)?;
        if length > limits.max_database_record_bytes {
            return Err(BackupError::LimitExceeded("secret snapshot bytes"));
        }
        let encoded: Vec<u8> = row.get(1)?;
        let snapshot: SecretVaultSnapshot = serde_json::from_slice(&encoded)?;
        drop(SecretVault::from_snapshot(
            snapshot,
            master_key.duplicate(),
        )?);
        seen += 1;
    }
    if seen != count {
        return Err(BackupError::InvalidDatabase(
            "secret snapshot count changed during verification",
        ));
    }
    Ok(())
}

fn derive_security_seed(seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.server.security-key.v1\0");
    hash.update(domain);
    hash.update(seed);
    hash.finalize().into()
}
