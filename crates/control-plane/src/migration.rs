//! Backend-neutral migration catalog and ledger identities.
//!
//! SQL and catalog inspection stay in the owning backend adapters. This
//! module owns the portable ordering, identity, digest, and report contract.

use crate::ControlPlaneError;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub const LOGICAL_SCHEMA_GENERATION: u32 = 6;
pub const LEGACY_BASELINE_SEQUENCE: u32 = 1;
pub const LEGACY_BASELINE_ID: &str = "legacy-baseline-v1";
pub const SQLITE_LEGACY_SCHEMA_VERSION: u32 = 34;
pub const POSTGRES_LEGACY_SCHEMA_VERSION: u32 = 12;

/// Deliberately exceeds every legacy SQLite generation. Older binaries reject
/// it before touching a database whose authority has moved to the unified
/// ledger.
pub const SQLITE_RETIRED_USER_VERSION: u32 = 0x5254_0019;

const BASELINE_DEFINITION: &str =
    include_str!("../migrations/unified/0001_legacy_baseline/definition.json");
const SQLITE_BASELINE_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0001_legacy_baseline/sqlite.json");
const POSTGRES_BASELINE_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0001_legacy_baseline/postgres.json");
const REPLACEMENT_DEFINITION: &str =
    include_str!("../migrations/unified/0002_runner_immutable_replacement/definition.json");
const SQLITE_REPLACEMENT_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0002_runner_immutable_replacement/sqlite.json");
const POSTGRES_REPLACEMENT_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0002_runner_immutable_replacement/postgres.json");
const APPROVALS_DEFINITION: &str =
    include_str!("../migrations/unified/0003_reusable_capability_approvals/definition.json");
const SQLITE_APPROVALS_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0003_reusable_capability_approvals/sqlite.json");
const POSTGRES_APPROVALS_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0003_reusable_capability_approvals/postgres.json");
const USER_MANAGEMENT_DEFINITION: &str =
    include_str!("../migrations/unified/0004_user_management/definition.json");
const SQLITE_USER_MANAGEMENT_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0004_user_management/sqlite.json");
const POSTGRES_USER_MANAGEMENT_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0004_user_management/postgres.json");
const EVENT_REPLAY_DEFINITION: &str =
    include_str!("../migrations/unified/0005_durable_event_replay/definition.json");
const SQLITE_EVENT_REPLAY_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0005_durable_event_replay/sqlite.json");
const POSTGRES_EVENT_REPLAY_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0005_durable_event_replay/postgres.json");
const SCM_EVENT_RECOVERY_DEFINITION: &str =
    include_str!("../migrations/unified/0006_scm_event_recovery/definition.json");
const SQLITE_SCM_EVENT_RECOVERY_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0006_scm_event_recovery/sqlite.json");
const POSTGRES_SCM_EVENT_RECOVERY_IMPLEMENTATION: &str =
    include_str!("../migrations/unified/0006_scm_event_recovery/postgres.json");
const HISTORY_DIGEST_DOMAIN: &[u8] = b"runtrue.migration.legacy-history.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationBackend {
    Sqlite,
    Postgres,
}

impl MigrationBackend {
    const fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedMigration {
    pub sequence: u32,
    pub migration_id: &'static str,
    pub logical_schema_generation: u32,
    pub definition_sha256: [u8; 32],
    pub implementation_sha256: [u8; 32],
    pub sql: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MigrationReport {
    pub backend: MigrationBackend,
    pub logical_schema_generation: u32,
    pub applied_migration_ids: Vec<String>,
    pub replayed_migration_ids: Vec<String>,
    pub bridged_legacy_lineage: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedDefinition {
    sequence: u32,
    migration_id: String,
    logical_schema_generation: u32,
    purpose: String,
    preconditions: Vec<String>,
    postconditions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendImplementation {
    backend: String,
    legacy_lineage: String,
    legacy_head: u32,
    legacy_history_sha256: String,
    schema_contract: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardImplementation {
    backend: String,
    sql: String,
    #[serde(default)]
    post_sql: String,
    #[serde(default)]
    trust_sql: String,
}

pub(crate) fn materialize_catalog(
    backend: MigrationBackend,
    legacy_migrations: &[&str],
) -> Result<(Vec<MaterializedMigration>, String), ControlPlaneError> {
    let (baseline, lineage) = materialize_legacy_baseline(backend, legacy_migrations)?;
    let mut catalog = vec![baseline];
    catalog.extend(forward_catalog_entries(backend)?);
    Ok((catalog, lineage))
}

/// Return the exact forward migration identities embedded in this binary.
/// Backup tooling combines these with the separately verified frozen baseline.
pub fn forward_catalog_entries(
    backend: MigrationBackend,
) -> Result<Vec<MaterializedMigration>, ControlPlaneError> {
    let definition: SharedDefinition = serde_json::from_str(REPLACEMENT_DEFINITION)?;
    if definition.sequence != 2
        || definition.migration_id != "runner-immutable-replacement-v1"
        || definition.logical_schema_generation != 2
        || definition.purpose.is_empty()
        || definition.preconditions.is_empty()
        || definition.postconditions.is_empty()
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "runner replacement migration definition is invalid".to_owned(),
        ));
    }
    let implementation_bytes = match backend {
        MigrationBackend::Sqlite => SQLITE_REPLACEMENT_IMPLEMENTATION,
        MigrationBackend::Postgres => POSTGRES_REPLACEMENT_IMPLEMENTATION,
    };
    let implementation: ForwardImplementation = serde_json::from_str(implementation_bytes)?;
    if implementation.backend != backend.name() || implementation.sql.trim().is_empty() {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "{} runner replacement migration implementation is invalid",
            backend.name()
        )));
    }
    let approvals = materialize_forward_migration(
        backend,
        APPROVALS_DEFINITION,
        SQLITE_APPROVALS_IMPLEMENTATION,
        POSTGRES_APPROVALS_IMPLEMENTATION,
        3,
        "reusable-capability-approvals-v1",
    )?;
    let user_management = materialize_forward_migration(
        backend,
        USER_MANAGEMENT_DEFINITION,
        SQLITE_USER_MANAGEMENT_IMPLEMENTATION,
        POSTGRES_USER_MANAGEMENT_IMPLEMENTATION,
        4,
        "user-management-v1",
    )?;
    let event_replay = materialize_forward_migration(
        backend,
        EVENT_REPLAY_DEFINITION,
        SQLITE_EVENT_REPLAY_IMPLEMENTATION,
        POSTGRES_EVENT_REPLAY_IMPLEMENTATION,
        5,
        "durable-event-replay-v1",
    )?;
    let scm_event_recovery = materialize_forward_migration(
        backend,
        SCM_EVENT_RECOVERY_DEFINITION,
        SQLITE_SCM_EVENT_RECOVERY_IMPLEMENTATION,
        POSTGRES_SCM_EVENT_RECOVERY_IMPLEMENTATION,
        6,
        "scm-event-recovery-v1",
    )?;
    Ok(vec![
        MaterializedMigration {
            sequence: definition.sequence,
            migration_id: "runner-immutable-replacement-v1",
            logical_schema_generation: definition.logical_schema_generation,
            definition_sha256: Sha256::digest(REPLACEMENT_DEFINITION.as_bytes()).into(),
            implementation_sha256: Sha256::digest(implementation_bytes.as_bytes()).into(),
            sql: Some(format!(
                "{} {} {}",
                implementation.sql, implementation.trust_sql, implementation.post_sql
            )),
        },
        approvals,
        user_management,
        event_replay,
        scm_event_recovery,
    ])
}

fn materialize_forward_migration(
    backend: MigrationBackend,
    definition_bytes: &'static str,
    sqlite_implementation: &'static str,
    postgres_implementation: &'static str,
    expected_sequence: u32,
    expected_id: &'static str,
) -> Result<MaterializedMigration, ControlPlaneError> {
    let definition: SharedDefinition = serde_json::from_str(definition_bytes)?;
    if definition.sequence != expected_sequence
        || definition.migration_id != expected_id
        || definition.logical_schema_generation != expected_sequence
        || definition.purpose.is_empty()
        || definition.preconditions.is_empty()
        || definition.postconditions.is_empty()
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "{expected_id} migration definition is invalid"
        )));
    }
    let implementation_bytes = match backend {
        MigrationBackend::Sqlite => sqlite_implementation,
        MigrationBackend::Postgres => postgres_implementation,
    };
    let implementation: ForwardImplementation = serde_json::from_str(implementation_bytes)?;
    if implementation.backend != backend.name() || implementation.sql.trim().is_empty() {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "{} {expected_id} migration implementation is invalid",
            backend.name()
        )));
    }
    Ok(MaterializedMigration {
        sequence: definition.sequence,
        migration_id: expected_id,
        logical_schema_generation: definition.logical_schema_generation,
        definition_sha256: Sha256::digest(definition_bytes.as_bytes()).into(),
        implementation_sha256: Sha256::digest(implementation_bytes.as_bytes()).into(),
        sql: Some(format!(
            "{} {} {}",
            implementation.sql, implementation.trust_sql, implementation.post_sql
        )),
    })
}

pub(crate) fn materialize_legacy_baseline(
    backend: MigrationBackend,
    legacy_migrations: &[&str],
) -> Result<(MaterializedMigration, String), ControlPlaneError> {
    let (materialized, implementation) = parse_legacy_baseline_catalog_entry(backend)?;
    let expected_head = match backend {
        MigrationBackend::Sqlite => SQLITE_LEGACY_SCHEMA_VERSION,
        MigrationBackend::Postgres => POSTGRES_LEGACY_SCHEMA_VERSION,
    };
    let history_digest = legacy_history_digest(backend, legacy_migrations);
    if implementation.legacy_head != expected_head
        || legacy_migrations.len() != expected_head as usize
        || implementation.legacy_history_sha256 != hex::encode(history_digest)
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "{} unified baseline implementation does not match its frozen legacy history",
            backend.name()
        )));
    }
    Ok((materialized, implementation.legacy_lineage))
}

/// Return the exact catalog identity used by tooling that validates a
/// database but does not own the backend's frozen legacy SQL history.
pub fn legacy_baseline_catalog_entry(
    backend: MigrationBackend,
) -> Result<(MaterializedMigration, String), ControlPlaneError> {
    let (materialized, implementation) = parse_legacy_baseline_catalog_entry(backend)?;
    Ok((materialized, implementation.legacy_lineage))
}

fn parse_legacy_baseline_catalog_entry(
    backend: MigrationBackend,
) -> Result<(MaterializedMigration, BackendImplementation), ControlPlaneError> {
    let definition: SharedDefinition = serde_json::from_str(BASELINE_DEFINITION)?;
    if definition.sequence != LEGACY_BASELINE_SEQUENCE
        || definition.migration_id != LEGACY_BASELINE_ID
        || definition.logical_schema_generation != 1
        || definition.purpose.is_empty()
        || definition.preconditions.is_empty()
        || definition.postconditions.is_empty()
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "unified migration catalog definition is invalid".to_owned(),
        ));
    }

    let implementation_bytes = match backend {
        MigrationBackend::Sqlite => SQLITE_BASELINE_IMPLEMENTATION,
        MigrationBackend::Postgres => POSTGRES_BASELINE_IMPLEMENTATION,
    };
    let implementation: BackendImplementation = serde_json::from_str(implementation_bytes)?;
    let expected_head = match backend {
        MigrationBackend::Sqlite => SQLITE_LEGACY_SCHEMA_VERSION,
        MigrationBackend::Postgres => POSTGRES_LEGACY_SCHEMA_VERSION,
    };
    if implementation.backend != backend.name()
        || implementation.legacy_head != expected_head
        || implementation.legacy_history_sha256.len() != 64
        || !matches!(
            hex::decode(&implementation.legacy_history_sha256),
            Ok(digest) if digest.len() == 32
        )
        || implementation.legacy_lineage.is_empty()
        || implementation.schema_contract.is_empty()
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "{} unified baseline implementation does not match its frozen legacy history",
            backend.name()
        )));
    }

    Ok((
        MaterializedMigration {
            sequence: definition.sequence,
            migration_id: LEGACY_BASELINE_ID,
            logical_schema_generation: definition.logical_schema_generation,
            definition_sha256: Sha256::digest(BASELINE_DEFINITION.as_bytes()).into(),
            implementation_sha256: Sha256::digest(implementation_bytes.as_bytes()).into(),
            sql: None,
        },
        implementation,
    ))
}

fn legacy_history_digest(backend: MigrationBackend, migrations: &[&str]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HISTORY_DIGEST_DOMAIN);
    let backend = backend.name().as_bytes();
    digest.update((backend.len() as u64).to_be_bytes());
    digest.update(backend);
    for (offset, migration) in migrations.iter().enumerate() {
        digest.update(u32::try_from(offset + 1).unwrap_or(u32::MAX).to_be_bytes());
        digest.update((migration.len() as u64).to_be_bytes());
        digest.update(migration.as_bytes());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_payloads_bind_distinct_exact_histories_to_one_definition() {
        let sqlite = materialize_legacy_baseline(MigrationBackend::Sqlite, &["one"]);
        assert!(matches!(
            sqlite,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));
        assert_ne!(
            Sha256::digest(SQLITE_BASELINE_IMPLEMENTATION),
            Sha256::digest(POSTGRES_BASELINE_IMPLEMENTATION)
        );
        let definition: SharedDefinition = serde_json::from_str(BASELINE_DEFINITION).unwrap();
        assert_eq!(definition.sequence, 1);
        assert_eq!(definition.migration_id, LEGACY_BASELINE_ID);
    }
}
