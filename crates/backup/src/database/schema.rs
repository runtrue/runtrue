use super::inspection::table_exists;
use crate::BackupError;
use runtrue_control_plane::migration::{
    forward_catalog_entries, legacy_baseline_catalog_entry, MigrationBackend,
    SQLITE_RETIRED_USER_VERSION,
};
use rusqlite::Connection;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 34;

pub(super) fn verify_schema(connection: &Connection) -> Result<u32, BackupError> {
    let version = physical_schema_version(connection)?;
    for table in [
        "schema_migrations",
        "installation_state",
        "repositories",
        "capsules",
        "runs",
        "jobs",
        "leases",
        "audit_events",
    ] {
        if !table_exists(connection, table)? {
            return Err(BackupError::InvalidDatabase("required table is missing"));
        }
    }
    for (introduced, table) in [
        (13, "runner_data_commits"),
        (13, "job_result_objects"),
        (14, "runner_object_transfers"),
        (15, "source_snapshots"),
        (15, "run_source_snapshots"),
        (15, "runner_source_tickets"),
        (16, "scm_installations"),
        (16, "scm_repository_links"),
        (16, "scm_source_fetches"),
        (17, "cache_trust_generations"),
        (17, "cache_promotion_journal"),
        (18, "artifacts_catalog"),
        (18, "artifact_download_tickets"),
        (18, "report_summaries"),
        (19, "tenant_storage_quotas"),
        (19, "tenant_storage_reservations"),
        (19, "artifact_scan_journal"),
        (19, "artifact_promotion_bindings"),
        (19, "backup_pins"),
        (19, "lifecycle_gc_control"),
        (19, "lifecycle_gc_marks"),
        (19, "lifecycle_gc_candidates"),
        (19, "lifecycle_gc_cycles"),
        (20, "expanded_job_sets"),
        (20, "normalized_trigger_events"),
        (20, "schedule_trigger_cursors"),
        (21, "tenant_storage_ticket_bindings"),
        (21, "tenant_storage_objects"),
        (22, "scm_check_publications"),
        (23, "tenants"),
        (23, "tenant_oidc_provider_configs"),
        (23, "human_users"),
        (23, "human_user_tenant_bindings"),
        (23, "human_identities"),
        (23, "tenant_memberships"),
        (23, "oidc_browser_transactions"),
        (23, "oidc_browser_transaction_events"),
        (23, "browser_sessions"),
        (23, "browser_session_events"),
        (23, "browser_refresh_family_tokens"),
        (23, "policy_bundle_drafts"),
        (23, "policy_simulation_reports"),
        (23, "policy_shadow_reports"),
        (23, "tenant_policy_states"),
        (23, "policy_activations"),
        (23, "emergency_deny_replacements"),
        (24, "tenant_provider_configurations"),
        (24, "tenant_provider_configuration_versions"),
        (24, "signer_policies"),
        (24, "signer_policy_versions"),
        (24, "environments"),
        (24, "environment_versions"),
        (24, "deployment_requests"),
        (24, "environment_concurrency_leases"),
        (24, "deployments"),
        (24, "deployment_request_events"),
        (24, "external_secret_release_journal"),
        (24, "signing_result_journal"),
        (25, "github_app_setup_transactions"),
        (25, "github_installation_profiles"),
        (25, "github_repository_catalog"),
        (25, "github_lifecycle_deliveries"),
        (26, "scm_webhook_events"),
        (33, "configuration_projects"),
        (33, "configuration_project_targets"),
        (34, "runner_pool_scaling_policies"),
        (34, "runner_pool_templates"),
        (34, "runner_fleet_requests"),
        (34, "runner_launch_claims"),
        (34, "runner_autoscaler_leases"),
    ] {
        if version >= introduced && !table_exists(connection, table)? {
            return Err(BackupError::InvalidDatabase(
                "versioned required table is missing",
            ));
        }
    }
    verify_merged_lineage(connection, version)?;
    if table_exists(connection, "runtrue_schema_migrations")? {
        let reusable_approval_index: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'index' AND name = 'approval_requests_reusable_subject'
            )",
            [],
            |row| row.get(0),
        )?;
        if !reusable_approval_index {
            return Err(BackupError::InvalidDatabase(
                "reusable capability-approval index is missing",
            ));
        }
    }
    let migrations = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")?
        .query_map([], |row| row.get::<_, u32>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = (1..=version).collect::<Vec<_>>();
    if migrations != expected {
        return Err(BackupError::InvalidDatabase(
            "schema migration history does not match user_version",
        ));
    }
    let installation_rows: u64 =
        connection.query_row("SELECT COUNT(*) FROM installation_state", [], |row| {
            row.get(0)
        })?;
    if installation_rows != 1 {
        return Err(BackupError::InvalidDatabase(
            "installation_state must contain exactly one row",
        ));
    }
    Ok(version)
}

fn physical_schema_version(connection: &Connection) -> Result<u32, BackupError> {
    let legacy_marker: u32 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !table_exists(connection, "runtrue_schema_migrations")? {
        if legacy_marker == 0 || legacy_marker > CURRENT_SCHEMA_VERSION {
            return Err(BackupError::UnsupportedSchema(legacy_marker));
        }
        return Ok(legacy_marker);
    }
    if legacy_marker != SQLITE_RETIRED_USER_VERSION {
        return Err(BackupError::InvalidDatabase(
            "unified migration ledger has an invalid legacy authority marker",
        ));
    }
    let (baseline, _) = legacy_baseline_catalog_entry(MigrationBackend::Sqlite).map_err(|_| {
        BackupError::InvalidDatabase("the embedded unified migration catalog is invalid")
    })?;
    let mut expected = vec![baseline];
    expected.extend(
        forward_catalog_entries(MigrationBackend::Sqlite).map_err(|_| {
            BackupError::InvalidDatabase("the embedded unified migration catalog is invalid")
        })?,
    );
    let rows: Vec<(u32, String, Vec<u8>, Vec<u8>)> = connection
        .prepare(
            "SELECT sequence,migration_id,definition_sha256,implementation_sha256
             FROM runtrue_schema_migrations ORDER BY sequence",
        )?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let matches_catalog = rows.len() == expected.len()
        && rows.iter().zip(&expected).all(|(row, migration)| {
            row.0 == migration.sequence
                && row.1 == migration.migration_id
                && row.2 == migration.definition_sha256
                && row.3 == migration.implementation_sha256
        });
    if !matches_catalog {
        return Err(BackupError::InvalidDatabase(
            "unified migration ledger does not match the embedded catalog",
        ));
    }
    Ok(CURRENT_SCHEMA_VERSION)
}

fn verify_merged_lineage(connection: &Connection, version: u32) -> Result<(), BackupError> {
    if version < 29 {
        return Ok(());
    }
    let frontend_reports = table_exists(connection, "workflow_frontend_reports")?;
    let credential_taint: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pragma_table_info('leases')
            WHERE name = 'terminal_credential_taint'
              AND type = 'TEXT' AND \"notnull\" = 1
        )",
        [],
        |row| row.get(0),
    )?;
    let repository_settings = table_exists(connection, "repository_workflow_settings")?;
    let workflow_path = column_exists(connection, "repository_workflow_settings", "workflow_path")?;
    let workflow_directory = column_exists(
        connection,
        "repository_workflow_settings",
        "workflow_directory",
    )?;

    let valid = match version {
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
        32..=34 => {
            frontend_reports
                && credential_taint
                && repository_settings
                && !workflow_path
                && workflow_directory
        }
        _ => false,
    };
    if !valid {
        return Err(BackupError::InvalidDatabase(
            "schema lineage features do not match the declared version",
        ));
    }
    Ok(())
}

fn column_exists(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        rusqlite::params![table, column],
        |row| row.get(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_control_plane::ControlPlane;

    #[test]
    fn schema_twenty_five_backup_validation_requires_github_installation_lifecycle_tables() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sqlite3");
        drop(ControlPlane::open(&path, "backup-schema-25", 1).unwrap());

        let connection = Connection::open(&path).unwrap();
        verify_schema(&connection).unwrap();
        connection
            .execute_batch("DROP TABLE github_lifecycle_deliveries;")
            .unwrap();
        drop(connection);

        // Unified-ledger startup and backup inspection both fail closed; the
        // missing authoritative table is never silently recreated.
        assert!(matches!(
            ControlPlane::open(&path, "backup-schema-25", 2),
            Err(runtrue_control_plane::ControlPlaneError::InvalidMigrationHistory(_))
        ));
        let connection = Connection::open(&path).unwrap();
        assert!(matches!(
            verify_schema(&connection),
            Err(BackupError::InvalidDatabase(
                "versioned required table is missing"
            ))
        ));
    }

    #[test]
    fn merged_schema_backup_validation_requires_all_durable_features() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sqlite3");
        drop(ControlPlane::open(&path, "backup-schema-32", 1).unwrap());

        let connection = Connection::open(&path).unwrap();
        verify_schema(&connection).unwrap();
        connection
            .pragma_update(None, "foreign_keys", false)
            .unwrap();
        connection
            .execute_batch("ALTER TABLE leases DROP COLUMN terminal_credential_taint;")
            .unwrap();
        assert!(matches!(
            verify_schema(&connection),
            Err(BackupError::InvalidDatabase(
                "schema lineage features do not match the declared version"
            ))
        ));

        drop(connection);
        let clean_path = directory.path().join("control-clean.sqlite3");
        drop(ControlPlane::open(&clean_path, "backup-schema-32", 1).unwrap());
        let connection = Connection::open(&clean_path).unwrap();
        connection
            .execute_batch("DROP TABLE workflow_frontend_reports;")
            .unwrap();
        assert!(matches!(
            verify_schema(&connection),
            Err(BackupError::InvalidDatabase(
                "schema lineage features do not match the declared version"
            ))
        ));
    }

    #[test]
    fn current_schema_requires_secret_project_and_runner_fleet_tables() {
        let directory = tempfile::tempdir().unwrap();
        for table in ["configuration_project_targets", "runner_launch_claims"] {
            let path = directory.path().join(format!("missing-{table}.sqlite3"));
            drop(ControlPlane::open(&path, "backup-schema-34", 1).unwrap());
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(&format!("DROP TABLE {table};"))
                .unwrap();
            assert!(matches!(
                verify_schema(&connection),
                Err(BackupError::InvalidDatabase(
                    "versioned required table is missing"
                ))
            ));
        }
    }
}
