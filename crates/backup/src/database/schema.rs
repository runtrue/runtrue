use super::inspection::table_exists;
use crate::BackupError;
use rusqlite::Connection;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 28;

pub(super) fn verify_schema(connection: &Connection) -> Result<(), BackupError> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 || version > CURRENT_SCHEMA_VERSION {
        return Err(BackupError::UnsupportedSchema(version));
    }
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
    ] {
        if version >= introduced && !table_exists(connection, table)? {
            return Err(BackupError::InvalidDatabase(
                "versioned required table is missing",
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
    Ok(())
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

        // Reopening SQLite cannot silently repair a database already claiming
        // schema 25; backup activation must reject the missing authoritative table.
        drop(ControlPlane::open(&path, "backup-schema-25", 2).unwrap());
        let connection = Connection::open(&path).unwrap();
        assert!(matches!(
            verify_schema(&connection),
            Err(BackupError::InvalidDatabase(
                "versioned required table is missing"
            ))
        ));
    }
}
