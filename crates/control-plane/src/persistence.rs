//! Database-backend contracts extracted at durable use-case boundaries.
//!
//! SQLite is the embedded backend and PostgreSQL is the external backend.
//! Both implement the same transaction-sized domain contracts collected by
//! `ControlPlaneStore`; backend activation depends on those shared behavioral
//! contracts, not merely on schema availability.

mod api_tokens;
pub use api_tokens::ApiTokenAuditStore;
mod artifacts_lifecycle;
pub use artifacts_lifecycle::{
    ArtifactCatalogStore, ArtifactScanPromotionStore, ArtifactStorageStore, CacheTrustStore,
};
mod browser_sessions;
pub use browser_sessions::BrowserSessionStore;
mod deployment_provider;
pub use deployment_provider::{
    DeploymentProviderStore, DeploymentRequestStore, DeploymentResultStore, EnvironmentGateStore,
    SigningResultStore,
};
mod durable_lifecycle;
pub use durable_lifecycle::{DurableTaskStore, LifecycleGcStore};
mod external_release;
pub use external_release::ExternalSecretReleaseStore;
mod events;
pub use events::EventStore;
mod scm_repositories;
pub use scm_repositories::ScmRepositoryStore;
mod user_management;
pub use user_management::UserManagementStore;
mod runner_authority;
mod runs_approvals;
pub use runner_authority::{
    AutoscaledReplacementPlan, PoolEnrollmentCompletion, RunnerFleetEnrollmentStore,
    RunnerLeaseBrokerStore, RunnerPoolConfiguration,
};
pub use runs_approvals::{
    ApprovalStore, RunCoreStore, SourceSnapshotStore, WorkflowSemanticsStore,
};
mod secrets_policy;
pub use secrets_policy::{
    ConfigurationProjectStore, OidcGrantStore, PolicyLifecycleStore, PolicyVersionStore,
    SecretConfigurationStore, VariableConfigurationStore,
};

#[cfg(feature = "postgres")]
use crate::migration::{
    materialize_catalog, MaterializedMigration, MigrationBackend, MigrationReport,
    LOGICAL_SCHEMA_GENERATION, POSTGRES_LEGACY_SCHEMA_VERSION,
};
#[cfg(feature = "postgres")]
use crate::store::database::SQLITE_LEGACY_TABLES;
use crate::{
    ControlPlane, ControlPlaneError, HumanIdentityRecord, HumanUserRecord,
    InstallationRecoveryState, TenantIdentityRecord, TenantMembershipRecord,
    TenantOidcProviderConfiguration,
};
#[cfg(any(feature = "postgres", test))]
use runtrue_model::ContentDigest;
#[cfg(feature = "postgres")]
use sha2::{Digest as _, Sha256};
#[cfg(feature = "postgres")]
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
    Connection as _, PgPool, Row as _,
};
#[cfg(feature = "postgres")]
use std::{collections::BTreeSet, fmt, net::IpAddr, str::FromStr as _, time::Duration};
use std::{future::Future, pin::Pin};

#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_1: &str =
    include_str!("../migrations/postgres/0001_installation_state.sql");
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_2: &str =
    include_str!("../migrations/postgres/0002_tenant_identities.sql");
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_3: &str = include_str!("../migrations/postgres/0003_human_identity.sql");
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_4: &str = api_tokens::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_5: &str = scm_repositories::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_6: &str = runner_authority::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_7: &str = browser_sessions::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_8: &str = secrets_policy::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_9: &str = runs_approvals::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_10: &str = artifacts_lifecycle::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_11: &str = deployment_provider::POSTGRES_MIGRATION;
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_12: &str =
    include_str!("../migrations/postgres/0012_transfer_lifecycle.sql");
#[cfg(feature = "postgres")]
const POSTGRES_MIGRATION_LOCK_KEY: i64 = 0x5275_6e54_7275_6501;

/// Current backend schema generation represented by the unified baseline.
#[cfg(feature = "postgres")]
pub const POSTGRES_SCHEMA_VERSION: u32 = POSTGRES_LEGACY_SCHEMA_VERSION;

#[cfg(feature = "postgres")]
const POSTGRES_MIGRATIONS: [(i32, &str); POSTGRES_SCHEMA_VERSION as usize] = [
    (1, POSTGRES_MIGRATION_1),
    (2, POSTGRES_MIGRATION_2),
    (3, POSTGRES_MIGRATION_3),
    (4, POSTGRES_MIGRATION_4),
    (5, POSTGRES_MIGRATION_5),
    (6, POSTGRES_MIGRATION_6),
    (7, POSTGRES_MIGRATION_7),
    (8, POSTGRES_MIGRATION_8),
    (9, POSTGRES_MIGRATION_9),
    (10, POSTGRES_MIGRATION_10),
    (11, POSTGRES_MIGRATION_11),
    (12, POSTGRES_MIGRATION_12),
];

#[cfg(feature = "postgres")]
const POSTGRES_UNIFIED_LEDGER_DDL: &str = "
CREATE TABLE runtrue_schema_migrations (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    migration_id TEXT NOT NULL UNIQUE CHECK (length(migration_id) BETWEEN 1 AND 200),
    definition_sha256 BYTEA NOT NULL CHECK (octet_length(definition_sha256) = 32),
    implementation_sha256 BYTEA NOT NULL CHECK (octet_length(implementation_sha256) = 32),
    applied_unix_ms BIGINT NOT NULL CHECK (applied_unix_ms >= 0)
);";

#[cfg(feature = "postgres")]
const POSTGRES_ONLY_LEGACY_TABLES: &[&str] = &[
    "postgres_transfer_state",
    "runner_enrollment_idempotency",
    "runner_oidc_grants",
];

type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ControlPlaneError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseBackendKind {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseReadiness {
    pub backend: DatabaseBackendKind,
    pub schema_version: u32,
    pub installation_id: String,
    pub recovery: InstallationRecoveryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresBoundaryStatus {
    Ported,
    Unported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PostgresBoundaryInventory {
    pub id: &'static str,
    pub status: PostgresBoundaryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<&'static str>,
}

const POSTGRES_BOUNDARIES: &[PostgresBoundaryInventory] = &[
    PostgresBoundaryInventory {
        id: "installation_readiness",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "installation_recovery",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "tenant_identity",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "oidc_and_human_identity",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "user_team_repository_access",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "browser_sessions",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "api_tokens_and_audit",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "scm_and_repositories",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "runs_and_approvals",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "runner_leases_and_brokers",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "runner_fleet_and_enrollment",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "secrets_variables_and_policy",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "artifacts_cache_and_lifecycle",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
    PostgresBoundaryInventory {
        id: "deployment_and_provider_state",
        status: PostgresBoundaryStatus::Ported,
        blocker: None,
    },
];

#[must_use]
pub const fn postgres_boundary_inventory() -> &'static [PostgresBoundaryInventory] {
    POSTGRES_BOUNDARIES
}

#[must_use]
pub fn postgres_transfer_ready() -> bool {
    POSTGRES_BOUNDARIES
        .iter()
        .all(|boundary| boundary.status == PostgresBoundaryStatus::Ported)
}

/// The first persistence seam: one complete read transaction used for
/// readiness and installation fencing checks.
pub trait InstallationStateStore: Send + Sync {
    fn backend_kind(&self) -> DatabaseBackendKind;

    fn installation_id(&self) -> &str;

    fn load_database_readiness(&self) -> StoreFuture<'_, DatabaseReadiness>;

    fn recovery_state(&self) -> StoreFuture<'_, InstallationRecoveryState> {
        Box::pin(async move { Ok(self.load_database_readiness().await?.recovery) })
    }

    fn advance_installation_fencing_epoch(
        &self,
        new_epoch: u64,
        completed_unix_ms: u64,
    ) -> StoreFuture<'_, ()>;

    fn enter_restore_safe_mode(
        &self,
        restored_unix_ms: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState>;

    fn leave_restore_safe_mode(
        &self,
        expected_fencing_epoch: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState>;
}

/// Complete backend-neutral persistence surface used by the server.
///
/// This is deliberately a supertrait over transaction-sized domain contracts,
/// rather than a SQL abstraction. A backend can be selected for the server
/// only after it implements every contract in this list.
pub trait ControlPlaneStore:
    InstallationStateStore
    + TenantIdentityStore
    + HumanIdentityStore
    + UserManagementStore
    + ApiTokenAuditStore
    + BrowserSessionStore
    + ScmRepositoryStore
    + RunCoreStore
    + ApprovalStore
    + SourceSnapshotStore
    + WorkflowSemanticsStore
    + RunnerLeaseBrokerStore
    + RunnerFleetEnrollmentStore
    + ConfigurationProjectStore
    + SecretConfigurationStore
    + VariableConfigurationStore
    + PolicyVersionStore
    + PolicyLifecycleStore
    + OidcGrantStore
    + ArtifactStorageStore
    + ArtifactCatalogStore
    + ArtifactScanPromotionStore
    + CacheTrustStore
    + DeploymentProviderStore
    + DeploymentRequestStore
    + EnvironmentGateStore
    + SigningResultStore
    + DeploymentResultStore
    + ExternalSecretReleaseStore
    + EventStore
    + DurableTaskStore
    + LifecycleGcStore
{
}

impl<T> ControlPlaneStore for T where
    T: InstallationStateStore
        + TenantIdentityStore
        + HumanIdentityStore
        + UserManagementStore
        + ApiTokenAuditStore
        + BrowserSessionStore
        + ScmRepositoryStore
        + RunCoreStore
        + ApprovalStore
        + SourceSnapshotStore
        + WorkflowSemanticsStore
        + RunnerLeaseBrokerStore
        + RunnerFleetEnrollmentStore
        + ConfigurationProjectStore
        + SecretConfigurationStore
        + VariableConfigurationStore
        + PolicyVersionStore
        + PolicyLifecycleStore
        + OidcGrantStore
        + ArtifactStorageStore
        + ArtifactCatalogStore
        + ArtifactScanPromotionStore
        + CacheTrustStore
        + DeploymentProviderStore
        + DeploymentRequestStore
        + EnvironmentGateStore
        + SigningResultStore
        + DeploymentResultStore
        + ExternalSecretReleaseStore
        + EventStore
        + DurableTaskStore
        + LifecycleGcStore
{
}

/// Tenant identity is one versioned compare-and-swap transaction boundary.
/// Canonical settings bytes and exact replay behavior are shared by both
/// backends.
pub trait TenantIdentityStore: Send + Sync {
    fn put_tenant_identity<'a>(
        &'a self,
        record: &'a TenantIdentityRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;

    fn tenant_identity<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, TenantIdentityRecord>;
}

pub trait HumanIdentityStore: Send + Sync {
    fn put_oidc_provider<'a>(
        &'a self,
        record: &'a TenantOidcProviderConfiguration,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn oidc_provider<'a>(
        &'a self,
        tenant_id: &'a str,
        provider_id: &'a str,
    ) -> StoreFuture<'a, TenantOidcProviderConfiguration>;
    fn put_human_user<'a>(
        &'a self,
        tenant_id: &'a str,
        record: &'a HumanUserRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
    fn human_user<'a>(
        &'a self,
        tenant_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, HumanUserRecord>;
    fn put_human_identity<'a>(
        &'a self,
        tenant_id: &'a str,
        record: &'a HumanIdentityRecord,
    ) -> StoreFuture<'a, bool>;
    fn human_identity_for_subject<'a>(
        &'a self,
        tenant_id: &'a str,
        provider_id: &'a str,
        issuer: &'a str,
        subject: &'a str,
    ) -> StoreFuture<'a, HumanIdentityRecord>;
    fn put_membership<'a>(
        &'a self,
        record: &'a TenantMembershipRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool>;
}

impl InstallationStateStore for ControlPlane {
    fn backend_kind(&self) -> DatabaseBackendKind {
        DatabaseBackendKind::Sqlite
    }

    fn installation_id(&self) -> &str {
        ControlPlane::installation_id(self)
    }

    fn load_database_readiness(&self) -> StoreFuture<'_, DatabaseReadiness> {
        // Complete the synchronous SQLite transaction before constructing the
        // future so no mutex guard can cross an await point.
        let result = self.database_readiness();
        Box::pin(async move { result })
    }

    fn advance_installation_fencing_epoch(
        &self,
        new_epoch: u64,
        completed_unix_ms: u64,
    ) -> StoreFuture<'_, ()> {
        let result =
            ControlPlane::advance_installation_fencing_epoch(self, new_epoch, completed_unix_ms);
        Box::pin(async move { result })
    }

    fn enter_restore_safe_mode(
        &self,
        restored_unix_ms: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState> {
        let result = ControlPlane::enter_restore_safe_mode(self, restored_unix_ms);
        Box::pin(async move { result })
    }

    fn leave_restore_safe_mode(
        &self,
        expected_fencing_epoch: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState> {
        let result = ControlPlane::leave_restore_safe_mode(self, expected_fencing_epoch);
        Box::pin(async move { result })
    }
}

impl TenantIdentityStore for ControlPlane {
    fn put_tenant_identity<'a>(
        &'a self,
        record: &'a TenantIdentityRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_tenant_identity(self, record, expected_version);
        Box::pin(async move { result })
    }

    fn tenant_identity<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, TenantIdentityRecord> {
        let result = ControlPlane::tenant_identity(self, tenant_id);
        Box::pin(async move { result })
    }
}

impl HumanIdentityStore for ControlPlane {
    fn put_oidc_provider<'a>(
        &'a self,
        record: &'a TenantOidcProviderConfiguration,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = self.put_tenant_oidc_provider_configuration(record, expected_version);
        Box::pin(async move { result })
    }
    fn oidc_provider<'a>(
        &'a self,
        tenant_id: &'a str,
        provider_id: &'a str,
    ) -> StoreFuture<'a, TenantOidcProviderConfiguration> {
        let result = self.tenant_oidc_provider_configuration(tenant_id, provider_id);
        Box::pin(async move { result })
    }
    fn put_human_user<'a>(
        &'a self,
        tenant_id: &'a str,
        record: &'a HumanUserRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_human_user(self, tenant_id, record, expected_version);
        Box::pin(async move { result })
    }
    fn human_user<'a>(
        &'a self,
        tenant_id: &'a str,
        user_id: &'a str,
    ) -> StoreFuture<'a, HumanUserRecord> {
        let result = self.human_user_for_tenant(tenant_id, user_id);
        Box::pin(async move { result })
    }
    fn put_human_identity<'a>(
        &'a self,
        tenant_id: &'a str,
        record: &'a HumanIdentityRecord,
    ) -> StoreFuture<'a, bool> {
        let result = ControlPlane::put_human_identity(self, tenant_id, record);
        Box::pin(async move { result })
    }
    fn human_identity_for_subject<'a>(
        &'a self,
        tenant_id: &'a str,
        provider_id: &'a str,
        issuer: &'a str,
        subject: &'a str,
    ) -> StoreFuture<'a, HumanIdentityRecord> {
        let result =
            ControlPlane::human_identity_for_subject(self, tenant_id, provider_id, issuer, subject);
        Box::pin(async move { result })
    }
    fn put_membership<'a>(
        &'a self,
        record: &'a TenantMembershipRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        let result = self.put_tenant_membership(record, expected_version);
        Box::pin(async move { result })
    }
}

/// Validated PostgreSQL connection configuration. Its debug representation
/// deliberately never contains the URL or credentials.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct PostgresDatabaseConfig {
    options: PgConnectOptions,
    maximum_connections: u32,
    acquire_timeout: Duration,
}

#[cfg(feature = "postgres")]
impl fmt::Debug for PostgresDatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresDatabaseConfig")
            .field("maximum_connections", &self.maximum_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "postgres")]
impl PostgresDatabaseConfig {
    /// Parse a PostgreSQL URL. Non-loopback TCP connections must use
    /// `sslmode=verify-full`; local development may explicitly disable TLS.
    pub fn parse(url: &str) -> Result<Self, ControlPlaneError> {
        let options = PgConnectOptions::from_str(url).map_err(|_| {
            ControlPlaneError::InvalidDatabaseConfiguration(
                "RUNTRUE_DATABASE_URL_FILE must contain a valid PostgreSQL URL",
            )
        })?;
        validate_postgres_transport(&options)?;
        Ok(Self {
            options,
            maximum_connections: 16,
            acquire_timeout: Duration::from_secs(5),
        })
    }

    #[must_use]
    pub fn with_maximum_connections(mut self, maximum_connections: u32) -> Self {
        self.maximum_connections = maximum_connections.max(1);
        self
    }

    #[must_use]
    pub fn with_acquire_timeout(mut self, acquire_timeout: Duration) -> Self {
        self.acquire_timeout = acquire_timeout;
        self
    }
}

#[cfg(feature = "postgres")]
fn validate_postgres_transport(options: &PgConnectOptions) -> Result<(), ControlPlaneError> {
    let host = options.get_host();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
        || host.starts_with('/');
    if !loopback && !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        return Err(ControlPlaneError::InvalidDatabaseConfiguration(
            "remote PostgreSQL requires sslmode=verify-full",
        ));
    }
    Ok(())
}

#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct PostgresInstallationStore {
    pool: PgPool,
    installation_id: String,
}

#[cfg(feature = "postgres")]
impl fmt::Debug for PostgresInstallationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresInstallationStore")
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "postgres")]
impl PostgresInstallationStore {
    /// Compatibility bootstrap entry point. Runtime processes must use
    /// [`Self::connect_existing`] so their credentials never require DDL.
    pub async fn connect(
        config: PostgresDatabaseConfig,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        Self::connect_and_migrate(config, installation_id, now_unix_ms).await
    }

    /// Connect, serialize migrations with a PostgreSQL advisory transaction
    /// lock, verify immutable migration checksums, and bind the installation
    /// identity. No credential is retained outside the SQLx pool.
    pub async fn connect_and_migrate(
        config: PostgresDatabaseConfig,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        Self::connect_and_migrate_with_report(config, installation_id, now_unix_ms)
            .await
            .map(|(store, _)| store)
    }

    /// Apply or replay the unified catalog and return the same portable
    /// migration report as the embedded backend.
    pub async fn connect_and_migrate_with_report(
        config: PostgresDatabaseConfig,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<(Self, MigrationReport), ControlPlaneError> {
        let installation_id = installation_id.into();
        if installation_id.is_empty() {
            return Err(ControlPlaneError::InvalidInput("installation_id"));
        }
        let now_unix_ms =
            i64::try_from(now_unix_ms).map_err(|_| ControlPlaneError::IntegerRange {
                field: "now_unix_ms",
            })?;
        let pool = PgPoolOptions::new()
            .max_connections(config.maximum_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.options)
            .await?;
        let migration_report = migrate_and_bind(
            &pool,
            &installation_id,
            now_unix_ms,
            InitialInstallationState::Active,
        )
        .await?;
        Ok((
            Self {
                pool,
                installation_id,
            },
            migration_report,
        ))
    }

    /// Connect to a fully initialized installation without taking migration
    /// locks or executing DDL. Runtime credentials therefore need only the
    /// data privileges required by normal control-plane operations.
    pub async fn connect_existing(
        config: PostgresDatabaseConfig,
        installation_id: impl Into<String>,
    ) -> Result<Self, ControlPlaneError> {
        let installation_id = installation_id.into();
        if installation_id.is_empty() {
            return Err(ControlPlaneError::InvalidInput("installation_id"));
        }
        let pool = PgPoolOptions::new()
            .max_connections(config.maximum_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.options)
            .await?;
        if let Err(error) = verify_existing_installation(&pool, &installation_id).await {
            pool.close().await;
            return Err(error);
        }
        Ok(Self {
            pool,
            installation_id,
        })
    }

    /// Migrate and bind a transfer destination. A brand-new installation is
    /// born in restore safe mode in the same transaction as its schema and
    /// identity, so a crash cannot expose an empty transfer target as active.
    /// Existing installations are never forced into safe mode by this step;
    /// the transfer preparation transaction proves emptiness first.
    pub async fn connect_for_transfer(
        config: PostgresDatabaseConfig,
        installation_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ControlPlaneError> {
        let installation_id = installation_id.into();
        if installation_id.is_empty() {
            return Err(ControlPlaneError::InvalidInput("installation_id"));
        }
        let now_unix_ms =
            i64::try_from(now_unix_ms).map_err(|_| ControlPlaneError::IntegerRange {
                field: "now_unix_ms",
            })?;
        let pool = PgPoolOptions::new()
            .max_connections(config.maximum_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.options)
            .await?;
        migrate_and_bind(
            &pool,
            &installation_id,
            now_unix_ms,
            InitialInstallationState::TransferSafeMode,
        )
        .await?;
        Ok(Self {
            pool,
            installation_id,
        })
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(feature = "postgres")]
impl InstallationStateStore for PostgresInstallationStore {
    fn backend_kind(&self) -> DatabaseBackendKind {
        DatabaseBackendKind::Postgres
    }

    fn installation_id(&self) -> &str {
        PostgresInstallationStore::installation_id(self)
    }

    fn load_database_readiness(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DatabaseReadiness, ControlPlaneError>> + Send + '_>>
    {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await?;
            let mut transaction = connection.begin().await?;
            let migration_generation: i32 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(sequence), 0) FROM runtrue_schema_migrations",
            )
            .fetch_one(&mut *transaction)
            .await?;
            let row = sqlx::query(
                "SELECT installation_id, fencing_epoch, safe_mode, last_restore_unix_ms
                 FROM installation_state WHERE singleton = TRUE",
            )
            .fetch_one(&mut *transaction)
            .await?;
            transaction.commit().await?;
            let stored_installation_id: String = row.try_get("installation_id")?;
            if stored_installation_id != self.installation_id {
                return Err(ControlPlaneError::InstallationMismatch {
                    expected: stored_installation_id,
                    actual: self.installation_id.clone(),
                });
            }
            if migration_generation != i32::try_from(LOGICAL_SCHEMA_GENERATION).unwrap() {
                return Err(ControlPlaneError::InvalidMigrationHistory(
                    "PostgreSQL unified migration generation changed after startup".to_owned(),
                ));
            }
            Ok(DatabaseReadiness {
                backend: DatabaseBackendKind::Postgres,
                schema_version: POSTGRES_SCHEMA_VERSION,
                installation_id: self.installation_id.clone(),
                recovery: InstallationRecoveryState {
                    fencing_epoch: postgres_u64(row.try_get("fencing_epoch")?, "fencing_epoch")?,
                    safe_mode: row.try_get("safe_mode")?,
                    last_restore_unix_ms: row
                        .try_get::<Option<i64>, _>("last_restore_unix_ms")?
                        .map(|value| postgres_u64(value, "last_restore_unix_ms"))
                        .transpose()?,
                },
            })
        })
    }

    fn advance_installation_fencing_epoch(
        &self,
        new_epoch: u64,
        completed_unix_ms: u64,
    ) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let new_epoch = postgres_i64(new_epoch, "fencing_epoch")?;
            let completed_unix_ms = postgres_i64(completed_unix_ms, "completed_unix_ms")?;
            let mut connection = self.pool.acquire().await?;
            let mut transaction = connection.begin().await?;
            let current: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state
                 WHERE singleton = TRUE FOR UPDATE",
            )
            .fetch_one(&mut *transaction)
            .await?;
            if new_epoch <= current {
                return Err(ControlPlaneError::EpochMustIncrease {
                    current: postgres_u64(current, "fencing_epoch")?,
                    proposed: postgres_u64(new_epoch, "fencing_epoch")?,
                });
            }
            sqlx::query(
                "UPDATE installation_state SET fencing_epoch = $1
                 WHERE singleton = TRUE",
            )
            .bind(new_epoch)
            .execute(&mut *transaction)
            .await?;
            runner_authority::fence_postgres_runner_authority(&mut transaction, completed_unix_ms)
                .await?;
            transaction.commit().await?;
            Ok(())
        })
    }

    fn enter_restore_safe_mode(
        &self,
        restored_unix_ms: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState> {
        Box::pin(async move {
            let restored_unix_ms = postgres_i64(restored_unix_ms, "restored_unix_ms")?;
            let mut connection = self.pool.acquire().await?;
            let mut transaction = connection.begin().await?;
            let current: i64 = sqlx::query_scalar(
                "SELECT fencing_epoch FROM installation_state
                 WHERE singleton = TRUE FOR UPDATE",
            )
            .fetch_one(&mut *transaction)
            .await?;
            let current = postgres_u64(current, "fencing_epoch")?;
            let new_epoch = current
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "fencing_epoch",
                })?;
            let encoded_epoch = postgres_i64(new_epoch, "fencing_epoch")?;
            sqlx::query(
                "UPDATE installation_state
                 SET fencing_epoch = $1, safe_mode = TRUE, last_restore_unix_ms = $2
                 WHERE singleton = TRUE",
            )
            .bind(encoded_epoch)
            .bind(restored_unix_ms)
            .execute(&mut *transaction)
            .await?;
            runner_authority::fence_postgres_runner_authority(&mut transaction, restored_unix_ms)
                .await?;
            transaction.commit().await?;
            Ok(InstallationRecoveryState {
                fencing_epoch: new_epoch,
                safe_mode: true,
                last_restore_unix_ms: Some(postgres_u64(restored_unix_ms, "last_restore_unix_ms")?),
            })
        })
    }

    fn leave_restore_safe_mode(
        &self,
        expected_fencing_epoch: u64,
    ) -> StoreFuture<'_, InstallationRecoveryState> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await?;
            let mut transaction = connection.begin().await?;
            let row = sqlx::query(
                "SELECT fencing_epoch, safe_mode, last_restore_unix_ms
                 FROM installation_state WHERE singleton = TRUE FOR UPDATE",
            )
            .fetch_one(&mut *transaction)
            .await?;
            let state = InstallationRecoveryState {
                fencing_epoch: postgres_u64(row.try_get("fencing_epoch")?, "fencing_epoch")?,
                safe_mode: row.try_get("safe_mode")?,
                last_restore_unix_ms: row
                    .try_get::<Option<i64>, _>("last_restore_unix_ms")?
                    .map(|value| postgres_u64(value, "last_restore_unix_ms"))
                    .transpose()?,
            };
            if !state.safe_mode {
                return Err(ControlPlaneError::NotInRestoreSafeMode);
            }
            if state.fencing_epoch != expected_fencing_epoch {
                return Err(ControlPlaneError::RestoreEpochMismatch {
                    expected: state.fencing_epoch,
                    actual: expected_fencing_epoch,
                });
            }
            let open_lease = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM leases
                 WHERE state IN ('offered','active','cancel_requested')
                 LIMIT 1 FOR UPDATE",
            )
            .fetch_optional(&mut *transaction)
            .await?;
            if open_lease.is_some() {
                return Err(ControlPlaneError::RestoreHasOpenLeases);
            }
            sqlx::query(
                "UPDATE installation_state SET safe_mode = FALSE
                 WHERE singleton = TRUE",
            )
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(InstallationRecoveryState {
                safe_mode: false,
                ..state
            })
        })
    }
}

#[cfg(feature = "postgres")]
impl TenantIdentityStore for PostgresInstallationStore {
    fn put_tenant_identity<'a>(
        &'a self,
        record: &'a TenantIdentityRecord,
        expected_version: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let settings = crate::store::validate_persistence_tenant_identity(record)?;
            let mut connection = self.pool.acquire().await?;
            let mut transaction = connection.begin().await?;
            let existing = sqlx::query(
                "SELECT id, slug, name, status, settings_json, created_unix_ms,
                        updated_unix_ms, version
                 FROM tenants WHERE id = $1 FOR UPDATE",
            )
            .bind(&record.id)
            .fetch_optional(&mut *transaction)
            .await?
            .map(postgres_tenant_identity)
            .transpose()?;

            if let Some(existing) = existing {
                if existing == *record {
                    transaction.commit().await?;
                    return Ok(false);
                }
                if expected_version != Some(existing.version)
                    || record.version
                        != existing.version.checked_add(1).ok_or(
                            ControlPlaneError::IntegerRange {
                                field: "tenant version",
                            },
                        )?
                    || record.created_unix_ms != existing.created_unix_ms
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let changed = sqlx::query(
                    "UPDATE tenants SET slug = $2, name = $3, status = $4,
                         settings_json = $5, updated_unix_ms = $6, version = $7
                     WHERE id = $1 AND version = $8",
                )
                .bind(&record.id)
                .bind(&record.slug)
                .bind(&record.name)
                .bind(&record.status)
                .bind(settings)
                .bind(postgres_i64(record.updated_unix_ms, "tenant update")?)
                .bind(postgres_i64(record.version, "tenant version")?)
                .bind(postgres_i64(existing.version, "tenant version")?)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if changed != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                transaction.commit().await?;
                return Ok(true);
            }

            if expected_version.is_some() || record.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query(
                "INSERT INTO tenants
                 (id, slug, name, status, settings_json, created_unix_ms,
                  updated_unix_ms, version)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
            )
            .bind(&record.id)
            .bind(&record.slug)
            .bind(&record.name)
            .bind(&record.status)
            .bind(settings)
            .bind(postgres_i64(record.created_unix_ms, "tenant creation")?)
            .bind(postgres_i64(record.updated_unix_ms, "tenant update")?)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(true)
        })
    }

    fn tenant_identity<'a>(&'a self, tenant_id: &'a str) -> StoreFuture<'a, TenantIdentityRecord> {
        Box::pin(async move {
            crate::store::validate_persistence_identity_identifier(tenant_id)?;
            let row = sqlx::query(
                "SELECT id, slug, name, status, settings_json, created_unix_ms,
                        updated_unix_ms, version FROM tenants WHERE id = $1",
            )
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "tenant",
                id: tenant_id.to_owned(),
            })?;
            postgres_tenant_identity(row)
        })
    }
}

#[cfg(feature = "postgres")]
impl HumanIdentityStore for PostgresInstallationStore {
    fn put_oidc_provider<'a>(
        &'a self,
        r: &'a TenantOidcProviderConfiguration,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let (scopes, mfa) = crate::store::validate_persistence_oidc_provider(r)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, &r.tenant_id).await?;
            let old = sqlx::query("SELECT * FROM tenant_oidc_provider_configs WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(&r.tenant_id).bind(&r.id).fetch_optional(&mut *tx).await?.map(pg_provider).transpose()?;
            if let Some(old) = old {
                if old == *r {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "OIDC provider version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                    || r.tenant_id != old.tenant_id
                    || r.issuer != old.issuer
                    || r.client_id != old.client_id
                    || r.redirect_uri != old.redirect_uri
                    || r.authorization_endpoint != old.authorization_endpoint
                    || r.token_endpoint != old.token_endpoint
                    || r.jwks_uri != old.jwks_uri
                    || r.scopes != old.scopes
                    || r.mfa_claim != old.mfa_claim
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let n=sqlx::query("UPDATE tenant_oidc_provider_configs SET status=$3,configuration_digest=$4,updated_unix_ms=$5,version=$6 WHERE tenant_id=$1 AND id=$2 AND version=$7").bind(&r.tenant_id).bind(&r.id).bind(&r.status).bind(r.configuration_digest.as_str()).bind(pg_i64(r.updated_unix_ms,"OIDC provider update")?).bind(pg_i64(r.version,"OIDC provider version")?).bind(pg_i64(old.version,"OIDC provider version")?).execute(&mut *tx).await?.rows_affected();
                if n != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            if expected.is_some() || r.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO tenant_oidc_provider_configs(id,tenant_id,issuer,client_id,authorization_endpoint,token_endpoint,jwks_uri,redirect_uri,scopes_json,mfa_claim_json,status,configuration_digest,created_unix_ms,updated_unix_ms,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1)").bind(&r.id).bind(&r.tenant_id).bind(&r.issuer).bind(&r.client_id).bind(&r.authorization_endpoint).bind(&r.token_endpoint).bind(&r.jwks_uri).bind(&r.redirect_uri).bind(scopes).bind(mfa).bind(&r.status).bind(r.configuration_digest.as_str()).bind(pg_i64(r.created_unix_ms,"OIDC provider creation")?).bind(pg_i64(r.updated_unix_ms,"OIDC provider update")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn oidc_provider<'a>(
        &'a self,
        tenant: &'a str,
        id: &'a str,
    ) -> StoreFuture<'a, TenantOidcProviderConfiguration> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, tenant).await?;
            let row = sqlx::query(
                "SELECT * FROM tenant_oidc_provider_configs WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "OIDC provider configuration",
                id: id.to_owned(),
            })?;
            let r = pg_provider(row)?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn put_human_user<'a>(
        &'a self,
        tenant: &'a str,
        r: &'a HumanUserRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            crate::store::validate_persistence_human_user(r)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, tenant).await?;
            let old = sqlx::query("SELECT * FROM human_users WHERE id=$1 FOR UPDATE")
                .bind(&r.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(pg_user)
                .transpose()?;
            if let Some(old) = old {
                let associated:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings WHERE tenant_id=$1 AND user_id=$2)").bind(tenant).bind(&r.id).fetch_one(&mut *tx).await?;
                if !associated {
                    return Err(ControlPlaneError::NotFound {
                        kind: "human user",
                        id: r.id.clone(),
                    });
                }
                if old == *r {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "human user version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let n=sqlx::query("UPDATE human_users SET display_name=$2,primary_email=$3,status=$4,updated_unix_ms=$5,last_seen_unix_ms=$6,version=$7 WHERE id=$1 AND version=$8").bind(&r.id).bind(&r.display_name).bind(&r.primary_email).bind(&r.status).bind(pg_i64(r.updated_unix_ms,"human user update")?).bind(r.last_seen_unix_ms.map(|v|pg_i64(v,"human user last seen")).transpose()?).bind(pg_i64(r.version,"human user version")?).bind(pg_i64(old.version,"human user version")?).execute(&mut *tx).await?.rows_affected();
                if n != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            if expected.is_some() || r.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO human_users(id,display_name,primary_email,status,created_unix_ms,updated_unix_ms,last_seen_unix_ms,version)VALUES($1,$2,$3,$4,$5,$6,$7,1)").bind(&r.id).bind(&r.display_name).bind(&r.primary_email).bind(&r.status).bind(pg_i64(r.created_unix_ms,"human user creation")?).bind(pg_i64(r.updated_unix_ms,"human user update")?).bind(r.last_seen_unix_ms.map(|v|pg_i64(v,"human user last seen")).transpose()?).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO human_user_tenant_bindings(tenant_id,user_id,created_unix_ms)VALUES($1,$2,$3)").bind(tenant).bind(&r.id).bind(pg_i64(r.created_unix_ms,"human user creation")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn human_user<'a>(
        &'a self,
        tenant: &'a str,
        user: &'a str,
    ) -> StoreFuture<'a, HumanUserRecord> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, tenant).await?;
            let row=sqlx::query("SELECT u.* FROM human_users u JOIN human_user_tenant_bindings b ON b.user_id=u.id WHERE b.tenant_id=$1 AND u.id=$2").bind(tenant).bind(user).fetch_optional(&mut *tx).await?.ok_or_else(||ControlPlaneError::NotFound{kind:"human user",id:user.to_owned()})?;
            let r = pg_user(row)?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn put_human_identity<'a>(
        &'a self,
        tenant: &'a str,
        r: &'a HumanIdentityRecord,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            crate::store::validate_persistence_human_identity(r)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, tenant).await?;
            if r.tenant_id != tenant {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let provider = sqlx::query(
                "SELECT * FROM tenant_oidc_provider_configs WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(&r.provider_configuration_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "OIDC provider configuration",
                id: r.provider_configuration_id.clone(),
            })
            .and_then(pg_provider)?;
            if provider.issuer != r.issuer {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let bound:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings WHERE tenant_id=$1 AND user_id=$2)").bind(tenant).bind(&r.user_id).fetch_one(&mut *tx).await?;
            if !bound {
                return Err(ControlPlaneError::NotFound {
                    kind: "human user",
                    id: r.user_id.clone(),
                });
            }
            let old = sqlx::query(
                "SELECT * FROM human_identities WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(tenant)
            .bind(&r.id)
            .fetch_optional(&mut *tx)
            .await?
            .map(pg_human_identity)
            .transpose()?;
            if let Some(old) = old {
                if old == *r {
                    tx.commit().await?;
                    return Ok(false);
                }
                if r.tenant_id != old.tenant_id
                    || r.user_id != old.user_id
                    || r.provider_configuration_id != old.provider_configuration_id
                    || r.issuer != old.issuer
                    || r.subject != old.subject
                    || r.provider_kind != old.provider_kind
                    || r.created_unix_ms != old.created_unix_ms
                    || r.last_authenticated_unix_ms <= old.last_authenticated_unix_ms
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let n=sqlx::query("UPDATE human_identities SET claims_digest=$3,last_authenticated_unix_ms=$4 WHERE tenant_id=$1 AND id=$2 AND last_authenticated_unix_ms=$5").bind(tenant).bind(&r.id).bind(r.claims_digest.as_str()).bind(pg_i64(r.last_authenticated_unix_ms,"human identity authentication")?).bind(pg_i64(old.last_authenticated_unix_ms,"human identity authentication")?).execute(&mut *tx).await?.rows_affected();
                if n != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            sqlx::query("INSERT INTO human_identities(id,tenant_id,user_id,provider_configuration_id,issuer,subject,provider_kind,claims_digest,created_unix_ms,last_authenticated_unix_ms)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(&r.id).bind(&r.tenant_id).bind(&r.user_id).bind(&r.provider_configuration_id).bind(&r.issuer).bind(&r.subject).bind(&r.provider_kind).bind(r.claims_digest.as_str()).bind(pg_i64(r.created_unix_ms,"human identity creation")?).bind(pg_i64(r.last_authenticated_unix_ms,"human identity authentication")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }
    fn human_identity_for_subject<'a>(
        &'a self,
        tenant: &'a str,
        provider: &'a str,
        issuer: &'a str,
        subject: &'a str,
    ) -> StoreFuture<'a, HumanIdentityRecord> {
        Box::pin(async move {
            crate::store::validate_persistence_identity_identifier(provider)?;
            crate::store::validate_persistence_https_uri(issuer)?;
            crate::store::validate_persistence_identity_identifier(subject)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, tenant).await?;
            let row=sqlx::query("SELECT i.* FROM human_identities i JOIN tenant_oidc_provider_configs p ON p.tenant_id=i.tenant_id AND p.id=i.provider_configuration_id WHERE i.tenant_id=$1 AND i.provider_configuration_id=$2 AND i.issuer=$3 AND i.subject=$4 AND p.status='active' AND p.issuer=$3").bind(tenant).bind(provider).bind(issuer).bind(subject).fetch_optional(&mut *tx).await?.ok_or_else(||ControlPlaneError::NotFound{kind:"human identity",id:subject.to_owned()})?;
            let r = pg_human_identity(row)?;
            tx.commit().await?;
            Ok(r)
        })
    }
    fn put_membership<'a>(
        &'a self,
        r: &'a TenantMembershipRecord,
        expected: Option<u64>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let attrs = crate::store::validate_persistence_tenant_membership(r)?;
            let mut tx = self.pool.begin().await?;
            pg_require_tenant(&mut tx, &r.tenant_id).await?;
            let bound:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM human_user_tenant_bindings WHERE tenant_id=$1 AND user_id=$2)").bind(&r.tenant_id).bind(&r.user_id).fetch_one(&mut *tx).await?;
            if !bound {
                return Err(ControlPlaneError::NotFound {
                    kind: "human user",
                    id: r.user_id.clone(),
                });
            }
            let old = sqlx::query(
                "SELECT * FROM tenant_memberships WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(&r.tenant_id)
            .bind(&r.id)
            .fetch_optional(&mut *tx)
            .await?
            .map(pg_membership)
            .transpose()?;
            if let Some(old) = old {
                if old == *r {
                    tx.commit().await?;
                    return Ok(false);
                }
                if expected != Some(old.version)
                    || r.version
                        != old
                            .version
                            .checked_add(1)
                            .ok_or(ControlPlaneError::IntegerRange {
                                field: "tenant membership version",
                            })?
                    || r.created_unix_ms != old.created_unix_ms
                    || r.tenant_id != old.tenant_id
                    || r.user_id != old.user_id
                    || r.role_template != old.role_template
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                let n=sqlx::query("UPDATE tenant_memberships SET attributes_json=$3,attributes_digest=$4,status=$5,updated_unix_ms=$6,version=$7 WHERE tenant_id=$1 AND id=$2 AND version=$8").bind(&r.tenant_id).bind(&r.id).bind(attrs).bind(r.attributes_digest.as_str()).bind(&r.status).bind(pg_i64(r.updated_unix_ms,"membership update")?).bind(pg_i64(r.version,"membership version")?).bind(pg_i64(old.version,"membership version")?).execute(&mut *tx).await?.rows_affected();
                if n != 1 {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
                tx.commit().await?;
                return Ok(true);
            }
            if expected.is_some() || r.version != 1 {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            sqlx::query("INSERT INTO tenant_memberships(id,tenant_id,user_id,role_template,attributes_json,attributes_digest,status,created_unix_ms,updated_unix_ms,version)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1)").bind(&r.id).bind(&r.tenant_id).bind(&r.user_id).bind(&r.role_template).bind(attrs).bind(r.attributes_digest.as_str()).bind(&r.status).bind(pg_i64(r.created_unix_ms,"membership creation")?).bind(pg_i64(r.updated_unix_ms,"membership update")?).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(true)
        })
    }
}

#[cfg(feature = "postgres")]
async fn pg_require_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<(), ControlPlaneError> {
    crate::store::validate_persistence_identity_identifier(id)?;
    let ok: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND status='active')")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    if ok {
        Ok(())
    } else {
        Err(ControlPlaneError::NotFound {
            kind: "tenant",
            id: id.to_owned(),
        })
    }
}
#[cfg(feature = "postgres")]
fn pg_json(
    row: &sqlx::postgres::PgRow,
    name: &str,
    max: usize,
) -> Result<serde_json::Value, ControlPlaneError> {
    let b: Vec<u8> = row.try_get(name)?;
    if b.len() > max {
        return Err(ControlPlaneError::CorruptState(format!(
            "PostgreSQL {name} exceeds its byte bound"
        )));
    }
    serde_json::from_slice(&b)
        .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {name} is invalid JSON")))
}
#[cfg(feature = "postgres")]
fn pg_provider(
    row: sqlx::postgres::PgRow,
) -> Result<TenantOidcProviderConfiguration, ControlPlaneError> {
    let r = TenantOidcProviderConfiguration {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        issuer: row.try_get("issuer")?,
        client_id: row.try_get("client_id")?,
        authorization_endpoint: row.try_get("authorization_endpoint")?,
        token_endpoint: row.try_get("token_endpoint")?,
        jwks_uri: row.try_get("jwks_uri")?,
        redirect_uri: row.try_get("redirect_uri")?,
        scopes: serde_json::from_value(pg_json(&row, "scopes_json", 65536)?).map_err(|_| {
            ControlPlaneError::CorruptState("PostgreSQL OIDC scopes are invalid".to_owned())
        })?,
        mfa_claim: pg_json(&row, "mfa_claim_json", 65536)?,
        status: row.try_get("status")?,
        configuration_digest: ContentDigest::parse(
            row.try_get::<String, _>("configuration_digest")?,
        )?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "OIDC provider creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "OIDC provider update")?,
        version: postgres_u64(row.try_get("version")?, "OIDC provider version")?,
    };
    crate::store::validate_persistence_oidc_provider(&r).map_err(|_| {
        ControlPlaneError::CorruptState("PostgreSQL OIDC provider is invalid".to_owned())
    })?;
    Ok(r)
}
#[cfg(feature = "postgres")]
fn pg_user(row: sqlx::postgres::PgRow) -> Result<HumanUserRecord, ControlPlaneError> {
    Ok(HumanUserRecord {
        id: row.try_get("id")?,
        display_name: row.try_get("display_name")?,
        primary_email: row.try_get("primary_email")?,
        status: row.try_get("status")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "human user creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "human user update")?,
        last_seen_unix_ms: row
            .try_get::<Option<i64>, _>("last_seen_unix_ms")?
            .map(|v| postgres_u64(v, "human user last seen"))
            .transpose()?,
        version: postgres_u64(row.try_get("version")?, "human user version")?,
    })
}
#[cfg(feature = "postgres")]
fn pg_human_identity(row: sqlx::postgres::PgRow) -> Result<HumanIdentityRecord, ControlPlaneError> {
    Ok(HumanIdentityRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        user_id: row.try_get("user_id")?,
        provider_configuration_id: row.try_get("provider_configuration_id")?,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
        provider_kind: row.try_get("provider_kind")?,
        claims_digest: ContentDigest::parse(row.try_get::<String, _>("claims_digest")?)?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "human identity creation")?,
        last_authenticated_unix_ms: postgres_u64(
            row.try_get("last_authenticated_unix_ms")?,
            "human identity authentication",
        )?,
    })
}
#[cfg(feature = "postgres")]
fn pg_membership(row: sqlx::postgres::PgRow) -> Result<TenantMembershipRecord, ControlPlaneError> {
    Ok(TenantMembershipRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        user_id: row.try_get("user_id")?,
        role_template: row.try_get("role_template")?,
        attributes: pg_json(&row, "attributes_json", 1024 * 1024)?,
        attributes_digest: ContentDigest::parse(row.try_get::<String, _>("attributes_digest")?)?,
        status: row.try_get("status")?,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "membership creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "membership update")?,
        version: postgres_u64(row.try_get("version")?, "membership version")?,
    })
}
#[cfg(feature = "postgres")]
fn pg_i64(v: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    postgres_i64(v, field)
}

#[cfg(feature = "postgres")]
fn postgres_tenant_identity(
    row: sqlx::postgres::PgRow,
) -> Result<TenantIdentityRecord, ControlPlaneError> {
    let settings: Vec<u8> = row.try_get("settings_json")?;
    if settings.len() > 1024 * 1024 {
        return Err(ControlPlaneError::CorruptState(
            "PostgreSQL tenant settings exceed their byte bound".to_owned(),
        ));
    }
    let settings = serde_json::from_slice(&settings).map_err(|_| {
        ControlPlaneError::CorruptState("PostgreSQL tenant settings are invalid JSON".to_owned())
    })?;
    Ok(TenantIdentityRecord {
        id: row.try_get("id")?,
        slug: row.try_get("slug")?,
        name: row.try_get("name")?,
        status: row.try_get("status")?,
        settings,
        created_unix_ms: postgres_u64(row.try_get("created_unix_ms")?, "tenant creation")?,
        updated_unix_ms: postgres_u64(row.try_get("updated_unix_ms")?, "tenant update")?,
        version: postgres_u64(row.try_get("version")?, "tenant version")?,
    })
}

#[cfg(feature = "postgres")]
#[derive(Clone, Copy)]
enum InitialInstallationState {
    Active,
    TransferSafeMode,
}

#[cfg(feature = "postgres")]
async fn verify_existing_installation(
    pool: &PgPool,
    installation_id: &str,
) -> Result<InstallationRecoveryState, ControlPlaneError> {
    let legacy = POSTGRES_MIGRATIONS
        .iter()
        .map(|(_, sql)| *sql)
        .collect::<Vec<_>>();
    let (catalog, _) = materialize_catalog(MigrationBackend::Postgres, &legacy)?;
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    verify_postgres_unified_ledger(&mut transaction, &catalog, false, true).await?;
    verify_postgres_schema_contract(&mut transaction, true, catalog.len().saturating_sub(1))
        .await?;
    let row = sqlx::query(
        "SELECT installation_id, fencing_epoch, safe_mode, last_restore_unix_ms
         FROM installation_state WHERE singleton = TRUE",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_existing_schema_error)?
    .ok_or_else(|| {
        ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL installation identity is missing; initialize or migrate it with migration credentials before starting the runtime"
                .to_owned(),
        )
    })?;
    let stored: String = row.try_get("installation_id")?;
    if stored != installation_id {
        return Err(ControlPlaneError::InstallationMismatch {
            expected: stored,
            actual: installation_id.to_owned(),
        });
    }
    let recovery = InstallationRecoveryState {
        fencing_epoch: postgres_u64(row.try_get("fencing_epoch")?, "fencing_epoch")?,
        safe_mode: row.try_get("safe_mode")?,
        last_restore_unix_ms: row
            .try_get::<Option<i64>, _>("last_restore_unix_ms")?
            .map(|value| postgres_u64(value, "last_restore_unix_ms"))
            .transpose()?,
    };
    if recovery.fencing_epoch == 0 {
        return Err(ControlPlaneError::CorruptState(
            "PostgreSQL installation fencing epoch is zero".to_owned(),
        ));
    }
    transaction.commit().await?;
    Ok(recovery)
}

#[cfg(feature = "postgres")]
fn map_existing_schema_error(error: sqlx::Error) -> ControlPlaneError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "42P01" || code == "42703")
    {
        return ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL schema is not initialized or is structurally incomplete; run the database initialize/migrate command with migration credentials before starting the runtime"
                .to_owned(),
        );
    }
    error.into()
}

#[cfg(feature = "postgres")]
async fn migrate_and_bind(
    pool: &PgPool,
    installation_id: &str,
    now_unix_ms: i64,
    initial_state: InitialInstallationState,
) -> Result<MigrationReport, ControlPlaneError> {
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(POSTGRES_MIGRATION_LOCK_KEY)
        .execute(&mut *transaction)
        .await?;
    let migration_report = ensure_postgres_current_schema(&mut transaction, now_unix_ms).await?;

    let (initial_safe_mode, initial_restore_unix_ms) = match initial_state {
        InitialInstallationState::Active => (false, None),
        InitialInstallationState::TransferSafeMode => (true, Some(now_unix_ms)),
    };
    sqlx::query(
        "INSERT INTO installation_state
         (singleton, installation_id, fencing_epoch, safe_mode, last_restore_unix_ms)
         VALUES (TRUE, $1, 1, $2, $3)
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(installation_id)
    .bind(initial_safe_mode)
    .bind(initial_restore_unix_ms)
    .execute(&mut *transaction)
    .await?;
    let stored: String = sqlx::query_scalar(
        "SELECT installation_id FROM installation_state
         WHERE singleton = TRUE FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if stored != installation_id {
        return Err(ControlPlaneError::InstallationMismatch {
            expected: stored,
            actual: installation_id.to_owned(),
        });
    }
    transaction.commit().await?;
    Ok(migration_report)
}

#[cfg(feature = "postgres")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresLedgerShape {
    Missing,
    Legacy,
    Unified,
}

#[cfg(feature = "postgres")]
async fn postgres_ledger_shape(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<PostgresLedgerShape, ControlPlaneError> {
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema=current_schema() AND table_name='runtrue_schema_migrations'
         ORDER BY ordinal_position",
    )
    .fetch_all(&mut **transaction)
    .await?;
    match columns.as_slice() {
        [] => Ok(PostgresLedgerShape::Missing),
        [version, checksum, applied]
            if version == "version" && checksum == "checksum" && applied == "applied_unix_ms" =>
        {
            Ok(PostgresLedgerShape::Legacy)
        }
        [sequence, migration_id, definition, implementation, applied]
            if sequence == "sequence"
                && migration_id == "migration_id"
                && definition == "definition_sha256"
                && implementation == "implementation_sha256"
                && applied == "applied_unix_ms" =>
        {
            Ok(PostgresLedgerShape::Unified)
        }
        _ => Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL runtrue_schema_migrations has an unrecognized shape".to_owned(),
        )),
    }
}

#[cfg(feature = "postgres")]
async fn ensure_postgres_current_schema(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    now_unix_ms: i64,
) -> Result<MigrationReport, ControlPlaneError> {
    let legacy = POSTGRES_MIGRATIONS
        .iter()
        .map(|(_, sql)| *sql)
        .collect::<Vec<_>>();
    let (catalog, lineage) = materialize_catalog(MigrationBackend::Postgres, &legacy)?;
    let baseline = &catalog[0];
    if postgres_ledger_shape(transaction).await? == PostgresLedgerShape::Unified {
        let applied = verify_postgres_unified_ledger(transaction, &catalog, true, false).await?;
        verify_postgres_schema_contract(transaction, false, applied.saturating_sub(1)).await?;
        let mut applied_ids = Vec::new();
        for migration in catalog.iter().skip(applied) {
            sqlx::raw_sql(migration.sql.as_deref().ok_or_else(|| {
                ControlPlaneError::InvalidMigrationHistory(
                    "forward PostgreSQL migration has no SQL payload".to_owned(),
                )
            })?)
            .execute(&mut **transaction)
            .await?;
            sqlx::query(
                "INSERT INTO runtrue_schema_migrations
                 (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(i32::try_from(migration.sequence).expect("migration sequence fits i32"))
            .bind(migration.migration_id)
            .bind(migration.definition_sha256.as_slice())
            .bind(migration.implementation_sha256.as_slice())
            .bind(now_unix_ms)
            .execute(&mut **transaction)
            .await?;
            applied_ids.push(migration.migration_id.to_owned());
        }
        verify_postgres_unified_ledger(transaction, &catalog, false, false).await?;
        verify_postgres_schema_contract(transaction, false, catalog.len().saturating_sub(1))
            .await?;
        return Ok(MigrationReport {
            backend: MigrationBackend::Postgres,
            logical_schema_generation: catalog.last().unwrap().logical_schema_generation,
            applied_migration_ids: applied_ids,
            replayed_migration_ids: catalog[..applied]
                .iter()
                .map(|migration| migration.migration_id.to_owned())
                .collect(),
            bridged_legacy_lineage: None,
        });
    }

    let fresh_schema = verify_postgres_schema_provenance(transaction).await?;
    if fresh_schema {
        sqlx::raw_sql(POSTGRES_MIGRATION_1)
            .execute(&mut **transaction)
            .await?;
    }
    record_postgres_migration(transaction, 1, POSTGRES_MIGRATION_1, now_unix_ms).await?;
    for (version, migration) in POSTGRES_MIGRATIONS.iter().skip(1) {
        apply_postgres_migration(transaction, *version, migration, now_unix_ms).await?;
    }
    verify_postgres_legacy_history(transaction).await?;
    verify_postgres_schema_contract(transaction, false, 0).await?;

    sqlx::query("ALTER TABLE runtrue_schema_migrations RENAME TO runtrue_legacy_schema_migrations")
        .execute(&mut **transaction)
        .await?;
    sqlx::raw_sql(POSTGRES_UNIFIED_LEDGER_DDL)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO runtrue_schema_migrations
         (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(i32::try_from(baseline.sequence).expect("migration sequence fits i32"))
    .bind(baseline.migration_id)
    .bind(baseline.definition_sha256.as_slice())
    .bind(baseline.implementation_sha256.as_slice())
    .bind(now_unix_ms)
    .execute(&mut **transaction)
    .await?;
    for migration in catalog.iter().skip(1) {
        sqlx::raw_sql(migration.sql.as_deref().ok_or_else(|| {
            ControlPlaneError::InvalidMigrationHistory(
                "forward PostgreSQL migration has no SQL payload".to_owned(),
            )
        })?)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "INSERT INTO runtrue_schema_migrations
             (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(i32::try_from(migration.sequence).expect("migration sequence fits i32"))
        .bind(migration.migration_id)
        .bind(migration.definition_sha256.as_slice())
        .bind(migration.implementation_sha256.as_slice())
        .bind(now_unix_ms)
        .execute(&mut **transaction)
        .await?;
    }
    verify_postgres_unified_ledger(transaction, &catalog, false, false).await?;
    verify_postgres_schema_contract(transaction, false, catalog.len().saturating_sub(1)).await?;
    Ok(MigrationReport {
        backend: MigrationBackend::Postgres,
        logical_schema_generation: catalog.last().unwrap().logical_schema_generation,
        applied_migration_ids: catalog
            .iter()
            .map(|migration| migration.migration_id.to_owned())
            .collect(),
        replayed_migration_ids: Vec::new(),
        bridged_legacy_lineage: Some(lineage),
    })
}

#[cfg(feature = "postgres")]
async fn verify_postgres_legacy_history(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), ControlPlaneError> {
    let rows =
        sqlx::query("SELECT version,checksum FROM runtrue_schema_migrations ORDER BY version")
            .fetch_all(&mut **transaction)
            .await?;
    if rows.len() != POSTGRES_MIGRATIONS.len() {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL legacy migration ledger is incomplete".to_owned(),
        ));
    }
    for (row, (expected_version, migration)) in rows.iter().zip(POSTGRES_MIGRATIONS) {
        let version: i32 = row.try_get("version")?;
        let checksum: Vec<u8> = row.try_get("checksum")?;
        if version != expected_version
            || checksum != Sha256::digest(migration.as_bytes()).as_slice()
        {
            return Err(ControlPlaneError::InvalidMigrationHistory(format!(
                "PostgreSQL legacy migration {expected_version} is missing or modified"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
async fn verify_postgres_unified_ledger(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &[MaterializedMigration],
    allow_prefix: bool,
    runtime: bool,
) -> Result<usize, ControlPlaneError> {
    let shape = postgres_ledger_shape(transaction)
        .await
        .map_err(|error| postgres_runtime_schema_error(error, runtime))?;
    if shape != PostgresLedgerShape::Unified {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL schema uses the legacy ledger; run the database migration command before starting the runtime"
                .to_owned(),
        ));
    }
    let columns = sqlx::query_as::<_, (String, String, String)>(
        "SELECT column_name,data_type,is_nullable
         FROM information_schema.columns
         WHERE table_schema=current_schema() AND table_name='runtrue_schema_migrations'
         ORDER BY ordinal_position",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| postgres_runtime_sql_error(error, runtime))?;
    let expected_columns = vec![
        ("sequence".to_owned(), "integer".to_owned(), "NO".to_owned()),
        (
            "migration_id".to_owned(),
            "text".to_owned(),
            "NO".to_owned(),
        ),
        (
            "definition_sha256".to_owned(),
            "bytea".to_owned(),
            "NO".to_owned(),
        ),
        (
            "implementation_sha256".to_owned(),
            "bytea".to_owned(),
            "NO".to_owned(),
        ),
        (
            "applied_unix_ms".to_owned(),
            "bigint".to_owned(),
            "NO".to_owned(),
        ),
    ];
    if columns != expected_columns {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL unified migration ledger columns do not match the contract".to_owned(),
        ));
    }
    let constraints = sqlx::query_scalar::<_, String>(
        "SELECT con.contype::text || ':' || pg_get_constraintdef(con.oid)
         FROM pg_constraint con
         JOIN pg_class rel ON rel.oid=con.conrelid
         WHERE rel.relnamespace=(SELECT oid FROM pg_namespace WHERE nspname=current_schema())
           AND rel.relname='runtrue_schema_migrations'",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| postgres_runtime_sql_error(error, runtime))?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let expected_constraints = [
        "c:CHECK (((length(migration_id) >= 1) AND (length(migration_id) <= 200)))",
        "c:CHECK ((applied_unix_ms >= 0))",
        "c:CHECK ((octet_length(definition_sha256) = 32))",
        "c:CHECK ((octet_length(implementation_sha256) = 32))",
        "c:CHECK ((sequence > 0))",
        "p:PRIMARY KEY (sequence)",
        "u:UNIQUE (migration_id)",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if constraints != expected_constraints {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL unified migration ledger constraints do not match the contract".to_owned(),
        ));
    }
    let rows = sqlx::query(
        "SELECT sequence,migration_id,definition_sha256,implementation_sha256
         FROM runtrue_schema_migrations ORDER BY sequence",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| postgres_runtime_sql_error(error, runtime))?;
    if rows.is_empty()
        || rows.len() > expected.len()
        || (!allow_prefix && rows.len() != expected.len())
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL unified migration ledger has missing, duplicate, or future entries"
                .to_owned(),
        ));
    }
    for (row, migration) in rows.iter().zip(expected) {
        let sequence: i32 = row.try_get("sequence")?;
        let migration_id: String = row.try_get("migration_id")?;
        let definition: Vec<u8> = row.try_get("definition_sha256")?;
        let implementation: Vec<u8> = row.try_get("implementation_sha256")?;
        if sequence != i32::try_from(migration.sequence).expect("migration sequence fits i32")
            || migration_id != migration.migration_id
            || definition != migration.definition_sha256
            || implementation != migration.implementation_sha256
        {
            return Err(ControlPlaneError::InvalidMigrationHistory(
                "PostgreSQL unified migration ledger does not match the catalog".to_owned(),
            ));
        }
    }
    Ok(rows.len())
}

#[cfg(feature = "postgres")]
async fn verify_postgres_schema_contract(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    runtime: bool,
    forward_migrations: usize,
) -> Result<(), ControlPlaneError> {
    let actual = sqlx::query_scalar::<_, String>(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema=current_schema() AND table_type='BASE TABLE'
           AND table_name NOT IN ('runtrue_schema_migrations','runtrue_legacy_schema_migrations')
         ORDER BY table_name",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| postgres_runtime_sql_error(error, runtime))?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut expected = SQLITE_LEGACY_TABLES
        .iter()
        .filter(|table| **table != "schema_migrations")
        .map(|table| (*table).to_owned())
        .collect::<BTreeSet<_>>();
    expected.extend(
        POSTGRES_ONLY_LEGACY_TABLES
            .iter()
            .map(|table| (*table).to_owned()),
    );
    if forward_migrations >= 1 {
        expected.extend(
            [
                "runner_pool_update_policies",
                "runner_replacements",
                "runner_slots",
                "runner_software_update_claims",
                "runner_enrollment_replays",
                "runner_update_releases",
                "runner_update_trust_states",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    if forward_migrations >= 2 {
        expected.extend(
            ["repository_access_grants", "team_memberships", "teams"]
                .into_iter()
                .map(str::to_owned),
        );
    }
    if forward_migrations >= 3 {
        expected.extend(
            ["durable_event_replays", "durable_events"]
                .into_iter()
                .map(str::to_owned),
        );
    }
    if forward_migrations >= 6 {
        expected.insert("repository_auto_approval_policies".to_owned());
    }
    if actual != expected {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL schema tables do not match the recognized v12 baseline".to_owned(),
        ));
    }
    let required_columns = [
        ("installation_state", "safe_mode"),
        ("installation_state", "last_restore_unix_ms"),
        ("leases", "terminal_credential_taint"),
        ("repository_workflow_settings", "workflow_directory"),
        ("configuration_projects", "version"),
        ("runner_fleet_requests", "state"),
    ];
    for (table, column) in required_columns {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM information_schema.columns
                 WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| postgres_runtime_sql_error(error, runtime))?;
        if !present {
            return Err(ControlPlaneError::InvalidMigrationHistory(format!(
                "PostgreSQL schema invariant {table}.{column} is missing"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "postgres")]
fn postgres_runtime_schema_error(error: ControlPlaneError, runtime: bool) -> ControlPlaneError {
    match error {
        ControlPlaneError::Postgres(error) if runtime => map_existing_schema_error(error),
        other => other,
    }
}

#[cfg(feature = "postgres")]
fn postgres_runtime_sql_error(error: sqlx::Error, runtime: bool) -> ControlPlaneError {
    if runtime {
        map_existing_schema_error(error)
    } else {
        error.into()
    }
}

/// Prove that migration 1 cannot adopt objects that were created outside the
/// Runtrue migration history. A fresh installation requires an empty current
/// schema. Once initialized, the immutable migration-1 checksum is the schema
/// provenance marker and both of its tables must still exist.
#[cfg(feature = "postgres")]
async fn verify_postgres_schema_provenance(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<bool, ControlPlaneError> {
    let objects: Vec<(String, String)> = sqlx::query_as(
        "SELECT class.relname, class.relkind::TEXT
         FROM pg_catalog.pg_class AS class
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = current_schema()
         ORDER BY class.relname",
    )
    .fetch_all(&mut **transaction)
    .await?;
    if objects.is_empty() {
        return Ok(true);
    }

    let migration_ledger = objects
        .iter()
        .find(|(name, _)| name == "runtrue_schema_migrations");
    let Some((_, ledger_kind)) = migration_ledger else {
        let names = objects
            .iter()
            .take(8)
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ControlPlaneError::InvalidMigrationHistory(format!(
            "PostgreSQL initialization requires an empty schema; unmanaged pre-existing objects were found: {names}"
        )));
    };
    if ledger_kind != "r" && ledger_kind != "p" {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL runtrue_schema_migrations provenance marker is not a table".to_owned(),
        ));
    }
    if !objects
        .iter()
        .any(|(name, kind)| name == "installation_state" && (kind == "r" || kind == "p"))
    {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL migration 1 is structurally incomplete; installation_state is missing"
                .to_owned(),
        ));
    }

    let recorded = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT checksum FROM runtrue_schema_migrations WHERE version = 1",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| {
        ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL migration provenance marker is structurally invalid".to_owned(),
        )
    })?;
    let expected = Sha256::digest(POSTGRES_MIGRATION_1);
    if recorded.as_deref() != Some(expected.as_slice()) {
        return Err(ControlPlaneError::InvalidMigrationHistory(
            "PostgreSQL migration 1 is missing or modified; refusing to adopt pre-existing schema objects"
                .to_owned(),
        ));
    }
    Ok(false)
}

#[cfg(feature = "postgres")]
async fn apply_postgres_migration(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    version: i32,
    sql: &str,
    now_unix_ms: i64,
) -> Result<(), ControlPlaneError> {
    let checksum = Sha256::digest(sql.as_bytes()).to_vec();
    let recorded: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM runtrue_schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_optional(&mut **transaction)
            .await?;
    if let Some(recorded) = recorded {
        if recorded != checksum {
            return Err(ControlPlaneError::InvalidMigrationHistory(format!(
                "PostgreSQL migration {version} checksum does not match the binary"
            )));
        }
        return Ok(());
    }
    sqlx::raw_sql(sql).execute(&mut **transaction).await?;
    sqlx::query(
        "INSERT INTO runtrue_schema_migrations(version, checksum, applied_unix_ms)
         VALUES ($1, $2, $3)",
    )
    .bind(version)
    .bind(checksum)
    .bind(now_unix_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn record_postgres_migration(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    version: i32,
    sql: &str,
    now_unix_ms: i64,
) -> Result<(), ControlPlaneError> {
    let checksum = Sha256::digest(sql.as_bytes()).to_vec();
    let recorded: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM runtrue_schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_optional(&mut **transaction)
            .await?;
    match recorded {
        Some(recorded) if recorded != checksum => Err(ControlPlaneError::InvalidMigrationHistory(
            format!("PostgreSQL migration {version} checksum does not match the binary"),
        )),
        Some(_) => Ok(()),
        None => {
            sqlx::query(
                "INSERT INTO runtrue_schema_migrations(version, checksum, applied_unix_ms)
                 VALUES ($1, $2, $3)",
            )
            .bind(version)
            .bind(checksum)
            .bind(now_unix_ms)
            .execute(&mut **transaction)
            .await?;
            Ok(())
        }
    }
}

#[cfg(feature = "postgres")]
fn postgres_u64(value: i64, field: &'static str) -> Result<u64, ControlPlaneError> {
    u64::try_from(value)
        .map_err(|_| ControlPlaneError::CorruptState(format!("PostgreSQL {field} is negative")))
}

#[cfg(feature = "postgres")]
fn postgres_i64(value: u64, field: &'static str) -> Result<i64, ControlPlaneError> {
    i64::try_from(value).map_err(|_| ControlPlaneError::IntegerRange { field })
}

#[cfg(all(test, feature = "postgres"))]
static POSTGRES_TEST_SCHEMA_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// A per-test PostgreSQL schema. Live PostgreSQL tests must not share the
/// public schema: their installation identities and durable fixtures are
/// intentionally incompatible and several contracts perform broad cleanup.
#[cfg(all(test, feature = "postgres"))]
pub(crate) struct PostgresTestSchema {
    config: PostgresDatabaseConfig,
    administration_pool: PgPool,
    schema: String,
}

#[cfg(all(test, feature = "postgres"))]
impl PostgresTestSchema {
    pub(crate) async fn create(url: &str, label: &str) -> Self {
        use std::sync::atomic::Ordering;

        let base = PostgresDatabaseConfig::parse(url).expect("test PostgreSQL URL");
        let sequence = POSTGRES_TEST_SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let label = label
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .take(24)
            .collect::<String>()
            .to_ascii_lowercase();
        let schema = format!("runtrue_test_{label}_{}_{sequence}", std::process::id());
        let administration_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(base.acquire_timeout)
            .connect_with(base.options.clone())
            .await
            .expect("connect to live PostgreSQL test database");
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(&administration_pool)
            .await
            .expect("create isolated PostgreSQL test schema");
        let config = PostgresDatabaseConfig {
            options: base.options.options([("search_path", schema.as_str())]),
            maximum_connections: base.maximum_connections,
            acquire_timeout: base.acquire_timeout,
        };
        Self {
            config,
            administration_pool,
            schema,
        }
    }

    pub(crate) fn config(&self) -> PostgresDatabaseConfig {
        self.config.clone()
    }

    pub(crate) async fn isolated_pool(&self) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(self.config.acquire_timeout)
            .connect_with(self.config.options.clone())
            .await
            .expect("connect to isolated PostgreSQL test schema")
    }

    pub(crate) async fn cleanup(self) {
        sqlx::raw_sql(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.administration_pool)
            .await
            .expect("drop isolated PostgreSQL test schema");
        self.administration_pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(version: u64) -> TenantIdentityRecord {
        TenantIdentityRecord {
            id: "tenant-contract".to_owned(),
            slug: "tenant-contract".to_owned(),
            name: if version == 1 {
                "Contract tenant".to_owned()
            } else {
                "Updated contract tenant".to_owned()
            },
            status: "active".to_owned(),
            settings: serde_json::json!({"region": "test", "version": version}),
            created_unix_ms: 100,
            updated_unix_ms: 100 + version,
            version,
        }
    }

    async fn tenant_identity_contract(store: &impl TenantIdentityStore) {
        assert!(matches!(
            store.tenant_identity("missing").await,
            Err(ControlPlaneError::NotFound { kind: "tenant", .. })
        ));

        let mut invalid = tenant(1);
        invalid.slug = "not a valid slug!".to_owned();
        assert!(matches!(
            store.put_tenant_identity(&invalid, None).await,
            Err(ControlPlaneError::InvalidInput(_))
        ));

        let initial = tenant(1);
        assert!(store
            .put_tenant_identity(&initial, None)
            .await
            .expect("create tenant"));
        assert!(!store
            .put_tenant_identity(&initial, None)
            .await
            .expect("exact tenant replay"));
        assert_eq!(
            store
                .tenant_identity(&initial.id)
                .await
                .expect("load initial tenant"),
            initial
        );

        let updated = tenant(2);
        assert!(matches!(
            store.put_tenant_identity(&updated, None).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
        assert!(store
            .put_tenant_identity(&updated, Some(1))
            .await
            .expect("compare-and-swap tenant"));
        assert!(!store
            .put_tenant_identity(&updated, Some(1))
            .await
            .expect("exact updated tenant replay"));
        assert_eq!(
            store
                .tenant_identity(&updated.id)
                .await
                .expect("load updated tenant"),
            updated
        );

        let stale = tenant(3);
        assert!(matches!(
            store.put_tenant_identity(&stale, Some(1)).await,
            Err(ControlPlaneError::IdempotencyConflict)
        ));
    }

    fn provider(status: &str, version: u64) -> TenantOidcProviderConfiguration {
        let mut record = TenantOidcProviderConfiguration {
            id: "provider-contract".to_owned(),
            tenant_id: "tenant-contract".to_owned(),
            issuer: "https://id.example.test".to_owned(),
            client_id: "client-contract".to_owned(),
            authorization_endpoint: "https://id.example.test/authorize".to_owned(),
            token_endpoint: "https://id.example.test/token".to_owned(),
            jwks_uri: "https://id.example.test/keys".to_owned(),
            redirect_uri: "https://runtrue.example.test/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            mfa_claim: serde_json::json!({"acr":"mfa"}),
            status: status.to_owned(),
            configuration_digest: ContentDigest::sha256([]),
            created_unix_ms: 300,
            updated_unix_ms: 300 + version,
            version,
        };
        record.configuration_digest = record.expected_configuration_digest().unwrap();
        record
    }

    async fn human_identity_contract(store: &impl HumanIdentityStore) {
        let p = provider("active", 1);
        assert!(store.put_oidc_provider(&p, None).await.unwrap());
        assert!(!store.put_oidc_provider(&p, None).await.unwrap());
        assert_eq!(store.oidc_provider(&p.tenant_id, &p.id).await.unwrap(), p);
        let user = HumanUserRecord {
            id: "user-contract".to_owned(),
            display_name: "Contract User".to_owned(),
            primary_email: "user@example.test".to_owned(),
            status: "active".to_owned(),
            created_unix_ms: 310,
            updated_unix_ms: 311,
            last_seen_unix_ms: Some(311),
            version: 1,
        };
        assert!(store
            .put_human_user("tenant-contract", &user, None)
            .await
            .unwrap());
        assert!(!store
            .put_human_user("tenant-contract", &user, None)
            .await
            .unwrap());
        assert_eq!(
            store.human_user("tenant-contract", &user.id).await.unwrap(),
            user
        );
        let mut membership = TenantMembershipRecord {
            id: "membership-contract".to_owned(),
            tenant_id: "tenant-contract".to_owned(),
            user_id: user.id.clone(),
            role_template: "developer".to_owned(),
            attributes: serde_json::json!({"team":"runtime"}),
            attributes_digest: ContentDigest::sha256([]),
            status: "active".to_owned(),
            created_unix_ms: 320,
            updated_unix_ms: 321,
            version: 1,
        };
        membership.attributes_digest = membership.expected_attributes_digest().unwrap();
        assert!(store.put_membership(&membership, None).await.unwrap());
        assert!(!store.put_membership(&membership, None).await.unwrap());
        let identity = HumanIdentityRecord {
            id: "identity-contract".to_owned(),
            tenant_id: "tenant-contract".to_owned(),
            user_id: user.id.clone(),
            provider_configuration_id: p.id.clone(),
            issuer: p.issuer.clone(),
            subject: "subject-contract".to_owned(),
            provider_kind: "oidc".to_owned(),
            claims_digest: ContentDigest::sha256(b"claims-1"),
            created_unix_ms: 330,
            last_authenticated_unix_ms: 331,
        };
        assert!(store
            .put_human_identity("tenant-contract", &identity)
            .await
            .unwrap());
        assert!(!store
            .put_human_identity("tenant-contract", &identity)
            .await
            .unwrap());
        assert_eq!(
            store
                .human_identity_for_subject("tenant-contract", &p.id, &p.issuer, &identity.subject)
                .await
                .unwrap(),
            identity
        );
        let mut relogin = identity.clone();
        relogin.claims_digest = ContentDigest::sha256(b"claims-2");
        relogin.last_authenticated_unix_ms = 332;
        assert!(store
            .put_human_identity("tenant-contract", &relogin)
            .await
            .unwrap());
        let disabled = provider("disabled", 2);
        assert!(store.put_oidc_provider(&disabled, Some(1)).await.unwrap());
        assert!(matches!(
            store
                .human_identity_for_subject("tenant-contract", &p.id, &p.issuer, &identity.subject)
                .await,
            Err(ControlPlaneError::NotFound { .. })
        ));
    }

    async fn installation_recovery_contract(store: &impl InstallationStateStore) {
        assert!(matches!(
            store.advance_installation_fencing_epoch(1, 150).await,
            Err(ControlPlaneError::EpochMustIncrease {
                current: 1,
                proposed: 1
            })
        ));
        store
            .advance_installation_fencing_epoch(2, 151)
            .await
            .expect("advance installation fence");
        assert_eq!(
            store
                .load_database_readiness()
                .await
                .expect("read advanced fence")
                .recovery
                .fencing_epoch,
            2
        );

        let safe = store
            .enter_restore_safe_mode(200)
            .await
            .expect("enter restore safe mode");
        assert_eq!(
            safe,
            InstallationRecoveryState {
                fencing_epoch: 3,
                safe_mode: true,
                last_restore_unix_ms: Some(200),
            }
        );
        assert!(matches!(
            store.leave_restore_safe_mode(2).await,
            Err(ControlPlaneError::RestoreEpochMismatch {
                expected: 3,
                actual: 2
            })
        ));
        let active = store
            .leave_restore_safe_mode(3)
            .await
            .expect("leave restore safe mode");
        assert_eq!(
            active,
            InstallationRecoveryState {
                fencing_epoch: 3,
                safe_mode: false,
                last_restore_unix_ms: Some(200),
            }
        );
        assert!(matches!(
            store.leave_restore_safe_mode(3).await,
            Err(ControlPlaneError::NotInRestoreSafeMode)
        ));
    }

    #[cfg(feature = "postgres")]
    async fn postgres_migration_upgrade_checksum_contract(pool: &PgPool) {
        let parent_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(pool)
            .await
            .expect("read parent test schema");
        let schema = format!("{parent_schema}_upgrade");
        let search_path = format!("SET LOCAL search_path TO {schema}");
        let migrations = [
            (1, POSTGRES_MIGRATION_1),
            (2, POSTGRES_MIGRATION_2),
            (3, POSTGRES_MIGRATION_3),
            (4, POSTGRES_MIGRATION_4),
            (5, POSTGRES_MIGRATION_5),
            (6, POSTGRES_MIGRATION_6),
            (7, POSTGRES_MIGRATION_7),
            (8, POSTGRES_MIGRATION_8),
            (9, POSTGRES_MIGRATION_9),
            (10, POSTGRES_MIGRATION_10),
            (11, POSTGRES_MIGRATION_11),
        ];
        sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
            .execute(pool)
            .await
            .expect("create isolated migration-upgrade schema");

        let mut connection = pool.acquire().await.expect("acquire migration connection");
        for (version, migration) in migrations {
            let mut transaction = connection.begin().await.expect("begin migration upgrade");
            sqlx::raw_sql(&search_path)
                .execute(&mut *transaction)
                .await
                .expect("select isolated migration schema");
            if version == 1 {
                sqlx::raw_sql(migration)
                    .execute(&mut *transaction)
                    .await
                    .expect("apply first PostgreSQL migration");
                record_postgres_migration(&mut transaction, version, migration, 1_000)
                    .await
                    .expect("record first PostgreSQL migration");
            } else {
                apply_postgres_migration(&mut transaction, version, migration, 1_000)
                    .await
                    .expect("upgrade one PostgreSQL schema generation");
            }
            transaction
                .commit()
                .await
                .expect("commit migration upgrade");
            let row: (i32, Vec<u8>) = sqlx::query_as(&format!(
                "SELECT version,checksum FROM {schema}.runtrue_schema_migrations
                 ORDER BY version DESC LIMIT 1"
            ))
            .fetch_one(&mut *connection)
            .await
            .expect("read upgraded migration generation");
            assert_eq!(row.0, version);
            assert_eq!(row.1, Sha256::digest(migration.as_bytes()).to_vec());
        }

        let mut transaction = connection.begin().await.expect("begin checksum test");
        sqlx::raw_sql(&search_path)
            .execute(&mut *transaction)
            .await
            .expect("select checksum-test schema");
        sqlx::query("UPDATE runtrue_schema_migrations SET checksum=$1 WHERE version=11")
            .bind(vec![0_u8; 32])
            .execute(&mut *transaction)
            .await
            .expect("corrupt isolated migration checksum");
        assert!(matches!(
            apply_postgres_migration(&mut transaction, 11, POSTGRES_MIGRATION_11, 1_001).await,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));
        transaction
            .rollback()
            .await
            .expect("rollback checksum corruption");
        drop(connection);
        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(pool)
            .await
            .expect("drop isolated migration-upgrade schema");
    }

    #[cfg(feature = "postgres")]
    fn postgres_error_has_code(error: &sqlx::Error, expected: &str) -> bool {
        error
            .as_database_error()
            .and_then(|database| database.code())
            .is_some_and(|code| code == expected)
    }

    #[cfg(feature = "postgres")]
    async fn postgres_transaction_failure_contract(store: &PostgresInstallationStore) {
        let pool = store.pool();
        sqlx::raw_sql(
            "DROP TABLE IF EXISTS runtrue_resilience_probe;
             CREATE TABLE runtrue_resilience_probe(
                 id INTEGER PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             INSERT INTO runtrue_resilience_probe(id,value) VALUES(1,0),(2,0),(10,0);",
        )
        .execute(pool)
        .await
        .expect("create PostgreSQL resilience probe");

        // A serialization victim is retried as a fresh transaction. No write
        // from the aborted attempt may survive.
        let mut first_connection = pool
            .acquire()
            .await
            .expect("acquire first serializable writer");
        let mut second_connection = pool
            .acquire()
            .await
            .expect("acquire second serializable writer");
        let mut first = first_connection
            .begin()
            .await
            .expect("begin first serializable writer");
        let mut second = second_connection
            .begin()
            .await
            .expect("begin second serializable writer");
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *first)
            .await
            .unwrap();
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *second)
            .await
            .unwrap();
        let first_value: i32 =
            sqlx::query_scalar("SELECT value FROM runtrue_resilience_probe WHERE id=10")
                .fetch_one(&mut *first)
                .await
                .unwrap();
        let second_value: i32 =
            sqlx::query_scalar("SELECT value FROM runtrue_resilience_probe WHERE id=10")
                .fetch_one(&mut *second)
                .await
                .unwrap();
        sqlx::query("UPDATE runtrue_resilience_probe SET value=$1 WHERE id=10")
            .bind(first_value + 1)
            .execute(&mut *first)
            .await
            .unwrap();
        first.commit().await.unwrap();
        let serialization = sqlx::query("UPDATE runtrue_resilience_probe SET value=$1 WHERE id=10")
            .bind(second_value + 1)
            .execute(&mut *second)
            .await
            .expect_err("second serializable writer must abort");
        assert!(postgres_error_has_code(&serialization, "40001"));
        second.rollback().await.ok();
        drop(first_connection);
        drop(second_connection);

        let mut retry = pool
            .begin()
            .await
            .expect("begin whole-boundary serialization retry");
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *retry)
            .await
            .unwrap();
        sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=10")
            .execute(&mut *retry)
            .await
            .unwrap();
        retry.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i32>("SELECT value FROM runtrue_resilience_probe WHERE id=10")
                .fetch_one(pool)
                .await
                .unwrap(),
            2
        );

        // Force a real PostgreSQL deadlock, commit the winner, then retry the
        // aborted use-case from its first statement in canonical lock order.
        let mut first_connection = pool.acquire().await.expect("acquire first deadlock writer");
        let mut second_connection = pool
            .acquire()
            .await
            .expect("acquire second deadlock writer");
        let mut first = first_connection
            .begin()
            .await
            .expect("begin first deadlock writer");
        let mut second = second_connection
            .begin()
            .await
            .expect("begin second deadlock writer");
        sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=1")
            .execute(&mut *first)
            .await
            .unwrap();
        sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=2")
            .execute(&mut *second)
            .await
            .unwrap();
        let (first_result, second_result) = tokio::join!(
            sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=2")
                .execute(&mut *first),
            sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=1")
                .execute(&mut *second),
        );
        match (first_result, second_result) {
            (Err(error), Ok(_)) => {
                assert!(postgres_error_has_code(&error, "40P01"));
                first.rollback().await.ok();
                second.commit().await.unwrap();
            }
            (Ok(_), Err(error)) => {
                assert!(postgres_error_has_code(&error, "40P01"));
                second.rollback().await.ok();
                first.commit().await.unwrap();
            }
            result => panic!("expected exactly one PostgreSQL deadlock victim: {result:?}"),
        }
        drop(first_connection);
        drop(second_connection);
        let mut retry = pool
            .begin()
            .await
            .expect("begin whole-boundary deadlock retry");
        for id in [1_i32, 2] {
            sqlx::query("UPDATE runtrue_resilience_probe SET value=value+1 WHERE id=$1")
                .bind(id)
                .execute(&mut *retry)
                .await
                .unwrap();
        }
        retry.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, Vec<i32>>(
                "SELECT array_agg(value ORDER BY id) FROM runtrue_resilience_probe WHERE id IN(1,2)"
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            vec![2, 2]
        );

        // Kill a backend after an uncommitted write. The transaction must be
        // lost, while the pool reconnects as it would after endpoint failover.
        let mut victim = pool
            .acquire()
            .await
            .expect("acquire connection-loss victim");
        let victim_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *victim)
            .await
            .unwrap();
        let mut transaction = victim
            .begin()
            .await
            .expect("begin connection-loss transaction");
        sqlx::query("INSERT INTO runtrue_resilience_probe(id,value) VALUES(99,1)")
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
                .bind(victim_pid)
                .fetch_one(pool)
                .await
                .expect("terminate test backend")
        );
        assert!(transaction.commit().await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM runtrue_resilience_probe WHERE id=99"
            )
            .fetch_one(pool)
            .await
            .expect("reconnect pool after backend replacement"),
            0
        );
        assert_eq!(
            store
                .load_database_readiness()
                .await
                .expect("read readiness after simulated failover")
                .installation_id,
            store.installation_id()
        );
        sqlx::raw_sql("DROP TABLE runtrue_resilience_probe")
            .execute(pool)
            .await
            .expect("drop PostgreSQL resilience probe");
    }

    #[cfg(feature = "postgres")]
    async fn postgres_startup_history_and_restore_contract(
        store: &PostgresInstallationStore,
        config: &PostgresDatabaseConfig,
    ) {
        PostgresInstallationStore::connect_existing(config.clone(), "pg-contract")
            .await
            .expect("runtime reconnects to an exact existing schema")
            .close()
            .await;
        let original_implementation: Vec<u8> = sqlx::query_scalar(
            "SELECT implementation_sha256 FROM runtrue_schema_migrations WHERE sequence=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("read unified implementation digest");
        sqlx::query(
            "UPDATE runtrue_schema_migrations SET implementation_sha256=$1 WHERE sequence=1",
        )
        .bind(vec![0_u8; 32])
        .execute(store.pool())
        .await
        .expect("corrupt unified implementation digest");
        let digest_result =
            PostgresInstallationStore::connect_existing(config.clone(), "pg-contract").await;
        sqlx::query(
            "UPDATE runtrue_schema_migrations SET implementation_sha256=$1 WHERE sequence=1",
        )
        .bind(original_implementation)
        .execute(store.pool())
        .await
        .expect("restore unified implementation digest");
        assert!(matches!(
            digest_result,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));

        let baseline: (String, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            "SELECT migration_id,definition_sha256,implementation_sha256,applied_unix_ms
             FROM runtrue_schema_migrations WHERE sequence=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("read unified baseline record");
        sqlx::query("DELETE FROM runtrue_schema_migrations WHERE sequence=1")
            .execute(store.pool())
            .await
            .expect("remove unified baseline record");
        let outdated =
            PostgresInstallationStore::connect_existing(config.clone(), "pg-contract").await;
        sqlx::query(
            "INSERT INTO runtrue_schema_migrations
             (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
             VALUES(1,$1,$2,$3,$4)",
        )
        .bind(&baseline.0)
        .bind(&baseline.1)
        .bind(&baseline.2)
        .bind(baseline.3)
        .execute(store.pool())
        .await
        .expect("restore unified baseline record");
        assert!(matches!(
            outdated,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));

        sqlx::query(
            "INSERT INTO runtrue_schema_migrations
             (sequence,migration_id,definition_sha256,implementation_sha256,applied_unix_ms)
             VALUES($1,'future-contract',$2,$3,$4)",
        )
        .bind(i32::try_from(LOGICAL_SCHEMA_GENERATION + 1).unwrap())
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .bind(1_101_i64)
        .execute(store.pool())
        .await
        .expect("insert future migration generation");
        let future_result =
            PostgresInstallationStore::connect_existing(config.clone(), "pg-contract").await;
        sqlx::query("DELETE FROM runtrue_schema_migrations WHERE sequence>$1")
            .bind(i32::try_from(LOGICAL_SCHEMA_GENERATION).unwrap())
            .execute(store.pool())
            .await
            .expect("remove future migration generation");
        assert!(matches!(
            future_result,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));

        let safe = store
            .enter_restore_safe_mode(1_200)
            .await
            .expect("enter durable PostgreSQL restore safe mode");
        let reconnected =
            PostgresInstallationStore::connect_existing(config.clone(), "pg-contract")
                .await
                .expect("reconnect during PostgreSQL restore safe mode");
        let readiness = reconnected
            .load_database_readiness()
            .await
            .expect("read restored PostgreSQL readiness");
        assert_eq!(readiness.recovery, safe);
        assert!(readiness.recovery.safe_mode);
        let active = reconnected
            .leave_restore_safe_mode(safe.fencing_epoch)
            .await
            .expect("activate restored PostgreSQL generation");
        assert!(!active.safe_mode);
        assert_eq!(active.fencing_epoch, safe.fencing_epoch);
        reconnected.close().await;
    }

    #[cfg(feature = "postgres")]
    async fn postgres_non_ddl_runtime_contract(
        store: &PostgresInstallationStore,
        config: &PostgresDatabaseConfig,
    ) {
        let role = format!("runtrue_runtime_contract_{}", std::process::id());
        let password = "runtime-contract-password";
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(store.pool())
            .await
            .expect("read PostgreSQL contract database");
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(store.pool())
            .await
            .expect("read PostgreSQL contract schema");
        let quoted_role = format!("\"{}\"", role.replace('"', "\"\""));
        let quoted_database = format!("\"{}\"", database.replace('"', "\"\""));
        let quoted_schema = format!("\"{}\"", schema.replace('"', "\"\""));
        sqlx::raw_sql(&format!(
            "DROP ROLE IF EXISTS {quoted_role};
             CREATE ROLE {quoted_role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
             GRANT CONNECT ON DATABASE {quoted_database} TO {quoted_role};
             GRANT USAGE ON SCHEMA {quoted_schema} TO {quoted_role};
             REVOKE CREATE ON SCHEMA {quoted_schema} FROM {quoted_role};
             GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA {quoted_schema} TO {quoted_role};
             GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA {quoted_schema} TO {quoted_role};"
        ))
        .execute(store.pool())
        .await
        .expect("create non-DDL PostgreSQL runtime role");

        let runtime_config = PostgresDatabaseConfig {
            options: config.options.clone().username(&role).password(password),
            maximum_connections: 1,
            acquire_timeout: config.acquire_timeout,
        };
        let runtime = PostgresInstallationStore::connect_existing(runtime_config, "pg-contract")
            .await
            .expect("connect with non-DDL runtime credentials");
        let readiness = runtime
            .load_database_readiness()
            .await
            .expect("runtime role reads installation readiness");
        assert_eq!(readiness.schema_version, POSTGRES_SCHEMA_VERSION);
        assert_eq!(readiness.installation_id, "pg-contract");
        let ddl = sqlx::raw_sql("CREATE TABLE runtrue_runtime_ddl_probe(id INTEGER)")
            .execute(runtime.pool())
            .await;
        assert!(
            ddl.as_ref()
                .err()
                .is_some_and(|error| postgres_error_has_code(error, "42501")),
            "runtime role unexpectedly has DDL privilege: {ddl:?}"
        );
        runtime.close().await;

        sqlx::raw_sql(&format!(
            "DROP OWNED BY {quoted_role}; DROP ROLE {quoted_role};"
        ))
        .execute(store.pool())
        .await
        .expect("remove non-DDL PostgreSQL runtime role");
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn remote_postgres_requires_verified_tls() {
        assert!(PostgresDatabaseConfig::parse(
            "postgres://runtrue:secret@db.example.test/runtrue?sslmode=disable"
        )
        .is_err());
        assert!(PostgresDatabaseConfig::parse(
            "postgres://runtrue:secret@db.example.test/runtrue?sslmode=verify-full"
        )
        .is_ok());
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn loopback_postgres_may_disable_tls_for_development() {
        assert!(PostgresDatabaseConfig::parse(
            "postgres://runtrue:secret@127.0.0.1/runtrue?sslmode=disable"
        )
        .is_ok());
    }

    #[tokio::test]
    async fn sqlite_installation_boundary_contract() {
        let store =
            ControlPlane::open_in_memory("sqlite-contract", 17).expect("initialize SQLite store");
        let readiness = store
            .load_database_readiness()
            .await
            .expect("read SQLite readiness");
        assert_eq!(readiness.backend, DatabaseBackendKind::Sqlite);
        assert_eq!(readiness.installation_id, "sqlite-contract");
        assert_eq!(readiness.recovery.fencing_epoch, 1);
        assert!(!readiness.recovery.safe_mode);
        assert!(readiness.schema_version >= 1);
        installation_recovery_contract(&store).await;
        tenant_identity_contract(&store).await;
        human_identity_contract(&store).await;
        scm_repositories::contract(&store).await;
        scm_repositories::github_contract(&store).await;
        {
            let connection = store.connection().expect("SQLite SCM dependency fixture");
            connection.execute_batch(
                "INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,lease_owner,lease_expires_unix_ms,created_unix_ms) VALUES
                 ('scm-event-task-contract','scm.event','{}','pending',0,0,NULL,NULL,0),
                 ('scm-check-task-contract','scm.check.publish','{}','claimed',0,1,'check-worker',1000,0),
                 ('scm-check-failure-task-contract','scm.check.publish','{}','claimed',0,1,'check-worker',1000,0),
                 ('scm-completion-task-contract','scm.event','{}','claimed',0,1,'scm-completion-worker',1000,600),
                 ('scm-analysis-origin-contract','scm.event','{}','completed',0,1,NULL,NULL,600),
                 ('scm-continuation-task-contract','scm.approval.continue','{}','claimed',0,1,'scm-continuation-worker',1000,700);
                 INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('capsule-contract','repository-contract','sha256:0000000000000000000000000000000000000000000000000000000000000000',X'00','{}','key',0);
                 INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES('run-contract','repository-contract','capsule-contract','queued',0,1,0);
                 INSERT INTO source_snapshots(id,tenant_id,repository_id,commit_sha,tree_manifest_digest,state,created_unix_ms,verified_unix_ms) VALUES('source-snapshot-contract','tenant-contract','repository-contract','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:0000000000000000000000000000000000000000000000000000000000000000','ready',0,1);",
            ).expect("seed SQLite SCM dependencies");
            let source = serde_json::json!({"normalized_event_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workflow_path":".runtrue/workflows/ci.yaml","proposed_workflow_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000002","reusable_workflow_digests":[],"policy_version_ids":["policy-contract"]});
            let context = serde_json::json!({"pending_execution_id":"scm-pending-contract","event":{},"role":"direct","source_identity":source.clone()});
            let run = serde_json::json!({"id":"scm-continuation-run-contract","repository_id":"repository-contract","capsule_id":"capsule-contract","priority":0,"remote":true,"created_unix_ms":700,"jobs":[{"id":"scm-continuation-job-contract","job_key":"build","attempt":1,"requirements":{"os":"linux","arch":"amd64","isolation":"microvm","cpu":1,"memory_bytes":1024,"storage_bytes":1024,"region":"test","required_capabilities":["kvm"],"allowed_pools":[]}}]});
            let approval = serde_json::json!({"id":"scm-approval-contract","kind":"workflow-definition","subject_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000003","risk_score":10,"created_unix_ms":600,"expires_unix_ms":1000,"rule":{"id":"rule-contract","required_approvals":1,"eligible_approvers":["approver"],"forbidden_approvers":[],"one_shot":true},"status":"approved","decisions":{}});
            connection.execute("UPDATE durable_tasks SET payload_json=?2 WHERE id=?1",rusqlite::params!["scm-continuation-task-contract",serde_json::to_string(&serde_json::json!({"pending_execution_id":"scm-pending-contract","approval_id":"scm-approval-contract"})).unwrap()]).unwrap();
            connection.execute("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES(?1,'repository-contract','capsule-contract',?2,'approved',?3,600,1000)",rusqlite::params!["scm-approval-contract","sha256:0000000000000000000000000000000000000000000000000000000000000003",serde_json::to_string(&approval).unwrap()]).unwrap();
            connection.execute("INSERT INTO scm_pending_executions(id,origin_task_id,repository_id,capsule_id,role,state,context_json,run_request_json,workflow_approval_id,created_unix_ms,expires_unix_ms) VALUES('scm-pending-contract','scm-analysis-origin-contract','repository-contract','capsule-contract','direct','awaiting-approval',?1,?2,'scm-approval-contract',600,1000)",rusqlite::params![serde_json::to_vec(&context).unwrap(),serde_json::to_vec(&run).unwrap()]).unwrap();
            connection.execute("INSERT INTO scm_proposed_analyses(id,origin_task_id,repository_id,status,source_identity_json,failure,created_unix_ms) VALUES('scm-analysis-contract','scm-analysis-origin-contract','repository-contract','invalid',?1,'contract analysis failed',600)",[serde_json::to_vec(&source).unwrap()]).unwrap();
        }
        scm_repositories::dependent_contract(&store).await;
        scm_repositories::completion_report_contract(&store).await;
        runs_approvals::core_contract(&store).await;
        runs_approvals::approval_contract(&store).await;
        runs_approvals::source_snapshot_contract(&store).await;
        {
            let connection = store.connection().expect("SQLite source ticket fixture");
            connection.execute_batch("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES('source-pool-contract','tenant-contract','source-pool','active',850); INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('source-runner-contract','source-pool-contract','online','{}',850,850); INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('source-lease-contract','source-job-contract','tenant-contract','source-runner-contract',1,3,'sha256:0000000000000000000000000000000000000000000000000000000000000000','active',850,855,950,960);").expect("seed SQLite source ticket lease");
        }
        runs_approvals::source_ticket_contract(&store).await;
        runs_approvals::workflow_record_contract(&store).await;
        {
            let connection = store
                .connection()
                .expect("SQLite workflow materialization fixture");
            connection.execute_batch("UPDATE job_fencing SET last_generation=1 WHERE job_id='workflow-producer-job-contract'; INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('workflow-expansion-lease-contract','workflow-producer-job-contract','tenant-contract','source-runner-contract',1,3,'sha256:0000000000000000000000000000000000000000000000000000000000000000','active',885,887,980,990);").expect("seed SQLite workflow materialization lease");
        }
        runs_approvals::workflow_materialize_contract(&store).await;
        scm_repositories::continuation_state_contract(&store).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_installation_boundary_contract() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = PostgresTestSchema::create(&url, "installation-boundary").await;
        let config = fixture.config();
        let (store, applied) = PostgresInstallationStore::connect_and_migrate_with_report(
            config.clone(),
            "pg-contract",
            17,
        )
        .await
        .expect("initialize PostgreSQL store");
        assert_eq!(
            applied.applied_migration_ids,
            [
                "legacy-baseline-v1",
                "runner-immutable-replacement-v1",
                "reusable-capability-approvals-v1",
                "user-management-v1",
                "durable-event-replay-v1",
                "scm-event-recovery-v1",
                "repository-writer-auto-approval-v1"
            ]
        );
        assert_eq!(
            applied.bridged_legacy_lineage.as_deref(),
            Some("postgres-v1-through-v12")
        );
        let (replayed_store, replayed) =
            PostgresInstallationStore::connect_and_migrate_with_report(
                config.clone(),
                "pg-contract",
                18,
            )
            .await
            .expect("replay PostgreSQL unified migration catalog");
        assert_eq!(
            replayed.replayed_migration_ids,
            [
                "legacy-baseline-v1",
                "runner-immutable-replacement-v1",
                "reusable-capability-approvals-v1",
                "user-management-v1",
                "durable-event-replay-v1",
                "scm-event-recovery-v1",
                "repository-writer-auto-approval-v1"
            ]
        );
        assert!(replayed.applied_migration_ids.is_empty());
        replayed_store.close().await;
        let readiness = store
            .load_database_readiness()
            .await
            .expect("read PostgreSQL readiness");
        assert_eq!(readiness.backend, DatabaseBackendKind::Postgres);
        assert_eq!(readiness.schema_version, POSTGRES_SCHEMA_VERSION);
        assert_eq!(readiness.installation_id, "pg-contract");
        assert_eq!(readiness.recovery.fencing_epoch, 1);
        assert!(!readiness.recovery.safe_mode);
        postgres_migration_upgrade_checksum_contract(store.pool()).await;
        installation_recovery_contract(&store).await;
        sqlx::raw_sql(
            "DELETE FROM workflow_frontend_reports;
             DELETE FROM scm_task_results;
             DELETE FROM scm_pending_executions;
             DELETE FROM scm_proposed_analyses;
             DELETE FROM expanded_job_sets;
             DELETE FROM normalized_trigger_events;
             DELETE FROM schedule_trigger_cursors;
             DELETE FROM runner_object_transfers;
             DELETE FROM runner_source_tickets;
             DELETE FROM replay_bundles;
             DELETE FROM run_approval_authorizations;
             DELETE FROM approval_decisions;
             DELETE FROM approval_requests;
             DELETE FROM capsule_api_metadata;
             DELETE FROM github_lifecycle_deliveries;
             DELETE FROM github_app_setup_transactions;
             DELETE FROM github_repository_catalog;
             DELETE FROM github_installation_profiles;
             DELETE FROM scm_check_publications;
             DELETE FROM scm_source_fetches;
             DELETE FROM leases;
             DELETE FROM job_fencing;
             DELETE FROM jobs;
             DELETE FROM run_source_snapshots;
             DELETE FROM source_snapshots;
             DELETE FROM runs;
             DELETE FROM capsules;
             DELETE FROM durable_tasks;
             DELETE FROM runners;
             DELETE FROM runner_pools;
             DELETE FROM scm_webhook_events;
             DELETE FROM scm_repository_links;
             DELETE FROM repository_auto_approval_policies;
             DELETE FROM repository_workflow_settings;
             DELETE FROM scm_installations;
             DELETE FROM repositories;
             DELETE FROM tenants;",
        )
        .execute(store.pool())
        .await
        .expect("reset tenant contract fixture");
        tenant_identity_contract(&store).await;
        human_identity_contract(&store).await;
        scm_repositories::contract(&store).await;
        scm_repositories::github_contract(&store).await;
        sqlx::raw_sql(
            "INSERT INTO durable_tasks(id,kind,payload_json,status,available_unix_ms,attempts,lease_owner,lease_expires_unix_ms,created_unix_ms) VALUES
             ('scm-event-task-contract','scm.event','{}','pending',0,0,NULL,NULL,0),
             ('scm-check-task-contract','scm.check.publish','{}','claimed',0,1,'check-worker',1000,0),
             ('scm-check-failure-task-contract','scm.check.publish','{}','claimed',0,1,'check-worker',1000,0),
             ('scm-completion-task-contract','scm.event','{}','claimed',0,1,'scm-completion-worker',1000,600),
             ('scm-analysis-origin-contract','scm.event','{}','completed',0,1,NULL,NULL,600),
             ('scm-continuation-task-contract','scm.approval.continue','{}','claimed',0,1,'scm-continuation-worker',1000,700);
             INSERT INTO capsules(id,repository_id,digest,canonical_capsule,signature_json,key_id,created_unix_ms) VALUES('capsule-contract','repository-contract','sha256:0000000000000000000000000000000000000000000000000000000000000000','\\x00','{}','key',0);
             INSERT INTO runs(id,repository_id,capsule_id,status,priority,remote,created_unix_ms) VALUES('run-contract','repository-contract','capsule-contract','queued',0,TRUE,0);
             INSERT INTO source_snapshots(id,tenant_id,repository_id,commit_sha,tree_manifest_digest,state,created_unix_ms,verified_unix_ms) VALUES('source-snapshot-contract','tenant-contract','repository-contract','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sha256:0000000000000000000000000000000000000000000000000000000000000000','ready',0,1);",
        ).execute(store.pool()).await.expect("seed PostgreSQL SCM dependencies");
        let source = serde_json::json!({"normalized_event_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workflow_path":".runtrue/workflows/ci.yaml","proposed_workflow_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000002","reusable_workflow_digests":[],"policy_version_ids":["policy-contract"]});
        let context = serde_json::json!({"pending_execution_id":"scm-pending-contract","event":{},"role":"direct","source_identity":source.clone()});
        let run = serde_json::json!({"id":"scm-continuation-run-contract","repository_id":"repository-contract","capsule_id":"capsule-contract","priority":0,"remote":true,"created_unix_ms":700,"jobs":[{"id":"scm-continuation-job-contract","job_key":"build","attempt":1,"requirements":{"os":"linux","arch":"amd64","isolation":"microvm","cpu":1,"memory_bytes":1024,"storage_bytes":1024,"region":"test","required_capabilities":["kvm"],"allowed_pools":[]}}]});
        let approval = serde_json::json!({"id":"scm-approval-contract","kind":"workflow-definition","subject_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000003","risk_score":10,"created_unix_ms":600,"expires_unix_ms":1000,"rule":{"id":"rule-contract","required_approvals":1,"eligible_approvers":["approver"],"forbidden_approvers":[],"one_shot":true},"status":"approved","decisions":{}});
        sqlx::query("UPDATE durable_tasks SET payload_json=$2 WHERE id=$1").bind("scm-continuation-task-contract").bind(serde_json::to_vec(&serde_json::json!({"pending_execution_id":"scm-pending-contract","approval_id":"scm-approval-contract"})).unwrap()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO approval_requests(id,repository_id,capsule_id,subject_digest,status,request_json,created_unix_ms,expires_unix_ms) VALUES($1,'repository-contract','capsule-contract',$2,'approved',$3,600,1000)").bind("scm-approval-contract").bind("sha256:0000000000000000000000000000000000000000000000000000000000000003").bind(serde_json::to_vec(&approval).unwrap()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO scm_pending_executions(id,origin_task_id,repository_id,capsule_id,role,state,context_json,run_request_json,workflow_approval_id,created_unix_ms,expires_unix_ms) VALUES('scm-pending-contract','scm-analysis-origin-contract','repository-contract','capsule-contract','direct','awaiting-approval',$1,$2,'scm-approval-contract',600,1000)").bind(serde_json::to_vec(&context).unwrap()).bind(serde_json::to_vec(&run).unwrap()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO scm_proposed_analyses(id,origin_task_id,repository_id,status,source_identity_json,failure,created_unix_ms) VALUES('scm-analysis-contract','scm-analysis-origin-contract','repository-contract','invalid',$1,'contract analysis failed',600)").bind(serde_json::to_vec(&source).unwrap()).execute(store.pool()).await.unwrap();
        scm_repositories::dependent_contract(&store).await;
        scm_repositories::completion_report_contract(&store).await;
        runs_approvals::core_contract(&store).await;
        runs_approvals::approval_contract(&store).await;
        runs_approvals::source_snapshot_contract(&store).await;
        sqlx::query("INSERT INTO runner_pools(id,tenant_id,name,status,created_unix_ms) VALUES('source-pool-contract','tenant-contract','source-pool','active',850)").execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO runners(id,pool_id,status,runner_json,created_unix_ms,updated_unix_ms) VALUES('source-runner-contract','source-pool-contract','online',$1,850,850)").bind(b"{}".as_slice()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('source-lease-contract','source-job-contract','tenant-contract','source-runner-contract',1,3,'sha256:0000000000000000000000000000000000000000000000000000000000000000','active',850,855,950,960)").execute(store.pool()).await.unwrap();
        runs_approvals::source_ticket_contract(&store).await;
        runs_approvals::workflow_record_contract(&store).await;
        sqlx::query("UPDATE job_fencing SET last_generation=1 WHERE job_id='workflow-producer-job-contract'").execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO leases(id,job_id,tenant_id,runner_id,fencing_generation,installation_fencing_epoch,capsule_digest,state,issued_unix_ms,accept_by_unix_ms,expires_unix_ms,hard_deadline_unix_ms) VALUES('workflow-expansion-lease-contract','workflow-producer-job-contract','tenant-contract','source-runner-contract',1,3,'sha256:0000000000000000000000000000000000000000000000000000000000000000','active',885,887,980,990)").execute(store.pool()).await.unwrap();
        runs_approvals::workflow_materialize_contract(&store).await;
        scm_repositories::continuation_state_contract(&store).await;
        postgres_non_ddl_runtime_contract(&store, &config).await;
        postgres_transaction_failure_contract(&store).await;
        postgres_startup_history_and_restore_contract(&store, &config).await;
        store.close().await;

        assert!(matches!(
            PostgresInstallationStore::connect(config.clone(), "other-installation", 18).await,
            Err(ControlPlaneError::InstallationMismatch { .. })
        ));
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn concurrent_postgres_starters_apply_unified_catalog_once() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = PostgresTestSchema::create(&url, "concurrent-migration").await;
        let first = PostgresInstallationStore::connect_and_migrate_with_report(
            fixture.config(),
            "concurrent-migration",
            1,
        );
        let second = PostgresInstallationStore::connect_and_migrate_with_report(
            fixture.config(),
            "concurrent-migration",
            2,
        );
        let ((first_store, first_report), (second_store, second_report)) =
            tokio::try_join!(first, second).expect("serialize concurrent migration starters");
        let applied = [&first_report, &second_report]
            .into_iter()
            .filter(|report| !report.applied_migration_ids.is_empty())
            .count();
        let replayed = [&first_report, &second_report]
            .into_iter()
            .filter(|report| !report.replayed_migration_ids.is_empty())
            .count();
        assert_eq!((applied, replayed), (1, 1));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtrue_schema_migrations")
            .fetch_one(first_store.pool())
            .await
            .unwrap();
        assert_eq!(rows, i64::from(LOGICAL_SCHEMA_GENERATION));
        first_store.close().await;
        second_store.close().await;
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn existing_postgres_legacy_head_bridges_only_after_exact_validation() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = PostgresTestSchema::create(&url, "legacy-bridge").await;
        let setup = fixture.isolated_pool().await;
        let mut transaction = setup.begin().await.unwrap();
        sqlx::raw_sql(POSTGRES_MIGRATION_1)
            .execute(&mut *transaction)
            .await
            .unwrap();
        record_postgres_migration(&mut transaction, 1, POSTGRES_MIGRATION_1, 1)
            .await
            .unwrap();
        for (version, migration) in POSTGRES_MIGRATIONS.iter().skip(1) {
            apply_postgres_migration(&mut transaction, *version, migration, 1)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO installation_state(singleton,installation_id,fencing_epoch)
             VALUES(TRUE,'legacy-bridge',1)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        assert!(matches!(
            PostgresInstallationStore::connect_existing(fixture.config(), "legacy-bridge").await,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));
        sqlx::query("UPDATE runtrue_schema_migrations SET checksum=$1 WHERE version=11")
            .bind(vec![0_u8; 32])
            .execute(&setup)
            .await
            .unwrap();
        assert!(matches!(
            PostgresInstallationStore::connect_and_migrate(fixture.config(), "legacy-bridge", 2)
                .await,
            Err(ControlPlaneError::InvalidMigrationHistory(_))
        ));
        let still_legacy: Vec<String> = sqlx::query_scalar(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema=current_schema() AND table_name='runtrue_schema_migrations'
             ORDER BY ordinal_position",
        )
        .fetch_all(&setup)
        .await
        .unwrap();
        assert_eq!(still_legacy, ["version", "checksum", "applied_unix_ms"]);

        sqlx::query("UPDATE runtrue_schema_migrations SET checksum=$1 WHERE version=11")
            .bind(Sha256::digest(POSTGRES_MIGRATION_11.as_bytes()).as_slice())
            .execute(&setup)
            .await
            .unwrap();
        let (store, report) = PostgresInstallationStore::connect_and_migrate_with_report(
            fixture.config(),
            "legacy-bridge",
            3,
        )
        .await
        .expect("bridge an exact committed PostgreSQL legacy head");
        assert_eq!(
            report.applied_migration_ids,
            [
                "legacy-baseline-v1",
                "runner-immutable-replacement-v1",
                "reusable-capability-approvals-v1",
                "user-management-v1",
                "durable-event-replay-v1",
                "scm-event-recovery-v1",
                "repository-writer-auto-approval-v1"
            ]
        );
        let legacy_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM runtrue_legacy_schema_migrations")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(legacy_rows, i64::from(POSTGRES_SCHEMA_VERSION));
        store.close().await;
        setup.close().await;
        fixture.cleanup().await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_initialization_rejects_unmanaged_schema_objects() {
        let Ok(url) = std::env::var("RUNTRUE_TEST_POSTGRES_URL") else {
            return;
        };
        let fixture = PostgresTestSchema::create(&url, "schema-provenance").await;
        let setup = fixture.isolated_pool().await;
        sqlx::raw_sql("CREATE TABLE installation_state(unmanaged TEXT)")
            .execute(&setup)
            .await
            .expect("create unmanaged Runtrue-named object");

        let rejected = PostgresInstallationStore::connect_and_migrate(
            fixture.config(),
            "schema-provenance",
            1,
        )
        .await;
        assert!(matches!(
            rejected,
            Err(ControlPlaneError::InvalidMigrationHistory(message))
                if message.contains("unmanaged pre-existing objects")
        ));
        let ledger_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('runtrue_schema_migrations') IS NOT NULL")
                .fetch_one(&setup)
                .await
                .expect("check rejected initialization did not create a ledger");
        assert!(!ledger_exists);

        sqlx::raw_sql("DROP TABLE installation_state")
            .execute(&setup)
            .await
            .expect("restore empty schema");
        sqlx::raw_sql(POSTGRES_MIGRATION_1)
            .execute(&setup)
            .await
            .expect("precreate migration-one tables without provenance");
        let fake_ledger = PostgresInstallationStore::connect_and_migrate(
            fixture.config(),
            "schema-provenance",
            2,
        )
        .await;
        assert!(matches!(
            fake_ledger,
            Err(ControlPlaneError::InvalidMigrationHistory(message))
                if message.contains("refusing to adopt pre-existing schema objects")
        ));
        sqlx::raw_sql("DROP TABLE installation_state, runtrue_schema_migrations")
            .execute(&setup)
            .await
            .expect("remove fake migration-one objects");
        let initialized = PostgresInstallationStore::connect_and_migrate(
            fixture.config(),
            "schema-provenance",
            3,
        )
        .await
        .expect("initialize canonical empty schema");
        initialized.close().await;
        let idempotent = PostgresInstallationStore::connect_and_migrate(
            fixture.config(),
            "schema-provenance",
            4,
        )
        .await
        .expect("reinitialize canonical schema idempotently");
        idempotent.close().await;
        setup.close().await;
        fixture.cleanup().await;
    }
}
