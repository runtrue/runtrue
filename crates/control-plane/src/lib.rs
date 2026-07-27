//! Durable SQLite control-plane state and transactional domain operations.
//!
//! This crate intentionally has no HTTP or executor dependency. It persists
//! signed capsules, lifecycle state, fencing, approvals, runner enrollment,
//! background work, metadata snapshots, and a tamper-evident audit chain.

mod error;
pub mod migration;
mod persistence;
#[cfg(feature = "postgres")]
mod postgres_transfer;
mod store;
mod types;

pub use error::ControlPlaneError;
pub use persistence::{
    postgres_boundary_inventory, postgres_transfer_ready, ApiTokenAuditStore, ApprovalStore,
    ArtifactCatalogStore, ArtifactScanPromotionStore, ArtifactStorageStore,
    AutoscaledReplacementPlan, BrowserSessionStore, CacheTrustStore, ConfigurationProjectStore,
    ControlPlaneStore, DatabaseBackendKind, DatabaseReadiness, DeploymentProviderStore,
    DeploymentRequestStore, DeploymentResultStore, DurableTaskStore, EnvironmentGateStore,
    EventStore, ExternalSecretReleaseStore, HumanIdentityStore, InstallationStateStore,
    LifecycleGcStore, OidcGrantStore, PolicyLifecycleStore, PolicyVersionStore,
    PoolEnrollmentCompletion, PostgresBoundaryInventory, PostgresBoundaryStatus, RunCoreStore,
    RunnerFleetEnrollmentStore, RunnerLeaseBrokerStore, RunnerPoolConfiguration,
    ScmRepositoryStore, SecretConfigurationStore, SigningResultStore, SourceSnapshotStore,
    TenantIdentityStore, VariableConfigurationStore, WorkflowSemanticsStore,
};
#[cfg(feature = "postgres")]
pub use persistence::{PostgresDatabaseConfig, PostgresInstallationStore, POSTGRES_SCHEMA_VERSION};
#[cfg(feature = "postgres")]
pub use postgres_transfer::{
    activate_verified_postgres_transfer, copy_sqlite_to_postgres,
    prepare_empty_postgres_destination, PostgresTransferError, PostgresTransferReport,
    PostgresTransferTableReport, SqliteTransferSource,
};
pub use store::{
    artifact_promotion_subject_digest, artifact_scan_subject_digest,
    authoritative_runner_posture_digest, cache_promotion_subject_digest, ControlPlane,
};
pub use types::*;
