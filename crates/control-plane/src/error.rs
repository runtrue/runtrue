use runtrue_attest::AttestError;
use runtrue_audit::AuditError;
use runtrue_auth::AuthError;
use runtrue_model::{ContentDigest, ModelError};
use runtrue_policy::PolicyError;
use std::{error::Error as StdError, fmt, io};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("unsafe control-plane database path `{path}`: {reason}")]
    UnsafeDatabasePath { path: String, reason: &'static str },
    #[error("control-plane database path operation failed for `{path}`: {source}")]
    DatabasePathIo {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("SQLite control-plane operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[cfg(feature = "postgres")]
    #[error("PostgreSQL control-plane operation failed: {0}")]
    Postgres(#[from] sqlx::Error),
    #[error("invalid database configuration: {0}")]
    InvalidDatabaseConfiguration(&'static str),
    #[error("database migration history is invalid: {0}")]
    InvalidMigrationHistory(String),
    #[error("control-plane JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid model value: {0}")]
    Model(#[from] ModelError),
    #[error("capsule attestation failed: {0}")]
    Attest(#[from] AttestError),
    #[error("capsule encoding failed: {0}")]
    Capsule(#[from] runtrue_workflow_ir::CapsuleError),
    #[error("approval policy rejected operation: {0}")]
    Policy(#[from] PolicyError),
    #[error("active policy lifecycle rejected operation: {0}")]
    ActivePolicy(#[from] runtrue_policy::ActivePolicyError),
    #[error("audit contract rejected operation: {0}")]
    Audit(#[from] AuditError),
    #[error("secret vault rejected operation: {0}")]
    Secrets(#[from] runtrue_secrets::SecretsError),
    #[error("OIDC contract rejected operation: {0}")]
    Oidc(#[from] runtrue_oidc::OidcError),
    #[error("authentication rejected operation: {0}")]
    Auth(#[from] AuthError),
    #[error("control-plane mutex is poisoned")]
    Poisoned,
    #[error("database contains an invalid encoded state: {0}")]
    CorruptState(String),
    #[error("unsupported database schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("database installation is `{expected}`, not `{actual}`")]
    InstallationMismatch { expected: String, actual: String },
    #[error("invalid control-plane input: {0}")]
    InvalidInput(&'static str),
    #[error("{kind} `{id}` was not found")]
    NotFound { kind: &'static str, id: String },
    #[error("repository identity `{owner}/{name}` is registered by multiple tenants")]
    AmbiguousRepositoryIdentity { owner: String, name: String },
    #[error("secret `{name}` is defined by multiple matching projects: {project_ids:?}")]
    AmbiguousSecretResolution {
        name: String,
        project_ids: Vec<String>,
    },
    #[error("configuration project `{id}` version is {actual}, not {expected}")]
    ConfigurationProjectVersionConflict {
        id: String,
        expected: u64,
        actual: u64,
    },
    #[error("secret resolution for `{name}` changed before the Capsule was sealed")]
    StaleSecretResolution { name: String },
    #[error("integer `{field}` cannot be represented durably")]
    IntegerRange { field: &'static str },
    #[error("canonical capsule bytes are not the canonical encoding of their decoded capsule")]
    NonCanonicalCapsule,
    #[error("capsule digest mismatch: expected {expected}, got {actual}")]
    CapsuleDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("idempotency key was already used with a different request body")]
    IdempotencyConflict,
    #[error("GitHub App setup state is invalid, expired, unauthorized, or terminal")]
    InvalidGitHubSetupState,
    #[error("GitHub lifecycle delivery lease is stale, expired, or owned by another worker")]
    GitHubLifecycleLeaseLost,
    #[error("the exact capsule requires an approved subject before a run can be created")]
    ApprovalRequired,
    #[error("OIDC grant does not match the active lease, job, step, capsule, or fence")]
    StaleOidcGrant,
    #[error("runner broker request does not match the active execution binding")]
    RunnerBrokerBindingMismatch,
    #[error("runner broker capability was not declared by the signed step")]
    RunnerBrokerCapabilityDenied,
    #[error("runner broker request was already consumed")]
    RunnerBrokerReplay,
    #[error("invalid {entity} lifecycle transition from `{from}` to `{to}`")]
    InvalidTransition {
        entity: &'static str,
        from: &'static str,
        to: &'static str,
    },
    #[error("installation fencing epoch must increase beyond {current}; got {proposed}")]
    EpochMustIncrease { current: u64, proposed: u64 },
    #[error("stale installation fencing epoch {actual}; expected {expected}")]
    StaleInstallationEpoch { expected: u64, actual: u64 },
    #[error("installation is not in restore safe mode")]
    NotInRestoreSafeMode,
    #[error("installation restore safe mode blocks SCM run creation")]
    InstallationSafeMode,
    #[error("restore safe-mode fencing epoch is {expected}, not {actual}")]
    RestoreEpochMismatch { expected: u64, actual: u64 },
    #[error("restore safe mode cannot end while an execution lease remains open")]
    RestoreHasOpenLeases,
    #[error("stale lease fencing generation {actual}; expected {expected}")]
    StaleLeaseGeneration { expected: u64, actual: u64 },
    #[error("lease belongs to a different runner")]
    WrongRunner,
    #[error("completion conflicts with an already accepted result")]
    ConflictingCompletion,
    #[error("invalid lease state: expected {expected}, got {actual}")]
    InvalidLeaseState {
        expected: &'static str,
        actual: &'static str,
    },
    #[error("lease offer expired before acceptance")]
    LeaseOfferExpired,
    #[error("lease expired before the operation was accepted")]
    LeaseExpired,
    #[error("enrollment token is invalid")]
    InvalidEnrollmentToken,
    #[error("enrollment token expired")]
    EnrollmentTokenExpired,
    #[error("enrollment token was already consumed")]
    EnrollmentTokenConsumed,
    #[error("runner certificate is not authorized")]
    RunnerCertificateUnauthorized,
    #[error("runner and certificate identity bindings do not match")]
    CertificateIdentityMismatch,
    #[error("certificate rotation fingerprint was already bound to a different CSR")]
    RunnerCertificateRotationConflict,
    #[error("runner certificate chain is empty or exceeds its durable bound")]
    InvalidRunnerCertificateChain,
    #[error("runner inventory or posture does not match its enrollment binding")]
    RunnerInventoryMismatch,
    #[error("runner predates authoritative inventory binding and must re-enroll")]
    RunnerReenrollmentRequired,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("durable task is not leased to this worker")]
    TaskNotOwned,
    #[error("durable task lease expired")]
    TaskLeaseExpired,
    #[error("runner autoscaler lease is stale, expired, or owned by another principal")]
    RunnerAutoscalerLeaseLost,
    #[error("tenant storage quota would be exceeded")]
    StorageQuotaExceeded,
    #[error("the installation-wide lifecycle GC lease is held by another worker")]
    LifecycleGcLeaseBusy,
    #[error("the lifecycle GC lease is stale, expired, or in another phase")]
    LifecycleGcLeaseLost,
    #[error("the configured lifecycle GC root bound was exceeded")]
    GcRootLimitExceeded,
    #[error("artifact promotion requires exact passed-scan or waiver evidence")]
    ArtifactPromotionEvidenceRequired,
    #[error("the active policy, environment timer, approval, or provider gate is not satisfied")]
    EnvironmentGateNotReady,
    #[error("the environment concurrency limit is currently exhausted")]
    EnvironmentConcurrencyLimit,
}

#[derive(Debug)]
pub(crate) struct DecodeError(pub(crate) String);

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for DecodeError {}

impl From<DecodeError> for ControlPlaneError {
    fn from(error: DecodeError) -> Self {
        Self::CorruptState(error.0)
    }
}
