CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE installation_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    installation_id TEXT NOT NULL UNIQUE,
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 1)
) STRICT;

CREATE TABLE repositories (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    visibility TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, owner, name)
) STRICT;

CREATE TABLE capsules (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    digest TEXT NOT NULL,
    canonical_capsule BLOB NOT NULL,
    signature_json TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (repository_id, digest)
) STRICT;

CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL REFERENCES capsules(id),
    status TEXT NOT NULL,
    priority INTEGER NOT NULL,
    remote INTEGER NOT NULL CHECK (remote IN (0, 1)),
    created_unix_ms INTEGER NOT NULL,
    started_unix_ms INTEGER,
    completed_unix_ms INTEGER,
    cancel_reason TEXT
) STRICT;

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_key TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    status TEXT NOT NULL,
    requirements_json TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER,
    UNIQUE (run_id, job_key, attempt)
) STRICT;

CREATE TABLE idempotency_records (
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (operation, idempotency_key)
) STRICT;

CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL REFERENCES capsules(id),
    subject_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    request_json TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE approval_decisions (
    approval_id TEXT NOT NULL REFERENCES approval_requests(id),
    actor_id TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    decided_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (approval_id, actor_id)
) STRICT;

CREATE TABLE runner_pools (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    region TEXT,
    status TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, name)
) STRICT;

CREATE TABLE runners (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    status TEXT NOT NULL,
    runner_json TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    consumed_unix_ms INTEGER
) STRICT;

CREATE TABLE job_fencing (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
    last_generation INTEGER NOT NULL CHECK (last_generation >= 0)
) STRICT;

CREATE TABLE leases (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    tenant_id TEXT NOT NULL,
    runner_id TEXT NOT NULL REFERENCES runners(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch INTEGER NOT NULL CHECK (installation_fencing_epoch >= 1),
    capsule_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    issued_unix_ms INTEGER NOT NULL,
    accept_by_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    terminal_result_digest TEXT,
    terminal_job_state TEXT,
    completed_unix_ms INTEGER,
    UNIQUE (job_id, fencing_generation)
) STRICT;

CREATE UNIQUE INDEX one_open_lease_per_job
    ON leases(job_id)
    WHERE state IN ('offered', 'active', 'cancel_requested');

CREATE TABLE durable_tasks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    available_unix_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_expires_unix_ms INTEGER,
    last_error TEXT,
    created_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER
) STRICT;

CREATE INDEX claimable_tasks
    ON durable_tasks(status, available_unix_ms, id);

CREATE TABLE variable_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    values_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, scope, version),
    UNIQUE (tenant_id, scope, digest)
) STRICT;

CREATE TABLE secret_metadata (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_reference TEXT,
    secret_type TEXT NOT NULL,
    status TEXT NOT NULL,
    current_version INTEGER,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, scope, name)
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
    installation_id TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    event_json TEXT NOT NULL
) STRICT;

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

PRAGMA user_version = 1;
