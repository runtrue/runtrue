CREATE TABLE runner_pools (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    region TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (tenant_id, name)
);

CREATE TABLE runners (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    status TEXT NOT NULL CHECK (status IN (
        'online', 'draining', 'quarantined', 'offline', 'revoked'
    )),
    runner_json BYTEA NOT NULL CHECK (octet_length(runner_json) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms)
);

CREATE TABLE runner_enrollment_postures (
    runner_id TEXT PRIMARY KEY REFERENCES runners(id),
    inventory_digest TEXT NOT NULL,
    posture_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0)
);

CREATE TABLE runner_certificates (
    fingerprint TEXT PRIMARY KEY,
    runner_id TEXT NOT NULL REFERENCES runners(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    serial_hex TEXT NOT NULL UNIQUE,
    not_before_unix_ms BIGINT NOT NULL CHECK (not_before_unix_ms >= 0),
    not_after_unix_ms BIGINT NOT NULL CHECK (not_after_unix_ms > not_before_unix_ms),
    status TEXT NOT NULL CHECK (status IN ('active', 'overlap', 'revoked')),
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    overlap_until_unix_ms BIGINT,
    revoked_unix_ms BIGINT,
    CHECK (
        (status = 'active' AND overlap_until_unix_ms IS NULL AND revoked_unix_ms IS NULL)
        OR (status = 'overlap' AND overlap_until_unix_ms IS NOT NULL AND revoked_unix_ms IS NULL)
        OR (status = 'revoked' AND revoked_unix_ms IS NOT NULL)
    )
);

CREATE UNIQUE INDEX one_active_certificate_per_runner
    ON runner_certificates(runner_id) WHERE status = 'active';

CREATE INDEX runner_certificates_runner_status
    ON runner_certificates(runner_id, status, issued_unix_ms);

CREATE TABLE runner_certificate_rotations (
    old_fingerprint TEXT PRIMARY KEY REFERENCES runner_certificates(fingerprint),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    csr_digest TEXT NOT NULL,
    new_fingerprint TEXT NOT NULL UNIQUE REFERENCES runner_certificates(fingerprint),
    new_certificate_json BYTEA NOT NULL CHECK (octet_length(new_certificate_json) <= 1048576),
    certificate_chain_pem BYTEA NOT NULL CHECK (octet_length(certificate_chain_pem) <= 262144),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0)
);

CREATE INDEX runner_certificate_rotations_by_runner
    ON runner_certificate_rotations(runner_id, created_unix_ms, old_fingerprint);

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    consumed_unix_ms BIGINT CHECK (consumed_unix_ms >= created_unix_ms)
);

CREATE TABLE runner_enrollment_idempotency (
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    enrollment_token_id TEXT NOT NULL REFERENCES enrollment_tokens(id),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (operation, idempotency_key)
);

-- Migration 0009 owns runs and jobs. Their stable identifiers remain scalar
-- bindings here because lease creation validates the run/job boundary in its
-- transaction and restore fencing joins back to jobs atomically.
CREATE TABLE job_fencing (
    job_id TEXT PRIMARY KEY,
    last_generation BIGINT NOT NULL CHECK (last_generation >= 0)
);

CREATE TABLE tenant_scheduler_quotas (
    tenant_id TEXT PRIMARY KEY,
    maximum_running_jobs INTEGER NOT NULL CHECK (maximum_running_jobs > 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0)
);

CREATE TABLE runner_scheduler_cursors (
    runner_id TEXT PRIMARY KEY REFERENCES runners(id),
    last_job_id TEXT NOT NULL,
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0)
);

CREATE TABLE runner_job_rejections (
    runner_id TEXT NOT NULL REFERENCES runners(id),
    job_id TEXT NOT NULL,
    rejection_count BIGINT NOT NULL CHECK (rejection_count > 0),
    last_code TEXT NOT NULL,
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    PRIMARY KEY (runner_id, job_id)
);

CREATE TABLE leases (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    runner_id TEXT NOT NULL REFERENCES runners(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch BIGINT NOT NULL CHECK (installation_fencing_epoch >= 1),
    capsule_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'offered', 'active', 'cancel_requested', 'completed', 'rejected', 'expired'
    )),
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    accept_by_unix_ms BIGINT NOT NULL CHECK (accept_by_unix_ms > issued_unix_ms),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    hard_deadline_unix_ms BIGINT NOT NULL CHECK (hard_deadline_unix_ms >= expires_unix_ms),
    terminal_result_digest TEXT,
    terminal_job_state TEXT,
    terminal_credential_taint TEXT NOT NULL DEFAULT 'unobserved' CHECK (
        terminal_credential_taint IN ('unobserved', 'unknown', 'none', 'credential_released')
    ),
    completed_unix_ms BIGINT,
    UNIQUE (job_id, fencing_generation)
);

CREATE UNIQUE INDEX one_open_lease_per_job
    ON leases(job_id) WHERE state IN ('offered', 'active', 'cancel_requested');

-- This binding is intentionally independent of the generic OIDC grant table
-- introduced by migration 0008 so restore and lease fencing can revoke every
-- derived grant, including grants for which no token was minted.
CREATE TABLE runner_oidc_grants (
    grant_id TEXT PRIMARY KEY,
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch BIGINT NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('authorized', 'revoked', 'expired')),
    authorized_unix_ms BIGINT NOT NULL CHECK (authorized_unix_ms >= 0),
    revoked_unix_ms BIGINT,
    CHECK ((state = 'authorized' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt, step_id,
            runner_posture_digest)
);

CREATE INDEX runner_oidc_grants_execution
    ON runner_oidc_grants(execution_lease_id, fencing_generation, state);

CREATE TABLE runner_secret_leases (
    id TEXT PRIMARY KEY,
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch BIGINT NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    secret_metadata_id TEXT NOT NULL,
    secret_version BIGINT NOT NULL CHECK (secret_version >= 1),
    purpose TEXT NOT NULL,
    guest_key_fingerprint TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    state TEXT NOT NULL CHECK (state IN ('delivered', 'revoked', 'expired')),
    revoked_unix_ms BIGINT,
    CHECK ((state = 'delivered' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt, step_id,
            secret_metadata_id, purpose)
);

CREATE INDEX runner_secret_leases_execution
    ON runner_secret_leases(execution_lease_id, fencing_generation, job_attempt, state);

CREATE TABLE runner_oidc_issuances (
    jti TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch BIGINT NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    state TEXT NOT NULL CHECK (state IN ('issued', 'revoked', 'expired')),
    revoked_unix_ms BIGINT,
    CHECK ((state = 'issued' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt, step_id, audience)
);

CREATE TABLE runner_log_frames (
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    monotonic_nanoseconds BIGINT NOT NULL CHECK (monotonic_nanoseconds >= 0),
    wall_time_unix_ms BIGINT NOT NULL CHECK (wall_time_unix_ms >= 0),
    payload BYTEA NOT NULL,
    redaction_state TEXT NOT NULL,
    PRIMARY KEY (execution_lease_id, job_attempt, step_id, stream, sequence)
);

CREATE INDEX runner_log_frames_lease
    ON runner_log_frames(execution_lease_id, job_attempt, step_id, stream, sequence);

CREATE TABLE runner_blob_uploads (
    ticket_id TEXT NOT NULL,
    blob_digest TEXT NOT NULL,
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('cache', 'artifact')),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    maximum_ticket_bytes BIGINT NOT NULL CHECK (maximum_ticket_bytes >= 1),
    recorded_unix_ms BIGINT NOT NULL CHECK (recorded_unix_ms >= 0),
    PRIMARY KEY (ticket_id, blob_digest)
);

CREATE INDEX runner_blob_uploads_scope
    ON runner_blob_uploads(execution_lease_id, fencing_generation, job_attempt, ticket_kind);

CREATE TABLE runner_data_commits (
    kind TEXT NOT NULL CHECK (kind IN ('cache', 'artifact')),
    object_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    output_name TEXT,
    lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    ticket_id TEXT NOT NULL UNIQUE,
    committed_unix_ms BIGINT NOT NULL CHECK (committed_unix_ms >= 0),
    PRIMARY KEY (kind, object_id)
);

CREATE INDEX runner_data_commits_completion_scope
    ON runner_data_commits(lease_id, fencing_generation, job_attempt, kind);

CREATE TABLE job_result_objects (
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('cache', 'artifact')),
    object_id TEXT NOT NULL,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (job_id, job_attempt, kind, object_id),
    UNIQUE (job_id, job_attempt, kind, ordinal),
    FOREIGN KEY (kind, object_id) REFERENCES runner_data_commits(kind, object_id)
);

CREATE TABLE runner_object_transfers (
    ticket_id TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('source', 'cache', 'artifact', 'report')),
    direction TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    expected_size_bytes BIGINT CHECK (expected_size_bytes IS NULL OR expected_size_bytes >= 0),
    transferred_size_bytes BIGINT NOT NULL CHECK (transferred_size_bytes >= 0),
    maximum_ticket_bytes BIGINT NOT NULL CHECK (maximum_ticket_bytes >= 1),
    state TEXT NOT NULL CHECK (state IN (
        'reserved', 'transferring', 'verified', 'committed', 'abandoned'
    )),
    reserved_unix_ms BIGINT NOT NULL CHECK (reserved_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= reserved_unix_ms),
    verified_unix_ms BIGINT,
    PRIMARY KEY (ticket_id, object_digest, direction),
    CHECK (state <> 'verified' OR verified_unix_ms IS NOT NULL)
);

CREATE INDEX runner_object_transfers_scope
    ON runner_object_transfers(
        execution_lease_id, fencing_generation, job_attempt, ticket_kind, direction, state
    );

CREATE INDEX runner_object_transfers_ticket_budget
    ON runner_object_transfers(ticket_id, direction, transferred_size_bytes);

CREATE TABLE runner_pool_scaling_policies (
    pool_id TEXT PRIMARY KEY REFERENCES runner_pools(id),
    baseline_runtime_compatibility_digest TEXT,
    minimum_workers INTEGER NOT NULL CHECK (minimum_workers >= 0),
    minimum_idle_workers INTEGER NOT NULL CHECK (minimum_idle_workers >= 0),
    maximum_workers INTEGER NOT NULL CHECK (maximum_workers > 0),
    scale_up_batch INTEGER NOT NULL CHECK (scale_up_batch > 0),
    idle_timeout_ms BIGINT NOT NULL CHECK (idle_timeout_ms > 0),
    offline_grace_ms BIGINT NOT NULL CHECK (offline_grace_ms > 0),
    cooldown_ms BIGINT NOT NULL CHECK (cooldown_ms > 0),
    enabled BOOLEAN NOT NULL,
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    CHECK (minimum_workers <= maximum_workers),
    CHECK (minimum_idle_workers <= maximum_workers),
    CHECK (scale_up_batch <= maximum_workers),
    CHECK (minimum_workers = 0 OR baseline_runtime_compatibility_digest IS NOT NULL),
    CHECK (minimum_idle_workers = 0 OR baseline_runtime_compatibility_digest IS NOT NULL)
);

CREATE TABLE runner_pool_templates (
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    runtime_compatibility_digest TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_template_id TEXT NOT NULL,
    runner_template_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    PRIMARY KEY (pool_id, runtime_compatibility_digest),
    UNIQUE (pool_id, provider, provider_template_id)
);

CREATE TABLE runner_fleet_requests (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    runtime_compatibility_digest TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_template_id TEXT NOT NULL,
    runner_template_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'requested', 'provisioning', 'bootstrapping', 'enrolled', 'online',
        'draining', 'terminating', 'terminated', 'failed', 'quarantined'
    )),
    provider_request_id TEXT,
    provider_instance_id TEXT,
    runner_id TEXT REFERENCES runners(id),
    failure_code TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (pool_id, provider, provider_request_id),
    UNIQUE (pool_id, provider, provider_instance_id)
);

CREATE INDEX runner_fleet_requests_reconcile
    ON runner_fleet_requests(pool_id, state, updated_unix_ms, id);

CREATE TABLE runner_launch_claims (
    id TEXT PRIMARY KEY,
    fleet_request_id TEXT NOT NULL UNIQUE REFERENCES runner_fleet_requests(id),
    enrollment_token_id TEXT NOT NULL UNIQUE REFERENCES enrollment_tokens(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    provider TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    runner_template_digest TEXT NOT NULL,
    identity_proof_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    consumed_unix_ms BIGINT CHECK (consumed_unix_ms >= created_unix_ms),
    runner_id TEXT UNIQUE REFERENCES runners(id)
);

CREATE INDEX runner_launch_claims_expiry
    ON runner_launch_claims(expires_unix_ms, consumed_unix_ms, id);

CREATE TABLE runner_autoscaler_leases (
    pool_id TEXT PRIMARY KEY REFERENCES runner_pools(id),
    owner_id TEXT NOT NULL,
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation > 0),
    acquired_unix_ms BIGINT NOT NULL CHECK (acquired_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > acquired_unix_ms)
);
