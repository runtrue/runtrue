CREATE TABLE runner_pool_scaling_policies (
    pool_id TEXT PRIMARY KEY REFERENCES runner_pools(id),
    baseline_runtime_compatibility_digest TEXT,
    minimum_workers INTEGER NOT NULL CHECK (minimum_workers >= 0),
    minimum_idle_workers INTEGER NOT NULL CHECK (minimum_idle_workers >= 0),
    maximum_workers INTEGER NOT NULL CHECK (maximum_workers > 0),
    scale_up_batch INTEGER NOT NULL CHECK (scale_up_batch > 0),
    idle_timeout_ms INTEGER NOT NULL CHECK (idle_timeout_ms > 0),
    offline_grace_ms INTEGER NOT NULL CHECK (offline_grace_ms > 0),
    cooldown_ms INTEGER NOT NULL CHECK (cooldown_ms > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_unix_ms INTEGER NOT NULL,
    CHECK (minimum_workers <= maximum_workers),
    CHECK (minimum_idle_workers <= maximum_workers),
    CHECK (scale_up_batch <= maximum_workers),
    CHECK (minimum_workers = 0 OR baseline_runtime_compatibility_digest IS NOT NULL),
    CHECK (minimum_idle_workers = 0 OR baseline_runtime_compatibility_digest IS NOT NULL)
) STRICT;

CREATE TABLE runner_pool_templates (
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    runtime_compatibility_digest TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_template_id TEXT NOT NULL,
    runner_template_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (pool_id, runtime_compatibility_digest),
    UNIQUE (pool_id, provider, provider_template_id)
) STRICT;

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
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (pool_id, provider, provider_request_id),
    UNIQUE (pool_id, provider, provider_instance_id)
) STRICT;

CREATE INDEX runner_fleet_requests_reconcile
    ON runner_fleet_requests(pool_id, state, updated_unix_ms, id);

-- The launch claim is bound to a normal enrollment-token row so existing
-- enrollment remains backward compatible. The corresponding state transition
-- and token consumption must happen in the same immediate transaction.
CREATE TABLE runner_launch_claims (
    id TEXT PRIMARY KEY,
    fleet_request_id TEXT NOT NULL UNIQUE REFERENCES runner_fleet_requests(id),
    enrollment_token_id TEXT NOT NULL UNIQUE REFERENCES enrollment_tokens(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    provider TEXT NOT NULL,
    provider_instance_id TEXT NOT NULL,
    runner_template_digest TEXT NOT NULL,
    identity_proof_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    consumed_unix_ms INTEGER,
    runner_id TEXT UNIQUE REFERENCES runners(id),
    CHECK (expires_unix_ms > created_unix_ms),
    CHECK (consumed_unix_ms IS NULL OR consumed_unix_ms >= created_unix_ms)
) STRICT;

CREATE INDEX runner_launch_claims_expiry
    ON runner_launch_claims(expires_unix_ms, consumed_unix_ms, id);

CREATE TABLE runner_autoscaler_leases (
    pool_id TEXT PRIMARY KEY REFERENCES runner_pools(id),
    owner_id TEXT NOT NULL,
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation > 0),
    acquired_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    CHECK (expires_unix_ms > acquired_unix_ms)
) STRICT;

PRAGMA user_version = 34;
