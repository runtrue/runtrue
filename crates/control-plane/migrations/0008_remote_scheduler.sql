-- Token ancestry was introduced after schema 7 shipped. Keep it here so an
-- existing schema-7 database receives the column during a normal upgrade.
ALTER TABLE api_tokens
    ADD COLUMN parent_token_id TEXT REFERENCES api_tokens(id);

CREATE INDEX api_tokens_parent ON api_tokens(parent_token_id);

-- The deadline is set exactly once when a lease is issued. Existing leases
-- are conservatively bounded by their last persisted expiry during upgrade.
ALTER TABLE leases
    ADD COLUMN hard_deadline_unix_ms INTEGER;

UPDATE leases
SET hard_deadline_unix_ms = expires_unix_ms
WHERE hard_deadline_unix_ms IS NULL;

CREATE INDEX leases_by_hard_deadline
    ON leases(state, hard_deadline_unix_ms, id);

CREATE TABLE tenant_scheduler_quotas (
    tenant_id TEXT PRIMARY KEY,
    maximum_running_jobs INTEGER NOT NULL CHECK (maximum_running_jobs > 0),
    updated_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE runner_enrollment_postures (
    runner_id TEXT PRIMARY KEY REFERENCES runners(id),
    inventory_digest TEXT NOT NULL,
    posture_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL
) STRICT;

ALTER TABLE jobs
    ADD COLUMN concurrency_group TEXT;

CREATE INDEX jobs_by_concurrency_group
    ON jobs(concurrency_group, status, created_unix_ms, id);

CREATE TABLE runner_scheduler_cursors (
    runner_id TEXT PRIMARY KEY REFERENCES runners(id),
    last_job_id TEXT NOT NULL,
    updated_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE runner_job_rejections (
    runner_id TEXT NOT NULL REFERENCES runners(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    rejection_count INTEGER NOT NULL CHECK (rejection_count > 0),
    last_code TEXT NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (runner_id, job_id)
) STRICT;

PRAGMA user_version = 8;
