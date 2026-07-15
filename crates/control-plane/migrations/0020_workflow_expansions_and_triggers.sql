CREATE TABLE expanded_job_sets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    parent_capsule_digest TEXT NOT NULL,
    template_id TEXT NOT NULL,
    producer_job_id TEXT NOT NULL,
    producer_output_name TEXT NOT NULL,
    matrix_input_digest TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch >= 0),
    generated_job_count INTEGER NOT NULL CHECK (generated_job_count > 0 AND generated_job_count <= 1024),
    canonical_job_set BLOB NOT NULL,
    job_set_digest TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (run_id, template_id),
    UNIQUE (tenant_id, job_set_digest)
) STRICT;

CREATE INDEX expanded_job_sets_by_run
    ON expanded_job_sets(tenant_id, run_id, template_id);

CREATE TABLE normalized_trigger_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    trigger_kind TEXT NOT NULL CHECK (
        trigger_kind IN (
            'tag', 'schedule', 'manual', 'api',
            'repository-dispatch', 'dependent-workflow'
        )
    ),
    idempotency_identity TEXT NOT NULL,
    normalized_digest TEXT NOT NULL,
    normalized_envelope_json TEXT NOT NULL,
    actor_identity TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, repository_id, trigger_kind, idempotency_identity)
) STRICT;

CREATE INDEX normalized_trigger_events_by_repository
    ON normalized_trigger_events(tenant_id, repository_id, created_unix_ms, id);

CREATE TABLE schedule_trigger_cursors (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    workflow_identity TEXT NOT NULL,
    schedule_key TEXT NOT NULL,
    cron_utc TEXT NOT NULL,
    catch_up_policy TEXT NOT NULL CHECK (catch_up_policy IN ('skip', 'latest', 'all-bounded')),
    maximum_catch_up INTEGER NOT NULL CHECK (maximum_catch_up >= 0 AND maximum_catch_up <= 100),
    next_fire_unix_ms INTEGER NOT NULL,
    last_fire_unix_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1),
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, workflow_identity, schedule_key)
) STRICT;

CREATE INDEX schedule_trigger_cursors_due
    ON schedule_trigger_cursors(next_fire_unix_ms, tenant_id, repository_id);

PRAGMA user_version = 20;
