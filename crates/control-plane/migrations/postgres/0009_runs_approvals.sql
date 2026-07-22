CREATE TABLE capsules (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    digest TEXT NOT NULL,
    canonical_capsule BYTEA NOT NULL CHECK (octet_length(canonical_capsule) <= 8388608),
    signature_json BYTEA NOT NULL CHECK (octet_length(signature_json) <= 1048576),
    key_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (repository_id, digest)
);

CREATE TABLE capsule_api_metadata (
    capsule_id TEXT PRIMARY KEY REFERENCES capsules(id),
    approval_subject_digest TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100)
);

CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL REFERENCES capsules(id),
    status TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK (priority BETWEEN -1000 AND 1000),
    remote BOOLEAN NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    started_unix_ms BIGINT,
    completed_unix_ms BIGINT,
    cancel_reason TEXT,
    CHECK (started_unix_ms IS NULL OR started_unix_ms >= created_unix_ms),
    CHECK (completed_unix_ms IS NULL OR completed_unix_ms >= created_unix_ms)
);

CREATE TABLE replay_bundles (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(id),
    digest TEXT NOT NULL UNIQUE,
    bundle_json BYTEA NOT NULL CHECK (octet_length(bundle_json) <= 8388608),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms)
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_key TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    status TEXT NOT NULL,
    requirements_json BYTEA NOT NULL CHECK (octet_length(requirements_json) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    completed_unix_ms BIGINT,
    concurrency_group TEXT,
    UNIQUE (run_id, job_key, attempt),
    UNIQUE (id, attempt),
    CHECK (completed_unix_ms IS NULL OR completed_unix_ms >= created_unix_ms)
);

CREATE INDEX jobs_by_concurrency_group
    ON jobs(concurrency_group, status, created_unix_ms, id);

CREATE TABLE idempotency_records (
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (operation, idempotency_key)
);

CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL REFERENCES capsules(id),
    subject_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    request_json BYTEA NOT NULL CHECK (octet_length(request_json) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms)
);

CREATE TABLE approval_decisions (
    approval_id TEXT NOT NULL REFERENCES approval_requests(id),
    actor_id TEXT NOT NULL,
    decision_json BYTEA NOT NULL CHECK (octet_length(decision_json) <= 1048576),
    decided_unix_ms BIGINT NOT NULL CHECK (decided_unix_ms >= 0),
    PRIMARY KEY (approval_id, actor_id)
);

CREATE TABLE run_approval_authorizations (
    run_id TEXT NOT NULL REFERENCES runs(id),
    approval_id TEXT NOT NULL REFERENCES approval_requests(id),
    kind TEXT NOT NULL CHECK (kind IN ('workflow-definition', 'privileged-execution')),
    subject_digest TEXT NOT NULL,
    one_shot BOOLEAN NOT NULL,
    authorized_unix_ms BIGINT NOT NULL CHECK (authorized_unix_ms >= 0),
    PRIMARY KEY (run_id, kind),
    UNIQUE (run_id, approval_id)
);

CREATE TABLE durable_tasks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload_json BYTEA NOT NULL CHECK (octet_length(payload_json) <= 8388608),
    status TEXT NOT NULL,
    available_unix_ms BIGINT NOT NULL CHECK (available_unix_ms >= 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_expires_unix_ms BIGINT,
    last_error TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    completed_unix_ms BIGINT,
    CHECK ((status = 'claimed') = (lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL))
);

CREATE INDEX claimable_tasks ON durable_tasks(status, available_unix_ms, id);

CREATE TABLE source_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    tree_manifest_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('building', 'ready', 'failed', 'retired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    verified_unix_ms BIGINT,
    UNIQUE (tenant_id, repository_id, commit_sha, tree_manifest_digest),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    CHECK ((state = 'ready' AND verified_unix_ms IS NOT NULL)
        OR (state <> 'ready' AND verified_unix_ms IS NULL))
);

CREATE INDEX source_snapshots_repository_commit
    ON source_snapshots(tenant_id, repository_id, commit_sha, state);

CREATE TABLE run_source_snapshots (
    run_id TEXT PRIMARY KEY REFERENCES runs(id),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id),
    capsule_digest TEXT NOT NULL,
    bound_unix_ms BIGINT NOT NULL CHECK (bound_unix_ms >= 0)
);

CREATE INDEX run_source_snapshots_snapshot ON run_source_snapshots(source_snapshot_id);

CREATE TABLE runner_source_tickets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id),
    tree_manifest_digest TEXT NOT NULL,
    maximum_bytes BIGINT NOT NULL CHECK (maximum_bytes >= 1),
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt),
    FOREIGN KEY (job_id, job_attempt) REFERENCES jobs(id, attempt)
);

CREATE INDEX runner_source_tickets_scope
    ON runner_source_tickets(tenant_id, runner_id, execution_lease_id, fencing_generation);

CREATE TABLE expanded_job_sets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(id),
    parent_capsule_digest TEXT NOT NULL,
    template_id TEXT NOT NULL,
    producer_job_id TEXT NOT NULL,
    producer_output_name TEXT NOT NULL,
    matrix_input_digest TEXT NOT NULL,
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 0),
    generated_job_count INTEGER NOT NULL CHECK (generated_job_count BETWEEN 1 AND 1024),
    canonical_job_set BYTEA NOT NULL CHECK (octet_length(canonical_job_set) <= 8388608),
    job_set_digest TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature BYTEA NOT NULL CHECK (octet_length(signature) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (run_id, template_id),
    UNIQUE (tenant_id, job_set_digest),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id)
);

CREATE INDEX expanded_job_sets_by_run ON expanded_job_sets(tenant_id, run_id, template_id);

CREATE TABLE normalized_trigger_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL,
    trigger_kind TEXT NOT NULL CHECK (trigger_kind IN
        ('tag', 'schedule', 'manual', 'api', 'repository-dispatch', 'dependent-workflow')),
    idempotency_identity TEXT NOT NULL,
    normalized_digest TEXT NOT NULL,
    normalized_envelope_json BYTEA NOT NULL CHECK (octet_length(normalized_envelope_json) <= 1048576),
    actor_identity TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (tenant_id, repository_id, trigger_kind, idempotency_identity),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id)
);

CREATE INDEX normalized_trigger_events_by_repository
    ON normalized_trigger_events(tenant_id, repository_id, created_unix_ms, id);

CREATE TABLE schedule_trigger_cursors (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL,
    workflow_identity TEXT NOT NULL,
    schedule_key TEXT NOT NULL,
    cron_utc TEXT NOT NULL,
    catch_up_policy TEXT NOT NULL CHECK (catch_up_policy IN ('skip', 'latest', 'all-bounded')),
    maximum_catch_up INTEGER NOT NULL CHECK (maximum_catch_up BETWEEN 0 AND 100),
    next_fire_unix_ms BIGINT NOT NULL CHECK (next_fire_unix_ms >= 0),
    last_fire_unix_ms BIGINT,
    version BIGINT NOT NULL CHECK (version >= 1),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    PRIMARY KEY (tenant_id, repository_id, workflow_identity, schedule_key),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id)
);

CREATE INDEX schedule_trigger_cursors_due
    ON schedule_trigger_cursors(next_fire_unix_ms, tenant_id, repository_id);

ALTER TABLE scm_source_fetches
    ADD CONSTRAINT scm_source_fetches_task_fk FOREIGN KEY (origin_task_id) REFERENCES durable_tasks(id),
    ADD CONSTRAINT scm_source_fetches_snapshot_fk FOREIGN KEY (source_snapshot_id) REFERENCES source_snapshots(id);
ALTER TABLE scm_check_publications
    ADD CONSTRAINT scm_check_publications_run_fk FOREIGN KEY (run_id) REFERENCES runs(id),
    ADD CONSTRAINT scm_check_publications_task_fk FOREIGN KEY (task_id) REFERENCES durable_tasks(id);
ALTER TABLE scm_task_results
    ADD CONSTRAINT scm_task_results_task_fk FOREIGN KEY (task_id) REFERENCES durable_tasks(id);
ALTER TABLE scm_proposed_analyses
    ADD CONSTRAINT scm_proposed_analyses_task_fk FOREIGN KEY (origin_task_id) REFERENCES durable_tasks(id),
    ADD CONSTRAINT scm_proposed_analyses_capsule_fk FOREIGN KEY (proposed_capsule_id) REFERENCES capsules(id);
ALTER TABLE scm_pending_executions
    ADD CONSTRAINT scm_pending_executions_task_fk FOREIGN KEY (origin_task_id) REFERENCES durable_tasks(id),
    ADD CONSTRAINT scm_pending_executions_capsule_fk FOREIGN KEY (capsule_id) REFERENCES capsules(id),
    ADD CONSTRAINT scm_pending_executions_workflow_approval_fk FOREIGN KEY (workflow_approval_id) REFERENCES approval_requests(id),
    ADD CONSTRAINT scm_pending_executions_privileged_approval_fk FOREIGN KEY (privileged_approval_id) REFERENCES approval_requests(id),
    ADD CONSTRAINT scm_pending_executions_run_fk FOREIGN KEY (run_id) REFERENCES runs(id);
ALTER TABLE workflow_frontend_reports
    ADD CONSTRAINT workflow_frontend_reports_capsule_fk FOREIGN KEY (capsule_id) REFERENCES capsules(id);
