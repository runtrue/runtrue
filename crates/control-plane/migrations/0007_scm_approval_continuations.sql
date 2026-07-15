CREATE TABLE scm_task_results (
    task_id TEXT PRIMARY KEY REFERENCES durable_tasks(id),
    request_hash TEXT NOT NULL,
    result_json BLOB NOT NULL,
    created_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE scm_proposed_analyses (
    id TEXT PRIMARY KEY,
    origin_task_id TEXT NOT NULL UNIQUE REFERENCES durable_tasks(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    status TEXT NOT NULL CHECK (status IN ('valid', 'invalid', 'deleted')),
    source_identity_json BLOB NOT NULL,
    analysis_json BLOB,
    failure TEXT,
    proposed_capsule_id TEXT REFERENCES capsules(id),
    created_unix_ms INTEGER NOT NULL,
    CHECK (
        (status = 'valid' AND analysis_json IS NOT NULL AND failure IS NULL
            AND proposed_capsule_id IS NOT NULL)
        OR (status = 'invalid' AND analysis_json IS NULL AND failure IS NOT NULL
            AND proposed_capsule_id IS NULL)
        OR (status = 'deleted' AND analysis_json IS NULL AND failure IS NULL
            AND proposed_capsule_id IS NULL)
    )
) STRICT;

CREATE TABLE scm_pending_executions (
    id TEXT PRIMARY KEY,
    origin_task_id TEXT NOT NULL REFERENCES durable_tasks(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL UNIQUE REFERENCES capsules(id),
    role TEXT NOT NULL CHECK (role IN ('direct', 'trusted-base', 'proposed-definition')),
    state TEXT NOT NULL CHECK (
        state IN (
            'awaiting-approval', 'continuation-pending', 'run-created',
            'denied', 'expired', 'stale'
        )
    ),
    context_json BLOB NOT NULL,
    run_request_json BLOB NOT NULL,
    workflow_approval_id TEXT REFERENCES approval_requests(id),
    privileged_approval_id TEXT REFERENCES approval_requests(id),
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    run_id TEXT UNIQUE REFERENCES runs(id),
    completed_unix_ms INTEGER,
    last_error TEXT,
    CHECK (expires_unix_ms > created_unix_ms),
    CHECK (workflow_approval_id IS NOT NULL OR privileged_approval_id IS NOT NULL),
    CHECK (
        (state IN ('awaiting-approval', 'continuation-pending')
            AND run_id IS NULL AND completed_unix_ms IS NULL)
        OR (state = 'run-created' AND run_id IS NOT NULL AND completed_unix_ms IS NOT NULL)
        OR (state IN ('denied', 'expired', 'stale')
            AND run_id IS NULL AND completed_unix_ms IS NOT NULL)
    ),
    UNIQUE (origin_task_id, role, capsule_id)
) STRICT;

CREATE INDEX scm_pending_by_workflow_approval
    ON scm_pending_executions(workflow_approval_id, state);

CREATE INDEX scm_pending_by_privileged_approval
    ON scm_pending_executions(privileged_approval_id, state);

CREATE INDEX scm_pending_by_state
    ON scm_pending_executions(state, expires_unix_ms, id);

PRAGMA user_version = 7;
