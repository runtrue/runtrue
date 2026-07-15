CREATE TABLE runner_data_commits (
    kind TEXT NOT NULL CHECK (kind IN ('cache', 'artifact')),
    object_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    output_name TEXT,
    lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    ticket_id TEXT NOT NULL,
    committed_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (kind, object_id),
    UNIQUE (ticket_id)
) STRICT;

CREATE INDEX runner_data_commits_completion_scope
    ON runner_data_commits(lease_id, fencing_generation, job_attempt, kind);

CREATE TABLE job_result_objects (
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('cache', 'artifact')),
    object_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (job_id, job_attempt, kind, object_id),
    UNIQUE (job_id, job_attempt, kind, ordinal),
    FOREIGN KEY (kind, object_id) REFERENCES runner_data_commits(kind, object_id)
) STRICT;

PRAGMA user_version = 13;
