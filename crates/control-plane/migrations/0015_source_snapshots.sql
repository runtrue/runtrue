CREATE TABLE source_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    commit_sha TEXT NOT NULL,
    tree_manifest_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('building', 'ready', 'failed', 'retired')),
    created_unix_ms INTEGER NOT NULL,
    verified_unix_ms INTEGER,
    CHECK (
        (state = 'ready' AND verified_unix_ms IS NOT NULL)
        OR (state != 'ready' AND verified_unix_ms IS NULL)
    ),
    UNIQUE (tenant_id, repository_id, commit_sha, tree_manifest_digest)
) STRICT;

CREATE INDEX source_snapshots_repository_commit
    ON source_snapshots(tenant_id, repository_id, commit_sha, state);

CREATE TABLE run_source_snapshots (
    run_id TEXT PRIMARY KEY REFERENCES runs(id),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id),
    capsule_digest TEXT NOT NULL,
    bound_unix_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX run_source_snapshots_snapshot
    ON run_source_snapshots(source_snapshot_id);

CREATE TABLE runner_source_tickets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    runner_id TEXT NOT NULL REFERENCES runners(id),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id),
    tree_manifest_digest TEXT NOT NULL,
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes >= 1),
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    CHECK (expires_unix_ms > issued_unix_ms),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt)
) STRICT;

CREATE INDEX runner_source_tickets_scope
    ON runner_source_tickets(tenant_id, runner_id, execution_lease_id, fencing_generation);

PRAGMA user_version = 15;
