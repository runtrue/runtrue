CREATE TABLE runner_blob_uploads (
    ticket_id TEXT NOT NULL,
    blob_digest TEXT NOT NULL,
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('cache', 'artifact')),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    maximum_ticket_bytes INTEGER NOT NULL CHECK (maximum_ticket_bytes >= 1),
    recorded_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (ticket_id, blob_digest)
) STRICT;

CREATE INDEX runner_blob_uploads_scope
    ON runner_blob_uploads(execution_lease_id, fencing_generation, job_attempt, ticket_kind);

PRAGMA user_version = 12;
