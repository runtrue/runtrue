CREATE TABLE runner_object_transfers (
    ticket_id TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('source', 'cache', 'artifact', 'report')),
    direction TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    expected_size_bytes INTEGER CHECK (expected_size_bytes IS NULL OR expected_size_bytes >= 0),
    transferred_size_bytes INTEGER NOT NULL CHECK (transferred_size_bytes >= 0),
    maximum_ticket_bytes INTEGER NOT NULL CHECK (maximum_ticket_bytes >= 1),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'transferring', 'verified', 'committed', 'abandoned')),
    reserved_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    verified_unix_ms INTEGER,
    PRIMARY KEY (ticket_id, object_digest, direction),
    CHECK (state != 'verified' OR verified_unix_ms IS NOT NULL)
) STRICT;

CREATE INDEX runner_object_transfers_scope
    ON runner_object_transfers(execution_lease_id, fencing_generation, job_attempt, ticket_kind, direction, state);

CREATE INDEX runner_object_transfers_ticket_budget
    ON runner_object_transfers(ticket_id, direction, transferred_size_bytes);

INSERT INTO runner_object_transfers
    (ticket_id, object_digest, ticket_kind, direction, execution_lease_id,
     fencing_generation, job_attempt, expected_size_bytes,
     transferred_size_bytes, maximum_ticket_bytes, state, reserved_unix_ms,
     updated_unix_ms, verified_unix_ms)
SELECT ticket_id, blob_digest, ticket_kind, 'upload', execution_lease_id,
       fencing_generation, job_attempt, size_bytes, size_bytes,
       maximum_ticket_bytes, 'verified', recorded_unix_ms, recorded_unix_ms,
       recorded_unix_ms
FROM runner_blob_uploads;

PRAGMA user_version = 14;
