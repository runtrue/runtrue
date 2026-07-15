CREATE TABLE runner_log_frames (
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    stream TEXT NOT NULL CHECK (stream IN ('stdout', 'stderr')),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    monotonic_nanoseconds INTEGER NOT NULL CHECK (monotonic_nanoseconds >= 0),
    wall_time_unix_ms INTEGER NOT NULL CHECK (wall_time_unix_ms >= 0),
    payload BLOB NOT NULL,
    redaction_state TEXT NOT NULL,
    PRIMARY KEY (execution_lease_id, job_attempt, step_id, stream, sequence)
) STRICT;

CREATE INDEX runner_log_frames_lease
    ON runner_log_frames(execution_lease_id, job_attempt, step_id, stream, sequence);

PRAGMA user_version = 11;
