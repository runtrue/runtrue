CREATE TABLE postgres_transfer_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    phase TEXT NOT NULL CHECK (phase IN ('prepared', 'verified', 'activated')),
    prepared_fencing_epoch BIGINT NOT NULL CHECK (prepared_fencing_epoch > 0),
    source_fencing_epoch BIGINT CHECK (source_fencing_epoch > 0),
    verified_fencing_epoch BIGINT CHECK (verified_fencing_epoch > prepared_fencing_epoch),
    verified_report_digest BYTEA CHECK (octet_length(verified_report_digest) = 32),
    prepared_unix_ms BIGINT NOT NULL CHECK (prepared_unix_ms >= 0),
    verified_unix_ms BIGINT CHECK (verified_unix_ms >= prepared_unix_ms),
    activated_unix_ms BIGINT CHECK (
        activated_unix_ms IS NULL OR activated_unix_ms >= verified_unix_ms
    ),
    CHECK (
        (phase = 'prepared'
         AND source_fencing_epoch IS NULL
         AND verified_fencing_epoch IS NULL
         AND verified_report_digest IS NULL
         AND verified_unix_ms IS NULL
         AND activated_unix_ms IS NULL)
        OR
        (phase = 'verified'
         AND source_fencing_epoch IS NOT NULL
         AND verified_fencing_epoch IS NOT NULL
         AND verified_report_digest IS NOT NULL
         AND verified_unix_ms IS NOT NULL
         AND activated_unix_ms IS NULL)
        OR
        (phase = 'activated'
         AND source_fencing_epoch IS NOT NULL
         AND verified_fencing_epoch IS NOT NULL
         AND verified_report_digest IS NOT NULL
         AND verified_unix_ms IS NOT NULL
         AND activated_unix_ms IS NOT NULL)
    )
);
