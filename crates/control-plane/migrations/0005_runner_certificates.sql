CREATE TABLE runner_certificates (
    fingerprint TEXT PRIMARY KEY,
    runner_id TEXT NOT NULL REFERENCES runners(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    serial_hex TEXT NOT NULL UNIQUE,
    not_before_unix_ms INTEGER NOT NULL,
    not_after_unix_ms INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'overlap', 'revoked')),
    issued_unix_ms INTEGER NOT NULL,
    overlap_until_unix_ms INTEGER,
    revoked_unix_ms INTEGER,
    CHECK (not_after_unix_ms > not_before_unix_ms),
    CHECK (
        (status = 'active' AND overlap_until_unix_ms IS NULL AND revoked_unix_ms IS NULL)
        OR (status = 'overlap' AND overlap_until_unix_ms IS NOT NULL AND revoked_unix_ms IS NULL)
        OR (status = 'revoked' AND revoked_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_active_certificate_per_runner
    ON runner_certificates(runner_id)
    WHERE status = 'active';

CREATE INDEX runner_certificates_runner_status
    ON runner_certificates(runner_id, status, issued_unix_ms);

PRAGMA user_version = 5;
