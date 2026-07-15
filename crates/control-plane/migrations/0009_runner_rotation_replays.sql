CREATE TABLE runner_certificate_rotations (
    old_fingerprint TEXT PRIMARY KEY REFERENCES runner_certificates(fingerprint),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    pool_id TEXT NOT NULL REFERENCES runner_pools(id),
    csr_digest TEXT NOT NULL,
    new_fingerprint TEXT NOT NULL UNIQUE REFERENCES runner_certificates(fingerprint),
    new_certificate_json TEXT NOT NULL,
    certificate_chain_pem BLOB NOT NULL,
    created_unix_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX runner_certificate_rotations_by_runner
    ON runner_certificate_rotations(runner_id, created_unix_ms, old_fingerprint);

PRAGMA user_version = 9;
