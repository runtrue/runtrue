CREATE TABLE runner_secret_leases_v10 (
    id TEXT PRIMARY KEY,
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch INTEGER NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    secret_metadata_id TEXT NOT NULL REFERENCES secret_metadata(id),
    secret_version INTEGER NOT NULL CHECK (secret_version >= 1),
    purpose TEXT NOT NULL,
    guest_key_fingerprint TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('delivered', 'revoked', 'expired')),
    revoked_unix_ms INTEGER,
    CHECK (expires_unix_ms > issued_unix_ms),
    CHECK ((state = 'delivered' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt, step_id,
            secret_metadata_id, purpose)
) STRICT;

INSERT INTO runner_secret_leases_v10
SELECT id, execution_lease_id, fencing_generation, installation_fencing_epoch,
       runner_id, tenant_id, repository_id, run_id, job_id, 1, step_id,
       secret_metadata_id, secret_version, purpose, guest_key_fingerprint,
       runner_posture_digest, issued_unix_ms, expires_unix_ms, state, revoked_unix_ms
FROM runner_secret_leases;
DROP TABLE runner_secret_leases;
ALTER TABLE runner_secret_leases_v10 RENAME TO runner_secret_leases;
CREATE INDEX runner_secret_leases_execution
    ON runner_secret_leases(execution_lease_id, fencing_generation, job_attempt, state);

CREATE TABLE runner_oidc_issuances_v10 (
    jti TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oidc_grants(id),
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch INTEGER NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'revoked', 'expired')),
    revoked_unix_ms INTEGER,
    CHECK (expires_unix_ms > issued_unix_ms),
    CHECK ((state = 'issued' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)),
    UNIQUE (execution_lease_id, fencing_generation, job_attempt, step_id, audience)
) STRICT;

INSERT INTO runner_oidc_issuances_v10
SELECT jti, grant_id, execution_lease_id, fencing_generation,
       installation_fencing_epoch, runner_id, tenant_id, repository_id, run_id,
       job_id, 1, step_id, audience, runner_posture_digest, issued_unix_ms,
       expires_unix_ms, state, revoked_unix_ms
FROM runner_oidc_issuances;
DROP TABLE runner_oidc_issuances;
ALTER TABLE runner_oidc_issuances_v10 RENAME TO runner_oidc_issuances;
CREATE INDEX runner_oidc_issuances_execution
    ON runner_oidc_issuances(execution_lease_id, fencing_generation, job_attempt, state);

PRAGMA user_version = 10;
