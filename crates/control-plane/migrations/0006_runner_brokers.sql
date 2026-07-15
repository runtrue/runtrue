CREATE TABLE runner_secret_leases (
    id TEXT PRIMARY KEY,
    execution_lease_id TEXT NOT NULL REFERENCES leases(id),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    installation_fencing_epoch INTEGER NOT NULL CHECK (installation_fencing_epoch >= 1),
    runner_id TEXT NOT NULL REFERENCES runners(id),
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
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
    CHECK (
        (state = 'delivered' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)
    ),
    UNIQUE (
        execution_lease_id,
        fencing_generation,
        step_id,
        secret_metadata_id,
        purpose
    )
) STRICT;

CREATE INDEX runner_secret_leases_execution
    ON runner_secret_leases(execution_lease_id, fencing_generation, state);

CREATE TABLE run_approval_authorizations (
    run_id TEXT NOT NULL REFERENCES runs(id),
    approval_id TEXT NOT NULL REFERENCES approval_requests(id),
    kind TEXT NOT NULL CHECK (kind IN ('workflow-definition', 'privileged-execution')),
    subject_digest TEXT NOT NULL,
    one_shot INTEGER NOT NULL CHECK (one_shot IN (0, 1)),
    authorized_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (run_id, kind),
    UNIQUE (run_id, approval_id)
) STRICT;

CREATE TABLE runner_oidc_issuances (
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
    step_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    runner_posture_digest TEXT NOT NULL,
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'revoked', 'expired')),
    revoked_unix_ms INTEGER,
    CHECK (expires_unix_ms > issued_unix_ms),
    CHECK (
        (state = 'issued' AND revoked_unix_ms IS NULL)
        OR (state IN ('revoked', 'expired') AND revoked_unix_ms IS NOT NULL)
    ),
    UNIQUE (execution_lease_id, fencing_generation, step_id, audience)
) STRICT;

CREATE INDEX runner_oidc_issuances_execution
    ON runner_oidc_issuances(execution_lease_id, fencing_generation, state);

PRAGMA user_version = 6;
