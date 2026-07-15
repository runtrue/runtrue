CREATE TABLE capsule_api_metadata (
    capsule_id TEXT PRIMARY KEY REFERENCES capsules(id),
    approval_subject_digest TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100)
) STRICT;

CREATE TABLE replay_bundles (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(id),
    digest TEXT NOT NULL UNIQUE,
    bundle_json BLOB NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL CHECK (expires_unix_ms > created_unix_ms)
) STRICT;

CREATE TABLE secret_vault_snapshots (
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    snapshot_json BLOB NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, scope)
) STRICT;

CREATE TABLE variables (
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, scope, name)
) STRICT;

CREATE TABLE variable_versions (
    tenant_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    value_json TEXT NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, scope, name, version)
) STRICT;

CREATE TABLE promotion_requests (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('cache', 'artifact')),
    source_id TEXT NOT NULL,
    target_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (kind, source_id, target_json, evidence_json)
) STRICT;

CREATE TABLE policy_versions (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    source TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('draft', 'shadow', 'enforce')),
    digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (policy_id, version),
    UNIQUE (policy_id, digest, mode)
) STRICT;

CREATE TABLE oidc_grants (
    id TEXT PRIMARY KEY,
    grant_json TEXT NOT NULL,
    revoked_unix_ms INTEGER
) STRICT;

CREATE TABLE oidc_issuances (
    grant_id TEXT NOT NULL REFERENCES oidc_grants(id),
    audience TEXT NOT NULL,
    jti TEXT NOT NULL UNIQUE,
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (grant_id, audience)
) STRICT;

PRAGMA user_version = 2;
