CREATE TABLE scm_installations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'github'),
    external_id TEXT NOT NULL,
    credential_reference TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (provider, external_id),
    UNIQUE (tenant_id, id)
) STRICT;

CREATE TABLE scm_repository_links (
    repository_id TEXT PRIMARY KEY REFERENCES repositories(id),
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL REFERENCES scm_installations(id),
    external_repository_id TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (installation_id, external_repository_id),
    UNIQUE (tenant_id, repository_id)
) STRICT;

CREATE INDEX scm_repository_links_installation
    ON scm_repository_links(tenant_id, installation_id, status);

-- This journal is the durable reconciliation identity for the external fetch.
-- It stores only the token scope digest; provider credentials are never durable.
CREATE TABLE scm_source_fetches (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    installation_id TEXT NOT NULL REFERENCES scm_installations(id),
    origin_task_id TEXT NOT NULL REFERENCES durable_tasks(id),
    normalized_event_digest TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    base_commit TEXT,
    origin_digest TEXT NOT NULL,
    token_scope_digest TEXT,
    mirror_identity_digest TEXT,
    tree_manifest_digest TEXT,
    source_snapshot_id TEXT REFERENCES source_snapshots(id),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'fetched', 'snapshot-ready', 'committed', 'failed')),
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    last_error_code TEXT,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, repository_id, normalized_event_digest)
) STRICT;

CREATE INDEX scm_source_fetches_recovery
    ON scm_source_fetches(state, updated_unix_ms, id);
CREATE INDEX scm_source_fetches_origin_task
    ON scm_source_fetches(origin_task_id);

PRAGMA user_version = 16;
