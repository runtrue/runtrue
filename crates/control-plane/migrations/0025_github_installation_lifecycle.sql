-- One-use GitHub App browser setup transactions. The raw callback state,
-- installation tokens, App JWTs, and private-key material are never durable.
CREATE TABLE github_app_setup_transactions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state_digest TEXT NOT NULL UNIQUE,
    github_web_origin TEXT NOT NULL,
    github_api_origin TEXT NOT NULL,
    return_path TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'exchanging', 'completed', 'rejected', 'expired')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 8),
    expires_unix_ms INTEGER NOT NULL,
    installation_id TEXT REFERENCES scm_installations(id),
    installation_external_id TEXT,
    completion_digest TEXT,
    last_error_code TEXT,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    completed_unix_ms INTEGER,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (expires_unix_ms > created_unix_ms),
    CHECK (completed_unix_ms IS NULL OR completed_unix_ms >= created_unix_ms),
    CHECK (
        (status = 'completed'
         AND installation_id IS NOT NULL
         AND installation_external_id IS NOT NULL
         AND completion_digest IS NOT NULL
         AND completed_unix_ms IS NOT NULL)
        OR
        (status <> 'completed'
         AND installation_id IS NULL
         AND installation_external_id IS NULL
         AND completion_digest IS NULL
         AND completed_unix_ms IS NULL)
    )
) STRICT;

CREATE INDEX github_app_setup_transactions_recovery
    ON github_app_setup_transactions(tenant_id, status, expires_unix_ms, id);
CREATE INDEX github_app_setup_transactions_principal
    ON github_app_setup_transactions(tenant_id, principal_id, status, id);

-- Schema 16's provider-neutral installation row remains the worker-facing
-- source of credential-reference and permission data. This additive profile
-- stores GitHub's verified account identity and lifecycle generation without
-- redefining the shipped schema.
CREATE TABLE github_installation_profiles (
    installation_id TEXT PRIMARY KEY REFERENCES scm_installations(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    web_origin TEXT NOT NULL,
    api_origin TEXT NOT NULL,
    account_external_id TEXT NOT NULL,
    account_login TEXT NOT NULL,
    account_kind TEXT NOT NULL CHECK (account_kind IN ('organization', 'user')),
    repository_selection TEXT NOT NULL CHECK (repository_selection IN ('all', 'selected')),
    lifecycle_generation INTEGER NOT NULL CHECK (lifecycle_generation >= 1),
    synchronized_unix_ms INTEGER NOT NULL,
    suspended_unix_ms INTEGER,
    revoked_unix_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, installation_id),
    UNIQUE (tenant_id, installation_id, web_origin, api_origin),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES scm_installations(tenant_id, id),
    CHECK (suspended_unix_ms IS NULL OR suspended_unix_ms <= synchronized_unix_ms),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms <= synchronized_unix_ms)
) STRICT;

CREATE INDEX github_installation_profiles_tenant
    ON github_installation_profiles(tenant_id, installation_id);

-- Provider-selected repositories are catalogued before a Runtrue repository is
-- created or linked. Reconciliation changes this bounded metadata only; it
-- never persists an installation token or trusts callback-supplied paths.
CREATE TABLE github_repository_catalog (
    installation_id TEXT NOT NULL,
    external_repository_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    web_origin TEXT NOT NULL,
    api_origin TEXT NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    full_name TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private', 'internal')),
    default_branch TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('selected', 'removed')),
    selection_generation INTEGER NOT NULL CHECK (selection_generation >= 1),
    first_seen_unix_ms INTEGER NOT NULL,
    last_seen_unix_ms INTEGER NOT NULL CHECK (last_seen_unix_ms >= first_seen_unix_ms),
    removed_unix_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1),
    PRIMARY KEY (installation_id, external_repository_id),
    UNIQUE (tenant_id, installation_id, external_repository_id),
    FOREIGN KEY (tenant_id, installation_id, web_origin, api_origin)
        REFERENCES github_installation_profiles(
            tenant_id, installation_id, web_origin, api_origin
        ),
    CHECK (
        (status = 'selected' AND removed_unix_ms IS NULL)
        OR (status = 'removed' AND removed_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX github_repository_catalog_tenant_page
    ON github_repository_catalog(tenant_id, installation_id, status, external_repository_id);
CREATE UNIQUE INDEX github_repository_catalog_selected_name
    ON github_repository_catalog(tenant_id, installation_id, owner, name)
    WHERE status = 'selected';

-- Signed GitHub lifecycle webhooks reserve this identity before mutating the
-- installation projection. Only normalized metadata and payload digests are
-- durable; raw webhook bodies and provider credentials are excluded.
CREATE TABLE github_lifecycle_deliveries (
    delivery_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    installation_external_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 8),
    available_unix_ms INTEGER NOT NULL,
    lease_owner TEXT,
    lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_unix_ms INTEGER,
    completion_digest TEXT,
    completed_lease_owner TEXT,
    completed_lease_generation INTEGER,
    last_failure_generation INTEGER,
    last_failure_lease_owner TEXT,
    last_error_digest TEXT,
    last_retry_unix_ms INTEGER,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    completed_unix_ms INTEGER,
    UNIQUE (tenant_id, delivery_id),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES github_installation_profiles(tenant_id, installation_id),
    CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL)
        OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)
    ),
    CHECK (
        (state = 'completed'
         AND completion_digest IS NOT NULL
         AND completed_lease_owner IS NOT NULL
         AND completed_lease_generation IS NOT NULL
         AND completed_unix_ms IS NOT NULL)
        OR
        (state <> 'completed'
         AND completion_digest IS NULL
         AND completed_lease_owner IS NULL
         AND completed_lease_generation IS NULL
         AND completed_unix_ms IS NULL)
    ),
    CHECK (
        (last_failure_generation IS NULL
         AND last_failure_lease_owner IS NULL
         AND last_error_digest IS NULL
         AND last_retry_unix_ms IS NULL)
        OR
        (last_failure_generation IS NOT NULL
         AND last_failure_lease_owner IS NOT NULL
         AND last_error_digest IS NOT NULL)
    )
) STRICT;

CREATE INDEX github_lifecycle_deliveries_recovery
    ON github_lifecycle_deliveries(state, available_unix_ms, lease_expires_unix_ms, delivery_id);
CREATE INDEX github_lifecycle_deliveries_tenant
    ON github_lifecycle_deliveries(tenant_id, installation_id, state, delivery_id);

PRAGMA user_version = 25;
