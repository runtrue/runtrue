CREATE TABLE repositories (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    visibility TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (tenant_id, owner, name),
    UNIQUE (tenant_id, id)
);

CREATE INDEX repositories_owner_name ON repositories(owner, name, tenant_id, id);

CREATE TABLE repository_workflow_settings (
    repository_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workflow_directory TEXT NOT NULL CHECK (octet_length(workflow_directory) <= 1024),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id)
);

CREATE TABLE scm_installations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL CHECK (provider = 'github'),
    external_id TEXT NOT NULL,
    credential_reference TEXT NOT NULL,
    permissions_json BYTEA NOT NULL CHECK (octet_length(permissions_json) <= 1048576),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (provider, external_id),
    UNIQUE (tenant_id, id)
);

CREATE INDEX scm_installations_tenant_status
    ON scm_installations(tenant_id, status, id);

CREATE TABLE scm_repository_links (
    repository_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    external_repository_id TEXT NOT NULL,
    clone_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (installation_id, external_repository_id),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, installation_id) REFERENCES scm_installations(tenant_id, id)
);

CREATE INDEX scm_repository_links_tenant_installation
    ON scm_repository_links(tenant_id, installation_id, repository_id);

CREATE TABLE scm_webhook_events (
    delivery_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    external_repository_id TEXT NOT NULL,
    provider_event_name TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    actor_login TEXT NOT NULL,
    ref_name TEXT,
    normalized_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    received_unix_ms BIGINT NOT NULL CHECK (received_unix_ms >= 0),
    UNIQUE (tenant_id, repository_id, delivery_id),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, installation_id) REFERENCES scm_installations(tenant_id, id)
);

CREATE INDEX scm_webhook_events_repository_page
    ON scm_webhook_events(tenant_id, repository_id, received_unix_ms DESC, delivery_id DESC);

-- Cross-boundary identifiers (tasks, runs, capsules, approvals, and source
-- snapshots) are deliberately retained as scalar identities here. Migration
-- 0009 owns those tables and adds their deferred foreign-key constraints once
-- the complete runs/approvals boundary is installed.
CREATE TABLE scm_source_fetches (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    origin_task_id TEXT NOT NULL,
    normalized_event_digest TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    base_commit TEXT,
    origin_digest TEXT NOT NULL,
    token_scope_digest TEXT,
    mirror_identity_digest TEXT,
    tree_manifest_digest TEXT,
    source_snapshot_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'fetched', 'snapshot-ready', 'committed', 'failed')),
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    last_error_code TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, repository_id, normalized_event_digest),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, installation_id) REFERENCES scm_installations(tenant_id, id)
);

CREATE INDEX scm_source_fetches_recovery
    ON scm_source_fetches(state, updated_unix_ms, id);
CREATE INDEX scm_source_fetches_origin_task
    ON scm_source_fetches(origin_task_id);

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
    status TEXT NOT NULL CHECK (status IN ('pending', 'exchanging', 'completed', 'rejected', 'expired')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    expires_unix_ms BIGINT NOT NULL,
    installation_id TEXT REFERENCES scm_installations(id),
    installation_external_id TEXT,
    completion_digest TEXT,
    last_error_code TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    completed_unix_ms BIGINT,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (expires_unix_ms > created_unix_ms),
    CHECK (completed_unix_ms IS NULL OR completed_unix_ms >= created_unix_ms),
    CHECK (
        (status = 'completed' AND installation_id IS NOT NULL
            AND installation_external_id IS NOT NULL AND completion_digest IS NOT NULL
            AND completed_unix_ms IS NOT NULL)
        OR
        (status <> 'completed' AND installation_id IS NULL
            AND installation_external_id IS NULL AND completion_digest IS NULL
            AND completed_unix_ms IS NULL)
    )
);

CREATE INDEX github_app_setup_transactions_recovery
    ON github_app_setup_transactions(tenant_id, status, expires_unix_ms, id);
CREATE INDEX github_app_setup_transactions_principal
    ON github_app_setup_transactions(tenant_id, principal_id, status, id);

CREATE TABLE github_installation_profiles (
    installation_id TEXT PRIMARY KEY REFERENCES scm_installations(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    web_origin TEXT NOT NULL,
    api_origin TEXT NOT NULL,
    account_external_id TEXT NOT NULL,
    account_login TEXT NOT NULL,
    account_kind TEXT NOT NULL CHECK (account_kind IN ('organization', 'user')),
    repository_selection TEXT NOT NULL CHECK (repository_selection IN ('all', 'selected')),
    lifecycle_generation BIGINT NOT NULL CHECK (lifecycle_generation >= 1),
    synchronized_unix_ms BIGINT NOT NULL CHECK (synchronized_unix_ms >= 0),
    suspended_unix_ms BIGINT,
    revoked_unix_ms BIGINT,
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, installation_id),
    UNIQUE (tenant_id, installation_id, web_origin, api_origin),
    FOREIGN KEY (tenant_id, installation_id) REFERENCES scm_installations(tenant_id, id),
    CHECK (suspended_unix_ms IS NULL OR suspended_unix_ms <= synchronized_unix_ms),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms <= synchronized_unix_ms)
);

CREATE INDEX github_installation_profiles_tenant
    ON github_installation_profiles(tenant_id, installation_id);

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
    selection_generation BIGINT NOT NULL CHECK (selection_generation >= 1),
    first_seen_unix_ms BIGINT NOT NULL CHECK (first_seen_unix_ms >= 0),
    last_seen_unix_ms BIGINT NOT NULL CHECK (last_seen_unix_ms >= first_seen_unix_ms),
    removed_unix_ms BIGINT,
    version BIGINT NOT NULL CHECK (version >= 1),
    PRIMARY KEY (installation_id, external_repository_id),
    UNIQUE (tenant_id, installation_id, external_repository_id),
    FOREIGN KEY (tenant_id, installation_id, web_origin, api_origin)
        REFERENCES github_installation_profiles(tenant_id, installation_id, web_origin, api_origin),
    CHECK ((status = 'selected' AND removed_unix_ms IS NULL)
        OR (status = 'removed' AND removed_unix_ms IS NOT NULL))
);

CREATE INDEX github_repository_catalog_tenant_page
    ON github_repository_catalog(tenant_id, installation_id, status, external_repository_id);
CREATE UNIQUE INDEX github_repository_catalog_selected_name
    ON github_repository_catalog(tenant_id, installation_id, owner, name)
    WHERE status = 'selected';

CREATE TABLE github_lifecycle_deliveries (
    delivery_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    installation_external_id TEXT NOT NULL,
    event_name TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    available_unix_ms BIGINT NOT NULL CHECK (available_unix_ms >= 0),
    lease_owner TEXT,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_unix_ms BIGINT,
    completion_digest TEXT,
    completed_lease_owner TEXT,
    completed_lease_generation BIGINT,
    last_failure_generation BIGINT,
    last_failure_lease_owner TEXT,
    last_error_digest TEXT,
    last_retry_unix_ms BIGINT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    completed_unix_ms BIGINT,
    UNIQUE (tenant_id, delivery_id),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES github_installation_profiles(tenant_id, installation_id),
    CHECK ((state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL)
        OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)),
    CHECK ((state = 'completed' AND completion_digest IS NOT NULL
            AND completed_lease_owner IS NOT NULL AND completed_lease_generation IS NOT NULL
            AND completed_unix_ms IS NOT NULL)
        OR (state <> 'completed' AND completion_digest IS NULL
            AND completed_lease_owner IS NULL AND completed_lease_generation IS NULL
            AND completed_unix_ms IS NULL)),
    CHECK ((last_failure_generation IS NULL AND last_failure_lease_owner IS NULL
            AND last_error_digest IS NULL AND last_retry_unix_ms IS NULL)
        OR (last_failure_generation IS NOT NULL AND last_failure_lease_owner IS NOT NULL
            AND last_error_digest IS NOT NULL))
);

CREATE INDEX github_lifecycle_deliveries_recovery
    ON github_lifecycle_deliveries(state, available_unix_ms, lease_expires_unix_ms, delivery_id);
CREATE INDEX github_lifecycle_deliveries_tenant
    ON github_lifecycle_deliveries(tenant_id, installation_id, state, delivery_id);

CREATE TABLE scm_check_publications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL CHECK (provider = 'github'),
    commit_sha TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    external_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    annotation_count INTEGER NOT NULL CHECK (annotation_count >= 0),
    provider_check_run_id BIGINT CHECK (provider_check_run_id > 0),
    confirmed_annotations INTEGER NOT NULL DEFAULT 0
        CHECK (confirmed_annotations >= 0 AND confirmed_annotations <= annotation_count),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'reconciling', 'published', 'failed')),
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    last_error_code TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id),
    FOREIGN KEY (tenant_id, installation_id) REFERENCES scm_installations(tenant_id, id),
    CHECK (state IN ('reserved', 'reconciling')
        OR (state = 'published' AND provider_check_run_id IS NOT NULL
            AND confirmed_annotations = annotation_count)
        OR state = 'failed')
);

CREATE INDEX scm_check_publications_recovery
    ON scm_check_publications(state, updated_unix_ms, id);
CREATE INDEX scm_check_publications_tenant_run
    ON scm_check_publications(tenant_id, run_id, logical_name);
CREATE INDEX scm_check_publications_external_revision
    ON scm_check_publications(provider, repository_id, external_id, created_unix_ms, id);

CREATE TABLE scm_task_results (
    task_id TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    result_json BYTEA NOT NULL CHECK (octet_length(result_json) <= 8388608),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0)
);

CREATE TABLE scm_proposed_analyses (
    id TEXT PRIMARY KEY,
    origin_task_id TEXT NOT NULL UNIQUE,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    status TEXT NOT NULL CHECK (status IN ('valid', 'invalid', 'deleted')),
    source_identity_json BYTEA NOT NULL CHECK (octet_length(source_identity_json) <= 1048576),
    analysis_json BYTEA CHECK (analysis_json IS NULL OR octet_length(analysis_json) <= 8388608),
    failure TEXT,
    proposed_capsule_id TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    CHECK ((status = 'valid' AND analysis_json IS NOT NULL AND failure IS NULL
            AND proposed_capsule_id IS NOT NULL)
        OR (status = 'invalid' AND analysis_json IS NULL AND failure IS NOT NULL
            AND proposed_capsule_id IS NULL)
        OR (status = 'deleted' AND analysis_json IS NULL AND failure IS NULL
            AND proposed_capsule_id IS NULL))
);

CREATE TABLE scm_pending_executions (
    id TEXT PRIMARY KEY,
    origin_task_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    capsule_id TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('direct', 'trusted-base', 'proposed-definition')),
    state TEXT NOT NULL CHECK (state IN ('awaiting-approval', 'continuation-pending',
        'run-created', 'denied', 'expired', 'stale')),
    context_json BYTEA NOT NULL CHECK (octet_length(context_json) <= 8388608),
    run_request_json BYTEA NOT NULL CHECK (octet_length(run_request_json) <= 8388608),
    workflow_approval_id TEXT,
    privileged_approval_id TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    run_id TEXT UNIQUE,
    completed_unix_ms BIGINT,
    last_error TEXT,
    CHECK (workflow_approval_id IS NOT NULL OR privileged_approval_id IS NOT NULL),
    CHECK ((state IN ('awaiting-approval', 'continuation-pending')
            AND run_id IS NULL AND completed_unix_ms IS NULL)
        OR (state = 'run-created' AND run_id IS NOT NULL AND completed_unix_ms IS NOT NULL)
        OR (state IN ('denied', 'expired', 'stale')
            AND run_id IS NULL AND completed_unix_ms IS NOT NULL)),
    UNIQUE (origin_task_id, role, capsule_id)
);

CREATE INDEX scm_pending_by_workflow_approval
    ON scm_pending_executions(workflow_approval_id, state);
CREATE INDEX scm_pending_by_privileged_approval
    ON scm_pending_executions(privileged_approval_id, state);
CREATE INDEX scm_pending_by_state
    ON scm_pending_executions(state, expires_unix_ms, id);

CREATE TABLE workflow_frontend_reports (
    capsule_id TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    report_bytes BYTEA NOT NULL CHECK (octet_length(report_bytes) <= 8388608)
);
