CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    settings_json BLOB NOT NULL CHECK (length(settings_json) <= 1048576),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version INTEGER NOT NULL CHECK (version >= 1)
) STRICT;

-- Existing schemas carried tenant identifiers without an authoritative tenant
-- row. Upgrade creates conservative active roots for every observed tenant;
-- operators can later replace display metadata with an exact-version update.
INSERT OR IGNORE INTO tenants
    (id, slug, name, status, settings_json, created_unix_ms, updated_unix_ms, version)
SELECT tenant_id, tenant_id, tenant_id, 'active', CAST('{}' AS BLOB), 0, 0, 1
FROM (
    SELECT tenant_id FROM repositories
    UNION SELECT tenant_id FROM runner_pools
    UNION SELECT tenant_id FROM leases
    UNION SELECT tenant_id FROM variable_snapshots
    UNION SELECT tenant_id FROM secret_metadata
    UNION SELECT tenant_id FROM secret_vault_snapshots
    UNION SELECT tenant_id FROM variables
    UNION SELECT tenant_id FROM variable_versions
    UNION SELECT tenant_id FROM api_tokens
    UNION SELECT tenant_id FROM runner_secret_leases
    UNION SELECT tenant_id FROM runner_oidc_issuances
    UNION SELECT tenant_id FROM tenant_scheduler_quotas
    UNION SELECT tenant_id FROM runner_data_commits
    UNION SELECT tenant_id FROM source_snapshots
    UNION SELECT tenant_id FROM runner_source_tickets
    UNION SELECT tenant_id FROM scm_installations
    UNION SELECT tenant_id FROM scm_repository_links
    UNION SELECT tenant_id FROM scm_source_fetches
    UNION SELECT tenant_id FROM cache_trust_generations
    UNION SELECT tenant_id FROM cache_promotion_journal
    UNION SELECT tenant_id FROM cache_access_observations
    UNION SELECT tenant_id FROM artifacts_catalog
    UNION SELECT tenant_id FROM artifact_download_tickets
    UNION SELECT tenant_id FROM artifact_promotions
    UNION SELECT tenant_id FROM report_summaries
    UNION SELECT tenant_id FROM tenant_storage_quotas
    UNION SELECT tenant_id FROM tenant_storage_reservations
    UNION SELECT tenant_id FROM artifact_scan_journal
    UNION SELECT tenant_id FROM backup_pins
    UNION SELECT tenant_id FROM expanded_job_sets
    UNION SELECT tenant_id FROM normalized_trigger_events
    UNION SELECT tenant_id FROM schedule_trigger_cursors
    UNION SELECT tenant_id FROM tenant_storage_ticket_bindings
    UNION SELECT tenant_id FROM tenant_storage_objects
    UNION SELECT tenant_id FROM scm_check_publications
)
WHERE tenant_id <> '';

CREATE TABLE tenant_oidc_provider_configs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes_json BLOB NOT NULL CHECK (length(scopes_json) <= 65536),
    mfa_claim_json BLOB NOT NULL CHECK (length(mfa_claim_json) <= 65536),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    configuration_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version INTEGER NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, issuer, client_id)
) STRICT;

CREATE INDEX tenant_oidc_provider_configs_tenant_status
    ON tenant_oidc_provider_configs(tenant_id, status, id);

CREATE TABLE human_users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    primary_email TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    last_seen_unix_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1)
) STRICT;

CREATE TABLE human_user_tenant_bindings (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
) STRICT;

CREATE TABLE human_identities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL,
    provider_configuration_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('oidc', 'github', 'recovery')),
    claims_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    last_authenticated_unix_ms INTEGER NOT NULL CHECK (last_authenticated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (issuer, subject),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_oidc_provider_configs(tenant_id, id)
) STRICT;

CREATE INDEX human_identities_user ON human_identities(user_id, id);

CREATE TABLE tenant_memberships (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    role_template TEXT NOT NULL,
    attributes_json BLOB NOT NULL CHECK (length(attributes_json) <= 1048576),
    attributes_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version INTEGER NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, user_id, role_template),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id)
) STRICT;

CREATE INDEX tenant_memberships_user
    ON tenant_memberships(tenant_id, user_id, status);

CREATE TABLE oidc_browser_transactions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider_configuration_id TEXT NOT NULL,
    provider_configuration_digest TEXT NOT NULL,
    provider_configuration_version INTEGER NOT NULL CHECK (provider_configuration_version >= 1),
    state_digest TEXT NOT NULL UNIQUE,
    nonce_digest TEXT NOT NULL,
    pkce_verifier_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json BLOB NOT NULL CHECK (length(record_json) <= 262144),
    status TEXT NOT NULL CHECK (status IN ('pending', 'exchanging', 'consumed', 'rejected', 'expired')),
    expires_unix_ms INTEGER NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_oidc_provider_configs(tenant_id, id)
) STRICT;

CREATE INDEX oidc_browser_transactions_expiry
    ON oidc_browser_transactions(tenant_id, status, expires_unix_ms, id);

CREATE TABLE oidc_browser_transaction_events (
    transaction_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'exchanging', 'consumed', 'rejected', 'expired')),
    record_digest TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    occurred_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (transaction_id, status),
    UNIQUE (tenant_id, transaction_id, status),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES oidc_browser_transactions(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE browser_sessions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    device_id TEXT NOT NULL,
    access_generation INTEGER NOT NULL CHECK (access_generation >= 1),
    access_digest TEXT NOT NULL UNIQUE,
    refresh_digest TEXT NOT NULL UNIQUE,
    csrf_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json BLOB NOT NULL CHECK (length(record_json) <= 2097152),
    access_expires_unix_ms INTEGER NOT NULL,
    refresh_expires_unix_ms INTEGER NOT NULL,
    absolute_expires_unix_ms INTEGER NOT NULL,
    revoked_unix_ms INTEGER,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id),
    CHECK (access_expires_unix_ms > created_unix_ms),
    CHECK (access_expires_unix_ms <= refresh_expires_unix_ms),
    CHECK (refresh_expires_unix_ms <= absolute_expires_unix_ms),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms >= created_unix_ms)
) STRICT;

CREATE INDEX browser_sessions_tenant_user
    ON browser_sessions(tenant_id, user_id, revoked_unix_ms, absolute_expires_unix_ms);

CREATE TABLE browser_session_events (
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    event_digest TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('created', 'rotated', 'reauthenticated', 'revoked')),
    access_generation INTEGER NOT NULL CHECK (access_generation >= 1),
    audit_correlation_id TEXT NOT NULL,
    occurred_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (session_id, event_digest),
    UNIQUE (tenant_id, session_id, event_digest),
    FOREIGN KEY (tenant_id, session_id)
        REFERENCES browser_sessions(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE browser_refresh_family_tokens (
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    refresh_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'revoked')),
    created_unix_ms INTEGER NOT NULL,
    consumed_unix_ms INTEGER,
    PRIMARY KEY (session_id, generation),
    UNIQUE (tenant_id, session_id, generation),
    FOREIGN KEY (tenant_id, session_id)
        REFERENCES browser_sessions(tenant_id, id) ON DELETE CASCADE,
    CHECK ((status = 'active' AND consumed_unix_ms IS NULL)
        OR (status IN ('consumed', 'revoked')
            AND consumed_unix_ms IS NOT NULL
            AND consumed_unix_ms >= created_unix_ms))
) STRICT;

CREATE UNIQUE INDEX browser_refresh_family_one_active
    ON browser_refresh_family_tokens(session_id) WHERE status = 'active';

CREATE TABLE policy_bundle_drafts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    author_id TEXT NOT NULL REFERENCES human_users(id),
    policy_digest TEXT NOT NULL,
    draft_json BLOB NOT NULL CHECK (length(draft_json) <= 2097152),
    status TEXT NOT NULL CHECK (status IN ('draft', 'simulated', 'shadow', 'activated', 'retired')),
    simulation_digest TEXT,
    activated_policy_epoch INTEGER,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, policy_digest)
) STRICT;

CREATE TABLE policy_simulation_reports (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    corpus_digest TEXT NOT NULL,
    report_json BLOB NOT NULL CHECK (length(report_json) <= 2097152),
    stored_case_count INTEGER NOT NULL CHECK (stored_case_count BETWEEN 0 AND 1024),
    caller_case_count INTEGER NOT NULL CHECK (caller_case_count BETWEEN 0 AND 128),
    evaluation_error_count INTEGER NOT NULL CHECK (evaluation_error_count >= 0),
    expectation_mismatch_count INTEGER NOT NULL CHECK (expectation_mismatch_count >= 0),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, draft_id, report_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
) STRICT;

CREATE TABLE policy_shadow_reports (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch >= 0),
    report_json BLOB NOT NULL CHECK (length(report_json) <= 2097152),
    case_count INTEGER NOT NULL CHECK (case_count BETWEEN 1 AND 512),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, draft_id, report_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
) STRICT;

CREATE TABLE tenant_policy_states (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch >= 0),
    decision_cache_generation INTEGER NOT NULL CHECK (decision_cache_generation >= 0),
    active_draft_id TEXT,
    active_policy_digest TEXT,
    state_digest TEXT NOT NULL,
    state_json BLOB NOT NULL CHECK (length(state_json) <= 2097152),
    version INTEGER NOT NULL CHECK (version >= 1),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, active_draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
) STRICT;

CREATE TABLE policy_activations (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    previous_policy_epoch INTEGER NOT NULL CHECK (previous_policy_epoch >= 0),
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch = previous_policy_epoch + 1),
    activation_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    simulation_digest TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    activation_json BLOB NOT NULL CHECK (length(activation_json) <= 262144),
    audit_correlation_id TEXT NOT NULL,
    activated_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, policy_epoch),
    UNIQUE (tenant_id, draft_id),
    UNIQUE (tenant_id, activation_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
) STRICT;

CREATE TABLE emergency_deny_replacements (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    previous_cache_generation INTEGER NOT NULL CHECK (previous_cache_generation >= 0),
    cache_generation INTEGER NOT NULL CHECK (cache_generation = previous_cache_generation + 1),
    deny_digest TEXT NOT NULL,
    denies_json BLOB NOT NULL CHECK (length(denies_json) <= 2097152),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    replaced_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, cache_generation)
) STRICT;

PRAGMA user_version = 23;
