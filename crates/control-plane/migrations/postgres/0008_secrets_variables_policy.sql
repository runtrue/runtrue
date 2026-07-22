CREATE TABLE configuration_projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL CHECK (octet_length(description) <= 8192),
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    version BIGINT NOT NULL CHECK (version >= 1),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX configuration_projects_tenant_status
    ON configuration_projects(tenant_id, status, name, id);

CREATE TABLE configuration_project_targets (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('scm_account', 'repository')),
    target_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (project_id, target_kind, target_id),
    FOREIGN KEY (tenant_id, project_id)
        REFERENCES configuration_projects(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX configuration_project_targets_match
    ON configuration_project_targets(tenant_id, target_kind, target_id, project_id);

CREATE TABLE secret_metadata (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_reference TEXT,
    secret_type TEXT NOT NULL,
    status TEXT NOT NULL,
    current_version BIGINT CHECK (current_version >= 1),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, scope, name)
);

CREATE INDEX secret_metadata_tenant_scope
    ON secret_metadata(tenant_id, scope, name, id);

CREATE TABLE secret_vault_snapshots (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    scope TEXT NOT NULL,
    snapshot_json BYTEA NOT NULL CHECK (octet_length(snapshot_json) <= 16777216),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    PRIMARY KEY (tenant_id, scope)
);

CREATE TABLE variables (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    value_json BYTEA NOT NULL CHECK (octet_length(value_json) <= 16777216),
    version BIGINT NOT NULL CHECK (version >= 1),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    PRIMARY KEY (tenant_id, scope, name)
);

CREATE TABLE variable_versions (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    value_json BYTEA NOT NULL CHECK (octet_length(value_json) <= 16777216),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    PRIMARY KEY (tenant_id, scope, name, version)
);

CREATE TABLE variable_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    scope TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    values_json BYTEA NOT NULL CHECK (octet_length(values_json) <= 16777216),
    digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (tenant_id, scope, version),
    UNIQUE (tenant_id, scope, digest)
);

CREATE TABLE policy_versions (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    source TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('draft', 'shadow', 'enforce')),
    digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (policy_id, version),
    UNIQUE (policy_id, digest, mode)
);

CREATE TABLE oidc_grants (
    id TEXT PRIMARY KEY,
    grant_json BYTEA NOT NULL CHECK (octet_length(grant_json) <= 1048576),
    revoked_unix_ms BIGINT CHECK (revoked_unix_ms >= 0)
);

CREATE TABLE oidc_issuances (
    grant_id TEXT NOT NULL REFERENCES oidc_grants(id),
    audience TEXT NOT NULL,
    jti TEXT NOT NULL UNIQUE,
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    PRIMARY KEY (grant_id, audience)
);

CREATE TABLE policy_bundle_drafts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    author_id TEXT NOT NULL REFERENCES human_users(id),
    policy_digest TEXT NOT NULL,
    draft_json BYTEA NOT NULL CHECK (octet_length(draft_json) <= 2097152),
    status TEXT NOT NULL CHECK (status IN ('draft', 'simulated', 'shadow', 'activated', 'retired')),
    simulation_digest TEXT,
    activated_policy_epoch BIGINT CHECK (activated_policy_epoch >= 0),
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, policy_digest)
);

CREATE TABLE policy_simulation_reports (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    corpus_digest TEXT NOT NULL,
    report_json BYTEA NOT NULL CHECK (octet_length(report_json) <= 2097152),
    stored_case_count BIGINT NOT NULL CHECK (stored_case_count BETWEEN 0 AND 1024),
    caller_case_count BIGINT NOT NULL CHECK (caller_case_count BETWEEN 0 AND 128),
    evaluation_error_count BIGINT NOT NULL CHECK (evaluation_error_count >= 0),
    expectation_mismatch_count BIGINT NOT NULL CHECK (expectation_mismatch_count >= 0),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, draft_id, report_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
);

CREATE TABLE policy_shadow_reports (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 0),
    report_json BYTEA NOT NULL CHECK (octet_length(report_json) <= 2097152),
    case_count BIGINT NOT NULL CHECK (case_count BETWEEN 1 AND 512),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, draft_id, report_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
);

CREATE TABLE tenant_policy_states (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch >= 0),
    decision_cache_generation BIGINT NOT NULL CHECK (decision_cache_generation >= 0),
    active_draft_id TEXT,
    active_policy_digest TEXT,
    state_digest TEXT NOT NULL,
    state_json BYTEA NOT NULL CHECK (octet_length(state_json) <= 2097152),
    version BIGINT NOT NULL CHECK (version >= 1),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    FOREIGN KEY (tenant_id, active_draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
);

CREATE TABLE policy_activations (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    draft_id TEXT NOT NULL,
    previous_policy_epoch BIGINT NOT NULL CHECK (previous_policy_epoch >= 0),
    policy_epoch BIGINT NOT NULL CHECK (policy_epoch = previous_policy_epoch + 1),
    activation_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    simulation_digest TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    activation_json BYTEA NOT NULL CHECK (octet_length(activation_json) <= 262144),
    audit_correlation_id TEXT NOT NULL,
    activated_unix_ms BIGINT NOT NULL CHECK (activated_unix_ms >= 0),
    PRIMARY KEY (tenant_id, policy_epoch),
    UNIQUE (tenant_id, draft_id),
    UNIQUE (tenant_id, activation_digest),
    FOREIGN KEY (tenant_id, draft_id)
        REFERENCES policy_bundle_drafts(tenant_id, id)
);

CREATE TABLE emergency_deny_replacements (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    previous_cache_generation BIGINT NOT NULL CHECK (previous_cache_generation >= 0),
    cache_generation BIGINT NOT NULL CHECK (cache_generation = previous_cache_generation + 1),
    deny_digest TEXT NOT NULL,
    denies_json BYTEA NOT NULL CHECK (octet_length(denies_json) <= 2097152),
    actor_id TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    replaced_unix_ms BIGINT NOT NULL CHECK (replaced_unix_ms >= 0),
    PRIMARY KEY (tenant_id, cache_generation)
);

CREATE FUNCTION reject_configuration_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER variable_versions_append_only
BEFORE UPDATE OR DELETE ON variable_versions
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER variable_snapshots_append_only
BEFORE UPDATE OR DELETE ON variable_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER policy_versions_append_only
BEFORE UPDATE OR DELETE ON policy_versions
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER policy_simulation_reports_append_only
BEFORE UPDATE OR DELETE ON policy_simulation_reports
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER policy_shadow_reports_append_only
BEFORE UPDATE OR DELETE ON policy_shadow_reports
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER policy_activations_append_only
BEFORE UPDATE OR DELETE ON policy_activations
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER emergency_deny_replacements_append_only
BEFORE UPDATE OR DELETE ON emergency_deny_replacements
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE TRIGGER oidc_issuances_append_only
BEFORE UPDATE OR DELETE ON oidc_issuances
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();

CREATE FUNCTION protect_policy_draft_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.author_id IS DISTINCT FROM NEW.author_id
       OR OLD.policy_digest IS DISTINCT FROM NEW.policy_digest
       OR OLD.created_unix_ms IS DISTINCT FROM NEW.created_unix_ms
       OR (convert_from(OLD.draft_json,'UTF8')::jsonb
              - 'status' - 'simulation_digest' - 'simulation_passed' - 'activated_policy_epoch')
          IS DISTINCT FROM
          (convert_from(NEW.draft_json,'UTF8')::jsonb
              - 'status' - 'simulation_digest' - 'simulation_passed' - 'activated_policy_epoch')
       OR NOT ((OLD.status='draft' AND NEW.status='simulated')
               OR (OLD.status='simulated' AND NEW.status='shadow')
               OR (OLD.status='shadow' AND NEW.status='activated'))
    THEN
        RAISE EXCEPTION 'policy draft immutable material or transition changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_bundle_drafts_identity_guard
BEFORE UPDATE ON policy_bundle_drafts
FOR EACH ROW EXECUTE FUNCTION protect_policy_draft_identity();

CREATE FUNCTION protect_oidc_grant() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.grant_json IS DISTINCT FROM NEW.grant_json
       OR OLD.revoked_unix_ms IS NOT NULL
       OR NEW.revoked_unix_ms IS NULL
    THEN
        RAISE EXCEPTION 'OIDC grant durable binding or revocation changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_grants_update_guard
BEFORE UPDATE ON oidc_grants
FOR EACH ROW EXECUTE FUNCTION protect_oidc_grant();

CREATE TRIGGER oidc_grants_no_delete
BEFORE DELETE ON oidc_grants
FOR EACH ROW EXECUTE FUNCTION reject_configuration_history_mutation();
