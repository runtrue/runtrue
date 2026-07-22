CREATE TABLE oidc_browser_transactions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    provider_configuration_id TEXT NOT NULL,
    provider_configuration_digest TEXT NOT NULL,
    provider_configuration_version BIGINT NOT NULL CHECK (provider_configuration_version >= 1),
    state_digest TEXT NOT NULL UNIQUE,
    nonce_digest TEXT NOT NULL,
    pkce_verifier_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json BYTEA NOT NULL CHECK (octet_length(record_json) <= 262144),
    status TEXT NOT NULL CHECK (status IN ('pending', 'exchanging', 'consumed', 'rejected', 'expired')),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms >= 0),
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_oidc_provider_configs(tenant_id, id)
);

CREATE INDEX oidc_browser_transactions_expiry
    ON oidc_browser_transactions(tenant_id, status, expires_unix_ms, id);

CREATE TABLE oidc_browser_transaction_events (
    transaction_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'exchanging', 'consumed', 'rejected', 'expired')),
    record_digest TEXT NOT NULL,
    audit_correlation_id TEXT NOT NULL,
    occurred_unix_ms BIGINT NOT NULL CHECK (occurred_unix_ms >= 0),
    PRIMARY KEY (transaction_id, status),
    UNIQUE (tenant_id, transaction_id, status),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES oidc_browser_transactions(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE browser_sessions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    device_id TEXT NOT NULL,
    access_generation BIGINT NOT NULL CHECK (access_generation >= 1),
    access_digest TEXT NOT NULL UNIQUE,
    refresh_digest TEXT NOT NULL UNIQUE,
    csrf_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json BYTEA NOT NULL CHECK (octet_length(record_json) <= 2097152),
    access_expires_unix_ms BIGINT NOT NULL CHECK (access_expires_unix_ms >= 0),
    refresh_expires_unix_ms BIGINT NOT NULL CHECK (refresh_expires_unix_ms >= 0),
    absolute_expires_unix_ms BIGINT NOT NULL CHECK (absolute_expires_unix_ms >= 0),
    revoked_unix_ms BIGINT CHECK (revoked_unix_ms >= 0),
    audit_correlation_id TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id),
    CHECK (access_expires_unix_ms > created_unix_ms),
    CHECK (access_expires_unix_ms <= refresh_expires_unix_ms),
    CHECK (refresh_expires_unix_ms <= absolute_expires_unix_ms),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms >= created_unix_ms)
);

CREATE INDEX browser_sessions_tenant_user
    ON browser_sessions(tenant_id, user_id, revoked_unix_ms, absolute_expires_unix_ms);

CREATE TABLE browser_session_events (
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    event_digest TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('created', 'rotated', 'reauthenticated', 'revoked')),
    access_generation BIGINT NOT NULL CHECK (access_generation >= 1),
    audit_correlation_id TEXT NOT NULL,
    occurred_unix_ms BIGINT NOT NULL CHECK (occurred_unix_ms >= 0),
    PRIMARY KEY (session_id, event_digest),
    UNIQUE (tenant_id, session_id, event_digest),
    FOREIGN KEY (tenant_id, session_id)
        REFERENCES browser_sessions(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE browser_refresh_family_tokens (
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    refresh_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'revoked')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    consumed_unix_ms BIGINT CHECK (consumed_unix_ms >= 0),
    PRIMARY KEY (session_id, generation),
    UNIQUE (tenant_id, session_id, generation),
    FOREIGN KEY (tenant_id, session_id)
        REFERENCES browser_sessions(tenant_id, id) ON DELETE CASCADE,
    CHECK ((status = 'active' AND consumed_unix_ms IS NULL)
        OR (status IN ('consumed', 'revoked')
            AND consumed_unix_ms IS NOT NULL
            AND consumed_unix_ms >= created_unix_ms))
);

CREATE UNIQUE INDEX browser_refresh_family_one_active
    ON browser_refresh_family_tokens(session_id) WHERE status = 'active';

CREATE FUNCTION reject_browser_journal_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER oidc_browser_transaction_events_append_only
BEFORE UPDATE OR DELETE ON oidc_browser_transaction_events
FOR EACH ROW EXECUTE FUNCTION reject_browser_journal_mutation();

CREATE TRIGGER browser_session_events_append_only
BEFORE UPDATE OR DELETE ON browser_session_events
FOR EACH ROW EXECUTE FUNCTION reject_browser_journal_mutation();

CREATE FUNCTION preserve_refresh_family_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.session_id <> NEW.session_id
       OR OLD.tenant_id <> NEW.tenant_id
       OR OLD.generation <> NEW.generation
       OR OLD.refresh_digest <> NEW.refresh_digest
       OR OLD.created_unix_ms <> NEW.created_unix_ms THEN
        RAISE EXCEPTION 'browser refresh-family identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER browser_refresh_family_identity_immutable
BEFORE UPDATE ON browser_refresh_family_tokens
FOR EACH ROW EXECUTE FUNCTION preserve_refresh_family_identity();

CREATE TRIGGER browser_refresh_family_no_delete
BEFORE DELETE ON browser_refresh_family_tokens
FOR EACH ROW EXECUTE FUNCTION reject_browser_journal_mutation();
