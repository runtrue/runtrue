CREATE TABLE audit_events (
    sequence BIGINT PRIMARY KEY CHECK (sequence >= 1),
    installation_id TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    event_json BYTEA NOT NULL
);

CREATE OR REPLACE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END $$;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    scopes_json BYTEA NOT NULL CHECK (octet_length(scopes_json) <= 8192),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    last_used_unix_ms BIGINT,
    revoked_unix_ms BIGINT,
    parent_token_id TEXT REFERENCES api_tokens(id),
    CHECK (last_used_unix_ms IS NULL OR
           (last_used_unix_ms >= created_unix_ms AND last_used_unix_ms < expires_unix_ms)),
    CHECK (revoked_unix_ms IS NULL OR revoked_unix_ms >= created_unix_ms)
);

CREATE INDEX api_tokens_tenant_created ON api_tokens(tenant_id, created_unix_ms, id);
CREATE INDEX api_tokens_parent ON api_tokens(parent_token_id);
