CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    scopes_json TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    last_used_unix_ms INTEGER,
    revoked_unix_ms INTEGER
) STRICT;

CREATE INDEX api_tokens_tenant_created
    ON api_tokens(tenant_id, created_unix_ms, id);

PRAGMA user_version = 4;
