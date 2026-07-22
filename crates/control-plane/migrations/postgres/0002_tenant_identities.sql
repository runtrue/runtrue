CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    settings_json BYTEA NOT NULL CHECK (octet_length(settings_json) <= 1048576),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1)
);
