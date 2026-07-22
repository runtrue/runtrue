CREATE TABLE IF NOT EXISTS runtrue_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_unix_ms BIGINT NOT NULL CHECK (applied_unix_ms >= 0)
);

CREATE TABLE IF NOT EXISTS installation_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    installation_id TEXT NOT NULL CHECK (installation_id <> ''),
    fencing_epoch BIGINT NOT NULL CHECK (fencing_epoch > 0),
    safe_mode BOOLEAN NOT NULL DEFAULT FALSE,
    last_restore_unix_ms BIGINT CHECK (last_restore_unix_ms >= 0)
);
