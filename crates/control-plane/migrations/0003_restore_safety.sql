ALTER TABLE installation_state
    ADD COLUMN safe_mode INTEGER NOT NULL DEFAULT 0 CHECK (safe_mode IN (0, 1));

ALTER TABLE installation_state
    ADD COLUMN last_restore_unix_ms INTEGER;

PRAGMA user_version = 3;
