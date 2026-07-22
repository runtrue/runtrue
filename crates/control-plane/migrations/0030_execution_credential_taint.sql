ALTER TABLE leases ADD COLUMN terminal_credential_taint TEXT NOT NULL DEFAULT 'unobserved'
    CHECK (terminal_credential_taint IN ('unobserved', 'unknown', 'none', 'credential_released'));

PRAGMA user_version = 30;
