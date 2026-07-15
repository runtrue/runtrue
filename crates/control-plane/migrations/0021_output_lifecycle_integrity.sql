-- Bind every quota reservation to the one data-plane ticket that may consume
-- it.  A ticket written to the filesystem but not present here is an orphan
-- and is rejected at commit, closing the reserve/issue crash window.
CREATE TABLE tenant_storage_ticket_bindings (
    reservation_id TEXT PRIMARY KEY
        REFERENCES tenant_storage_reservations(id),
    tenant_id TEXT NOT NULL,
    ticket_kind TEXT NOT NULL
        CHECK (ticket_kind IN ('cache','artifact','report','source')),
    ticket_id TEXT NOT NULL UNIQUE,
    object_id TEXT,
    actual_bytes INTEGER CHECK (actual_bytes IS NULL OR actual_bytes >= 0),
    actual_objects INTEGER CHECK (actual_objects IS NULL OR actual_objects >= 1),
    state TEXT NOT NULL
        CHECK (state IN ('issued','committed','accounted','released')),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER,
    CHECK (
        (state = 'issued' AND object_id IS NULL AND actual_bytes IS NULL
            AND actual_objects IS NULL AND completed_unix_ms IS NULL)
        OR (state = 'committed' AND object_id IS NOT NULL
            AND actual_bytes IS NOT NULL AND actual_objects IS NOT NULL
            AND completed_unix_ms IS NULL)
        OR (state IN ('accounted','released') AND completed_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX tenant_storage_ticket_bindings_tenant_state
    ON tenant_storage_ticket_bindings(tenant_id, state, updated_unix_ms);

-- Logical tenant accounting is separate from physical CAS deduplication.
-- This makes quota decisions deterministic even when two tenants or two
-- records reference identical immutable bytes.
CREATE TABLE tenant_storage_objects (
    tenant_id TEXT NOT NULL,
    object_kind TEXT NOT NULL
        CHECK (object_kind IN ('cache','artifact','report','source')),
    object_id TEXT NOT NULL,
    billed_bytes INTEGER NOT NULL CHECK (billed_bytes >= 0),
    billed_objects INTEGER NOT NULL CHECK (billed_objects >= 1),
    state TEXT NOT NULL CHECK (state IN ('active','retired')),
    created_unix_ms INTEGER NOT NULL,
    retired_unix_ms INTEGER,
    PRIMARY KEY (tenant_id, object_kind, object_id),
    CHECK (
        (state = 'active' AND retired_unix_ms IS NULL)
        OR (state = 'retired' AND retired_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX tenant_storage_objects_usage
    ON tenant_storage_objects(tenant_id, state, object_kind);

-- Existing retained artifact rows were already authoritative before the
-- ticket-binding ledger existed. Backfill their logical quota charge without
-- changing any shipped catalog row.
INSERT INTO tenant_storage_objects
    (tenant_id, object_kind, object_id, billed_bytes, billed_objects, state,
     created_unix_ms, retired_unix_ms)
SELECT tenant_id, 'artifact', artifact_id, size_bytes, 1,
       CASE state WHEN 'retired' THEN 'retired' ELSE 'active' END,
       created_unix_ms,
       CASE state WHEN 'retired' THEN created_unix_ms ELSE NULL END
  FROM artifacts_catalog;

PRAGMA user_version = 21;
