CREATE TABLE tenant_storage_quotas (
    tenant_id TEXT PRIMARY KEY,
    maximum_stored_bytes INTEGER NOT NULL CHECK (maximum_stored_bytes >= 1),
    maximum_object_count INTEGER NOT NULL CHECK (maximum_object_count >= 1),
    updated_unix_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE tenant_storage_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('cache','artifact','report','source')),
    object_digest TEXT,
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    reserved_objects INTEGER NOT NULL CHECK (reserved_objects >= 1),
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','expired')),
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    completed_unix_ms INTEGER,
    CHECK (
        (state = 'reserved' AND completed_unix_ms IS NULL)
        OR (state != 'reserved' AND completed_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX tenant_storage_reservations_active
    ON tenant_storage_reservations(tenant_id, state, expires_unix_ms);

CREATE TABLE artifact_scan_journal (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    scanner TEXT NOT NULL,
    subject_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending','claimed','passed','failed','error')),
    result_digest TEXT,
    lease_owner TEXT,
    lease_expires_unix_ms INTEGER,
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    created_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER,
    last_error_code TEXT,
    UNIQUE (artifact_id, scanner),
    CHECK (
        (state = 'pending' AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL
            AND completed_unix_ms IS NULL)
        OR (state = 'claimed' AND lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL
            AND completed_unix_ms IS NULL)
        OR (state IN ('passed','failed','error') AND lease_owner IS NULL
            AND lease_expires_unix_ms IS NULL AND completed_unix_ms IS NOT NULL)
    ),
    CHECK ((state IN ('passed','failed')) = (result_digest IS NOT NULL))
) STRICT;

CREATE INDEX artifact_scan_journal_claimable
    ON artifact_scan_journal(state, lease_expires_unix_ms, created_unix_ms, id);

CREATE TABLE artifact_promotion_bindings (
    promotion_id TEXT PRIMARY KEY REFERENCES artifact_promotions(id),
    subject_digest TEXT NOT NULL UNIQUE,
    source_manifest_digest TEXT NOT NULL,
    source_provenance_digest TEXT NOT NULL,
    source_classification TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    scan_evidence_digest TEXT,
    approval_evidence_digest TEXT,
    promoted_manifest_digest TEXT,
    last_error_code TEXT
) STRICT;

CREATE TABLE backup_pins (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    root_kind TEXT NOT NULL CHECK (root_kind IN ('artifact','cache','source','evidence','object')),
    root_id TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER,
    released_unix_ms INTEGER,
    CHECK (expires_unix_ms IS NULL OR expires_unix_ms > created_unix_ms)
) STRICT;

CREATE INDEX backup_pins_active
    ON backup_pins(released_unix_ms, expires_unix_ms, object_digest);

CREATE TABLE lifecycle_gc_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    current_generation INTEGER NOT NULL CHECK (current_generation >= 0),
    phase TEXT NOT NULL CHECK (phase IN ('idle','marking','sweeping')),
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_unix_ms INTEGER,
    updated_unix_ms INTEGER NOT NULL,
    CHECK (
        (phase = 'idle' AND lease_owner IS NULL AND lease_token IS NULL
            AND lease_expires_unix_ms IS NULL)
        OR (phase != 'idle' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_unix_ms IS NOT NULL)
    )
) STRICT;

INSERT INTO lifecycle_gc_control
    (singleton, current_generation, phase, updated_unix_ms)
VALUES (1, 0, 'idle', 0);

CREATE TABLE lifecycle_gc_marks (
    generation INTEGER NOT NULL CHECK (generation >= 1),
    object_digest TEXT NOT NULL,
    root_kind TEXT NOT NULL,
    root_id TEXT NOT NULL,
    PRIMARY KEY (generation, object_digest, root_kind, root_id)
) STRICT;

CREATE INDEX lifecycle_gc_marks_digest
    ON lifecycle_gc_marks(generation, object_digest);

CREATE TABLE lifecycle_gc_candidates (
    object_digest TEXT PRIMARY KEY,
    first_absent_generation INTEGER NOT NULL CHECK (first_absent_generation >= 1),
    last_absent_generation INTEGER NOT NULL CHECK (last_absent_generation >= first_absent_generation),
    observed_unix_ms INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    swept_unix_ms INTEGER
) STRICT;

CREATE TABLE lifecycle_gc_cycles (
    generation INTEGER PRIMARY KEY CHECK (generation >= 1),
    lease_token TEXT NOT NULL UNIQUE,
    started_unix_ms INTEGER NOT NULL,
    marked_objects INTEGER NOT NULL DEFAULT 0 CHECK (marked_objects >= 0),
    candidate_objects INTEGER NOT NULL DEFAULT 0 CHECK (candidate_objects >= 0),
    swept_objects INTEGER NOT NULL DEFAULT 0 CHECK (swept_objects >= 0),
    swept_bytes INTEGER NOT NULL DEFAULT 0 CHECK (swept_bytes >= 0),
    completed_unix_ms INTEGER,
    state TEXT NOT NULL CHECK (state IN ('marking','sweeping','completed','failed'))
) STRICT;

PRAGMA user_version = 19;
