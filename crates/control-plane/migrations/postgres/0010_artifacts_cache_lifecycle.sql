CREATE TABLE cache_trust_generations (
    cache_entry_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    identity_digest TEXT NOT NULL,
    key_material_digest TEXT NOT NULL,
    key_material_json BYTEA NOT NULL CHECK (octet_length(key_material_json) <= 1048576),
    trust_domain_json BYTEA NOT NULL CHECK (octet_length(trust_domain_json) <= 1048576),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    manifest_digest TEXT NOT NULL,
    tree_manifest_digest TEXT NOT NULL,
    fencing_generation BIGINT NOT NULL CHECK (fencing_generation >= 1),
    source_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    promotion_evidence_digest TEXT,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (identity_digest, generation),
    CHECK ((source_cache_entry_id IS NULL AND promotion_evidence_digest IS NULL)
        OR (source_cache_entry_id IS NOT NULL AND promotion_evidence_digest IS NOT NULL))
);
CREATE INDEX cache_trust_generations_tenant_repository
    ON cache_trust_generations(tenant_id,repository_id,key_material_digest,created_unix_ms);

CREATE TABLE cache_trust_current_heads (
    identity_digest TEXT PRIMARY KEY,
    cache_entry_id TEXT NOT NULL UNIQUE REFERENCES cache_trust_generations(cache_entry_id),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0)
);

CREATE TABLE cache_promotion_journal (
    id TEXT PRIMARY KEY,
    subject_digest TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    source_cache_entry_id TEXT NOT NULL REFERENCES cache_trust_generations(cache_entry_id),
    target_identity_digest TEXT NOT NULL,
    target_trust_domain_json BYTEA NOT NULL CHECK (octet_length(target_trust_domain_json) <= 1048576),
    expected_target_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    evidence_digest TEXT NOT NULL,
    evidence_json BYTEA NOT NULL CHECK (octet_length(evidence_json) <= 1048576),
    state TEXT NOT NULL CHECK (state IN ('pending','completed','failed')),
    promoted_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    completed_unix_ms BIGINT,
    last_error TEXT,
    CHECK ((state='pending' AND promoted_cache_entry_id IS NULL AND completed_unix_ms IS NULL)
        OR (state='completed' AND promoted_cache_entry_id IS NOT NULL AND completed_unix_ms IS NOT NULL)
        OR (state='failed' AND promoted_cache_entry_id IS NULL AND completed_unix_ms IS NOT NULL))
);
CREATE INDEX cache_promotion_journal_pending ON cache_promotion_journal(state,created_unix_ms);

CREATE TABLE cache_access_observations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('restore','save')),
    key_material_digest TEXT NOT NULL,
    candidates_json BYTEA NOT NULL CHECK (octet_length(candidates_json) <= 1048576),
    outcome TEXT NOT NULL CHECK (outcome IN
        ('hit','miss','bypassed-health','saved','save-failed','denied')),
    selected_trust_domain_json BYTEA,
    selected_generation BIGINT CHECK (selected_generation IS NULL OR selected_generation >= 1),
    transferred_bytes BIGINT NOT NULL CHECK (transferred_bytes >= 0),
    latency_ms BIGINT NOT NULL CHECK (latency_ms >= 0),
    breaker_state TEXT NOT NULL CHECK (breaker_state IN ('closed','open','half-open')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    FOREIGN KEY (job_id,job_attempt) REFERENCES jobs(id,attempt)
);
CREATE INDEX cache_access_observations_run_job
    ON cache_access_observations(tenant_id,run_id,job_id,created_unix_ms);

CREATE TABLE artifacts_catalog (
    artifact_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL,
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    result_kind TEXT NOT NULL DEFAULT 'artifact' CHECK (result_kind='artifact'),
    step_id TEXT NOT NULL,
    output_name TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    scan_state TEXT NOT NULL CHECK (scan_state IN ('pending','passed','failed','waived')),
    retention_until_unix_seconds BIGINT NOT NULL CHECK (retention_until_unix_seconds >= 0),
    legal_hold BOOLEAN NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('available','quarantined','retired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    UNIQUE (job_id,job_attempt,output_name),
    FOREIGN KEY (job_id,job_attempt,result_kind,artifact_id)
        REFERENCES job_result_objects(job_id,job_attempt,kind,object_id)
);
CREATE INDEX artifacts_catalog_tenant_run
    ON artifacts_catalog(tenant_id,run_id,created_unix_ms,artifact_id);
CREATE INDEX artifacts_catalog_tenant_job
    ON artifacts_catalog(tenant_id,job_id,created_unix_ms,artifact_id);

CREATE TABLE artifact_download_tickets (
    token_hash TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    principal_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    issued_unix_ms BIGINT NOT NULL CHECK (issued_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    used_unix_ms BIGINT
);
CREATE INDEX artifact_download_tickets_expiry
    ON artifact_download_tickets(expires_unix_ms,used_unix_ms);

CREATE TABLE artifact_scan_results (
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    scanner TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed','failed','error')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (artifact_id,scanner,result_digest)
);

CREATE TABLE artifact_promotions (
    id TEXT PRIMARY KEY,
    source_artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    promoted_artifact_id TEXT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    target_classification TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','succeeded','failed')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    completed_unix_ms BIGINT
);

CREATE TABLE report_summaries (
    artifact_id TEXT PRIMARY KEY REFERENCES artifacts_catalog(artifact_id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    format TEXT NOT NULL CHECK (format IN ('junit','sarif','coverage','custom')),
    summary_json BYTEA NOT NULL CHECK (octet_length(summary_json) <= 8388608),
    summary_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0)
);

CREATE TABLE tenant_storage_quotas (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
    maximum_stored_bytes BIGINT NOT NULL CHECK (maximum_stored_bytes >= 1),
    maximum_object_count BIGINT NOT NULL CHECK (maximum_object_count >= 1),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0)
);

CREATE TABLE tenant_storage_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('cache','artifact','report','source')),
    object_digest TEXT,
    reserved_bytes BIGINT NOT NULL CHECK (reserved_bytes >= 0),
    reserved_objects BIGINT NOT NULL CHECK (reserved_objects >= 1),
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','expired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT NOT NULL CHECK (expires_unix_ms > created_unix_ms),
    completed_unix_ms BIGINT,
    CHECK ((state='reserved' AND completed_unix_ms IS NULL)
        OR (state<>'reserved' AND completed_unix_ms IS NOT NULL))
);
CREATE INDEX tenant_storage_reservations_active
    ON tenant_storage_reservations(tenant_id,state,expires_unix_ms);

CREATE TABLE tenant_storage_ticket_bindings (
    reservation_id TEXT PRIMARY KEY REFERENCES tenant_storage_reservations(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    ticket_kind TEXT NOT NULL CHECK (ticket_kind IN ('cache','artifact','report','source')),
    ticket_id TEXT NOT NULL UNIQUE,
    object_id TEXT,
    actual_bytes BIGINT CHECK (actual_bytes IS NULL OR actual_bytes >= 0),
    actual_objects BIGINT CHECK (actual_objects IS NULL OR actual_objects >= 1),
    state TEXT NOT NULL CHECK (state IN ('issued','committed','accounted','released')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    completed_unix_ms BIGINT,
    CHECK ((state='issued' AND object_id IS NULL AND actual_bytes IS NULL
            AND actual_objects IS NULL AND completed_unix_ms IS NULL)
        OR (state='committed' AND object_id IS NOT NULL AND actual_bytes IS NOT NULL
            AND actual_objects IS NOT NULL AND completed_unix_ms IS NULL)
        OR (state IN ('accounted','released') AND completed_unix_ms IS NOT NULL))
);
CREATE INDEX tenant_storage_ticket_bindings_tenant_state
    ON tenant_storage_ticket_bindings(tenant_id,state,updated_unix_ms);

CREATE TABLE tenant_storage_objects (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    object_kind TEXT NOT NULL CHECK (object_kind IN ('cache','artifact','report','source')),
    object_id TEXT NOT NULL,
    billed_bytes BIGINT NOT NULL CHECK (billed_bytes >= 0),
    billed_objects BIGINT NOT NULL CHECK (billed_objects >= 1),
    state TEXT NOT NULL CHECK (state IN ('active','retired')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    retired_unix_ms BIGINT,
    PRIMARY KEY (tenant_id,object_kind,object_id),
    CHECK ((state='active' AND retired_unix_ms IS NULL)
        OR (state='retired' AND retired_unix_ms IS NOT NULL))
);
CREATE INDEX tenant_storage_objects_usage
    ON tenant_storage_objects(tenant_id,state,object_kind);

CREATE TABLE artifact_scan_journal (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    scanner TEXT NOT NULL,
    subject_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending','claimed','passed','failed','error')),
    result_digest TEXT,
    lease_owner TEXT,
    lease_expires_unix_ms BIGINT,
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    completed_unix_ms BIGINT,
    last_error_code TEXT,
    UNIQUE (artifact_id,scanner),
    CHECK ((state='pending' AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL
            AND completed_unix_ms IS NULL)
        OR (state='claimed' AND lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL
            AND completed_unix_ms IS NULL)
        OR (state IN ('passed','failed','error') AND lease_owner IS NULL
            AND lease_expires_unix_ms IS NULL AND completed_unix_ms IS NOT NULL)),
    CHECK ((state IN ('passed','failed'))=(result_digest IS NOT NULL))
);
CREATE INDEX artifact_scan_journal_claimable
    ON artifact_scan_journal(state,lease_expires_unix_ms,created_unix_ms,id);

CREATE TABLE artifact_promotion_bindings (
    promotion_id TEXT PRIMARY KEY REFERENCES artifact_promotions(id),
    subject_digest TEXT NOT NULL UNIQUE,
    source_manifest_digest TEXT NOT NULL,
    source_provenance_digest TEXT NOT NULL,
    source_classification TEXT NOT NULL,
    evidence_json BYTEA NOT NULL CHECK (octet_length(evidence_json) <= 1048576),
    scan_evidence_digest TEXT,
    approval_evidence_digest TEXT,
    promoted_manifest_digest TEXT,
    last_error_code TEXT
);

CREATE TABLE backup_pins (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    root_kind TEXT NOT NULL CHECK (root_kind IN ('artifact','cache','source','evidence','object')),
    root_id TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    expires_unix_ms BIGINT,
    released_unix_ms BIGINT,
    CHECK (expires_unix_ms IS NULL OR expires_unix_ms > created_unix_ms)
);
CREATE INDEX backup_pins_active
    ON backup_pins(released_unix_ms,expires_unix_ms,object_digest);

CREATE TABLE lifecycle_gc_control (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    current_generation BIGINT NOT NULL CHECK (current_generation >= 0),
    phase TEXT NOT NULL CHECK (phase IN ('idle','marking','sweeping')),
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_unix_ms BIGINT,
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= 0),
    CHECK ((phase='idle' AND lease_owner IS NULL AND lease_token IS NULL
            AND lease_expires_unix_ms IS NULL)
        OR (phase<>'idle' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL
            AND lease_expires_unix_ms IS NOT NULL))
);
INSERT INTO lifecycle_gc_control(singleton,current_generation,phase,updated_unix_ms)
VALUES(TRUE,0,'idle',0);

CREATE TABLE lifecycle_gc_marks (
    generation BIGINT NOT NULL CHECK (generation >= 1),
    object_digest TEXT NOT NULL,
    root_kind TEXT NOT NULL,
    root_id TEXT NOT NULL,
    PRIMARY KEY (generation,object_digest,root_kind,root_id)
);
CREATE INDEX lifecycle_gc_marks_digest ON lifecycle_gc_marks(generation,object_digest);

CREATE TABLE lifecycle_gc_candidates (
    object_digest TEXT PRIMARY KEY,
    first_absent_generation BIGINT NOT NULL CHECK (first_absent_generation >= 1),
    last_absent_generation BIGINT NOT NULL CHECK (last_absent_generation >= first_absent_generation),
    observed_unix_ms BIGINT NOT NULL CHECK (observed_unix_ms >= 0),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    swept_unix_ms BIGINT
);

CREATE TABLE lifecycle_gc_cycles (
    generation BIGINT PRIMARY KEY CHECK (generation >= 1),
    lease_token TEXT NOT NULL UNIQUE,
    started_unix_ms BIGINT NOT NULL CHECK (started_unix_ms >= 0),
    marked_objects BIGINT NOT NULL DEFAULT 0 CHECK (marked_objects >= 0),
    candidate_objects BIGINT NOT NULL DEFAULT 0 CHECK (candidate_objects >= 0),
    swept_objects BIGINT NOT NULL DEFAULT 0 CHECK (swept_objects >= 0),
    swept_bytes BIGINT NOT NULL DEFAULT 0 CHECK (swept_bytes >= 0),
    completed_unix_ms BIGINT,
    state TEXT NOT NULL CHECK (state IN ('marking','sweeping','completed','failed'))
);
CREATE TABLE promotion_requests (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN('cache','artifact')),
    source_id TEXT NOT NULL,
    target_json BYTEA NOT NULL,
    evidence_json BYTEA NOT NULL,
    status TEXT NOT NULL CHECK(status IN('pending','completed','failed')),
    created_unix_ms BIGINT NOT NULL CHECK(created_unix_ms>=0),
    UNIQUE(kind,source_id,target_json,evidence_json)
);
