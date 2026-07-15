CREATE TABLE artifacts_catalog (
    artifact_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt > 0),
    result_kind TEXT NOT NULL DEFAULT 'artifact' CHECK (result_kind = 'artifact'),
    step_id TEXT NOT NULL,
    output_name TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    scan_state TEXT NOT NULL CHECK (scan_state IN ('pending','passed','failed','waived')),
    retention_until_unix_seconds INTEGER NOT NULL,
    legal_hold INTEGER NOT NULL CHECK (legal_hold IN (0,1)),
    state TEXT NOT NULL CHECK (state IN ('available','quarantined','retired')),
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (job_id, job_attempt, output_name),
    FOREIGN KEY (job_id, job_attempt, result_kind, artifact_id)
      REFERENCES job_result_objects(job_id, job_attempt, kind, object_id)
) STRICT;

CREATE INDEX artifacts_catalog_tenant_run
    ON artifacts_catalog(tenant_id, run_id, created_unix_ms, artifact_id);
CREATE INDEX artifacts_catalog_tenant_job
    ON artifacts_catalog(tenant_id, job_id, created_unix_ms, artifact_id);

CREATE TABLE artifact_download_tickets (
    token_hash TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL CHECK (expires_unix_ms > issued_unix_ms),
    used_unix_ms INTEGER
) STRICT;

CREATE INDEX artifact_download_tickets_expiry
    ON artifact_download_tickets(expires_unix_ms, used_unix_ms);

CREATE TABLE artifact_scan_results (
    artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    scanner TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('passed','failed','error')),
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (artifact_id, scanner, result_digest)
) STRICT;

CREATE TABLE artifact_promotions (
    id TEXT PRIMARY KEY,
    source_artifact_id TEXT NOT NULL REFERENCES artifacts_catalog(artifact_id),
    promoted_artifact_id TEXT,
    tenant_id TEXT NOT NULL,
    target_classification TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','succeeded','failed')),
    created_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER
) STRICT;

CREATE TABLE report_summaries (
    artifact_id TEXT PRIMARY KEY REFERENCES artifacts_catalog(artifact_id),
    tenant_id TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('junit','sarif','coverage','custom')),
    summary_json BLOB NOT NULL,
    summary_digest TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL
) STRICT;

PRAGMA user_version = 18;
