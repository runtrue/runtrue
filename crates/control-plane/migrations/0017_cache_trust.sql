CREATE TABLE cache_trust_generations (
    cache_entry_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    identity_digest TEXT NOT NULL,
    key_material_digest TEXT NOT NULL,
    key_material_json TEXT NOT NULL,
    trust_domain_json TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    manifest_digest TEXT NOT NULL,
    tree_manifest_digest TEXT NOT NULL,
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation >= 1),
    source_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    promotion_evidence_digest TEXT,
    created_unix_ms INTEGER NOT NULL,
    UNIQUE (identity_digest, generation),
    CHECK (
        (source_cache_entry_id IS NULL AND promotion_evidence_digest IS NULL)
        OR (source_cache_entry_id IS NOT NULL AND promotion_evidence_digest IS NOT NULL)
    )
) STRICT;

CREATE INDEX cache_trust_generations_tenant_repository
    ON cache_trust_generations(tenant_id, repository_id, key_material_digest, created_unix_ms);

CREATE TABLE cache_trust_current_heads (
    identity_digest TEXT PRIMARY KEY,
    cache_entry_id TEXT NOT NULL REFERENCES cache_trust_generations(cache_entry_id),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (cache_entry_id)
) STRICT;

CREATE TABLE cache_promotion_journal (
    id TEXT PRIMARY KEY,
    subject_digest TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    source_cache_entry_id TEXT NOT NULL REFERENCES cache_trust_generations(cache_entry_id),
    target_identity_digest TEXT NOT NULL,
    target_trust_domain_json TEXT NOT NULL,
    expected_target_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    evidence_digest TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed', 'failed')),
    promoted_cache_entry_id TEXT REFERENCES cache_trust_generations(cache_entry_id),
    created_unix_ms INTEGER NOT NULL,
    completed_unix_ms INTEGER,
    last_error TEXT,
    CHECK (
        (state = 'pending' AND promoted_cache_entry_id IS NULL AND completed_unix_ms IS NULL)
        OR (state = 'completed' AND promoted_cache_entry_id IS NOT NULL AND completed_unix_ms IS NOT NULL)
        OR (state = 'failed' AND promoted_cache_entry_id IS NULL AND completed_unix_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX cache_promotion_journal_pending
    ON cache_promotion_journal(state, created_unix_ms);

CREATE TABLE cache_access_observations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    job_id TEXT NOT NULL REFERENCES jobs(id),
    job_attempt INTEGER NOT NULL CHECK (job_attempt >= 1),
    step_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('restore', 'save')),
    key_material_digest TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('hit', 'miss', 'bypassed-health', 'saved', 'save-failed', 'denied')
    ),
    selected_trust_domain_json TEXT,
    selected_generation INTEGER CHECK (selected_generation IS NULL OR selected_generation >= 1),
    transferred_bytes INTEGER NOT NULL CHECK (transferred_bytes >= 0),
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    breaker_state TEXT NOT NULL CHECK (breaker_state IN ('closed', 'open', 'half-open')),
    created_unix_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX cache_access_observations_run_job
    ON cache_access_observations(tenant_id, run_id, job_id, created_unix_ms);

PRAGMA user_version = 17;
