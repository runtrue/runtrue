-- Durable reconciliation journal for GitHub check projections. Provider
-- credentials and response bodies are deliberately absent; only immutable
-- request identity and provider progress are retained.
CREATE TABLE scm_check_publications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    installation_id TEXT NOT NULL REFERENCES scm_installations(id),
    run_id TEXT NOT NULL REFERENCES runs(id),
    task_id TEXT NOT NULL UNIQUE REFERENCES durable_tasks(id),
    provider TEXT NOT NULL CHECK (provider = 'github'),
    commit_sha TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    external_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    annotation_count INTEGER NOT NULL CHECK (annotation_count >= 0),
    provider_check_run_id INTEGER CHECK (provider_check_run_id > 0),
    confirmed_annotations INTEGER NOT NULL DEFAULT 0
        CHECK (confirmed_annotations >= 0 AND confirmed_annotations <= annotation_count),
    state TEXT NOT NULL
        CHECK (state IN ('reserved','reconciling','published','failed')),
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    last_error_code TEXT,
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL,
    UNIQUE (provider, repository_id, commit_sha, run_id, logical_name),
    UNIQUE (provider, repository_id, external_id),
    CHECK (
        (state IN ('reserved','reconciling') )
        OR (state = 'published' AND provider_check_run_id IS NOT NULL
            AND confirmed_annotations = annotation_count)
        OR state = 'failed'
    )
) STRICT;

CREATE INDEX scm_check_publications_recovery
    ON scm_check_publications(state, updated_unix_ms, id);
CREATE INDEX scm_check_publications_tenant_run
    ON scm_check_publications(tenant_id, run_id, logical_name);

PRAGMA user_version = 22;
