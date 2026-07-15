-- A single provider check is projected more than once as its run advances.
-- Each revision has its own durable publication journal, while `external_id`
-- remains stable so the provider reconciles and updates the same check run.
ALTER TABLE scm_check_publications RENAME TO scm_check_publications_v22;

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
    UNIQUE (provider, repository_id, external_id, logical_name),
    CHECK (
        state IN ('reserved','reconciling')
        OR (state = 'published' AND provider_check_run_id IS NOT NULL
            AND confirmed_annotations = annotation_count)
        OR state = 'failed'
    )
) STRICT;

INSERT INTO scm_check_publications (
    id, tenant_id, repository_id, installation_id, run_id, task_id,
    provider, commit_sha, logical_name, external_id, request_digest,
    annotation_count, provider_check_run_id, confirmed_annotations, state,
    attempts, last_error_code, created_unix_ms, updated_unix_ms
)
SELECT
    id, tenant_id, repository_id, installation_id, run_id, task_id,
    provider, commit_sha, logical_name, external_id, request_digest,
    annotation_count, provider_check_run_id, confirmed_annotations, state,
    attempts, last_error_code, created_unix_ms, updated_unix_ms
FROM scm_check_publications_v22;

DROP TABLE scm_check_publications_v22;

CREATE INDEX scm_check_publications_recovery
    ON scm_check_publications(state, updated_unix_ms, id);
CREATE INDEX scm_check_publications_tenant_run
    ON scm_check_publications(tenant_id, run_id, logical_name);
CREATE INDEX scm_check_publications_external_revision
    ON scm_check_publications(provider, repository_id, external_id, created_unix_ms);

PRAGMA user_version = 27;
