CREATE TABLE configuration_projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_unix_ms INTEGER NOT NULL,
    updated_unix_ms INTEGER NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
) STRICT;

CREATE INDEX configuration_projects_tenant_status
    ON configuration_projects(tenant_id, status, name, id);

CREATE TABLE configuration_project_targets (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('scm_account', 'repository')),
    target_id TEXT NOT NULL,
    created_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (project_id, target_kind, target_id),
    FOREIGN KEY (tenant_id, project_id)
        REFERENCES configuration_projects(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX configuration_project_targets_match
    ON configuration_project_targets(tenant_id, target_kind, target_id, project_id);

PRAGMA user_version = 33;
