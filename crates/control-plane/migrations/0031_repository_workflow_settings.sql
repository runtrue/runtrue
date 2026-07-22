CREATE TABLE repository_workflow_settings (
    repository_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workflow_path TEXT NOT NULL CHECK (
        length(workflow_path) BETWEEN 1 AND 1024
        AND instr(workflow_path, char(0)) = 0
    ),
    updated_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories(tenant_id, id)
) STRICT;

PRAGMA user_version = 31;
