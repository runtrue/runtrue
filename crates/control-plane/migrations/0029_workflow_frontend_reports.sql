CREATE TABLE workflow_frontend_reports (
    capsule_id TEXT PRIMARY KEY REFERENCES capsules(id),
    media_type TEXT NOT NULL,
    report_bytes BLOB NOT NULL
) STRICT;

PRAGMA user_version = 29;
