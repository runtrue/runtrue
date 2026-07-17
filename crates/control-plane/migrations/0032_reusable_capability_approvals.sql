CREATE INDEX approval_requests_reusable_subject
    ON approval_requests(repository_id, subject_digest, status, expires_unix_ms, created_unix_ms, id);

PRAGMA user_version = 32;
