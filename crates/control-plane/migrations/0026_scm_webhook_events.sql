-- Verified, redaction-safe webhook receipts used for repository operations.
-- Raw provider payloads, signatures, tokens, and request headers are excluded.
CREATE TABLE scm_webhook_events (
    delivery_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL REFERENCES repositories(id),
    installation_id TEXT NOT NULL REFERENCES scm_installations(id),
    external_repository_id TEXT NOT NULL,
    provider_event_name TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    actor_login TEXT NOT NULL,
    ref_name TEXT,
    normalized_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    received_unix_ms INTEGER NOT NULL,
    UNIQUE (tenant_id, repository_id, delivery_id),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES scm_installations(tenant_id, id)
) STRICT;

CREATE INDEX scm_webhook_events_repository_page
    ON scm_webhook_events(tenant_id, repository_id, received_unix_ms DESC, delivery_id DESC);

PRAGMA user_version = 26;
