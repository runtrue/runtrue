CREATE TABLE tenant_oidc_provider_configs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes_json BYTEA NOT NULL CHECK (octet_length(scopes_json) <= 65536),
    mfa_claim_json BYTEA NOT NULL CHECK (octet_length(mfa_claim_json) <= 65536),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    configuration_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, issuer, client_id)
);

CREATE INDEX tenant_oidc_provider_configs_tenant_status
    ON tenant_oidc_provider_configs(tenant_id, status, id);

CREATE TABLE human_users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    primary_email TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    last_seen_unix_ms BIGINT CHECK (last_seen_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1)
);

CREATE TABLE human_user_tenant_bindings (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE human_identities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL,
    provider_configuration_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('oidc', 'github', 'recovery')),
    claims_digest TEXT NOT NULL,
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    last_authenticated_unix_ms BIGINT NOT NULL
        CHECK (last_authenticated_unix_ms >= created_unix_ms),
    UNIQUE (tenant_id, id),
    UNIQUE (issuer, subject),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id),
    FOREIGN KEY (tenant_id, provider_configuration_id)
        REFERENCES tenant_oidc_provider_configs(tenant_id, id)
);

CREATE INDEX human_identities_user ON human_identities(user_id, id);

CREATE TABLE tenant_memberships (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL REFERENCES human_users(id),
    role_template TEXT NOT NULL,
    attributes_json BYTEA NOT NULL CHECK (octet_length(attributes_json) <= 1048576),
    attributes_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_unix_ms BIGINT NOT NULL CHECK (created_unix_ms >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms >= created_unix_ms),
    version BIGINT NOT NULL CHECK (version >= 1),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, user_id, role_template),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES human_user_tenant_bindings(tenant_id, user_id)
);

CREATE INDEX tenant_memberships_user
    ON tenant_memberships(tenant_id, user_id, status);
