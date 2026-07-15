use super::*;
pub(super) fn r9_tenant(id: &str) -> TenantIdentityRecord {
    TenantIdentityRecord {
        id: id.to_owned(),
        slug: id.to_owned(),
        name: format!("Tenant {id}"),
        status: "active".to_owned(),
        settings: json!({}),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        version: 1,
    }
}

pub(super) fn r9_provider(tenant_id: &str, id: &str) -> TenantOidcProviderConfiguration {
    let mut provider = TenantOidcProviderConfiguration {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        issuer: format!("https://{tenant_id}.identity.example"),
        client_id: format!("client-{tenant_id}"),
        authorization_endpoint: format!("https://{tenant_id}.identity.example/oauth/authorize"),
        token_endpoint: format!("https://{tenant_id}.identity.example/oauth/token"),
        jwks_uri: format!("https://{tenant_id}.identity.example/.well-known/jwks.json"),
        redirect_uri: format!("https://runtrue.example/login/{tenant_id}/callback"),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        mfa_claim: json!({"name":"amr","value":"mfa"}),
        status: "active".to_owned(),
        configuration_digest: ContentDigest::sha256(b"placeholder"),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        version: 1,
    };
    provider.configuration_digest = provider.expected_configuration_digest().unwrap();
    provider
}

pub(super) fn r9_user(id: &str) -> HumanUserRecord {
    HumanUserRecord {
        id: id.to_owned(),
        display_name: format!("User {id}"),
        primary_email: format!("{id}@example.test"),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        last_seen_unix_ms: Some(NOW),
        version: 1,
    }
}

pub(super) fn r9_membership(tenant_id: &str, user_id: &str, role: &str) -> TenantMembershipRecord {
    let mut membership = TenantMembershipRecord {
        id: format!("membership-{tenant_id}-{user_id}-{role}"),
        tenant_id: tenant_id.to_owned(),
        user_id: user_id.to_owned(),
        role_template: role.to_owned(),
        attributes: json!({"source":"test"}),
        attributes_digest: ContentDigest::sha256(b"placeholder"),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        version: 1,
    };
    membership.attributes_digest = membership.expected_attributes_digest().unwrap();
    membership
}

pub(super) fn r9_audit(actor_id: &str, correlation_id: &str, occurred: u64) -> R9AuditMetadata {
    R9AuditMetadata {
        actor_id: actor_id.to_owned(),
        correlation_id: correlation_id.to_owned(),
        occurred_unix_ms: occurred,
    }
}

pub(super) fn add_r9_user(control: &ControlPlane, tenant_id: &str, user_id: &str, role: &str) {
    control
        .put_human_user(tenant_id, &r9_user(user_id), None)
        .unwrap();
    control
        .put_tenant_membership(&r9_membership(tenant_id, user_id, role), None)
        .unwrap();
}

pub(super) fn r10_provider(
    tenant_id: &str,
    id: &str,
    capability: &str,
) -> TenantProviderConfiguration {
    let mut record = TenantProviderConfiguration {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        capability: capability.to_owned(),
        provider_kind: if capability == "signing" {
            "unix-non-exportable-signer".to_owned()
        } else {
            "vault-kv-v2".to_owned()
        },
        endpoint_origin: if capability == "signing" {
            "unix:///run/runtrue/signer.sock".to_owned()
        } else {
            "https://vault.example.test".to_owned()
        },
        credential_reference: if capability == "signing" {
            "signer-identity://release-signer".to_owned()
        } else {
            "secret-metadata://vault-token".to_owned()
        },
        trust_bundle_digest: ContentDigest::sha256(b"r10-trust"),
        public_key_digest: (capability == "signing")
            .then(|| ContentDigest::sha256(b"r10-public-key")),
        configuration_digest: ContentDigest::sha256([]),
        status: "active".to_owned(),
        created_unix_ms: NOW,
        updated_unix_ms: NOW,
        version: 1,
    };
    record.configuration_digest = record.expected_configuration_digest().unwrap();
    record
}
