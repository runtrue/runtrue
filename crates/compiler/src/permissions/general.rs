pub(crate) fn validate_permissions(
    permissions: &ast::Permissions,
    path: &str,
) -> Result<(), CompileError> {
    match &permissions.network {
        ast::NetworkPermission::Keyword(keyword) if keyword == "deny" => {}
        ast::NetworkPermission::Keyword(keyword) => {
            return Err(CompileError::semantic(
                format!("{path}.network"),
                format!("unknown network permission keyword `{keyword}`"),
            ));
        }
        ast::NetworkPermission::Policy(policy) => {
            validate_network_policy(policy, &format!("{path}.network"))?
        }
    }
    match &permissions.oidc {
        ast::OidcPermission::Keyword(keyword) if keyword == "deny" => {}
        ast::OidcPermission::Keyword(keyword) => {
            return Err(CompileError::semantic(
                format!("{path}.oidc"),
                format!("unknown OIDC permission keyword `{keyword}`"),
            ));
        }
        ast::OidcPermission::Allow(allow) => {
            if allow.audiences.is_empty() || allow.audiences.iter().any(String::is_empty) {
                return Err(CompileError::semantic(
                    format!("{path}.oidc.audiences"),
                    "OIDC audiences must contain at least one non-empty value",
                ));
            }
        }
    }
    let mut secrets = BTreeSet::new();
    for secret in &permissions.secrets {
        if secret.name.is_empty() {
            return Err(CompileError::semantic(
                format!("{path}.secrets"),
                "secret name cannot be empty",
            ));
        }
        if !secrets.insert(&secret.name) {
            return Err(CompileError::semantic(
                format!("{path}.secrets"),
                format!("duplicate secret request `{}`", secret.name),
            ));
        }
    }
    validate_signing_requests(&permissions.signing, &format!("{path}.signing"))?;
    Ok(())
}

pub(crate) fn convert_permissions(
    permissions: &ast::Permissions,
) -> Result<ir::PermissionSet, CompileError> {
    validate_permissions(permissions, "permissions")?;
    let network = match &permissions.network {
        ast::NetworkPermission::Keyword(_) => ir::NetworkPermission::Deny,
        ast::NetworkPermission::Policy(policy) => convert_network_policy(policy)?,
    };
    let mut oidc_audiences = match &permissions.oidc {
        ast::OidcPermission::Keyword(_) => Vec::new(),
        ast::OidcPermission::Allow(allow) => allow.audiences.clone(),
    };
    oidc_audiences.sort();
    oidc_audiences.dedup();
    let mut secrets = permissions
        .secrets
        .iter()
        .map(secret_reference)
        .collect::<Vec<_>>();
    secrets.sort();
    let mut signing = permissions
        .signing
        .iter()
        .map(signing_capability)
        .collect::<Vec<_>>();
    signing.sort();
    let (cache_read, cache_write) = convert_cache_permissions(&permissions.cache);
    Ok(ir::PermissionSet {
        repository: convert_access(permissions.repository),
        scm: ir::ScmPermissions {
            contents: convert_access(permissions.scm.contents),
            issues: convert_access(permissions.scm.issues),
            pull_requests: convert_access(permissions.scm.pull_requests),
            checks: convert_access(permissions.scm.checks),
            statuses: convert_access(permissions.scm.statuses),
        },
        checks: convert_access(permissions.checks),
        artifacts: convert_access(permissions.artifacts),
        registry: convert_access(permissions.registry),
        network,
        oidc_audiences,
        cache_read,
        cache_write,
        secrets,
        signing,
    })
}

pub(crate) fn secret_reference(request: &ast::SecretRequest) -> SecretReference {
    let identity = format!(
        "{}\0{}",
        request.name,
        request.purpose.as_deref().unwrap_or("")
    );
    SecretReference {
        metadata_id: format!("local:{}", ContentDigest::sha256(identity).as_str()),
        name: request.name.clone(),
        purpose: request.purpose.clone(),
        resolution: None,
    }
}
use crate::{
    ast, convert_access, convert_cache_permissions, convert_network_policy, ir, signing_capability,
    validate_network_policy, validate_signing_requests, BTreeSet, CompileError, ContentDigest,
    SecretReference,
};
