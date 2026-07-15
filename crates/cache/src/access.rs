use crate::{
    validate_identifier, CacheError, CacheIdentity, CacheKeyMaterial, CacheLimits, TrustDomain,
};

/// Server-owned source classification used to derive cache scopes. Callers
/// may submit only [`CacheKeyMaterial`], never this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheSourceTrust {
    UntrustedChange { change_id: String },
    TrustedBranch { branch: String },
    ProtectedMain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheReadPolicy {
    Deny,
    Public,
    Verified,
    Branch,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheWritePolicy {
    Deny,
    Quarantine,
    Branch,
    Verified,
}

/// Authoritative inputs to trust-scope derivation. In particular,
/// `verified_write_authorized` represents the server's approval/policy result,
/// not a runner assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheAccessContext {
    pub installation_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub run_id: String,
    pub default_branch: String,
    pub source: CacheSourceTrust,
    pub read: CacheReadPolicy,
    pub write: CacheWritePolicy,
    pub verified_write_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheAccessScopes {
    /// Ordered candidates. The order is security-sensitive and owned by the
    /// control plane; a runner cannot select or reorder these identities.
    pub read_candidates: Vec<CacheIdentity>,
    pub write_identity: Option<CacheIdentity>,
}

/// Derive ordered read candidates and the sole permitted write identity from
/// server-owned trust and policy state.
pub fn derive_cache_access(
    material: &CacheKeyMaterial,
    context: &CacheAccessContext,
    limits: CacheLimits,
) -> Result<CacheAccessScopes, CacheError> {
    material.validate(limits)?;
    for (field, value) in [
        ("access.installation_id", context.installation_id.as_str()),
        ("access.tenant_id", context.tenant_id.as_str()),
        ("access.repository_id", context.repository_id.as_str()),
        ("access.run_id", context.run_id.as_str()),
        ("access.default_branch", context.default_branch.as_str()),
    ] {
        validate_identifier(field, value, limits)?;
    }
    if material.tenant_id != context.tenant_id || material.repository_id != context.repository_id {
        return Err(CacheError::InvalidIdentity(
            "cache material does not belong to the server access scope".to_owned(),
        ));
    }
    match &context.source {
        CacheSourceTrust::UntrustedChange { change_id } => {
            validate_identifier("access.change_id", change_id, limits)?
        }
        CacheSourceTrust::TrustedBranch { branch } => {
            validate_identifier("access.branch", branch, limits)?
        }
        CacheSourceTrust::ProtectedMain => {}
    }

    let run = TrustDomain::RunPrivate {
        installation_id: context.installation_id.clone(),
        tenant_id: context.tenant_id.clone(),
        repository_id: context.repository_id.clone(),
        run_id: context.run_id.clone(),
    };
    let main = TrustDomain::RepositoryMainVerified {
        installation_id: context.installation_id.clone(),
        tenant_id: context.tenant_id.clone(),
        repository_id: context.repository_id.clone(),
    };
    let source_domain = match &context.source {
        CacheSourceTrust::UntrustedChange { change_id } => TrustDomain::PullRequestQuarantine {
            installation_id: context.installation_id.clone(),
            tenant_id: context.tenant_id.clone(),
            repository_id: context.repository_id.clone(),
            change_id: change_id.clone(),
        },
        CacheSourceTrust::TrustedBranch { branch } => TrustDomain::RepositoryBranchVerified {
            installation_id: context.installation_id.clone(),
            tenant_id: context.tenant_id.clone(),
            repository_id: context.repository_id.clone(),
            branch: branch.clone(),
        },
        CacheSourceTrust::ProtectedMain => main.clone(),
    };
    let public = TrustDomain::PublicVerified;
    let protected_branch = TrustDomain::RepositoryBranchVerified {
        installation_id: context.installation_id.clone(),
        tenant_id: context.tenant_id.clone(),
        repository_id: context.repository_id.clone(),
        branch: context.default_branch.clone(),
    };

    let domains = match context.read {
        CacheReadPolicy::Deny => Vec::new(),
        CacheReadPolicy::Public => vec![public],
        CacheReadPolicy::Verified => vec![main.clone(), public],
        CacheReadPolicy::Branch => match context.source {
            CacheSourceTrust::UntrustedChange { .. } => {
                vec![main.clone(), source_domain.clone(), public]
            }
            CacheSourceTrust::TrustedBranch { .. } => {
                vec![source_domain.clone(), main.clone(), public]
            }
            CacheSourceTrust::ProtectedMain => {
                vec![protected_branch.clone(), main.clone(), public]
            }
        },
        CacheReadPolicy::Run => vec![run.clone()],
    };
    let mut read_candidates = Vec::with_capacity(domains.len());
    for domain in domains {
        let identity = material.with_trust_domain(domain);
        identity.validate(limits)?;
        if !read_candidates.contains(&identity) {
            read_candidates.push(identity);
        }
    }

    let write_domain = match context.write {
        CacheWritePolicy::Deny => None,
        CacheWritePolicy::Quarantine => Some(match context.source {
            CacheSourceTrust::UntrustedChange { .. } => source_domain.clone(),
            CacheSourceTrust::TrustedBranch { .. } | CacheSourceTrust::ProtectedMain => run,
        }),
        CacheWritePolicy::Branch => Some(match context.source {
            CacheSourceTrust::UntrustedChange { .. } => source_domain.clone(),
            CacheSourceTrust::TrustedBranch { .. } => source_domain.clone(),
            CacheSourceTrust::ProtectedMain => protected_branch,
        }),
        CacheWritePolicy::Verified
            if context.verified_write_authorized
                && matches!(context.source, CacheSourceTrust::ProtectedMain) =>
        {
            Some(main)
        }
        CacheWritePolicy::Verified => None,
    };
    let write_identity = write_domain
        .map(|domain| material.with_trust_domain(domain))
        .map(|identity| -> Result<CacheIdentity, CacheError> {
            identity.validate(limits)?;
            Ok(identity)
        })
        .transpose()?;
    Ok(CacheAccessScopes {
        read_candidates,
        write_identity,
    })
}
