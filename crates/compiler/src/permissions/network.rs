pub(crate) fn validate_network_policy(
    policy: &ast::NetworkPolicy,
    path: &str,
) -> Result<(), CompileError> {
    let mut destinations = BTreeSet::new();
    for destination in &policy.allow {
        if destination.port == 0 {
            return Err(CompileError::semantic(
                format!("{path}.allow"),
                "network destination port must be between 1 and 65535",
            ));
        }
        validate_host(&destination.host, &format!("{path}.allow"))?;
        if !destinations.insert((
            destination.host.to_ascii_lowercase(),
            destination.port,
            destination.protocol,
        )) {
            return Err(CompileError::semantic(
                format!("{path}.allow"),
                "duplicate network destination",
            ));
        }
    }
    if policy.listen.contains(&0) {
        return Err(CompileError::semantic(
            format!("{path}.listen"),
            "listen port must be between 1 and 65535",
        ));
    }
    Ok(())
}

pub(crate) fn validate_host(host: &str, path: &str) -> Result<(), CompileError> {
    let value = host.strip_prefix("*.").unwrap_or(host);
    let valid_dns_name = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if host == "*"
        || host.matches('*').count() > usize::from(host.starts_with("*."))
        || !valid_dns_name
    {
        return Err(CompileError::semantic(
            path,
            format!("invalid network host `{host}`"),
        ));
    }
    Ok(())
}

pub(crate) fn convert_network_policy(
    policy: &ast::NetworkPolicy,
) -> Result<ir::NetworkPermission, CompileError> {
    validate_network_policy(policy, "network")?;
    let mut destinations = policy
        .allow
        .iter()
        .map(|destination| ir::NetworkDestination {
            host: destination.host.to_ascii_lowercase(),
            port: destination.port,
            protocol: match destination.protocol {
                ast::NetworkProtocol::Tcp => ir::NetworkProtocol::Tcp,
                ast::NetworkProtocol::Udp => ir::NetworkProtocol::Udp,
            },
        })
        .collect::<Vec<_>>();
    destinations.sort();
    destinations.dedup();
    let mut listen = policy.listen.clone();
    listen.sort_unstable();
    listen.dedup();
    let dns = match policy.dns {
        ast::DnsPolicy::Deny => ir::DnsPolicy::Deny,
        ast::DnsPolicy::Restricted => ir::DnsPolicy::Restricted,
        ast::DnsPolicy::Allow => ir::DnsPolicy::Allow,
    };
    if dns == ir::DnsPolicy::Deny && destinations.is_empty() && listen.is_empty() {
        Ok(ir::NetworkPermission::Deny)
    } else {
        Ok(ir::NetworkPermission::Allow {
            dns,
            deny_private_ranges: policy.deny_private_ranges,
            destinations,
            listen,
        })
    }
}

pub(crate) fn intersect_permissions(
    maximum: &ir::PermissionSet,
    requested: &ir::PermissionSet,
) -> ir::PermissionSet {
    let maximum_secrets = maximum.secrets.iter().collect::<BTreeSet<_>>();
    let mut secrets = requested
        .secrets
        .iter()
        .filter(|secret| maximum_secrets.contains(secret))
        .cloned()
        .collect::<Vec<_>>();
    secrets.sort();

    let maximum_signing = maximum.signing.iter().collect::<BTreeSet<_>>();
    let mut signing = requested
        .signing
        .iter()
        .filter(|capability| maximum_signing.contains(capability))
        .cloned()
        .collect::<Vec<_>>();
    signing.sort();

    let maximum_audiences = maximum.oidc_audiences.iter().collect::<BTreeSet<_>>();
    let mut oidc_audiences = requested
        .oidc_audiences
        .iter()
        .filter(|audience| maximum_audiences.contains(audience))
        .cloned()
        .collect::<Vec<_>>();
    oidc_audiences.sort();

    ir::PermissionSet {
        repository: min_access(maximum.repository, requested.repository),
        scm: ir::ScmPermissions {
            contents: min_access(maximum.scm.contents, requested.scm.contents),
            issues: min_access(maximum.scm.issues, requested.scm.issues),
            pull_requests: min_access(maximum.scm.pull_requests, requested.scm.pull_requests),
            checks: min_access(maximum.scm.checks, requested.scm.checks),
            statuses: min_access(maximum.scm.statuses, requested.scm.statuses),
        },
        checks: min_access(maximum.checks, requested.checks),
        artifacts: min_access(maximum.artifacts, requested.artifacts),
        registry: min_access(maximum.registry, requested.registry),
        network: intersect_network(&maximum.network, &requested.network),
        oidc_audiences,
        cache_read: min_cache_read(maximum.cache_read, requested.cache_read),
        cache_write: min_cache_write(maximum.cache_write, requested.cache_write),
        secrets,
        signing,
    }
}

pub(crate) fn intersect_network(
    maximum: &ir::NetworkPermission,
    requested: &ir::NetworkPermission,
) -> ir::NetworkPermission {
    let (
        ir::NetworkPermission::Allow {
            dns: max_dns,
            deny_private_ranges: max_private,
            destinations: max_destinations,
            listen: max_listen,
        },
        ir::NetworkPermission::Allow {
            dns: req_dns,
            deny_private_ranges: req_private,
            destinations: req_destinations,
            listen: req_listen,
        },
    ) = (maximum, requested)
    else {
        return ir::NetworkPermission::Deny;
    };

    let max_destinations = max_destinations.iter().collect::<BTreeSet<_>>();
    let destinations: Vec<ir::NetworkDestination> = req_destinations
        .iter()
        .filter(|destination| max_destinations.contains(destination))
        .cloned()
        .collect();
    let max_listen = max_listen.iter().collect::<BTreeSet<_>>();
    let listen: Vec<u16> = req_listen
        .iter()
        .filter(|port| max_listen.contains(port))
        .copied()
        .collect();
    let dns = min_dns(*max_dns, *req_dns);
    if dns == ir::DnsPolicy::Deny && destinations.is_empty() && listen.is_empty() {
        ir::NetworkPermission::Deny
    } else {
        ir::NetworkPermission::Allow {
            dns,
            deny_private_ranges: *max_private || *req_private,
            destinations,
            listen,
        }
    }
}
use crate::{
    ast, ir, min_access, min_cache_read, min_cache_write, min_dns, BTreeSet, CompileError,
};
