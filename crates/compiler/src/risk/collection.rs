pub(crate) fn collect_permission_risks(
    permissions: &ir::PermissionSet,
    path: &str,
    risks: &mut Vec<RiskFinding>,
) {
    if !permissions.secrets.is_empty() {
        risks.push(RiskFinding::high(
            "secret-access",
            format!("{path}.permissions.secrets"),
            "job may request step-scoped secret metadata",
        ));
    }
    if !permissions.oidc_audiences.is_empty() {
        risks.push(RiskFinding::high(
            "oidc-access",
            format!("{path}.permissions.oidc"),
            "job may mint audience-bound workload identity",
        ));
    }
    if !permissions.signing.is_empty() {
        risks.push(RiskFinding::high(
            "signing-access",
            format!("{path}.permissions.signing"),
            "job requests a non-exportable signing operation",
        ));
    }
    for (name, access) in [
        ("repository", permissions.repository),
        ("checks", permissions.checks),
        ("artifacts", permissions.artifacts),
        ("registry", permissions.registry),
    ] {
        if access == ir::Access::Write {
            risks.push(RiskFinding::high(
                &format!("{name}-write"),
                format!("{path}.permissions.{name}"),
                "job requests write access",
            ));
        }
    }
    for (name, access) in [
        ("contents", permissions.scm.contents),
        ("issues", permissions.scm.issues),
        ("pull-requests", permissions.scm.pull_requests),
        ("checks", permissions.scm.checks),
        ("statuses", permissions.scm.statuses),
    ] {
        if access == ir::Access::Write {
            risks.push(RiskFinding::high(
                &format!("scm-{name}-write"),
                format!("{path}.permissions.scm.{name}"),
                "job requests source-control provider write access",
            ));
        }
    }
    if let ir::NetworkPermission::Allow {
        dns,
        destinations,
        listen,
        ..
    } = &permissions.network
    {
        if !destinations.is_empty() {
            let wildcard = destinations
                .iter()
                .any(|destination| destination.host.starts_with("*."));
            risks.push(if wildcard {
                RiskFinding::high(
                    "wildcard-network-egress",
                    format!("{path}.permissions.network"),
                    "job requests wildcard network egress",
                )
            } else {
                RiskFinding::medium(
                    "network-egress",
                    format!("{path}.permissions.network"),
                    "job requests allowlisted network egress",
                )
            });
        }
        if *dns != ir::DnsPolicy::Deny {
            risks.push(RiskFinding::medium(
                "network-dns-access",
                format!("{path}.permissions.network.dns"),
                "job requests DNS access",
            ));
        }
        if !listen.is_empty() {
            risks.push(RiskFinding::high(
                "network-listen",
                format!("{path}.permissions.network.listen"),
                "job requests inbound listen capabilities",
            ));
        }
    }
    if permissions.cache_write == ir::CacheWrite::Verified {
        risks.push(RiskFinding::high(
            "verified-cache-write",
            format!("{path}.permissions.cache.write"),
            "job requests writes to the verified cache trust domain",
        ));
    }
}

pub(crate) fn collect_step_risks(
    capabilities: &ir::StepCapabilitySet,
    path: &str,
    risks: &mut Vec<RiskFinding>,
) {
    if !capabilities.secrets.is_empty() {
        risks.push(RiskFinding::high(
            "step-secret-access",
            format!("{path}.capabilities.secrets"),
            "step requests scoped secret release",
        ));
    }
    if !capabilities.oidc_audiences.is_empty() {
        risks.push(RiskFinding::high(
            "step-oidc-access",
            format!("{path}.capabilities.oidc"),
            "step requests scoped OIDC identity",
        ));
    }
    if !capabilities.signing.is_empty() {
        risks.push(RiskFinding::high(
            "step-signing-access",
            format!("{path}.capabilities.signing"),
            "step requests an exact non-exportable signing operation",
        ));
    }
    if let ir::NetworkPermission::Allow {
        dns,
        destinations,
        listen,
        ..
    } = &capabilities.network
    {
        if *dns != ir::DnsPolicy::Deny || !destinations.is_empty() || !listen.is_empty() {
            risks.push(RiskFinding::medium(
                "step-network-access",
                format!("{path}.capabilities.network"),
                "step requests scoped network access",
            ));
        }
    }
    if capabilities.checks == ir::Access::Write || capabilities.artifacts == ir::Access::Write {
        risks.push(RiskFinding::high(
            "step-control-plane-write",
            format!("{path}.capabilities"),
            "step requests checks or artifact write access",
        ));
    }
    if capabilities.cache_write == ir::CacheWrite::Verified {
        risks.push(RiskFinding::high(
            "step-verified-cache-write",
            format!("{path}.capabilities.cache"),
            "step requests verified cache writes",
        ));
    }
}
use crate::{ir, RiskFinding};
