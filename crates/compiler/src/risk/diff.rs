/// Produce a deterministic semantic risk report for a proposed capsule change.
///
/// This compares executable meaning rather than YAML text. It is deliberately
/// conservative: new privilege, identity, egress, isolation, environment, and
/// dependency surfaces are highlighted even when another policy will later
/// deny execution.
#[must_use]
pub fn semantic_risk_diff(
    base: &ir::ExecutionCapsule,
    proposed: &ir::ExecutionCapsule,
) -> RiskReport {
    let base_jobs = capsule_jobs(base)
        .map(|job| (job.id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    let proposed_jobs = capsule_jobs(proposed)
        .map(|job| (job.id.as_str(), job))
        .collect::<BTreeMap<_, _>>();
    let base_dynamic = base
        .dynamic_jobs
        .iter()
        .map(|template| (template.id.as_str(), template))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();

    compare_permissions(
        &base.permissions,
        &proposed.permissions,
        "permissions",
        &mut findings,
    );
    if base.context.lockfile_digest != proposed.context.lockfile_digest {
        findings.push(RiskFinding::high(
            "lockfile-digest-changed",
            "context.lockfile_digest".to_owned(),
            "proposed capsule changes security-sensitive dependency lock content",
        ));
    }

    for (job_id, proposed_job) in &proposed_jobs {
        let path = format!("jobs.{job_id}");
        let Some(base_job) = base_jobs.get(job_id) else {
            findings.push(RiskFinding::medium(
                "job-added",
                path.clone(),
                "proposed capsule adds an executable job",
            ));
            collect_permission_risks(&proposed_job.permissions, &path, &mut findings);
            if proposed_job.runner.isolation == ir::Isolation::Native {
                findings.push(RiskFinding::high(
                    "native-execution-added",
                    format!("{path}.runner.isolation"),
                    "new job requests native host execution",
                ));
            }
            continue;
        };

        compare_job(base_job, proposed_job, &path, &mut findings);
    }

    for template in &proposed.dynamic_jobs {
        let Some(base_template) = base_dynamic.get(template.id.as_str()) else {
            continue;
        };
        let path = format!("jobs.{}.dynamic-matrix", template.id);
        if base_template.source.producer_job_id != template.source.producer_job_id
            || base_template.source.output_name != template.source.output_name
        {
            findings.push(RiskFinding::high(
                "dynamic-matrix-source-changed",
                format!("{path}.from"),
                "proposed capsule changes the signed producer or typed output used for dynamic expansion",
            ));
        }
        if template.source.maximum_jobs > base_template.source.maximum_jobs {
            findings.push(RiskFinding::medium(
                "dynamic-matrix-fanout-increased",
                format!("{path}.max-jobs"),
                "proposed capsule increases the bounded dynamic job fan-out",
            ));
        }
    }

    if base.workflow.digest != proposed.workflow.digest && findings.is_empty() {
        findings.push(RiskFinding::low(
            "workflow-semantics-changed",
            "workflow.digest".to_owned(),
            "workflow execution semantics changed without a recognized privilege increase",
        ));
    }

    findings.sort();
    findings.dedup();
    RiskReport::from_findings(findings)
}

pub(crate) fn compare_job(
    base: &ir::PlannedJob,
    proposed: &ir::PlannedJob,
    path: &str,
    findings: &mut Vec<RiskFinding>,
) {
    compare_permissions(
        &base.permissions,
        &proposed.permissions,
        &format!("{path}.permissions"),
        findings,
    );

    let base_dependencies = base.needs.iter().collect::<BTreeSet<_>>();
    let proposed_dependencies = proposed.needs.iter().collect::<BTreeSet<_>>();
    for dependency in base_dependencies.difference(&proposed_dependencies) {
        findings.push(RiskFinding::high(
            "job-dependency-removed",
            format!("{path}.needs"),
            &format!(
                "proposed capsule removes dependency `{dependency}` and may execute before its signed gate"
            ),
        ));
    }
    for dependency in proposed_dependencies.difference(&base_dependencies) {
        findings.push(RiskFinding::medium(
            "job-dependency-added",
            format!("{path}.needs"),
            &format!("proposed capsule adds typed inputs from dependency `{dependency}`"),
        ));
    }

    if isolation_strength(proposed.runner.isolation) < isolation_strength(base.runner.isolation) {
        findings.push(RiskFinding::high(
            "isolation-weakened",
            format!("{path}.runner.isolation"),
            "proposed capsule weakens the runner isolation floor",
        ));
    }
    if base.runner.image != proposed.runner.image {
        findings.push(RiskFinding::medium(
            "runner-image-changed",
            format!("{path}.runner.image"),
            "proposed capsule adds or changes the immutable OCI job image",
        ));
    }
    let base_capabilities = base.runner.capabilities.iter().collect::<BTreeSet<_>>();
    for capability in proposed
        .runner
        .capabilities
        .iter()
        .filter(|capability| !base_capabilities.contains(capability))
    {
        findings.push(RiskFinding::high(
            "runner-capability-added",
            format!("{path}.runner.capabilities"),
            &format!("proposed capsule adds runner capability `{capability}`"),
        ));
    }
    if base.environment != proposed.environment {
        findings.push(RiskFinding::high(
            "environment-changed",
            format!("{path}.environment"),
            "proposed capsule changes the protected environment target",
        ));
    }

    let base_images = base
        .services
        .iter()
        .map(|service| (service.id.as_str(), service.image.as_str()))
        .collect::<BTreeMap<_, _>>();
    for service in &proposed.services {
        if base_images.get(service.id.as_str()).copied() != Some(service.image.as_str()) {
            findings.push(RiskFinding::medium(
                "service-image-changed",
                format!("{path}.services.{}.image", service.id),
                "proposed capsule adds or changes an immutable service image",
            ));
        }
    }

    let base_steps = base
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    for step in &proposed.steps {
        let step_path = format!("{path}.steps.{}", step.id);
        let Some(base_step) = base_steps.get(step.id.as_str()) else {
            findings.push(RiskFinding::medium(
                "step-added",
                step_path.clone(),
                "proposed capsule adds an executable step",
            ));
            collect_step_risks(&step.capabilities, &step_path, findings);
            continue;
        };
        if base_step.action != step.action {
            let code = if matches!(step.action, ir::StepAction::Component { .. }) {
                "component-digest-changed"
            } else {
                "command-changed"
            };
            findings.push(RiskFinding::medium(
                code,
                format!("{step_path}.action"),
                "proposed capsule changes executable step content",
            ));
        }
        compare_step_capabilities(
            &base_step.capabilities,
            &step.capabilities,
            &format!("{step_path}.capabilities"),
            findings,
        );
    }

    let base_finalizers = base
        .finalizers
        .iter()
        .map(|finalizer| (finalizer.step.id.as_str(), finalizer))
        .collect::<BTreeMap<_, _>>();
    for finalizer in &proposed.finalizers {
        let step = &finalizer.step;
        let step_path = format!("{path}.finalizers.{}", step.id);
        let Some(base_finalizer) = base_finalizers.get(step.id.as_str()) else {
            findings.push(RiskFinding::medium(
                "finalizer-added",
                step_path.clone(),
                "proposed capsule adds executable attempt cleanup",
            ));
            collect_step_risks(&step.capabilities, &step_path, findings);
            continue;
        };
        if base_finalizer.step.action != step.action {
            findings.push(RiskFinding::medium(
                "finalizer-action-changed",
                format!("{step_path}.action"),
                "proposed capsule changes executable finalizer content",
            ));
        }
        compare_step_capabilities(
            &base_finalizer.step.capabilities,
            &step.capabilities,
            &format!("{step_path}.capabilities"),
            findings,
        );
        if !base_finalizer.run_on_cancel && finalizer.run_on_cancel {
            findings.push(RiskFinding::high(
                "cancel-finalizer-enabled",
                format!("{step_path}.run-on-cancel"),
                "proposed finalizer may execute after cancellation begins",
            ));
        }
        if base_finalizer.required != finalizer.required {
            findings.push(RiskFinding::medium(
                "finalizer-requirement-changed",
                format!("{step_path}.required"),
                "proposed capsule changes whether finalizer failure affects job success",
            ));
        }
    }
}

pub(crate) fn compare_permissions(
    base: &ir::PermissionSet,
    proposed: &ir::PermissionSet,
    path: &str,
    findings: &mut Vec<RiskFinding>,
) {
    for (name, previous, next) in [
        ("repository", base.repository, proposed.repository),
        ("checks", base.checks, proposed.checks),
        ("artifacts", base.artifacts, proposed.artifacts),
        ("registry", base.registry, proposed.registry),
    ] {
        if next > previous {
            findings.push(RiskFinding::high(
                &format!("{name}-access-increased"),
                format!("{path}.{name}"),
                "proposed capsule increases access",
            ));
        }
    }
    for (name, previous, next) in [
        ("scm-contents", base.scm.contents, proposed.scm.contents),
        ("scm-issues", base.scm.issues, proposed.scm.issues),
        (
            "scm-pull-requests",
            base.scm.pull_requests,
            proposed.scm.pull_requests,
        ),
        ("scm-checks", base.scm.checks, proposed.scm.checks),
        ("scm-statuses", base.scm.statuses, proposed.scm.statuses),
    ] {
        if next > previous {
            findings.push(RiskFinding::high(
                &format!("{name}-access-increased"),
                format!("{path}.{name}"),
                "proposed capsule increases source-control provider access",
            ));
        }
    }

    let base_secrets = base
        .secrets
        .iter()
        .map(|secret| secret.metadata_id.as_str())
        .collect::<BTreeSet<_>>();
    for secret in base_missing_secrets(&base_secrets, &proposed.secrets) {
        findings.push(RiskFinding::high(
            "secret-added",
            format!("{path}.secrets"),
            &format!("proposed capsule adds secret `{}`", secret.name),
        ));
    }

    let base_audiences = base.oidc_audiences.iter().collect::<BTreeSet<_>>();
    for audience in proposed
        .oidc_audiences
        .iter()
        .filter(|audience| !base_audiences.contains(audience))
    {
        findings.push(RiskFinding::high(
            "oidc-audience-added",
            format!("{path}.oidc"),
            &format!("proposed capsule adds OIDC audience `{audience}`"),
        ));
    }

    let base_signing = base.signing.iter().collect::<BTreeSet<_>>();
    for signing in proposed
        .signing
        .iter()
        .filter(|signing| !base_signing.contains(signing))
    {
        findings.push(RiskFinding::high(
            "signing-capability-added",
            format!("{path}.signing"),
            &format!(
                "proposed capsule adds signing purpose `{}` under key policy `{}`",
                signing.purpose, signing.key_policy
            ),
        ));
    }

    compare_network(&base.network, &proposed.network, path, findings);
    if cache_write_rank(proposed.cache_write) > cache_write_rank(base.cache_write) {
        let (severity, message) = if proposed.cache_write == ir::CacheWrite::Verified {
            (
                RiskSeverity::High,
                "proposed capsule can write the verified cache trust domain",
            )
        } else {
            (
                RiskSeverity::Medium,
                "proposed capsule increases cache write scope",
            )
        };
        findings.push(RiskFinding {
            severity,
            code: "cache-write-increased".to_owned(),
            path: format!("{path}.cache.write"),
            message: message.to_owned(),
        });
    }
}

pub(crate) fn compare_step_capabilities(
    base: &ir::StepCapabilitySet,
    proposed: &ir::StepCapabilitySet,
    path: &str,
    findings: &mut Vec<RiskFinding>,
) {
    let base_secrets = base
        .secrets
        .iter()
        .map(|secret| secret.metadata_id.as_str())
        .collect::<BTreeSet<_>>();
    for secret in base_missing_secrets(&base_secrets, &proposed.secrets) {
        findings.push(RiskFinding::high(
            "step-secret-added",
            format!("{path}.secrets"),
            &format!("proposed step adds secret `{}`", secret.name),
        ));
    }
    compare_network(&base.network, &proposed.network, path, findings);
    if proposed.checks > base.checks || proposed.artifacts > base.artifacts {
        findings.push(RiskFinding::high(
            "step-write-capability-increased",
            path.to_owned(),
            "proposed step increases control-plane write capabilities",
        ));
    }
}

pub(crate) fn base_missing_secrets<'a>(
    base: &BTreeSet<&str>,
    proposed: &'a [SecretReference],
) -> Vec<&'a SecretReference> {
    proposed
        .iter()
        .filter(|secret| !base.contains(secret.metadata_id.as_str()))
        .collect()
}

pub(crate) fn compare_network(
    base: &ir::NetworkPermission,
    proposed: &ir::NetworkPermission,
    path: &str,
    findings: &mut Vec<RiskFinding>,
) {
    let base_destinations = match base {
        ir::NetworkPermission::Deny => BTreeSet::new(),
        ir::NetworkPermission::Allow { destinations, .. } => destinations.iter().collect(),
    };
    if let ir::NetworkPermission::Allow { destinations, .. } = proposed {
        for destination in destinations
            .iter()
            .filter(|destination| !base_destinations.contains(destination))
        {
            let wildcard = destination.host.starts_with("*.");
            findings.push(RiskFinding {
                severity: if wildcard {
                    RiskSeverity::High
                } else {
                    RiskSeverity::Medium
                },
                code: if wildcard {
                    "wildcard-network-added".to_owned()
                } else {
                    "network-destination-added".to_owned()
                },
                path: format!("{path}.network"),
                message: format!(
                    "proposed capsule adds egress to {}:{}",
                    destination.host, destination.port
                ),
            });
        }
    }
}

pub(crate) const fn isolation_strength(isolation: ir::Isolation) -> u8 {
    match isolation {
        ir::Isolation::Native => 0,
        ir::Isolation::Oci => 1,
        ir::Isolation::Wasm => 2,
        ir::Isolation::Microvm => 3,
    }
}
use crate::{
    cache_write_rank, capsule_jobs, collect_permission_risks, collect_step_risks, ir, BTreeMap,
    BTreeSet, RiskFinding, RiskReport, RiskSeverity, SecretReference,
};
