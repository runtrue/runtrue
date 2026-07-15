// Schema-valid authorization policies for the embedded Runtrue Cedar engine.

// Workflow security owners may approve an exact workflow subject when they
// are not the author and their MFA assertion is recent.
permit (
  principal in Team::"platform-security",
  action == Action::"ApproveWorkflow",
  resource is ApprovalRequest
)
when {
  resource.risk_score < 90 &&
  resource has author_id &&
  resource.author_id != principal.id &&
  context has mfa_age_seconds &&
  context.mfa_age_seconds < 300
};

// Production privileged execution also requires release engineering.
permit (
  principal in Team::"release-engineering",
  action == Action::"ApprovePrivilegedRun",
  resource is ApprovalRequest
)
when {
  resource.privileged &&
  resource has author_id &&
  resource.author_id != principal.id &&
  context has mfa_age_seconds &&
  context.mfa_age_seconds < 300
};

// Nobody may approve their own request.
forbid (
  principal,
  action in [Action::"ApproveWorkflow", Action::"ApprovePrivilegedRun"],
  resource is ApprovalRequest
)
when {
  resource has author_id && resource.author_id == principal.id
};
