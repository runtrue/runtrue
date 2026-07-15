use crate::TrustedPlannerError;
use runtrue_scm::{EventEnvelope, EventType};
use runtrue_workflow_ir::SourceTrust;

/// Derive source trust exclusively from an authenticated SCM envelope and the
/// repository's durable default branch. A payload-supplied default branch is
/// never authoritative.
pub fn derive_source_trust(
    event: &EventEnvelope,
    durable_default_branch: &str,
) -> Result<SourceTrust, TrustedPlannerError> {
    if durable_default_branch.is_empty()
        || durable_default_branch.len() > 255
        || durable_default_branch
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(TrustedPlannerError::InvalidDefaultBranch);
    }
    match event.event_type {
        EventType::IssueComment { .. } | EventType::CheckRun { .. } | EventType::Ping => {
            Err(TrustedPlannerError::NoExecutableRevision)
        }
        EventType::PullRequest { .. } | EventType::MergeGroup => Ok(SourceTrust::Untrusted),
        EventType::Push => {
            if event.source.repository_full_name.as_deref()
                != Some(event.repository.full_name.as_str())
            {
                return Err(TrustedPlannerError::InvalidEvent);
            }
            let expected = format!("refs/heads/{durable_default_branch}");
            if event.source.ref_name.as_deref() == Some(expected.as_str())
                && event.ref_name.as_deref() == Some(expected.as_str())
            {
                Ok(SourceTrust::ProtectedBranch)
            } else {
                Ok(SourceTrust::Trusted)
            }
        }
    }
}
