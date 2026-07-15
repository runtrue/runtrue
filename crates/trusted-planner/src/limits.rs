use crate::TrustedPlannerError;
use runtrue_scm::WebhookLimits;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrustedPlannerLimits {
    pub webhook: WebhookLimits,
}

pub(crate) fn normalize_policy_versions(
    mut values: Vec<String>,
) -> Result<Vec<String>, TrustedPlannerError> {
    values.sort();
    values.dedup();
    if values.is_empty()
        || values.len() > 128
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || value.bytes().any(|byte| byte.is_ascii_control())
        })
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(TrustedPlannerError::InvalidPolicyVersions);
    }
    Ok(values)
}
