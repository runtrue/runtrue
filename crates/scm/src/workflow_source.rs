use super::{EventEnvelope, EventType, GitRevision, WebhookLimits};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_POLICY_VERSIONS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_APPROVAL_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowSourceInputs {
    pub workflow_path: String,
    pub proposed_workflow_digest: ContentDigest,
    pub base_workflow_digest: Option<ContentDigest>,
    pub proposed_lockfile_digest: Option<ContentDigest>,
    pub base_lockfile_digest: Option<ContentDigest>,
    /// Compiler-produced digest binding the complete proposed execution capsule,
    /// permissions, dependencies, policies, environment, and runner profile.
    pub proposed_approval_subject_digest: Option<ContentDigest>,
    pub policy_version_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinitionApprovalEvidence {
    pub approval_id: String,
    pub normalized_event_digest: ContentDigest,
    pub event_received_unix_ms: u64,
    pub repository_full_name: String,
    pub source_commit: String,
    pub base_commit: String,
    pub workflow_path: String,
    pub proposed_workflow_digest: ContentDigest,
    pub base_workflow_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_lockfile_digest: Option<ContentDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_lockfile_digest: Option<ContentDigest>,
    pub proposed_approval_subject_digest: ContentDigest,
    pub policy_version_ids: Vec<String>,
    pub approved_unix_ms: u64,
    pub expires_unix_ms: u64,
}

impl WorkflowDefinitionApprovalEvidence {
    pub fn subject_digest(&self) -> Result<ContentDigest, WorkflowSourceError> {
        let value = serde_json::to_value(self).map_err(|_| WorkflowSourceError::Serialize)?;
        let bytes = serde_json::to_vec(&canonicalize_value(value))
            .map_err(|_| WorkflowSourceError::Serialize)?;
        Ok(ContentDigest::sha256(bytes))
    }
}

/// Verifies that approval evidence came from the trusted approval service and
/// is still active. The resolver then independently compares every bound
/// field; a verifier cannot broaden the evidence after verification.
pub trait WorkflowDefinitionApprovalVerifier {
    fn verify(
        &self,
        evidence: &WorkflowDefinitionApprovalEvidence,
    ) -> Result<(), WorkflowSourceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedWorkflowSelection {
    /// Source tree checked out for job code.
    pub code_revision: GitRevision,
    /// Revision from which the executable workflow and lockfile are read.
    pub workflow_revision: GitRevision,
    /// Proposed workflow revision parsed only for diff/risk presentation when
    /// it is not yet approved for execution.
    pub analysis_workflow_revision: Option<GitRevision>,
    pub definition_changed: bool,
    pub trusted_base_workflow_executed: bool,
    pub workflow_definition_approval_required: bool,
    pub approval_id: Option<String>,
}

pub fn select_trusted_workflow_source(
    event: &EventEnvelope,
    inputs: &WorkflowSourceInputs,
    approval: Option<&WorkflowDefinitionApprovalEvidence>,
    verifier: &dyn WorkflowDefinitionApprovalVerifier,
    now_unix_ms: u64,
    webhook_limits: WebhookLimits,
) -> Result<TrustedWorkflowSelection, WorkflowSourceError> {
    event
        .verify(webhook_limits)
        .map_err(|_| WorkflowSourceError::InvalidEvent)?;
    validate_inputs(inputs)?;
    match event.event_type {
        EventType::PullRequest { .. } => {
            select_pull_request(event, inputs, approval, verifier, now_unix_ms)
        }
        EventType::Push | EventType::MergeGroup => {
            if approval.is_some() {
                return Err(WorkflowSourceError::UnexpectedApproval);
            }
            Ok(TrustedWorkflowSelection {
                code_revision: event.source.clone(),
                workflow_revision: event.source.clone(),
                analysis_workflow_revision: None,
                definition_changed: false,
                trusted_base_workflow_executed: false,
                workflow_definition_approval_required: false,
                approval_id: None,
            })
        }
        EventType::IssueComment { .. } | EventType::CheckRun { .. } => {
            Err(WorkflowSourceError::NoExecutableRevision)
        }
        EventType::Ping => Err(WorkflowSourceError::NoExecutableRevision),
    }
}

fn select_pull_request(
    event: &EventEnvelope,
    inputs: &WorkflowSourceInputs,
    approval: Option<&WorkflowDefinitionApprovalEvidence>,
    verifier: &dyn WorkflowDefinitionApprovalVerifier,
    now_unix_ms: u64,
) -> Result<TrustedWorkflowSelection, WorkflowSourceError> {
    let base = event
        .base
        .as_ref()
        .ok_or(WorkflowSourceError::InvalidEvent)?;
    let base_workflow_digest = inputs
        .base_workflow_digest
        .as_ref()
        .ok_or(WorkflowSourceError::MissingBaseDefinition)?;
    let definition_changed = base_workflow_digest != &inputs.proposed_workflow_digest
        || inputs.base_lockfile_digest != inputs.proposed_lockfile_digest;

    if !definition_changed {
        if approval.is_some() {
            return Err(WorkflowSourceError::UnexpectedApproval);
        }
        return Ok(TrustedWorkflowSelection {
            code_revision: event.source.clone(),
            workflow_revision: base.clone(),
            analysis_workflow_revision: None,
            definition_changed: false,
            trusted_base_workflow_executed: true,
            workflow_definition_approval_required: false,
            approval_id: None,
        });
    }

    let Some(approval) = approval else {
        return Ok(TrustedWorkflowSelection {
            code_revision: event.source.clone(),
            workflow_revision: base.clone(),
            analysis_workflow_revision: Some(event.source.clone()),
            definition_changed: true,
            trusted_base_workflow_executed: true,
            workflow_definition_approval_required: true,
            approval_id: None,
        });
    };
    verifier.verify(approval)?;
    validate_approval(event, inputs, approval, now_unix_ms)?;
    Ok(TrustedWorkflowSelection {
        code_revision: event.source.clone(),
        workflow_revision: event.source.clone(),
        analysis_workflow_revision: None,
        definition_changed: true,
        trusted_base_workflow_executed: false,
        workflow_definition_approval_required: false,
        approval_id: Some(approval.approval_id.clone()),
    })
}

fn validate_inputs(inputs: &WorkflowSourceInputs) -> Result<(), WorkflowSourceError> {
    let normalized = normalize_relative_path(&inputs.workflow_path)
        .map_err(|_| WorkflowSourceError::InvalidWorkflowPath)?;
    if normalized != inputs.workflow_path
        || inputs.policy_version_ids.is_empty()
        || inputs.policy_version_ids.len() > MAX_POLICY_VERSIONS
        || !sorted_unique_identifiers(&inputs.policy_version_ids)
    {
        return Err(WorkflowSourceError::InvalidInputs);
    }
    Ok(())
}

fn validate_approval(
    event: &EventEnvelope,
    inputs: &WorkflowSourceInputs,
    approval: &WorkflowDefinitionApprovalEvidence,
    now_unix_ms: u64,
) -> Result<(), WorkflowSourceError> {
    let base = event
        .base
        .as_ref()
        .ok_or(WorkflowSourceError::InvalidEvent)?;
    let base_workflow_digest = inputs
        .base_workflow_digest
        .as_ref()
        .ok_or(WorkflowSourceError::MissingBaseDefinition)?;
    let approval_lifetime = approval
        .expires_unix_ms
        .checked_sub(approval.approved_unix_ms)
        .ok_or(WorkflowSourceError::ApprovalMismatch)?;
    if approval.approval_id.is_empty()
        || approval.approval_id.len() > MAX_IDENTIFIER_BYTES
        || approval
            .approval_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || approval.normalized_event_digest != event.normalized_digest
        || approval.event_received_unix_ms != event.received_unix_ms
        || approval.repository_full_name != event.repository.full_name
        || approval.source_commit != event.source.commit
        || approval.base_commit != base.commit
        || approval.workflow_path != inputs.workflow_path
        || approval.proposed_workflow_digest != inputs.proposed_workflow_digest
        || &approval.base_workflow_digest != base_workflow_digest
        || approval.proposed_lockfile_digest != inputs.proposed_lockfile_digest
        || approval.base_lockfile_digest != inputs.base_lockfile_digest
        || inputs.proposed_approval_subject_digest.as_ref()
            != Some(&approval.proposed_approval_subject_digest)
        || approval.policy_version_ids != inputs.policy_version_ids
        || approval.approved_unix_ms < event.received_unix_ms
        || approval.approved_unix_ms > now_unix_ms
        || approval.expires_unix_ms <= now_unix_ms
        || approval_lifetime > MAX_APPROVAL_LIFETIME_MS
        || !sorted_unique_identifiers(&approval.policy_version_ids)
    {
        return Err(WorkflowSourceError::ApprovalMismatch);
    }
    Ok(())
}

fn sorted_unique_identifiers(values: &[String]) -> bool {
    values.iter().all(|value| {
        !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && !value.bytes().any(|byte| byte.is_ascii_control())
    }) && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_value).collect())
        }
        serde_json::Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            serde_json::Value::Object(values.into_iter().collect())
        }
        other => other,
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkflowSourceError {
    #[error("normalized SCM event is invalid")]
    InvalidEvent,
    #[error("workflow source inputs are invalid")]
    InvalidInputs,
    #[error("workflow path must be a normalized repository-relative path")]
    InvalidWorkflowPath,
    #[error("pull request is missing the trusted base workflow definition")]
    MissingBaseDefinition,
    #[error("workflow-definition approval is invalid")]
    ApprovalInvalid,
    #[error("workflow-definition approval does not bind the exact source decision")]
    ApprovalMismatch,
    #[error("workflow-definition approval was supplied where none is allowed")]
    UnexpectedApproval,
    #[error("event has no executable revision")]
    NoExecutableRevision,
    #[error("failed to canonicalize workflow-definition approval")]
    Serialize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorIdentity, EventType, ProviderKind, PullRequestAction, PullRequestEvent,
        RepositoryIdentity,
    };
    use std::cell::Cell;

    const NOW: u64 = 10_000;

    fn digest(value: &str) -> ContentDigest {
        ContentDigest::sha256(value.as_bytes())
    }

    fn event(event_type: EventType) -> EventEnvelope {
        let is_pull = matches!(event_type, EventType::PullRequest { .. });
        let is_merge = matches!(event_type, EventType::MergeGroup);
        let is_ping = matches!(event_type, EventType::Ping);
        let base = (is_pull || is_merge).then_some(GitRevision {
            commit: "b".repeat(40),
            ref_name: Some("main".to_owned()),
            repository_full_name: Some("octo/runtrue".to_owned()),
        });
        let mut event = EventEnvelope {
            version: 1,
            provider: ProviderKind::GitHub,
            installation_id: "installation-1".to_owned(),
            repository: RepositoryIdentity {
                external_id: "42".to_owned(),
                owner: "octo".to_owned(),
                name: "runtrue".to_owned(),
                full_name: "octo/runtrue".to_owned(),
                private: true,
                default_branch: Some("main".to_owned()),
            },
            event_id: "delivery-1".to_owned(),
            event_type,
            actor: ActorIdentity {
                external_id: "7".to_owned(),
                login: "developer".to_owned(),
                is_bot: false,
            },
            source: GitRevision {
                commit: if is_ping {
                    "0".repeat(40)
                } else {
                    "a".repeat(40)
                },
                ref_name: Some("feature".to_owned()),
                repository_full_name: Some(if is_pull {
                    "contributor/fork".to_owned()
                } else {
                    "octo/runtrue".to_owned()
                }),
            },
            base,
            ref_name: Some(if is_pull || is_merge {
                "main".to_owned()
            } else {
                "feature".to_owned()
            }),
            pull_request: is_pull.then_some(PullRequestEvent {
                number: 17,
                draft: false,
                merged: false,
            }),
            issue_comment: None,
            check_run: None,
            changed_paths: if is_ping {
                Vec::new()
            } else {
                vec!["src/lib.rs".to_owned()]
            },
            received_unix_ms: NOW - 100,
            raw_payload_digest: digest("raw"),
            normalized_digest: digest("placeholder"),
        };
        event.normalized_digest =
            ContentDigest::sha256(event.canonical_normalized_bytes().unwrap());
        event
    }

    fn pull_event() -> EventEnvelope {
        event(EventType::PullRequest {
            action: PullRequestAction::Synchronize,
        })
    }

    fn changed_inputs() -> WorkflowSourceInputs {
        WorkflowSourceInputs {
            workflow_path: ".runtrue/workflows/ci.yaml".to_owned(),
            proposed_workflow_digest: digest("proposed-workflow"),
            base_workflow_digest: Some(digest("base-workflow")),
            proposed_lockfile_digest: Some(digest("proposed-lock")),
            base_lockfile_digest: Some(digest("base-lock")),
            proposed_approval_subject_digest: Some(digest("proposed-approval-subject")),
            policy_version_ids: vec!["policy-a".to_owned(), "policy-b".to_owned()],
        }
    }

    fn approval(
        event: &EventEnvelope,
        inputs: &WorkflowSourceInputs,
    ) -> WorkflowDefinitionApprovalEvidence {
        WorkflowDefinitionApprovalEvidence {
            approval_id: "approval-1".to_owned(),
            normalized_event_digest: event.normalized_digest.clone(),
            event_received_unix_ms: event.received_unix_ms,
            repository_full_name: event.repository.full_name.clone(),
            source_commit: event.source.commit.clone(),
            base_commit: event.base.as_ref().unwrap().commit.clone(),
            workflow_path: inputs.workflow_path.clone(),
            proposed_workflow_digest: inputs.proposed_workflow_digest.clone(),
            base_workflow_digest: inputs.base_workflow_digest.clone().unwrap(),
            proposed_lockfile_digest: inputs.proposed_lockfile_digest.clone(),
            base_lockfile_digest: inputs.base_lockfile_digest.clone(),
            proposed_approval_subject_digest: inputs
                .proposed_approval_subject_digest
                .clone()
                .unwrap(),
            policy_version_ids: inputs.policy_version_ids.clone(),
            approved_unix_ms: NOW - 10,
            expires_unix_ms: NOW + 60_000,
        }
    }

    struct Verifier {
        accepted: bool,
        calls: Cell<usize>,
    }

    impl Verifier {
        fn accepting() -> Self {
            Self {
                accepted: true,
                calls: Cell::new(0),
            }
        }
    }

    impl WorkflowDefinitionApprovalVerifier for Verifier {
        fn verify(
            &self,
            _evidence: &WorkflowDefinitionApprovalEvidence,
        ) -> Result<(), WorkflowSourceError> {
            self.calls.set(self.calls.get() + 1);
            if self.accepted {
                Ok(())
            } else {
                Err(WorkflowSourceError::ApprovalInvalid)
            }
        }
    }

    #[test]
    fn changed_pull_request_defaults_to_target_branch_workflow() {
        let event = pull_event();
        let inputs = changed_inputs();
        let verifier = Verifier::accepting();
        let selection = select_trusted_workflow_source(
            &event,
            &inputs,
            None,
            &verifier,
            NOW,
            WebhookLimits::default(),
        )
        .unwrap();
        assert_eq!(selection.code_revision, event.source);
        assert_eq!(selection.workflow_revision, event.base.clone().unwrap());
        assert_eq!(selection.analysis_workflow_revision, Some(event.source));
        assert!(selection.trusted_base_workflow_executed);
        assert!(selection.workflow_definition_approval_required);
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn exact_verified_approval_selects_proposed_workflow() {
        let event = pull_event();
        let inputs = changed_inputs();
        let evidence = approval(&event, &inputs);
        let verifier = Verifier::accepting();
        let selection = select_trusted_workflow_source(
            &event,
            &inputs,
            Some(&evidence),
            &verifier,
            NOW,
            WebhookLimits::default(),
        )
        .unwrap();
        assert_eq!(selection.workflow_revision, event.source);
        assert!(!selection.trusted_base_workflow_executed);
        assert_eq!(selection.approval_id.as_deref(), Some("approval-1"));
        assert_eq!(verifier.calls.get(), 1);
    }

    #[test]
    fn verifier_cannot_broaden_mismatched_approval_evidence() {
        let event = pull_event();
        let inputs = changed_inputs();
        let mut evidence = approval(&event, &inputs);
        evidence.proposed_workflow_digest = digest("substitution");
        assert!(matches!(
            select_trusted_workflow_source(
                &event,
                &inputs,
                Some(&evidence),
                &Verifier::accepting(),
                NOW,
                WebhookLimits::default()
            ),
            Err(WorkflowSourceError::ApprovalMismatch)
        ));

        let mut replayed_event = event.clone();
        replayed_event.received_unix_ms = event.received_unix_ms.saturating_sub(1);
        let exact_evidence = approval(&event, &inputs);
        assert!(matches!(
            select_trusted_workflow_source(
                &replayed_event,
                &inputs,
                Some(&exact_evidence),
                &Verifier::accepting(),
                NOW,
                WebhookLimits::default()
            ),
            Err(WorkflowSourceError::ApprovalMismatch)
        ));
    }

    #[test]
    fn unchanged_definition_still_reads_trusted_base_without_approval() {
        let event = pull_event();
        let mut inputs = changed_inputs();
        inputs.proposed_workflow_digest = inputs.base_workflow_digest.clone().unwrap();
        inputs
            .proposed_lockfile_digest
            .clone_from(&inputs.base_lockfile_digest);
        let selection = select_trusted_workflow_source(
            &event,
            &inputs,
            None,
            &Verifier::accepting(),
            NOW,
            WebhookLimits::default(),
        )
        .unwrap();
        assert!(!selection.definition_changed);
        assert_eq!(selection.workflow_revision, event.base.unwrap());
        assert!(selection.trusted_base_workflow_executed);
    }

    #[test]
    fn lockfile_only_change_is_approval_material() {
        let event = pull_event();
        let mut inputs = changed_inputs();
        inputs.proposed_workflow_digest = inputs.base_workflow_digest.clone().unwrap();
        let selection = select_trusted_workflow_source(
            &event,
            &inputs,
            None,
            &Verifier::accepting(),
            NOW,
            WebhookLimits::default(),
        )
        .unwrap();
        assert!(selection.definition_changed);
        assert!(selection.workflow_definition_approval_required);
    }

    #[test]
    fn push_uses_exact_event_source_and_ping_never_executes() {
        let push = event(EventType::Push);
        let selection = select_trusted_workflow_source(
            &push,
            &changed_inputs(),
            None,
            &Verifier::accepting(),
            NOW,
            WebhookLimits::default(),
        )
        .unwrap();
        assert_eq!(selection.code_revision, push.source);
        assert_eq!(selection.workflow_revision, push.source);

        let ping = event(EventType::Ping);
        assert!(matches!(
            select_trusted_workflow_source(
                &ping,
                &changed_inputs(),
                None,
                &Verifier::accepting(),
                NOW,
                WebhookLimits::default()
            ),
            Err(WorkflowSourceError::NoExecutableRevision)
        ));
    }

    #[test]
    fn tampered_event_and_unsafe_path_fail_before_selection() {
        let mut event = pull_event();
        event.source.commit = "c".repeat(40);
        assert!(matches!(
            select_trusted_workflow_source(
                &event,
                &changed_inputs(),
                None,
                &Verifier::accepting(),
                NOW,
                WebhookLimits::default()
            ),
            Err(WorkflowSourceError::InvalidEvent)
        ));
        let mut inputs = changed_inputs();
        "../ci.yaml".clone_into(&mut inputs.workflow_path);
        assert!(matches!(
            select_trusted_workflow_source(
                &pull_event(),
                &inputs,
                None,
                &Verifier::accepting(),
                NOW,
                WebhookLimits::default()
            ),
            Err(WorkflowSourceError::InvalidWorkflowPath)
        ));
    }
}
