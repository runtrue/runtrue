use super::super::validation::parse_strict_json;
use super::{
    events::{
        normalize_github_check_run, normalize_github_issue_comment, normalize_github_merge_group,
        normalize_github_ping, normalize_github_pull_request, normalize_github_push,
    },
    validation::{
        integer_or_string, object_at, object_field, optional_string, required_bool,
        required_string, validate_envelope, validate_identifier,
    },
    NORMALIZED_EVENT_VERSION,
};
use crate::{
    ActorIdentity, CheckRunEvent, EventEnvelope, EventType, GitHubDeliveryMetadata, GitRevision,
    IssueCommentEvent, ProviderKind, PullRequestEvent, RepositoryIdentity, ScmError,
    VerifiedDelivery, WebhookLimits,
};
use runtrue_model::ContentDigest;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
struct NormalizedEvent<'a> {
    version: u32,
    provider: ProviderKind,
    installation_id: &'a str,
    repository: &'a RepositoryIdentity,
    event_id: &'a str,
    event_type: &'a EventType,
    actor: &'a ActorIdentity,
    source: &'a GitRevision,
    base: &'a Option<GitRevision>,
    ref_name: &'a Option<String>,
    pull_request: &'a Option<PullRequestEvent>,
    issue_comment: &'a Option<IssueCommentEvent>,
    check_run: &'a Option<CheckRunEvent>,
    changed_paths: &'a [String],
}

impl EventEnvelope {
    fn normalized_projection(&self) -> NormalizedEvent<'_> {
        NormalizedEvent {
            version: self.version,
            provider: self.provider,
            installation_id: &self.installation_id,
            repository: &self.repository,
            event_id: &self.event_id,
            event_type: &self.event_type,
            actor: &self.actor,
            source: &self.source,
            base: &self.base,
            ref_name: &self.ref_name,
            pull_request: &self.pull_request,
            issue_comment: &self.issue_comment,
            check_run: &self.check_run,
            changed_paths: &self.changed_paths,
        }
    }

    pub fn canonical_normalized_bytes(&self) -> Result<Vec<u8>, ScmError> {
        serde_json::to_vec(&self.normalized_projection()).map_err(ScmError::Serialize)
    }

    pub fn verify(&self, limits: WebhookLimits) -> Result<(), ScmError> {
        let limits = limits.validate()?;
        validate_envelope(self, limits)?;
        let digest = ContentDigest::sha256(self.canonical_normalized_bytes()?);
        if digest != self.normalized_digest {
            return Err(ScmError::NormalizedDigestMismatch);
        }
        Ok(())
    }
}

/// Convert an authenticated GitHub delivery to the provider-neutral contract.
pub fn normalize_github(
    delivery: &VerifiedDelivery,
    installation_id: &str,
    received_unix_ms: u64,
    limits: WebhookLimits,
) -> Result<EventEnvelope, ScmError> {
    let limits = limits.validate()?;
    if delivery.provider != ProviderKind::GitHub {
        return Err(ScmError::ProviderMismatch);
    }
    let payload = parse_strict_json(delivery.raw_payload())?;
    let installation_id = match payload.get("installation") {
        Some(installation @ Value::Object(_)) => integer_or_string(installation, "id", limits)?,
        Some(_) => {
            return Err(ScmError::InvalidPayload(
                "installation must be an object".to_owned(),
            ))
        }
        None => validate_identifier("installation id", installation_id, limits)?,
    };
    let common = github_common(&payload, limits)?;

    let (event_type, source, base, ref_name, pull_request, issue_comment, check_run, changed_paths) =
        match delivery.event_name.as_str() {
            "push" => normalize_github_push(&payload, limits)?,
            "pull_request" => normalize_github_pull_request(&payload, limits)?,
            "issue_comment" => normalize_github_issue_comment(&payload, limits)?,
            "check_run" => normalize_github_check_run(&payload, limits)?,
            "merge_group" => normalize_github_merge_group(&payload, limits)?,
            "ping" => normalize_github_ping(&payload, limits)?,
            event => return Err(ScmError::UnsupportedEvent(event.to_owned())),
        };

    let mut envelope = EventEnvelope {
        version: NORMALIZED_EVENT_VERSION,
        provider: ProviderKind::GitHub,
        installation_id,
        repository: common.repository,
        event_id: delivery.delivery_id.clone(),
        event_type,
        actor: common.actor,
        source,
        base,
        ref_name,
        pull_request,
        issue_comment,
        check_run,
        changed_paths,
        received_unix_ms,
        raw_payload_digest: delivery.raw_payload_digest.clone(),
        normalized_digest: ContentDigest::sha256([]),
    };
    validate_envelope(&envelope, limits)?;
    envelope.normalized_digest = ContentDigest::sha256(envelope.canonical_normalized_bytes()?);
    envelope.verify(limits)?;
    Ok(envelope)
}

/// Extract the common repository binding and actor from any authenticated
/// GitHub repository delivery. Callers may journal this metadata for operator
/// visibility, but must not treat it as an executable trigger unless the same
/// delivery also passes [`normalize_github`].
pub fn inspect_github_delivery(
    delivery: &VerifiedDelivery,
    installation_id: &str,
    limits: WebhookLimits,
) -> Result<GitHubDeliveryMetadata, ScmError> {
    let limits = limits.validate()?;
    if delivery.provider != ProviderKind::GitHub {
        return Err(ScmError::ProviderMismatch);
    }
    let payload = parse_strict_json(delivery.raw_payload())?;
    let installation_id = match payload.get("installation") {
        Some(installation @ Value::Object(_)) => integer_or_string(installation, "id", limits)?,
        Some(_) => {
            return Err(ScmError::InvalidPayload(
                "installation must be an object".to_owned(),
            ))
        }
        None => validate_identifier("installation id", installation_id, limits)?,
    };
    let common = github_common(&payload, limits)?;
    let action = optional_string(&payload, "action", limits)?;
    #[derive(Serialize)]
    struct Projection<'a> {
        version: u32,
        event_id: &'a str,
        event_name: &'a str,
        installation_id: &'a str,
        repository: &'a RepositoryIdentity,
        actor: &'a ActorIdentity,
        action: &'a Option<String>,
    }
    let projection = Projection {
        version: NORMALIZED_EVENT_VERSION,
        event_id: &delivery.delivery_id,
        event_name: &delivery.event_name,
        installation_id: &installation_id,
        repository: &common.repository,
        actor: &common.actor,
        action: &action,
    };
    let normalized_digest =
        ContentDigest::sha256(serde_json::to_vec(&projection).map_err(ScmError::Serialize)?);
    Ok(GitHubDeliveryMetadata {
        installation_id,
        repository: common.repository,
        actor: common.actor,
        action,
        normalized_digest,
    })
}

struct GitHubCommon {
    repository: RepositoryIdentity,
    actor: ActorIdentity,
}

fn github_common(payload: &Value, limits: WebhookLimits) -> Result<GitHubCommon, ScmError> {
    let repository = object_at(payload, "repository")?;
    let owner = object_field(repository, "owner")?;
    let actor = object_at(payload, "sender")?;
    Ok(GitHubCommon {
        repository: RepositoryIdentity {
            external_id: integer_or_string(repository, "id", limits)?,
            owner: required_string(owner, "login", limits)?,
            name: required_string(repository, "name", limits)?,
            full_name: required_string(repository, "full_name", limits)?,
            private: required_bool(repository, "private")?,
            default_branch: optional_string(repository, "default_branch", limits)?,
        },
        actor: ActorIdentity {
            external_id: integer_or_string(actor, "id", limits)?,
            login: required_string(actor, "login", limits)?,
            is_bot: actor
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "Bot"),
        },
    })
}
