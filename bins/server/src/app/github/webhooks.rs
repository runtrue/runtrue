use crate::app::{
    control_plane_problem, internal_problem, now_unix_ms, payload_too_large_problem,
    problem_response, scm_problem, AppState, RequestId,
};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use runtrue_control_plane::{
    ControlPlaneError, DurableEventRecord, DurableEventSource, NewScmWebhookEvent,
    ReserveGitHubLifecycleDelivery,
};
use runtrue_model::ContentDigest;
use runtrue_scm::{
    GitHubInstallationAction, GitHubInstallationRepositoriesAction, GitHubInstallationWebhook,
    ScmError, WebhookHeaders,
};
use std::sync::atomic::Ordering;
pub(in crate::app) async fn github_webhook(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return payload_too_large_problem(&request_id),
    };
    let Some(verifier) = &state.webhook else {
        return problem_response(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "Webhook unavailable",
            "GitHub webhook ingestion is not configured",
        );
    };
    let header_pairs = match webhook_header_pairs(&headers) {
        Ok(pairs) => pairs,
        Err(error) => return scm_problem(&request_id, error),
    };
    let webhook_headers = match WebhookHeaders::from_pairs(header_pairs, state.webhook_limits) {
        Ok(headers) => headers,
        Err(error) => return scm_problem(&request_id, error),
    };
    let delivery = match verifier.verify(&webhook_headers, body.to_vec()) {
        Ok(delivery) => delivery,
        Err(error) => return scm_problem(&request_id, error),
    };
    let now = match now_unix_ms(&request_id) {
        Ok(now) => now,
        Err(response) => return response,
    };
    if matches!(
        delivery.event_name.as_str(),
        "installation" | "installation_repositories"
    ) {
        return github_installation_webhook(&state, &request_id, &delivery, now).await;
    }
    let envelope = match normalize_github(
        &delivery,
        state.store.installation_id(),
        now,
        state.webhook_limits,
    ) {
        Ok(envelope) => envelope,
        Err(ScmError::UnsupportedEvent(_)) | Err(ScmError::UnsupportedAction(_)) => {
            return journal_observed_github_delivery(&state, &request_id, &delivery, now).await;
        }
        Err(error) => return scm_problem(&request_id, error),
    };
    let payload = match serde_json::to_value(&envelope) {
        Ok(payload) => payload,
        Err(_) => return internal_problem(&request_id),
    };
    let event_kind = match &envelope.event_type {
        runtrue_scm::EventType::Push => "push",
        runtrue_scm::EventType::PullRequest { .. } => "pull_request",
        runtrue_scm::EventType::IssueComment { .. } => "issue_comment",
        runtrue_scm::EventType::CheckRun { .. } => "check_run",
        runtrue_scm::EventType::MergeGroup => "merge_group",
        runtrue_scm::EventType::Ping => "ping",
    };
    let journal = match state
        .store
        .record_scm_webhook_event(&NewScmWebhookEvent {
            delivery_id: delivery.delivery_id.clone(),
            installation_external_id: envelope.installation_id.clone(),
            external_repository_id: envelope.repository.external_id.clone(),
            provider_event_name: delivery.event_name.clone(),
            event_kind: event_kind.to_owned(),
            actor_login: envelope.actor.login.clone(),
            ref_name: envelope.ref_name.clone(),
            normalized_digest: envelope.normalized_digest.clone(),
            payload_digest: delivery.raw_payload_digest.clone(),
            received_unix_ms: now,
        })
        .await
    {
        Ok(result) => result,
        Err(error) => return control_plane_problem(&request_id, error),
    };
    let digest = ContentDigest::sha256(envelope.event_id.as_bytes());
    let event_id = format!(
        "event-scm-github-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    if journal.replayed {
        match state.store.event(&event_id).await {
            Ok(existing)
                if existing.tenant_id == journal.value.tenant_id
                    && existing.idempotency_identity == delivery.delivery_id
                    && existing.handler_kind == "scm.event" =>
            {
                return StatusCode::ACCEPTED.into_response();
            }
            Ok(_) => {
                return problem_response(
                    &request_id,
                    StatusCode::CONFLICT,
                    "Webhook conflict",
                    "the delivery identifier was already used for a different event",
                );
            }
            Err(ControlPlaneError::NotFound { .. }) => {}
            Err(error) => return control_plane_problem(&request_id, error),
        }
    }
    let task_id = format!(
        "scm-github-{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    let canonical_payload = runtrue_workflow_ir::canonicalize_value(payload.clone());
    let payload_digest = match serde_json::to_vec(&canonical_payload) {
        Ok(bytes) => ContentDigest::sha256(bytes),
        Err(_) => return internal_problem(&request_id),
    };
    let event = DurableEventRecord {
        id: event_id,
        tenant_id: journal.value.tenant_id,
        source: DurableEventSource::Backend,
        kind: format!("github.{}.{event_kind}", delivery.event_name),
        handler_kind: "scm.event".to_owned(),
        payload: canonical_payload,
        payload_digest,
        idempotency_identity: delivery.delivery_id.clone(),
        actor_identity: envelope.actor.login.clone(),
        task_id,
        created_unix_ms: journal.value.received_unix_ms,
    };
    match state.store.record_event(&event).await {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(ControlPlaneError::IdempotencyConflict) => problem_response(
            &request_id,
            StatusCode::CONFLICT,
            "Webhook conflict",
            "the delivery identifier was already used for a different event",
        ),
        Err(error) => control_plane_problem(&request_id, error),
    }
}

pub(in crate::app) async fn journal_observed_github_delivery(
    state: &AppState,
    request_id: &RequestId,
    delivery: &runtrue_scm::VerifiedDelivery,
    now_unix_ms: u64,
) -> Response {
    let metadata = match inspect_github_delivery(
        delivery,
        state.store.installation_id(),
        state.webhook_limits,
    ) {
        Ok(metadata) => metadata,
        Err(error) => return scm_problem(request_id, error),
    };
    let event_kind = metadata.action.as_ref().map_or_else(
        || delivery.event_name.clone(),
        |action| format!("{}.{}", delivery.event_name, action),
    );
    match state
        .store
        .record_scm_webhook_event(&NewScmWebhookEvent {
            delivery_id: delivery.delivery_id.clone(),
            installation_external_id: metadata.installation_id,
            external_repository_id: metadata.repository.external_id,
            provider_event_name: delivery.event_name.clone(),
            event_kind,
            actor_login: metadata.actor.login,
            ref_name: None,
            normalized_digest: metadata.normalized_digest,
            payload_digest: delivery.raw_payload_digest.clone(),
            received_unix_ms: now_unix_ms,
        })
        .await
    {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(error) => control_plane_problem(request_id, error),
    }
}

pub(in crate::app) async fn github_installation_webhook(
    state: &AppState,
    request_id: &RequestId,
    delivery: &runtrue_scm::VerifiedDelivery,
    now_unix_ms: u64,
) -> Response {
    let Some(github) = state.github_installation.as_ref() else {
        return problem_response(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "GitHub App unavailable",
            "GitHub installation lifecycle handling is not configured",
        );
    };
    let lifecycle = match parse_github_installation_webhook(delivery, github.public_config.app_id())
    {
        Ok(lifecycle) => lifecycle,
        Err(_) => {
            return problem_response(
                request_id,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid GitHub installation event",
                "the authenticated installation event failed strict identity validation",
            )
        }
    };
    let (external_id, action) = match &lifecycle {
        GitHubInstallationWebhook::Installation {
            action,
            installation,
            ..
        } => (
            installation.installation_id,
            match action {
                GitHubInstallationAction::Created => "created",
                GitHubInstallationAction::Deleted => "deleted",
                GitHubInstallationAction::NewPermissionsAccepted => "new_permissions_accepted",
                GitHubInstallationAction::Suspend => "suspend",
                GitHubInstallationAction::Unsuspend => "unsuspend",
            },
        ),
        GitHubInstallationWebhook::RepositoriesChanged {
            action,
            installation,
            ..
        } => (
            installation.installation_id,
            match action {
                GitHubInstallationRepositoriesAction::Added => "repositories_added",
                GitHubInstallationRepositoriesAction::Removed => "repositories_removed",
            },
        ),
    };
    let current = match state
        .store
        .github_installation_by_external_id(
            github.public_config.web_origin(),
            github.public_config.api_origin(),
            &external_id.to_string(),
        )
        .await
    {
        Ok(current) => current,
        Err(ControlPlaneError::NotFound { .. }) => {
            // A created event commonly races the browser setup callback. The
            // opaque callback state remains the only authority that selects a
            // tenant, so an unbound webhook is acknowledged but cannot create
            // tenant state on its own.
            return StatusCode::ACCEPTED.into_response();
        }
        Err(error) => return control_plane_problem(request_id, error),
    };
    let reservation = ReserveGitHubLifecycleDelivery {
        delivery_id: delivery.delivery_id.clone(),
        tenant_id: current.installation.tenant_id,
        installation_id: current.installation.id,
        installation_external_id: external_id.to_string(),
        event_name: delivery.event_name.clone(),
        action: action.to_owned(),
        payload_digest: delivery.raw_payload_digest.clone(),
        now_unix_ms,
    };
    match state
        .store
        .reserve_github_lifecycle_delivery(&reservation)
        .await
    {
        Ok(result) => {
            if result.replayed {
                github
                    .metrics
                    .lifecycle_delivery_replays
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                github
                    .metrics
                    .lifecycle_deliveries_reserved
                    .fetch_add(1, Ordering::Relaxed);
            }
            StatusCode::ACCEPTED.into_response()
        }
        Err(ControlPlaneError::IdempotencyConflict) => problem_response(
            request_id,
            StatusCode::CONFLICT,
            "Webhook conflict",
            "the delivery identifier was already used for different authenticated lifecycle data",
        ),
        Err(error) => control_plane_problem(request_id, error),
    }
}
pub(in crate::app) fn webhook_header_pairs(
    headers: &HeaderMap,
) -> Result<Vec<(String, String)>, ScmError> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = value
                .to_str()
                .map_err(|_| ScmError::InvalidHeaderValue(name.to_string()))?;
            Ok((name.to_string(), value.to_owned()))
        })
        .collect()
}
use axum::response::IntoResponse as _;
use runtrue_scm::{inspect_github_delivery, normalize_github, parse_github_installation_webhook};
