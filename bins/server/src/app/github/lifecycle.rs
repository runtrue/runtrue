use crate::app::{
    wall_clock_unix_ms, AppState, GitHubLifecycleWorkerError, GITHUB_LIFECYCLE_RETRY_BASE_MS,
    GITHUB_LIFECYCLE_RETRY_MAX_MS,
};
use runtrue_control_plane::{
    CompleteGitHubLifecycleDelivery, FailGitHubLifecycleDelivery, GitHubInstallationRecord,
    GitHubLifecycleDeliveryRecord, GitHubLifecycleDeliveryState, SetGitHubInstallationStatus,
};
use runtrue_model::ContentDigest;
use runtrue_scm::GitHubError;
use std::sync::atomic::Ordering;
use std::sync::Arc;
#[derive(Debug, Clone, Copy)]
pub(in crate::app) struct GitHubLifecycleProjectionFailure {
    code: &'static str,
    retryable: bool,
    retry_after_ms: Option<u64>,
}

pub(in crate::app) enum GitHubLifecycleProjectionOutcome {
    Completed(ContentDigest),
    Failed(GitHubLifecycleProjectionFailure),
}

pub(in crate::app) async fn reconcile_claimed_github_lifecycle(
    state: &AppState,
    worker_id: &str,
    delivery: GitHubLifecycleDeliveryRecord,
) -> Result<(), GitHubLifecycleWorkerError> {
    let outcome = github_lifecycle_projection(state, &delivery).await?;
    let now_unix_ms = wall_clock_unix_ms()?.max(delivery.updated_unix_ms);
    match outcome {
        GitHubLifecycleProjectionOutcome::Completed(completion_digest) => {
            state
                .store
                .complete_github_lifecycle_delivery(&CompleteGitHubLifecycleDelivery {
                    tenant_id: delivery.tenant_id,
                    delivery_id: delivery.delivery_id,
                    worker_id: worker_id.to_owned(),
                    lease_generation: delivery.lease_generation,
                    completion_digest,
                    now_unix_ms,
                })
                .await?;
        }
        GitHubLifecycleProjectionOutcome::Failed(failure) => {
            let error_digest = ContentDigest::sha256(
                format!("runtrue.github.lifecycle.failure.v1\0{}", failure.code).as_bytes(),
            );
            let retry_unix_ms = if failure.retryable && delivery.attempts < 8 {
                let exponent = delivery.attempts.saturating_sub(1).min(6);
                let exponential = GITHUB_LIFECYCLE_RETRY_BASE_MS
                    .checked_shl(exponent)
                    .unwrap_or(GITHUB_LIFECYCLE_RETRY_MAX_MS)
                    .min(GITHUB_LIFECYCLE_RETRY_MAX_MS);
                let delay = failure
                    .retry_after_ms
                    .unwrap_or(exponential)
                    .clamp(GITHUB_LIFECYCLE_RETRY_BASE_MS, 60 * 60 * 1_000);
                Some(
                    now_unix_ms
                        .checked_add(delay)
                        .ok_or(GitHubLifecycleWorkerError::Clock)?,
                )
            } else {
                None
            };
            let result = state
                .store
                .fail_github_lifecycle_delivery(&FailGitHubLifecycleDelivery {
                    tenant_id: delivery.tenant_id,
                    delivery_id: delivery.delivery_id,
                    worker_id: worker_id.to_owned(),
                    lease_generation: delivery.lease_generation,
                    error_digest,
                    retry_unix_ms,
                    now_unix_ms,
                })
                .await?;
            if let Some(github) = &state.github_installation {
                if result.value.state == GitHubLifecycleDeliveryState::Failed {
                    github
                        .metrics
                        .lifecycle_terminal_failures
                        .fetch_add(u64::from(!result.replayed), Ordering::Relaxed);
                } else {
                    github
                        .metrics
                        .lifecycle_retries
                        .fetch_add(u64::from(!result.replayed), Ordering::Relaxed);
                }
            }
        }
    }
    Ok(())
}

pub(in crate::app) async fn github_lifecycle_projection(
    state: &AppState,
    delivery: &GitHubLifecycleDeliveryRecord,
) -> Result<GitHubLifecycleProjectionOutcome, GitHubLifecycleWorkerError> {
    let Some(github) = state.github_installation.as_ref() else {
        return Ok(GitHubLifecycleProjectionOutcome::Failed(
            github_lifecycle_retry("provider-not-configured", None),
        ));
    };
    let mut current = match state
        .store
        .github_installation_for_tenant(&delivery.tenant_id, &delivery.installation_id)
        .await
    {
        Ok(current) => current,
        Err(_) => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_terminal("installation-binding-missing"),
            ))
        }
    };
    if current.installation.external_id != delivery.installation_external_id {
        return Ok(GitHubLifecycleProjectionOutcome::Failed(
            github_lifecycle_terminal("installation-substitution"),
        ));
    }
    if current.web_origin != github.public_config.web_origin()
        || current.api_origin != github.public_config.api_origin()
    {
        return Ok(GitHubLifecycleProjectionOutcome::Failed(
            github_lifecycle_terminal("provider-origin-substitution"),
        ));
    }
    if current.installation.status == "revoked" {
        return Ok(GitHubLifecycleProjectionOutcome::Completed(
            github_lifecycle_completion_digest(delivery, &current),
        ));
    }

    let terminal_status = match delivery.action.as_str() {
        "deleted" => Some("revoked"),
        "suspend" => Some("suspended"),
        "created"
        | "new_permissions_accepted"
        | "unsuspend"
        | "repositories_added"
        | "repositories_removed" => None,
        _ => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_terminal("unsupported-action"),
            ))
        }
    };
    if let Some(status) = terminal_status {
        if current.installation.status != status {
            let Some(lifecycle_generation) = current.lifecycle_generation.checked_add(1) else {
                return Ok(GitHubLifecycleProjectionOutcome::Failed(
                    github_lifecycle_terminal("lifecycle-generation-exhausted"),
                ));
            };
            let transition = SetGitHubInstallationStatus {
                tenant_id: delivery.tenant_id.clone(),
                installation_id: delivery.installation_id.clone(),
                expected_version: current.version,
                status: status.to_owned(),
                lifecycle_generation,
                now_unix_ms: wall_clock_unix_ms()?.max(delivery.updated_unix_ms),
            };
            current = match state
                .store
                .set_github_installation_status(&transition)
                .await
            {
                Ok(result) => result.value,
                Err(_) => {
                    return Ok(GitHubLifecycleProjectionOutcome::Failed(
                        github_lifecycle_retry("status-transition-conflict", None),
                    ))
                }
            };
            if status == "revoked" {
                github
                    .metrics
                    .installations_revoked
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        return Ok(GitHubLifecycleProjectionOutcome::Completed(
            github_lifecycle_completion_digest(delivery, &current),
        ));
    }

    // Permission and repository-selection events fail closed while provider
    // metadata is refreshed. A transient provider failure therefore cannot
    // leave stale source/check authorization active.
    if current.installation.status != "suspended" {
        let Some(lifecycle_generation) = current.lifecycle_generation.checked_add(1) else {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_terminal("lifecycle-generation-exhausted"),
            ));
        };
        if state
            .store
            .set_github_installation_status(&SetGitHubInstallationStatus {
                tenant_id: delivery.tenant_id.clone(),
                installation_id: delivery.installation_id.clone(),
                expected_version: current.version,
                status: "suspended".to_owned(),
                lifecycle_generation,
                now_unix_ms: wall_clock_unix_ms()?.max(delivery.updated_unix_ms),
            })
            .await
            .is_err()
        {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_retry("fail-close-transition-conflict", None),
            ));
        }
    }

    let external_id = match delivery.installation_external_id.parse::<u64>() {
        Ok(external_id) if external_id != 0 => external_id,
        _ => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_terminal("invalid-external-installation-id"),
            ))
        }
    };
    let permit = match Arc::clone(&github.admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_retry("provider-capacity-exhausted", None),
            ))
        }
    };
    let provider = Arc::clone(&github.provider);
    let inspect_now = wall_clock_unix_ms()? / 1_000;
    let inspected = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        provider.inspect_installation(external_id, inspect_now)
    })
    .await;
    let snapshot = match inspected {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(error)) => {
            github
                .metrics
                .provider_failures
                .fetch_add(1, Ordering::Relaxed);
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_provider_failure(error),
            ));
        }
        Err(_) => {
            github
                .metrics
                .provider_failures
                .fetch_add(1, Ordering::Relaxed);
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_retry("provider-worker-failed", None),
            ));
        }
    };
    if snapshot.installation_id != external_id {
        return Ok(GitHubLifecycleProjectionOutcome::Failed(
            github_lifecycle_terminal("provider-installation-substitution"),
        ));
    }
    let now_unix_ms = wall_clock_unix_ms()?.max(delivery.updated_unix_ms);
    let reconciliation = match github_reconciliation_from_snapshot(
        state,
        &delivery.tenant_id,
        snapshot,
        now_unix_ms,
    )
    .await
    {
        Ok(reconciliation) => reconciliation,
        Err(_) => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_retry("reconciliation-build-conflict", None),
            ))
        }
    };
    let reconciled = match state
        .store
        .reconcile_github_installation(&reconciliation)
        .await
    {
        Ok(reconciled) => reconciled,
        Err(_) => {
            return Ok(GitHubLifecycleProjectionOutcome::Failed(
                github_lifecycle_retry("reconciliation-commit-conflict", None),
            ))
        }
    };
    if provision_selected_github_repositories(state, &reconciliation)
        .await
        .is_err()
    {
        return Ok(GitHubLifecycleProjectionOutcome::Failed(
            github_lifecycle_retry("repository-link-reconciliation-failed", None),
        ));
    }
    github
        .metrics
        .reconciliations
        .fetch_add(1, Ordering::Relaxed);
    Ok(GitHubLifecycleProjectionOutcome::Completed(
        github_lifecycle_completion_digest(delivery, &reconciled.value.installation),
    ))
}

pub(in crate::app) fn github_lifecycle_completion_digest(
    delivery: &GitHubLifecycleDeliveryRecord,
    installation: &GitHubInstallationRecord,
) -> ContentDigest {
    ContentDigest::sha256(
        format!(
            "runtrue.github.lifecycle.complete.v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            delivery.payload_digest.as_str(),
            delivery.action,
            installation.web_origin,
            installation.api_origin,
            installation.installation.status,
            installation.lifecycle_generation,
            installation.version,
        )
        .as_bytes(),
    )
}

pub(in crate::app) const fn github_lifecycle_retry(
    code: &'static str,
    retry_after_ms: Option<u64>,
) -> GitHubLifecycleProjectionFailure {
    GitHubLifecycleProjectionFailure {
        code,
        retryable: true,
        retry_after_ms,
    }
}

pub(in crate::app) const fn github_lifecycle_terminal(
    code: &'static str,
) -> GitHubLifecycleProjectionFailure {
    GitHubLifecycleProjectionFailure {
        code,
        retryable: false,
        retry_after_ms: None,
    }
}

pub(in crate::app) fn github_lifecycle_provider_failure(
    error: GitHubError,
) -> GitHubLifecycleProjectionFailure {
    match error {
        GitHubError::RateLimited {
            retry_after_seconds,
        } => github_lifecycle_retry(
            "provider-rate-limited",
            retry_after_seconds.checked_mul(1_000),
        ),
        GitHubError::Transport | GitHubError::JwtProvider => {
            github_lifecycle_retry("provider-unavailable", None)
        }
        GitHubError::UnexpectedStatus(status) if status >= 500 => {
            github_lifecycle_retry("provider-server-error", None)
        }
        GitHubError::InsufficientInstallationPermissions => {
            github_lifecycle_terminal("insufficient-installation-permissions")
        }
        GitHubError::InstallationSubstitution => {
            github_lifecycle_terminal("provider-installation-substitution")
        }
        _ => github_lifecycle_terminal("provider-response-rejected"),
    }
}

use super::installations::{
    github_reconciliation_from_snapshot, provision_selected_github_repositories,
};
