use super::*;
use rusqlite::params;

pub(in crate::store) fn github_lifecycle_delivery_row(
    row: &Row<'_>,
) -> rusqlite::Result<GitHubLifecycleDeliveryRecord> {
    let state: String = row.get(7)?;
    let state = match state.as_str() {
        "pending" => GitHubLifecycleDeliveryState::Pending,
        "leased" => GitHubLifecycleDeliveryState::Leased,
        "completed" => GitHubLifecycleDeliveryState::Completed,
        "failed" => GitHubLifecycleDeliveryState::Failed,
        other => {
            return Err(conversion(
                7,
                DecodeError(format!("unknown GitHub lifecycle state `{other}`")),
            ))
        }
    };
    let attempts = u64_column(row, 8, "GitHub lifecycle attempts")?;
    Ok(GitHubLifecycleDeliveryRecord {
        delivery_id: row.get(0)?,
        tenant_id: row.get(1)?,
        installation_id: row.get(2)?,
        installation_external_id: row.get(3)?,
        event_name: row.get(4)?,
        action: row.get(5)?,
        payload_digest: digest_column(row, 6)?,
        state,
        attempts: u32::try_from(attempts)
            .map_err(|error| conversion(8, DecodeError(error.to_string())))?,
        available_unix_ms: u64_column(row, 9, "GitHub lifecycle availability")?,
        lease_owner: row.get(10)?,
        lease_generation: u64_column(row, 11, "GitHub lifecycle lease generation")?,
        lease_expires_unix_ms: optional_u64_column(row, 12, "GitHub lifecycle lease expiry")?,
        completion_digest: optional_digest_column(row, 13)?,
        completed_lease_owner: row.get(14)?,
        completed_lease_generation: optional_u64_column(
            row,
            15,
            "GitHub lifecycle completed generation",
        )?,
        last_failure_generation: optional_u64_column(
            row,
            16,
            "GitHub lifecycle failure generation",
        )?,
        last_failure_lease_owner: row.get(17)?,
        last_error_digest: optional_digest_column(row, 18)?,
        last_retry_unix_ms: optional_u64_column(row, 19, "GitHub lifecycle retry")?,
        created_unix_ms: u64_column(row, 20, "GitHub lifecycle creation")?,
        updated_unix_ms: u64_column(row, 21, "GitHub lifecycle update")?,
        completed_unix_ms: optional_u64_column(row, 22, "GitHub lifecycle completion")?,
    })
}

pub(in crate::store) fn github_lifecycle_delivery_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    delivery_id: &str,
) -> Result<Option<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {GITHUB_LIFECYCLE_COLUMNS} FROM github_lifecycle_deliveries
                 WHERE tenant_id = ?1 AND delivery_id = ?2"
            ),
            params![tenant_id, delivery_id],
            github_lifecycle_delivery_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn validate_github_lifecycle_reservation(
    request: &ReserveGitHubLifecycleDelivery,
) -> Result<(), ControlPlaneError> {
    for value in [
        request.delivery_id.as_str(),
        request.tenant_id.as_str(),
        request.installation_id.as_str(),
        request.installation_external_id.as_str(),
        request.event_name.as_str(),
        request.action.as_str(),
    ] {
        validate_text("GitHub lifecycle identity", value)?;
    }
    if request
        .installation_external_id
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .is_none()
        || request.event_name.len() > 64
        || request.action.len() > 64
        || !request
            .event_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || !request.action.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle delivery",
        ));
    }
    Ok(())
}

pub(in crate::store) fn validate_github_lifecycle_claim(
    worker_id: &str,
    now_unix_ms: u64,
    lease_duration_ms: u64,
) -> Result<(), ControlPlaneError> {
    validate_text("GitHub lifecycle worker", worker_id)?;
    if lease_duration_ms == 0 || lease_duration_ms > MAX_GITHUB_LIFECYCLE_LEASE_MS {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle lease duration",
        ));
    }
    now_unix_ms
        .checked_add(lease_duration_ms)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "GitHub lifecycle lease expiry",
        })?;
    Ok(())
}

pub(in crate::store) fn validate_github_lifecycle_mutation(
    tenant_id: &str,
    delivery_id: &str,
    worker_id: &str,
    lease_generation: u64,
) -> Result<(), ControlPlaneError> {
    for value in [tenant_id, delivery_id, worker_id] {
        validate_text("GitHub lifecycle binding", value)?;
    }
    if lease_generation == 0 {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub lifecycle lease generation",
        ));
    }
    Ok(())
}

pub(in crate::store) fn claim_github_lifecycle_tx(
    transaction: &Transaction<'_>,
    record: GitHubLifecycleDeliveryRecord,
    worker_id: &str,
    now_unix_ms: u64,
    lease_duration_ms: u64,
) -> Result<Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>, ControlPlaneError> {
    if record.state == GitHubLifecycleDeliveryState::Leased
        && record
            .lease_expires_unix_ms
            .is_some_and(|expiry| expiry > now_unix_ms)
    {
        return if record.lease_owner.as_deref() == Some(worker_id) {
            Ok(Some(IdempotentResult {
                value: record,
                replayed: true,
            }))
        } else {
            Ok(None)
        };
    }
    if matches!(
        record.state,
        GitHubLifecycleDeliveryState::Completed | GitHubLifecycleDeliveryState::Failed
    ) || (record.state == GitHubLifecycleDeliveryState::Pending
        && record.available_unix_ms > now_unix_ms)
    {
        return Ok(None);
    }
    if record.attempts >= MAX_GITHUB_LIFECYCLE_ATTEMPTS {
        fail_exhausted_github_lifecycle_delivery_tx(transaction, &record, now_unix_ms)?;
        return Ok(None);
    }
    let generation =
        record
            .lease_generation
            .checked_add(1)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "GitHub lifecycle lease generation",
            })?;
    let expiry =
        now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or(ControlPlaneError::IntegerRange {
                field: "GitHub lifecycle lease expiry",
            })?;
    transaction.execute(
        "UPDATE github_lifecycle_deliveries SET state = 'leased', attempts = attempts + 1,
             lease_owner = ?3, lease_generation = ?4, lease_expires_unix_ms = ?5,
             updated_unix_ms = ?6
         WHERE tenant_id = ?1 AND delivery_id = ?2",
        params![
            record.tenant_id,
            record.delivery_id,
            worker_id,
            to_i64(generation)?,
            to_i64(expiry)?,
            to_i64(now_unix_ms)?,
        ],
    )?;
    let claimed =
        github_lifecycle_delivery_tx(transaction, &record.tenant_id, &record.delivery_id)?
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "claimed GitHub lifecycle delivery was not readable".to_owned(),
                )
            })?;
    Ok(Some(IdempotentResult {
        value: claimed,
        replayed: false,
    }))
}

pub(in crate::store) fn require_github_lifecycle_lease(
    record: &GitHubLifecycleDeliveryRecord,
    worker_id: &str,
    lease_generation: u64,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if record.state != GitHubLifecycleDeliveryState::Leased
        || record.lease_owner.as_deref() != Some(worker_id)
        || record.lease_generation != lease_generation
        || record
            .lease_expires_unix_ms
            .is_none_or(|expiry| expiry <= now_unix_ms)
    {
        return Err(ControlPlaneError::GitHubLifecycleLeaseLost);
    }
    Ok(())
}

pub(in crate::store) fn fail_exhausted_github_lifecycle_delivery_tx(
    transaction: &Transaction<'_>,
    record: &GitHubLifecycleDeliveryRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let error = ContentDigest::sha256(b"github lifecycle delivery attempts exhausted");
    transaction.execute(
        "UPDATE github_lifecycle_deliveries SET state = 'failed',
             lease_owner = NULL, lease_expires_unix_ms = NULL,
             last_failure_generation = lease_generation,
             last_failure_lease_owner = COALESCE(lease_owner, 'github-lifecycle-exhaustion'),
             last_error_digest = ?3, last_retry_unix_ms = NULL,
             updated_unix_ms = ?4
         WHERE tenant_id = ?1 AND delivery_id = ?2 AND state IN ('pending', 'leased')",
        params![
            record.tenant_id,
            record.delivery_id,
            error.as_str(),
            to_i64(now_unix_ms)?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn fail_exhausted_github_lifecycle_deliveries_tx(
    transaction: &Transaction<'_>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    let error = ContentDigest::sha256(b"github lifecycle delivery attempts exhausted");
    transaction.execute(
        "UPDATE github_lifecycle_deliveries SET state = 'failed',
             last_failure_generation = lease_generation,
             last_failure_lease_owner = COALESCE(lease_owner, 'github-lifecycle-exhaustion'),
             last_error_digest = ?1, last_retry_unix_ms = NULL,
             lease_owner = NULL, lease_expires_unix_ms = NULL, updated_unix_ms = ?2
         WHERE attempts >= ?3 AND (
             state = 'pending' OR (state = 'leased' AND lease_expires_unix_ms <= ?2)
         )",
        params![
            error.as_str(),
            to_i64(now_unix_ms)?,
            i64::from(MAX_GITHUB_LIFECYCLE_ATTEMPTS),
        ],
    )?;
    Ok(())
}

impl ControlPlane {
    pub fn reserve_github_lifecycle_delivery(
        &self,
        request: &ReserveGitHubLifecycleDelivery,
    ) -> Result<IdempotentResult<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
        validate_github_lifecycle_reservation(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let installation =
            github_installation_tx(&transaction, &request.tenant_id, &request.installation_id)?
                .filter(|record| {
                    record.installation.external_id == request.installation_external_id
                })
                .ok_or_else(|| not_found("GitHub lifecycle authorization", &request.delivery_id))?;
        if installation.installation.id != request.installation_id {
            return Err(not_found(
                "GitHub lifecycle authorization",
                &request.delivery_id,
            ));
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO github_lifecycle_deliveries
             (delivery_id, tenant_id, installation_id, installation_external_id,
              event_name, action, payload_digest, state, attempts,
              available_unix_ms, lease_generation, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 0, ?8, 0, ?8, ?8)",
            params![
                request.delivery_id,
                request.tenant_id,
                request.installation_id,
                request.installation_external_id,
                request.event_name,
                request.action,
                request.payload_digest.as_str(),
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let existing =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?;
        let Some(existing) = existing else {
            return Err(not_found(
                "GitHub lifecycle authorization",
                &request.delivery_id,
            ));
        };
        if existing.installation_id != request.installation_id
            || existing.installation_external_id != request.installation_external_id
            || existing.event_name != request.event_name
            || existing.action != request.action
            || existing.payload_digest != request.payload_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if inserted == 1 {
            append_github_audit_tx(
                &transaction,
                &self.installation_id,
                request.now_unix_ms,
                &request.tenant_id,
                "github-webhook",
                "github.lifecycle.reserve",
                "github-lifecycle-delivery",
                &request.delivery_id,
                &request.delivery_id,
                BTreeMap::from([
                    (
                        "payload_digest".to_owned(),
                        AuditValue::Digest(request.payload_digest.clone()),
                    ),
                    (
                        "external_installation_id".to_owned(),
                        AuditValue::String(request.installation_external_id.clone()),
                    ),
                ]),
            )?;
        }
        transaction.commit()?;
        Ok(IdempotentResult {
            value: existing,
            replayed: inserted == 0,
        })
    }

    pub fn claim_github_lifecycle_delivery(
        &self,
        request: &ClaimGitHubLifecycleDelivery,
    ) -> Result<Option<IdempotentResult<GitHubLifecycleDeliveryRecord>>, ControlPlaneError> {
        validate_github_lifecycle_claim(
            &request.worker_id,
            request.now_unix_ms,
            request.lease_duration_ms,
        )?;
        validate_text("GitHub lifecycle tenant", &request.tenant_id)?;
        validate_text("GitHub lifecycle delivery", &request.delivery_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let record =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &request.delivery_id))?;
        let claimed = claim_github_lifecycle_tx(
            &transaction,
            record,
            &request.worker_id,
            request.now_unix_ms,
            request.lease_duration_ms,
        )?;
        transaction.commit()?;
        Ok(claimed)
    }

    /// Internal bounded worker claim across tenants. The returned record
    /// carries its exact tenant and installation binding; public APIs must not
    /// expose this cross-tenant selector.
    pub fn claim_next_github_lifecycle_delivery(
        &self,
        worker_id: &str,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
        validate_github_lifecycle_claim(worker_id, now_unix_ms, lease_duration_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        fail_exhausted_github_lifecycle_deliveries_tx(&transaction, now_unix_ms)?;
        let candidate = transaction
            .query_row(
                &format!(
                    "SELECT {GITHUB_LIFECYCLE_COLUMNS}
                     FROM github_lifecycle_deliveries
                     WHERE attempts < ?1 AND (
                         (state = 'pending' AND available_unix_ms <= ?2)
                         OR (state = 'leased' AND lease_expires_unix_ms <= ?2)
                     )
                     ORDER BY available_unix_ms, delivery_id LIMIT 1"
                ),
                params![
                    i64::from(MAX_GITHUB_LIFECYCLE_ATTEMPTS),
                    to_i64(now_unix_ms)?,
                ],
                github_lifecycle_delivery_row,
            )
            .optional()?;
        let claimed = if let Some(candidate) = candidate {
            claim_github_lifecycle_tx(
                &transaction,
                candidate,
                worker_id,
                now_unix_ms,
                lease_duration_ms,
            )?
            .map(|result| result.value)
        } else {
            None
        };
        transaction.commit()?;
        Ok(claimed)
    }

    pub fn complete_github_lifecycle_delivery(
        &self,
        request: &CompleteGitHubLifecycleDelivery,
    ) -> Result<IdempotentResult<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
        validate_github_lifecycle_mutation(
            &request.tenant_id,
            &request.delivery_id,
            &request.worker_id,
            request.lease_generation,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let record =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &request.delivery_id))?;
        if record.state == GitHubLifecycleDeliveryState::Completed {
            if record.completion_digest.as_ref() != Some(&request.completion_digest)
                || record.completed_lease_owner.as_deref() != Some(&request.worker_id)
                || record.completed_lease_generation != Some(request.lease_generation)
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: record,
                replayed: true,
            });
        }
        require_github_lifecycle_lease(
            &record,
            request.worker_id.as_str(),
            request.lease_generation,
            request.now_unix_ms,
        )?;
        transaction.execute(
            "UPDATE github_lifecycle_deliveries SET state = 'completed',
                 lease_owner = NULL, lease_expires_unix_ms = NULL,
                 completion_digest = ?3, completed_lease_owner = ?4,
                 completed_lease_generation = ?5, updated_unix_ms = ?6,
                 completed_unix_ms = ?6
             WHERE tenant_id = ?1 AND delivery_id = ?2",
            params![
                request.tenant_id,
                request.delivery_id,
                request.completion_digest.as_str(),
                request.worker_id,
                to_i64(request.lease_generation)?,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let completed =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?
                .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "completed GitHub lifecycle delivery was not readable".to_owned(),
                )
            })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            &request.worker_id,
            "github.lifecycle.complete",
            "github-lifecycle-delivery",
            &request.delivery_id,
            &request.delivery_id,
            BTreeMap::from([(
                "completion_digest".to_owned(),
                AuditValue::Digest(request.completion_digest.clone()),
            )]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: completed,
            replayed: false,
        })
    }

    pub fn fail_github_lifecycle_delivery(
        &self,
        request: &FailGitHubLifecycleDelivery,
    ) -> Result<IdempotentResult<GitHubLifecycleDeliveryRecord>, ControlPlaneError> {
        validate_github_lifecycle_mutation(
            &request.tenant_id,
            &request.delivery_id,
            &request.worker_id,
            request.lease_generation,
        )?;
        if let Some(retry) = request.retry_unix_ms {
            let maximum = request
                .now_unix_ms
                .checked_add(MAX_GITHUB_LIFECYCLE_BACKOFF_MS)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "GitHub lifecycle retry deadline",
                })?;
            if retry < request.now_unix_ms || retry > maximum {
                return Err(ControlPlaneError::InvalidInput(
                    "GitHub lifecycle retry is outside its bound",
                ));
            }
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &request.tenant_id)?;
        let record =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?
                .ok_or_else(|| not_found("GitHub lifecycle delivery", &request.delivery_id))?;
        if record.last_failure_generation == Some(request.lease_generation)
            && record.last_failure_lease_owner.as_deref() == Some(&request.worker_id)
        {
            if record.last_error_digest.as_ref() != Some(&request.error_digest)
                || record.last_retry_unix_ms != request.retry_unix_ms
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: record,
                replayed: true,
            });
        }
        require_github_lifecycle_lease(
            &record,
            request.worker_id.as_str(),
            request.lease_generation,
            request.now_unix_ms,
        )?;
        let retry = request
            .retry_unix_ms
            .filter(|_| record.attempts < MAX_GITHUB_LIFECYCLE_ATTEMPTS);
        let state = if retry.is_some() { "pending" } else { "failed" };
        let available = retry.unwrap_or(request.now_unix_ms);
        transaction.execute(
            "UPDATE github_lifecycle_deliveries SET state = ?3,
                 available_unix_ms = ?4, lease_owner = NULL,
                 lease_expires_unix_ms = NULL, last_failure_generation = ?5,
                 last_failure_lease_owner = ?6, last_error_digest = ?7,
                 last_retry_unix_ms = ?8, updated_unix_ms = ?9
             WHERE tenant_id = ?1 AND delivery_id = ?2",
            params![
                request.tenant_id,
                request.delivery_id,
                state,
                to_i64(available)?,
                to_i64(request.lease_generation)?,
                request.worker_id,
                request.error_digest.as_str(),
                retry.map(to_i64).transpose()?,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let failed =
            github_lifecycle_delivery_tx(&transaction, &request.tenant_id, &request.delivery_id)?
                .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "failed GitHub lifecycle delivery was not readable".to_owned(),
                )
            })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            &request.worker_id,
            "github.lifecycle.fail",
            "github-lifecycle-delivery",
            &request.delivery_id,
            &format!("{}:{}", request.delivery_id, request.lease_generation),
            BTreeMap::from([
                (
                    "error_digest".to_owned(),
                    AuditValue::Digest(request.error_digest.clone()),
                ),
                (
                    "retry_scheduled".to_owned(),
                    AuditValue::Boolean(retry.is_some()),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: failed,
            replayed: false,
        })
    }

    /// Resolve an authenticated provider event through the exact installation
    /// and external repository mapping. All tenant predicates are evaluated in
    /// this query so a mismatch is indistinguishable from an absent link.
    pub fn github_repository_for_event(
        &self,
        installation_external_id: &str,
        repository_external_id: &str,
        owner: &str,
        name: &str,
    ) -> Result<
        (
            RepositoryRecord,
            ScmInstallationRecord,
            ScmRepositoryLinkRecord,
        ),
        ControlPlaneError,
    > {
        for (field, value) in [
            ("SCM installation external id", installation_external_id),
            ("SCM repository external id", repository_external_id),
            ("repository owner", owner),
            ("repository name", name),
        ] {
            validate_text(field, value)?;
        }
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT
                    r.id, r.tenant_id, r.owner, r.name, r.default_branch, r.visibility,
                    r.created_unix_ms,
                    i.id, i.tenant_id, i.provider, i.external_id, i.credential_reference,
                    i.permissions_json, i.status, i.created_unix_ms, i.updated_unix_ms,
                    l.repository_id, l.tenant_id, l.installation_id,
                    l.external_repository_id, l.clone_url, l.status,
                    l.created_unix_ms, l.updated_unix_ms
                 FROM scm_installations i
                 JOIN scm_repository_links l ON l.installation_id = i.id
                    AND l.tenant_id = i.tenant_id
                 JOIN repositories r ON r.id = l.repository_id
                    AND r.tenant_id = l.tenant_id
                 WHERE i.provider = 'github' AND i.external_id = ?1
                   AND l.external_repository_id = ?2 AND r.owner = ?3 AND r.name = ?4
                   AND i.status = 'active' AND l.status = 'active'",
                params![
                    installation_external_id,
                    repository_external_id,
                    owner,
                    name
                ],
                |row| {
                    let repository = RepositoryRecord {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        owner: row.get(2)?,
                        name: row.get(3)?,
                        default_branch: row.get(4)?,
                        visibility: row.get(5)?,
                        created_unix_ms: u64_column(row, 6, "repository created_unix_ms")?,
                    };
                    let installation = scm_installation_row_at(row, 7)?;
                    let link = scm_repository_link_row_at(row, 16)?;
                    Ok((repository, installation, link))
                },
            )
            .optional()?
            .ok_or_else(|| ControlPlaneError::NotFound {
                kind: "SCM repository authorization",
                id: format!("{owner}/{name}"),
            })
    }
}
