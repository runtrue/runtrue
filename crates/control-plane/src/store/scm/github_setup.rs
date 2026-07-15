use super::*;
use rusqlite::params;

pub(in crate::store) fn github_setup_row(
    row: &Row<'_>,
) -> rusqlite::Result<GitHubSetupTransactionRecord> {
    let status: String = row.get(9)?;
    let status = match status.as_str() {
        "pending" => GitHubSetupStatus::Pending,
        "exchanging" => GitHubSetupStatus::Exchanging,
        "completed" => GitHubSetupStatus::Completed,
        "rejected" => GitHubSetupStatus::Rejected,
        "expired" => GitHubSetupStatus::Expired,
        other => {
            return Err(conversion(
                9,
                DecodeError(format!("unknown GitHub setup status `{other}`")),
            ))
        }
    };
    let attempts = u64_column(row, 10, "GitHub setup attempts")?;
    Ok(GitHubSetupTransactionRecord {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        principal_id: row.get(2)?,
        idempotency_key: row.get(3)?,
        request_digest: digest_column(row, 4)?,
        state_digest: digest_column(row, 5)?,
        github_web_origin: row.get(6)?,
        github_api_origin: row.get(7)?,
        return_path: row.get(8)?,
        status,
        attempts: u32::try_from(attempts)
            .map_err(|error| conversion(10, DecodeError(error.to_string())))?,
        expires_unix_ms: u64_column(row, 11, "GitHub setup expiry")?,
        installation_id: row.get(12)?,
        installation_external_id: row.get(13)?,
        completion_digest: optional_digest_column(row, 14)?,
        last_error_code: row.get(15)?,
        created_unix_ms: u64_column(row, 16, "GitHub setup creation")?,
        updated_unix_ms: u64_column(row, 17, "GitHub setup update")?,
        completed_unix_ms: optional_u64_column(row, 18, "GitHub setup completion")?,
    })
}

pub(in crate::store) fn github_setup_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    id: &str,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {GITHUB_SETUP_COLUMNS} FROM github_app_setup_transactions
                 WHERE tenant_id = ?1 AND id = ?2"
            ),
            params![tenant_id, id],
            github_setup_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn github_setup_by_idempotency_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    idempotency_key: &str,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {GITHUB_SETUP_COLUMNS} FROM github_app_setup_transactions
                 WHERE tenant_id = ?1 AND idempotency_key = ?2"
            ),
            params![tenant_id, idempotency_key],
            github_setup_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn github_setup_by_state_tx(
    transaction: &Transaction<'_>,
    state_digest: &ContentDigest,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {GITHUB_SETUP_COLUMNS} FROM github_app_setup_transactions
                 WHERE state_digest = ?1"
            ),
            [state_digest.as_str()],
            github_setup_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn github_setup_exact_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    principal_id: &str,
    id: &str,
    state_digest: &ContentDigest,
) -> Result<Option<GitHubSetupTransactionRecord>, ControlPlaneError> {
    transaction
        .query_row(
            &format!(
                "SELECT {GITHUB_SETUP_COLUMNS} FROM github_app_setup_transactions
                 WHERE tenant_id = ?1 AND principal_id = ?2 AND id = ?3
                   AND state_digest = ?4"
            ),
            params![tenant_id, principal_id, id, state_digest.as_str()],
            github_setup_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(in crate::store) fn validate_github_setup_request(
    request: &CreateGitHubSetupTransaction,
) -> Result<(), ControlPlaneError> {
    for value in [
        request.id.as_str(),
        request.tenant_id.as_str(),
        request.principal_id.as_str(),
    ] {
        validate_text("GitHub setup identity", value)?;
    }
    validate_github_origins(&request.github_web_origin, &request.github_api_origin)?;
    validate_idempotency_key(&request.idempotency_key)?;
    let lifetime = request
        .expires_unix_ms
        .checked_sub(request.created_unix_ms)
        .filter(|lifetime| *lifetime > 0 && *lifetime <= MAX_GITHUB_SETUP_LIFETIME_MS)
        .ok_or(ControlPlaneError::InvalidInput(
            "invalid GitHub setup expiry",
        ))?;
    if lifetime == 0
        || request.return_path.is_empty()
        || request.return_path.len() > 2_048
        || !request.return_path.starts_with('/')
        || request.return_path.starts_with("//")
        || request.return_path.contains('\0')
        || request.return_path.contains('\\')
        || request
            .return_path
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || request.expected_request_digest()? != request.request_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid GitHub setup request",
        ));
    }
    Ok(())
}

pub(in crate::store) fn github_setup_principal_active_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    principal_id: &str,
    now_unix_ms: u64,
) -> Result<bool, ControlPlaneError> {
    require_r9_tenant_tx(transaction, tenant_id)?;
    if principal_id == "bootstrap" {
        return Ok(true);
    }
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM human_users u
                 JOIN human_user_tenant_bindings b ON b.user_id = u.id
                 JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = b.tenant_id
                 WHERE b.tenant_id = ?1 AND u.id = ?2
                   AND u.status = 'active' AND m.status = 'active'
                 UNION ALL
                 SELECT 1 FROM api_tokens t
                 WHERE t.tenant_id = ?1 AND t.principal_id = ?2
                   AND t.revoked_unix_ms IS NULL AND t.expires_unix_ms > ?3
             )",
            params![tenant_id, principal_id, to_i64(now_unix_ms)?],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(in crate::store) fn require_github_setup_principal_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    principal_id: &str,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    validate_text("GitHub setup tenant", tenant_id)?;
    validate_text("GitHub setup principal", principal_id)?;
    if github_setup_principal_active_tx(transaction, tenant_id, principal_id, now_unix_ms)? {
        Ok(())
    } else {
        Err(ControlPlaneError::NotFound {
            kind: "GitHub setup authorization",
            id: principal_id.to_owned(),
        })
    }
}

pub(in crate::store) fn advance_github_setup_tx(
    transaction: &Transaction<'_>,
    record: GitHubSetupTransactionRecord,
    now_unix_ms: u64,
) -> Result<Option<IdempotentResult<GitHubSetupTransactionRecord>>, ControlPlaneError> {
    if now_unix_ms < record.updated_unix_ms
        || !matches!(
            record.status,
            GitHubSetupStatus::Pending | GitHubSetupStatus::Exchanging
        )
    {
        return Ok(None);
    }
    if now_unix_ms >= record.expires_unix_ms {
        transaction.execute(
            "UPDATE github_app_setup_transactions
             SET status = 'expired', updated_unix_ms = ?3, last_error_code = 'expired'
             WHERE tenant_id = ?1 AND id = ?2 AND status IN ('pending', 'exchanging')",
            params![record.tenant_id, record.id, to_i64(now_unix_ms)?],
        )?;
        return Ok(None);
    }
    if record.attempts >= MAX_GITHUB_SETUP_ATTEMPTS {
        transaction.execute(
            "UPDATE github_app_setup_transactions
             SET status = 'rejected', updated_unix_ms = ?3,
                 last_error_code = 'attempt-limit'
             WHERE tenant_id = ?1 AND id = ?2 AND status IN ('pending', 'exchanging')",
            params![record.tenant_id, record.id, to_i64(now_unix_ms)?],
        )?;
        return Ok(None);
    }
    let replayed = record.status == GitHubSetupStatus::Exchanging;
    transaction.execute(
        "UPDATE github_app_setup_transactions
         SET status = 'exchanging', attempts = attempts + 1, updated_unix_ms = ?3
         WHERE tenant_id = ?1 AND id = ?2 AND status IN ('pending', 'exchanging')",
        params![record.tenant_id, record.id, to_i64(now_unix_ms)?],
    )?;
    let updated =
        github_setup_tx(transaction, &record.tenant_id, &record.id)?.ok_or_else(|| {
            ControlPlaneError::CorruptState("advanced GitHub setup was not readable".to_owned())
        })?;
    Ok(Some(IdempotentResult {
        value: updated,
        replayed,
    }))
}

impl ControlPlane {
    /// Reserve one bounded, one-use GitHub App setup callback. Only the state
    /// digest is durable; the raw opaque state remains with the HTTP adapter.
    pub fn create_github_setup_transaction(
        &self,
        request: &CreateGitHubSetupTransaction,
    ) -> Result<IdempotentResult<GitHubSetupTransactionRecord>, ControlPlaneError> {
        validate_github_setup_request(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_github_setup_principal_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            request.created_unix_ms,
        )?;
        if let Some(existing) = github_setup_by_idempotency_tx(
            &transaction,
            &request.tenant_id,
            &request.idempotency_key,
        )? {
            if existing.request_digest != request.request_digest
                || existing.tenant_id != request.tenant_id
                || existing.principal_id != request.principal_id
                || existing.github_web_origin != request.github_web_origin
                || existing.github_api_origin != request.github_api_origin
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO github_app_setup_transactions
             (id, tenant_id, principal_id, idempotency_key, request_digest,
              state_digest, github_web_origin, github_api_origin, return_path,
              status, attempts, expires_unix_ms, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', 0,
                     ?10, ?11, ?11)",
            params![
                request.id,
                request.tenant_id,
                request.principal_id,
                request.idempotency_key,
                request.request_digest.as_str(),
                request.state_digest.as_str(),
                request.github_web_origin,
                request.github_api_origin,
                request.return_path,
                to_i64(request.expires_unix_ms)?,
                to_i64(request.created_unix_ms)?,
            ],
        )?;
        if inserted == 0 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let record =
            github_setup_tx(&transaction, &request.tenant_id, &request.id)?.ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "GitHub setup insertion was not readable".to_owned(),
                )
            })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.created_unix_ms,
            &request.tenant_id,
            &request.principal_id,
            "github.setup.create",
            "github-setup",
            &request.id,
            &request.idempotency_key,
            BTreeMap::from([
                (
                    "request_digest".to_owned(),
                    AuditValue::Digest(request.request_digest.clone()),
                ),
                (
                    "expires_unix_ms".to_owned(),
                    AuditValue::Integer(to_i64(request.expires_unix_ms)?),
                ),
                (
                    "github_origin_digest".to_owned(),
                    AuditValue::Digest(github_origin_digest(
                        &request.github_web_origin,
                        &request.github_api_origin,
                    )?),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: false,
        })
    }

    /// Resolve the opaque callback state before any callback-controlled
    /// installation metadata is trusted. Missing, expired, unauthorized, and
    /// terminal states deliberately share one rejection.
    pub fn begin_github_setup_by_state(
        &self,
        state_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<IdempotentResult<GitHubSetupTransactionRecord>, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = github_setup_by_state_tx(&transaction, state_digest)?;
        let Some(record) = record else {
            return Err(ControlPlaneError::InvalidGitHubSetupState);
        };
        if !github_setup_principal_active_tx(
            &transaction,
            &record.tenant_id,
            &record.principal_id,
            now_unix_ms,
        )? {
            return Err(ControlPlaneError::InvalidGitHubSetupState);
        }
        let outcome = advance_github_setup_tx(&transaction, record, now_unix_ms)?;
        transaction.commit()?;
        outcome.ok_or(ControlPlaneError::InvalidGitHubSetupState)
    }

    /// Session-bound variant used by authenticated API adapters and tests.
    pub fn begin_github_setup_transaction(
        &self,
        request: &BeginGitHubSetupTransaction,
    ) -> Result<IdempotentResult<GitHubSetupTransactionRecord>, ControlPlaneError> {
        for value in [
            request.tenant_id.as_str(),
            request.principal_id.as_str(),
            request.transaction_id.as_str(),
        ] {
            validate_text("GitHub setup binding", value)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_github_setup_principal_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            request.now_unix_ms,
        )?;
        let record = github_setup_exact_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            &request.transaction_id,
            &request.state_digest,
        )?;
        let Some(record) = record else {
            return Err(ControlPlaneError::InvalidGitHubSetupState);
        };
        let outcome = advance_github_setup_tx(&transaction, record, request.now_unix_ms)?;
        transaction.commit()?;
        outcome.ok_or(ControlPlaneError::InvalidGitHubSetupState)
    }

    pub fn reject_github_setup_transaction(
        &self,
        request: &BeginGitHubSetupTransaction,
        error_code: &str,
    ) -> Result<IdempotentResult<GitHubSetupTransactionRecord>, ControlPlaneError> {
        validate_text("GitHub setup error code", error_code)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_github_setup_principal_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            request.now_unix_ms,
        )?;
        let record = github_setup_exact_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            &request.transaction_id,
            &request.state_digest,
        )?
        .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
        if record.status == GitHubSetupStatus::Rejected {
            if record.last_error_code.as_deref() != Some(error_code) {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: record,
                replayed: true,
            });
        }
        if !matches!(
            record.status,
            GitHubSetupStatus::Pending | GitHubSetupStatus::Exchanging
        ) || request.now_unix_ms < record.updated_unix_ms
        {
            return Err(ControlPlaneError::InvalidGitHubSetupState);
        }
        transaction.execute(
            "UPDATE github_app_setup_transactions
             SET status = 'rejected', last_error_code = ?5, updated_unix_ms = ?6
             WHERE tenant_id = ?1 AND principal_id = ?2 AND id = ?3 AND state_digest = ?4",
            params![
                request.tenant_id,
                request.principal_id,
                request.transaction_id,
                request.state_digest.as_str(),
                error_code,
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let updated = github_setup_tx(&transaction, &request.tenant_id, &request.transaction_id)?
            .ok_or_else(|| {
            ControlPlaneError::CorruptState("rejected GitHub setup was not readable".to_owned())
        })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            &request.principal_id,
            "github.setup.reject",
            "github-setup",
            &request.transaction_id,
            &request.transaction_id,
            BTreeMap::from([(
                "error_digest".to_owned(),
                AuditValue::Digest(ContentDigest::sha256(error_code.as_bytes())),
            )]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: updated,
            replayed: false,
        })
    }

    /// Atomically complete a callback and publish the exact verified provider
    /// installation/catalog snapshot. A crash leaves the callback exchanging;
    /// exact retry converges without re-binding a different installation.
    pub fn complete_github_setup_transaction(
        &self,
        request: &CompleteGitHubSetupTransaction,
    ) -> Result<IdempotentResult<GitHubSetupTransactionRecord>, ControlPlaneError> {
        if request.now_unix_ms != request.reconciliation.now_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "GitHub setup completion timestamps differ",
            ));
        }
        validate_github_reconciliation(&request.reconciliation)?;
        let completion_digest = github_reconciliation_digest(&request.reconciliation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_github_setup_principal_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            request.now_unix_ms,
        )?;
        let record = github_setup_exact_tx(
            &transaction,
            &request.tenant_id,
            &request.principal_id,
            &request.transaction_id,
            &request.state_digest,
        )?
        .ok_or(ControlPlaneError::InvalidGitHubSetupState)?;
        let requested_installation = &request.reconciliation.installation.installation;
        if record.status == GitHubSetupStatus::Completed {
            if record.installation_id.as_deref() != Some(&requested_installation.id)
                || record.installation_external_id.as_deref()
                    != Some(&requested_installation.external_id)
                || record.github_web_origin != request.reconciliation.installation.web_origin
                || record.github_api_origin != request.reconciliation.installation.api_origin
                || record.completion_digest.as_ref() != Some(&completion_digest)
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: record,
                replayed: true,
            });
        }
        if record.status != GitHubSetupStatus::Exchanging
            || request.now_unix_ms >= record.expires_unix_ms
            || request.now_unix_ms < record.updated_unix_ms
            || requested_installation.tenant_id != record.tenant_id
            || record.github_web_origin != request.reconciliation.installation.web_origin
            || record.github_api_origin != request.reconciliation.installation.api_origin
        {
            return Err(ControlPlaneError::InvalidGitHubSetupState);
        }
        reconcile_github_installation_tx(&transaction, &request.reconciliation)?;
        transaction.execute(
            "UPDATE github_app_setup_transactions
             SET status = 'completed', installation_id = ?5,
                 installation_external_id = ?6, completion_digest = ?7,
                 updated_unix_ms = ?8, completed_unix_ms = ?8
             WHERE tenant_id = ?1 AND principal_id = ?2 AND id = ?3 AND state_digest = ?4
               AND status = 'exchanging'",
            params![
                request.tenant_id,
                request.principal_id,
                request.transaction_id,
                request.state_digest.as_str(),
                requested_installation.id,
                requested_installation.external_id,
                completion_digest.as_str(),
                to_i64(request.now_unix_ms)?,
            ],
        )?;
        let completed = github_setup_tx(&transaction, &request.tenant_id, &request.transaction_id)?
            .ok_or_else(|| {
                ControlPlaneError::CorruptState(
                    "completed GitHub setup was not readable".to_owned(),
                )
            })?;
        append_github_audit_tx(
            &transaction,
            &self.installation_id,
            request.now_unix_ms,
            &request.tenant_id,
            &request.principal_id,
            "github.setup.complete",
            "github-installation",
            &requested_installation.id,
            &request.transaction_id,
            BTreeMap::from([
                (
                    "completion_digest".to_owned(),
                    AuditValue::Digest(completion_digest),
                ),
                (
                    "external_installation_id".to_owned(),
                    AuditValue::String(requested_installation.external_id.clone()),
                ),
                (
                    "github_origin_digest".to_owned(),
                    AuditValue::Digest(github_origin_digest(
                        &request.reconciliation.installation.web_origin,
                        &request.reconciliation.installation.api_origin,
                    )?),
                ),
                (
                    "selected_repository_count".to_owned(),
                    AuditValue::Integer(
                        i64::try_from(request.reconciliation.selected_repositories.len()).map_err(
                            |_| ControlPlaneError::IntegerRange {
                                field: "GitHub selected repository count",
                            },
                        )?,
                    ),
                ),
            ]),
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: completed,
            replayed: false,
        })
    }
}
