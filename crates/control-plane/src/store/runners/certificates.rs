use super::*;

pub(in crate::store) fn validate_new_runner_certificate(
    certificate: &RunnerCertificateRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    validate_text("certificate runner id", &certificate.runner_id)?;
    validate_text("certificate pool id", &certificate.pool_id)?;
    if certificate.status != RunnerCertificateStatus::Active
        || certificate.overlap_until_unix_ms.is_some()
        || certificate.revoked_unix_ms.is_some()
        || certificate.not_before_unix_ms > now_unix_ms
        || certificate.not_after_unix_ms <= now_unix_ms
        || certificate.issued_unix_ms > now_unix_ms
        || certificate.serial_hex.is_empty()
        || certificate.serial_hex.len() > 128
        || !certificate
            .serial_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ControlPlaneError::InvalidInput(
            "invalid runner certificate metadata",
        ));
    }
    Ok(())
}

pub(in crate::store) fn runner_certificate_status_name(
    status: RunnerCertificateStatus,
) -> &'static str {
    match status {
        RunnerCertificateStatus::Active => "active",
        RunnerCertificateStatus::Overlap => "overlap",
        RunnerCertificateStatus::Revoked => "revoked",
    }
}

pub(in crate::store) fn parse_runner_certificate_status(
    value: &str,
) -> Result<RunnerCertificateStatus, ControlPlaneError> {
    match value {
        "active" => Ok(RunnerCertificateStatus::Active),
        "overlap" => Ok(RunnerCertificateStatus::Overlap),
        "revoked" => Ok(RunnerCertificateStatus::Revoked),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown runner certificate status".to_owned(),
        )),
    }
}

pub(in crate::store) fn runner_certificate_row(
    row: &Row<'_>,
) -> rusqlite::Result<RunnerCertificateRecord> {
    let status: String = row.get(6)?;
    Ok(RunnerCertificateRecord {
        fingerprint: digest_column(row, 0)?,
        runner_id: row.get(1)?,
        pool_id: row.get(2)?,
        serial_hex: row.get(3)?,
        not_before_unix_ms: u64_column(row, 4, "certificate not before")?,
        not_after_unix_ms: u64_column(row, 5, "certificate not after")?,
        status: parse_runner_certificate_status(&status).map_err(|error| conversion(6, error))?,
        issued_unix_ms: u64_column(row, 7, "certificate issued")?,
        overlap_until_unix_ms: optional_u64_column(row, 8, "certificate overlap deadline")?,
        revoked_unix_ms: optional_u64_column(row, 9, "certificate revoked")?,
    })
}

const RUNNER_CERTIFICATE_COLUMNS: &str =
    "fingerprint, runner_id, pool_id, serial_hex, not_before_unix_ms, not_after_unix_ms, \
     status, issued_unix_ms, overlap_until_unix_ms, revoked_unix_ms";

pub(in crate::store) fn runner_certificate_by_fingerprint(
    connection: &Connection,
    fingerprint: &ContentDigest,
) -> Result<Option<RunnerCertificateRecord>, ControlPlaneError> {
    connection
        .query_row(
            &format!(
                "SELECT {RUNNER_CERTIFICATE_COLUMNS} FROM runner_certificates \
                 WHERE fingerprint = ?1"
            ),
            [fingerprint.as_str()],
            runner_certificate_row,
        )
        .optional()
        .map_err(ControlPlaneError::from)
}

pub(in crate::store) fn runner_certificate_by_fingerprint_tx(
    transaction: &Transaction<'_>,
    fingerprint: &ContentDigest,
) -> Result<Option<RunnerCertificateRecord>, ControlPlaneError> {
    runner_certificate_by_fingerprint(transaction, fingerprint)
}

pub(in crate::store) fn runner_certificate_rotation_conn(
    connection: &Connection,
    old_fingerprint: &ContentDigest,
) -> Result<Option<RunnerCertificateRotationRecord>, ControlPlaneError> {
    type RotationRow = (String, String, String, String, String, String, Vec<u8>, i64);
    let raw: Option<RotationRow> = connection
        .query_row(
            "SELECT old_fingerprint, runner_id, pool_id, csr_digest, new_fingerprint,
                    new_certificate_json, certificate_chain_pem, created_unix_ms
             FROM runner_certificate_rotations WHERE old_fingerprint = ?1",
            [old_fingerprint.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((old, runner_id, pool_id, csr, new, certificate, chain, created)) = raw else {
        return Ok(None);
    };
    let new_certificate: RunnerCertificateRecord = serde_json::from_str(&certificate)?;
    let record = RunnerCertificateRotationRecord {
        old_fingerprint: ContentDigest::parse(old)?,
        runner_id,
        pool_id,
        csr_digest: ContentDigest::parse(csr)?,
        new_certificate,
        certificate_chain_pem: chain,
        created_unix_ms: from_i64("certificate rotation creation", created)?,
    };
    if record.old_fingerprint != *old_fingerprint
        || record.new_certificate.fingerprint != ContentDigest::parse(new)?
        || record.new_certificate.runner_id != record.runner_id
        || record.new_certificate.pool_id != record.pool_id
        || record.certificate_chain_pem.is_empty()
        || record.certificate_chain_pem.len() > MAX_RUNNER_CERTIFICATE_CHAIN_BYTES
    {
        return Err(ControlPlaneError::CorruptState(
            "runner certificate rotation journal is inconsistent".to_owned(),
        ));
    }
    Ok(Some(record))
}

pub(in crate::store) fn runner_certificate_rotation_tx(
    transaction: &Transaction<'_>,
    old_fingerprint: &ContentDigest,
) -> Result<Option<RunnerCertificateRotationRecord>, ControlPlaneError> {
    runner_certificate_rotation_conn(transaction, old_fingerprint)
}

pub(in crate::store) fn authorize_runner_certificate_tx(
    transaction: &Transaction<'_>,
    fingerprint: &ContentDigest,
    now_unix_ms: u64,
) -> Result<AuthenticatedRunnerCertificate, ControlPlaneError> {
    let certificate = runner_certificate_by_fingerprint_tx(transaction, fingerprint)?
        .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
    if certificate.status == RunnerCertificateStatus::Revoked
        || now_unix_ms < certificate.not_before_unix_ms
        || now_unix_ms >= certificate.not_after_unix_ms
        || (certificate.status == RunnerCertificateStatus::Overlap
            && certificate
                .overlap_until_unix_ms
                .is_none_or(|deadline| now_unix_ms >= deadline))
    {
        return Err(ControlPlaneError::RunnerCertificateUnauthorized);
    }
    let runner = persisted_runner_tx(transaction, &certificate.runner_id)?;
    if runner.runner.pool_id != certificate.pool_id
        || matches!(
            runner.runner.status,
            RunnerStatus::Revoked | RunnerStatus::Quarantined
        )
    {
        return Err(ControlPlaneError::RunnerCertificateUnauthorized);
    }
    let pool_status: String = transaction
        .query_row(
            "SELECT status FROM runner_pools WHERE id = ?1",
            [&certificate.pool_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
    if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
        return Err(ControlPlaneError::RunnerCertificateUnauthorized);
    }
    Ok(AuthenticatedRunnerCertificate {
        runner,
        certificate,
    })
}

pub(in crate::store) fn insert_runner_certificate_tx(
    transaction: &Transaction<'_>,
    certificate: &RunnerCertificateRecord,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "INSERT INTO runner_certificates
         (fingerprint, runner_id, pool_id, serial_hex, not_before_unix_ms,
          not_after_unix_ms, status, issued_unix_ms, overlap_until_unix_ms,
          revoked_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            certificate.fingerprint.as_str(),
            certificate.runner_id,
            certificate.pool_id,
            certificate.serial_hex,
            to_i64(certificate.not_before_unix_ms)?,
            to_i64(certificate.not_after_unix_ms)?,
            runner_certificate_status_name(certificate.status),
            to_i64(certificate.issued_unix_ms)?,
            certificate.overlap_until_unix_ms.map(to_i64).transpose()?,
            certificate.revoked_unix_ms.map(to_i64).transpose()?,
        ],
    )?;
    Ok(())
}

pub(in crate::store) fn expire_runner_certificates_tx(
    transaction: &Transaction<'_>,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    transaction.execute(
        "UPDATE runner_certificates
         SET status = 'revoked', revoked_unix_ms = ?1
         WHERE status != 'revoked'
           AND (not_after_unix_ms <= ?1
                OR (status = 'overlap' AND overlap_until_unix_ms <= ?1))",
        [to_i64(now_unix_ms)?],
    )?;
    Ok(())
}

pub(in crate::store) fn persisted_runner_tx(
    transaction: &Transaction<'_>,
    runner_id: &str,
) -> Result<PersistedRunner, ControlPlaneError> {
    transaction
        .query_row(
            "SELECT runner_json, created_unix_ms, updated_unix_ms
             FROM runners WHERE id = ?1",
            [runner_id],
            |row| {
                Ok(PersistedRunner {
                    runner: json_column(row, 0)?,
                    created_unix_ms: u64_column(row, 1, "created_unix_ms")?,
                    updated_unix_ms: u64_column(row, 2, "updated_unix_ms")?,
                })
            },
        )
        .optional()?
        .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)
}

pub(in crate::store) fn enrollment_token_hash(token: &str) -> ContentDigest {
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_HASH_DOMAIN);
    hasher.update(token.as_bytes());
    ContentDigest::parse(format!("sha256:{}", hex::encode(hasher.finalize())))
        .expect("SHA-256 output is always a valid content digest")
}

impl ControlPlane {
    pub fn authenticate_runner_certificate(
        &self,
        fingerprint: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedRunnerCertificate, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire_runner_certificates_tx(&transaction, now_unix_ms)?;
        let authorization = authorize_runner_certificate_tx(&transaction, fingerprint, now_unix_ms);
        transaction.commit()?;
        authorization
    }

    /// Rotate only from the exact currently-active certificate. The previous
    /// certificate remains authorized for the bounded overlap and any older
    /// overlap certificate is revoked in the same transaction.
    #[cfg(test)]
    pub fn rotate_runner_certificate(
        &self,
        authenticated_fingerprint: &ContentDigest,
        runner_id: &str,
        certificate: &RunnerCertificateRecord,
        now_unix_ms: u64,
        overlap_millis: u64,
    ) -> Result<RunnerCertificateRecord, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        validate_new_runner_certificate(certificate, now_unix_ms)?;
        if overlap_millis == 0
            || certificate.runner_id != runner_id
            || certificate.fingerprint == *authenticated_fingerprint
        {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }
        let requested_overlap_until =
            now_unix_ms
                .checked_add(overlap_millis)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "certificate overlap deadline",
                })?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire_runner_certificates_tx(&transaction, now_unix_ms)?;
        let current =
            runner_certificate_by_fingerprint_tx(&transaction, authenticated_fingerprint)?
                .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
        if current.runner_id != runner_id
            || current.pool_id != certificate.pool_id
            || current.status != RunnerCertificateStatus::Active
            || now_unix_ms < current.not_before_unix_ms
            || now_unix_ms >= current.not_after_unix_ms
        {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        let runner = persisted_runner_tx(&transaction, runner_id)?;
        if runner.runner.pool_id != current.pool_id
            || matches!(
                runner.runner.status,
                RunnerStatus::Revoked | RunnerStatus::Quarantined
            )
        {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        let pool_status: String = transaction
            .query_row(
                "SELECT status FROM runner_pools WHERE id = ?1",
                [&current.pool_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }

        transaction.execute(
            "UPDATE runner_certificates
             SET status = 'revoked', revoked_unix_ms = ?2
             WHERE runner_id = ?1 AND status = 'overlap'",
            params![runner_id, to_i64(now_unix_ms)?],
        )?;
        let overlap_until = requested_overlap_until.min(current.not_after_unix_ms);
        let changed = transaction.execute(
            "UPDATE runner_certificates
             SET status = 'overlap', overlap_until_unix_ms = ?2
             WHERE fingerprint = ?1 AND status = 'active'",
            params![authenticated_fingerprint.as_str(), to_i64(overlap_until)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        insert_runner_certificate_tx(&transaction, certificate)?;
        transaction.commit()?;
        Ok(certificate.clone())
    }

    /// Journal and apply a certificate rotation exactly once. A retry with
    /// the same old fingerprint and CSR returns the original public response,
    /// even after the old certificate has entered overlap or was revoked.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_runner_certificate_idempotent(
        &self,
        authenticated_fingerprint: &ContentDigest,
        runner_id: &str,
        csr_digest: &ContentDigest,
        certificate: &RunnerCertificateRecord,
        certificate_chain_pem: &[u8],
        now_unix_ms: u64,
        overlap_millis: u64,
    ) -> Result<IdempotentResult<RunnerCertificateRotationRecord>, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        if certificate_chain_pem.is_empty()
            || certificate_chain_pem.len() > MAX_RUNNER_CERTIFICATE_CHAIN_BYTES
        {
            return Err(ControlPlaneError::InvalidRunnerCertificateChain);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            runner_certificate_rotation_tx(&transaction, authenticated_fingerprint)?
        {
            if existing.runner_id != runner_id || existing.csr_digest != *csr_digest {
                return Err(ControlPlaneError::RunnerCertificateRotationConflict);
            }
            transaction.commit()?;
            return Ok(IdempotentResult {
                value: existing,
                replayed: true,
            });
        }

        validate_new_runner_certificate(certificate, now_unix_ms)?;
        if overlap_millis == 0
            || certificate.runner_id != runner_id
            || certificate.fingerprint == *authenticated_fingerprint
        {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }
        let requested_overlap_until =
            now_unix_ms
                .checked_add(overlap_millis)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "certificate overlap deadline",
                })?;
        expire_runner_certificates_tx(&transaction, now_unix_ms)?;
        let current =
            runner_certificate_by_fingerprint_tx(&transaction, authenticated_fingerprint)?
                .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
        if current.runner_id != runner_id
            || current.pool_id != certificate.pool_id
            || current.status != RunnerCertificateStatus::Active
            || now_unix_ms < current.not_before_unix_ms
            || now_unix_ms >= current.not_after_unix_ms
        {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        let runner = persisted_runner_tx(&transaction, runner_id)?;
        if runner.runner.pool_id != current.pool_id
            || matches!(
                runner.runner.status,
                RunnerStatus::Revoked | RunnerStatus::Quarantined
            )
        {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        let (pool_status, tenant_id): (String, String) = transaction
            .query_row(
                "SELECT status, tenant_id FROM runner_pools WHERE id = ?1",
                [&current.pool_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }

        transaction.execute(
            "UPDATE runner_certificates
             SET status = 'revoked', revoked_unix_ms = ?2
             WHERE runner_id = ?1 AND status = 'overlap'",
            params![runner_id, to_i64(now_unix_ms)?],
        )?;
        let overlap_until = requested_overlap_until.min(current.not_after_unix_ms);
        let changed = transaction.execute(
            "UPDATE runner_certificates
             SET status = 'overlap', overlap_until_unix_ms = ?2
             WHERE fingerprint = ?1 AND status = 'active'",
            params![authenticated_fingerprint.as_str(), to_i64(overlap_until)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::RunnerCertificateUnauthorized);
        }
        insert_runner_certificate_tx(&transaction, certificate)?;
        let record = RunnerCertificateRotationRecord {
            old_fingerprint: authenticated_fingerprint.clone(),
            runner_id: runner_id.to_owned(),
            pool_id: current.pool_id,
            csr_digest: csr_digest.clone(),
            new_certificate: certificate.clone(),
            certificate_chain_pem: certificate_chain_pem.to_vec(),
            created_unix_ms: now_unix_ms,
        };
        transaction.execute(
            "INSERT INTO runner_certificate_rotations
             (old_fingerprint, runner_id, pool_id, csr_digest, new_fingerprint,
              new_certificate_json, certificate_chain_pem, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.old_fingerprint.as_str(),
                record.runner_id,
                record.pool_id,
                record.csr_digest.as_str(),
                record.new_certificate.fingerprint.as_str(),
                serde_json::to_string(&record.new_certificate)?,
                record.certificate_chain_pem,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id,
                actor: AuditPrincipal {
                    kind: "runner_certificate".to_owned(),
                    id: authenticated_fingerprint.to_string(),
                },
                action: "runner.certificate.rotate".to_owned(),
                resource: AuditResource {
                    kind: "runner".to_owned(),
                    id: runner_id.to_owned(),
                },
                result: "success".to_owned(),
                request_id: format!("runner-rotation:{}", csr_digest.as_str()),
                decision_id: None,
                metadata: BTreeMap::from([
                    (
                        "csr_digest".to_owned(),
                        AuditValue::String(csr_digest.to_string()),
                    ),
                    (
                        "new_fingerprint".to_owned(),
                        AuditValue::String(certificate.fingerprint.to_string()),
                    ),
                ]),
            },
        )?;
        transaction.commit()?;
        Ok(IdempotentResult {
            value: record,
            replayed: false,
        })
    }

    pub fn runner_certificate_rotation(
        &self,
        old_fingerprint: &ContentDigest,
    ) -> Result<Option<RunnerCertificateRotationRecord>, ControlPlaneError> {
        let connection = self.connection()?;
        runner_certificate_rotation_conn(&connection, old_fingerprint)
    }

    pub fn runner_certificate(
        &self,
        fingerprint: &ContentDigest,
    ) -> Result<RunnerCertificateRecord, ControlPlaneError> {
        let connection = self.connection()?;
        runner_certificate_by_fingerprint(&connection, fingerprint)?
            .ok_or(ControlPlaneError::RunnerCertificateUnauthorized)
    }
}
