use super::*;

pub(in crate::store) fn validate_enrollment_token(token: &str) -> Result<(), ControlPlaneError> {
    if token.len() != ENROLLMENT_TOKEN_BYTES * 2
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ControlPlaneError::InvalidEnrollmentToken);
    }
    Ok(())
}

pub(in crate::store) fn validate_usable_enrollment_token(
    record: &EnrollmentTokenRecord,
    now_unix_ms: u64,
) -> Result<(), ControlPlaneError> {
    if record.consumed_unix_ms.is_some() {
        return Err(ControlPlaneError::EnrollmentTokenConsumed);
    }
    if now_unix_ms >= record.expires_unix_ms {
        return Err(ControlPlaneError::EnrollmentTokenExpired);
    }
    Ok(())
}

pub(in crate::store) fn enrollment_token_by_hash(
    connection: &Connection,
    token_hash: &ContentDigest,
) -> Result<Option<EnrollmentTokenRecord>, ControlPlaneError> {
    connection
        .query_row(
            "SELECT id, pool_id, created_unix_ms, expires_unix_ms, consumed_unix_ms
             FROM enrollment_tokens WHERE token_hash = ?1",
            [token_hash.as_str()],
            |row| {
                Ok(EnrollmentTokenRecord {
                    id: row.get(0)?,
                    pool_id: row.get(1)?,
                    created_unix_ms: u64_column(row, 2, "created_unix_ms")?,
                    expires_unix_ms: u64_column(row, 3, "expires_unix_ms")?,
                    consumed_unix_ms: optional_u64_column(row, 4, "consumed_unix_ms")?,
                })
            },
        )
        .optional()
        .map_err(ControlPlaneError::from)
}

impl ControlPlane {
    pub fn create_enrollment_token(
        &self,
        pool_id: &str,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<IssuedEnrollmentToken, ControlPlaneError> {
        if expires_unix_ms <= now_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "enrollment expiry must be in the future",
            ));
        }
        let mut raw = [0_u8; ENROLLMENT_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut raw)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let token = hex::encode(raw);
        raw.zeroize();
        let token_hash = enrollment_token_hash(&token);
        let mut id_bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let id = format!("enroll-{}", hex::encode(id_bytes));
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pool_status: String = transaction
            .query_row(
                "SELECT status FROM runner_pools WHERE id = ?1",
                [pool_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", pool_id))?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
        }
        transaction.execute(
            "INSERT INTO enrollment_tokens
             (id, pool_id, token_hash, created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                pool_id,
                token_hash.as_str(),
                to_i64(now_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(IssuedEnrollmentToken {
            metadata: EnrollmentTokenRecord {
                id,
                pool_id: pool_id.to_owned(),
                created_unix_ms: now_unix_ms,
                expires_unix_ms,
                consumed_unix_ms: None,
            },
            token: EnrollmentToken::new(token),
        })
    }

    pub fn create_enrollment_token_idempotent(
        &self,
        idempotency_key: &str,
        pool_id: &str,
        lifetime_seconds: u64,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<EnrollmentTokenIssueResult, ControlPlaneError> {
        validate_idempotency_key(idempotency_key)?;
        validate_text("runner pool id", pool_id)?;
        let expected_expiry = lifetime_seconds
            .checked_mul(1000)
            .and_then(|delta| now_unix_ms.checked_add(delta))
            .ok_or(ControlPlaneError::IntegerRange {
                field: "enrollment expiry",
            })?;
        if lifetime_seconds == 0 || expires_unix_ms != expected_expiry {
            return Err(ControlPlaneError::InvalidInput(
                "enrollment lifetime and expiry do not match",
            ));
        }
        let operation = format!("runner-pool.enrollment-token.create:{pool_id}");
        let request_hash = hash_serializable(&(pool_id, lifetime_seconds))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_hash, resource_id)) =
            idempotency_tx(&transaction, &operation, idempotency_key)?
        {
            require_same_idempotency(&stored_hash, &request_hash)?;
            let metadata = transaction
                .query_row(
                    "SELECT id, pool_id, created_unix_ms, expires_unix_ms, consumed_unix_ms
                     FROM enrollment_tokens WHERE id = ?1",
                    [&resource_id],
                    |row| {
                        Ok(EnrollmentTokenRecord {
                            id: row.get(0)?,
                            pool_id: row.get(1)?,
                            created_unix_ms: u64_column(row, 2, "created_unix_ms")?,
                            expires_unix_ms: u64_column(row, 3, "expires_unix_ms")?,
                            consumed_unix_ms: optional_u64_column(row, 4, "consumed_unix_ms")?,
                        })
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ControlPlaneError::CorruptState(
                        "idempotent enrollment token is missing".to_owned(),
                    )
                })?;
            transaction.commit()?;
            return Ok(EnrollmentTokenIssueResult::Replayed(metadata));
        }
        let pool_status: String = transaction
            .query_row(
                "SELECT status FROM runner_pools WHERE id = ?1",
                [pool_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", pool_id))?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
        }

        let mut raw = [0_u8; ENROLLMENT_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut raw)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let token = EnrollmentToken::new(hex::encode(raw));
        raw.zeroize();
        let token_hash = enrollment_token_hash(token.expose());
        let mut id_bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let id = format!("enroll-{}", hex::encode(id_bytes));
        transaction.execute(
            "INSERT INTO enrollment_tokens
             (id, pool_id, token_hash, created_unix_ms, expires_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                pool_id,
                token_hash.as_str(),
                to_i64(now_unix_ms)?,
                to_i64(expires_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO idempotency_records
             (operation, idempotency_key, request_hash, resource_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                idempotency_key,
                request_hash.as_str(),
                id,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(EnrollmentTokenIssueResult::Issued(IssuedEnrollmentToken {
            metadata: EnrollmentTokenRecord {
                id,
                pool_id: pool_id.to_owned(),
                created_unix_ms: now_unix_ms,
                expires_unix_ms,
                consumed_unix_ms: None,
            },
            token,
        }))
    }

    pub fn consume_enrollment_token(
        &self,
        token: &str,
        now_unix_ms: u64,
    ) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
        validate_enrollment_token(token)?;
        let token_hash = enrollment_token_hash(token);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw = transaction
            .query_row(
                "SELECT id, pool_id, created_unix_ms, expires_unix_ms, consumed_unix_ms
                 FROM enrollment_tokens WHERE token_hash = ?1",
                [token_hash.as_str()],
                |row| {
                    Ok(EnrollmentTokenRecord {
                        id: row.get(0)?,
                        pool_id: row.get(1)?,
                        created_unix_ms: u64_column(row, 2, "created_unix_ms")?,
                        expires_unix_ms: u64_column(row, 3, "expires_unix_ms")?,
                        consumed_unix_ms: optional_u64_column(row, 4, "consumed_unix_ms")?,
                    })
                },
            )
            .optional()?
            .ok_or(ControlPlaneError::InvalidEnrollmentToken)?;
        if raw.consumed_unix_ms.is_some() {
            return Err(ControlPlaneError::EnrollmentTokenConsumed);
        }
        if now_unix_ms >= raw.expires_unix_ms {
            return Err(ControlPlaneError::EnrollmentTokenExpired);
        }
        let changed = transaction.execute(
            "UPDATE enrollment_tokens SET consumed_unix_ms = ?2
             WHERE id = ?1 AND consumed_unix_ms IS NULL",
            params![raw.id, to_i64(now_unix_ms)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::EnrollmentTokenConsumed);
        }
        transaction.commit()?;
        Ok(EnrollmentTokenRecord {
            consumed_unix_ms: Some(now_unix_ms),
            ..raw
        })
    }

    /// Validate an enrollment bearer and return its pool binding without
    /// consuming it. Callers must still use `complete_runner_enrollment`,
    /// which repeats these checks and consumes the bearer atomically with the
    /// runner and certificate inserts.
    pub fn inspect_enrollment_token(
        &self,
        token: &str,
        now_unix_ms: u64,
    ) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
        validate_enrollment_token(token)?;
        let token_hash = enrollment_token_hash(token);
        let connection = self.connection()?;
        let record = enrollment_token_by_hash(&connection, &token_hash)?
            .ok_or(ControlPlaneError::InvalidEnrollmentToken)?;
        validate_usable_enrollment_token(&record, now_unix_ms)?;
        let pool_status: String = connection
            .query_row(
                "SELECT status FROM runner_pools WHERE id = ?1",
                [&record.pool_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", &record.pool_id))?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
        }
        Ok(record)
    }

    /// Consume a one-time pool-bound bearer and persist the runner identity
    /// and its initial certificate in one immediate transaction.
    pub fn complete_runner_enrollment(
        &self,
        token: &str,
        runner: &RunnerRecord,
        certificate: &RunnerCertificateRecord,
        inventory_digest: &ContentDigest,
        now_unix_ms: u64,
    ) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
        let posture_digest = authoritative_runner_posture_digest(runner, inventory_digest)?;
        self.complete_runner_enrollment_bound(
            token,
            runner,
            certificate,
            inventory_digest,
            &posture_digest,
            None,
            now_unix_ms,
        )
    }

    pub fn replay_runner_enrollment(
        &self,
        token: &str,
        request_digest: &ContentDigest,
    ) -> Result<Option<RunnerEnrollmentReplay>, ControlPlaneError> {
        validate_enrollment_token(token)?;
        let token_hash = enrollment_token_hash(token);
        let connection = self.connection()?;
        let Some(record) = enrollment_token_by_hash(&connection, &token_hash)? else {
            return Err(ControlPlaneError::InvalidEnrollmentToken);
        };
        let replay = connection
            .query_row(
                "SELECT request_digest,runner_id,pool_id,certificate_chain_pem,certificate_expires_unix_ms,authoritative_posture_digest,selected_protocol_version,created_unix_ms FROM runner_enrollment_replays WHERE enrollment_token_id=?1",
                [&record.id],
                |row| Ok(RunnerEnrollmentReplay {
                    request_digest: digest_column(row, 0)?,
                    runner_id: row.get(1)?,
                    pool_id: row.get(2)?,
                    certificate_chain_pem: row.get(3)?,
                    certificate_expires_unix_ms: u64_column(row, 4, "enrollment replay certificate expiry")?,
                    authoritative_posture_digest: digest_column(row, 5)?,
                    selected_protocol_version: row.get(6)?,
                    created_unix_ms: u64_column(row, 7, "enrollment replay creation")?,
                }),
            )
            .optional()?;
        match replay {
            Some(value) if &value.request_digest == request_digest => Ok(Some(value)),
            Some(_) => Err(ControlPlaneError::EnrollmentTokenConsumed),
            None => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_runner_enrollment_idempotent(
        &self,
        token: &str,
        request_digest: &ContentDigest,
        runner: &RunnerRecord,
        certificate: &RunnerCertificateRecord,
        certificate_chain_pem: &[u8],
        inventory_digest: &ContentDigest,
        selected_protocol_version: u32,
        now_unix_ms: u64,
    ) -> Result<RunnerEnrollmentReplay, ControlPlaneError> {
        if certificate_chain_pem.is_empty() || certificate_chain_pem.len() > 256 * 1024 {
            return Err(ControlPlaneError::InvalidInput(
                "runner enrollment certificate chain is empty or exceeds its bound",
            ));
        }
        let posture_digest = authoritative_runner_posture_digest(runner, inventory_digest)?;
        self.complete_runner_enrollment_bound(
            token,
            runner,
            certificate,
            inventory_digest,
            &posture_digest,
            Some((
                request_digest,
                certificate_chain_pem,
                selected_protocol_version,
            )),
            now_unix_ms,
        )?;
        self.replay_runner_enrollment(token, request_digest)?
            .ok_or_else(|| ControlPlaneError::CorruptState("enrollment replay is missing".into()))
    }

    fn complete_runner_enrollment_bound(
        &self,
        token: &str,
        runner: &RunnerRecord,
        certificate: &RunnerCertificateRecord,
        inventory_digest: &ContentDigest,
        posture_digest: &ContentDigest,
        replay: Option<(&ContentDigest, &[u8], u32)>,
        now_unix_ms: u64,
    ) -> Result<EnrollmentTokenRecord, ControlPlaneError> {
        validate_enrollment_token(token)?;
        validate_runner_record(runner)?;
        validate_new_runner_certificate(certificate, now_unix_ms)?;
        if !matches!(
            runner.status,
            RunnerStatus::Offline | RunnerStatus::Probationary
        ) || runner.id != certificate.runner_id
            || runner.pool_id != certificate.pool_id
        {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }

        let token_hash = enrollment_token_hash(token);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = enrollment_token_by_hash(&transaction, &token_hash)?
            .ok_or(ControlPlaneError::InvalidEnrollmentToken)?;
        if record.consumed_unix_ms.is_some() {
            if let Some((request_digest, _, _)) = replay {
                let existing: Option<String> = transaction
                    .query_row(
                        "SELECT request_digest FROM runner_enrollment_replays WHERE enrollment_token_id=?1",
                        [&record.id],
                        |row| row.get(0),
                    )
                    .optional()?;
                return match existing {
                    Some(value) if value == request_digest.as_str() => Ok(record),
                    _ => Err(ControlPlaneError::EnrollmentTokenConsumed),
                };
            }
        }
        validate_usable_enrollment_token(&record, now_unix_ms)?;
        if record.pool_id != runner.pool_id {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }
        let software_replacement: Option<(String,String,String,u64)> = transaction.query_row(
            "SELECT c.replacement_id,c.source_runner_id,c.source_posture_digest,c.generation
             FROM runner_software_update_claims c
             JOIN runner_replacements r ON r.id=c.replacement_id AND r.state='claim-issued'
             JOIN runner_pool_update_policies p ON p.pool_id=c.pool_id AND p.version=c.policy_version
                AND p.enabled=1 AND p.paused=0 AND p.release_id=c.release_id
             JOIN runner_update_releases u ON u.id=c.release_id AND u.revoked_unix_ms IS NULL
             WHERE c.enrollment_token_id=?1 AND c.consumed_unix_ms IS NULL
               AND c.canceled_unix_ms IS NULL AND c.expires_unix_ms>?2",
            params![record.id,to_i64(now_unix_ms)?],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,u64_column(row,3,"replacement generation")?)),
        ).optional()?;
        if (software_replacement.is_some()) != (runner.status == RunnerStatus::Probationary) {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }
        if let Some((_, source_runner_id, expected_posture, _)) = &software_replacement {
            let current_posture: String = transaction.query_row(
                "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=?1",
                [source_runner_id],
                |row| row.get(0),
            )?;
            if &current_posture != expected_posture {
                return Err(ControlPlaneError::InvalidInput(
                    "software update source posture changed",
                ));
            }
        }
        let (pool_status, pool_tenant, pool_region): (String, String, Option<String>) = transaction
            .query_row(
                "SELECT status, tenant_id, region FROM runner_pools WHERE id = ?1",
                [&record.pool_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| not_found("runner pool", &record.pool_id))?;
        if parse_runner_pool_status(&pool_status)? != RunnerPoolStatus::Active {
            return Err(ControlPlaneError::InvalidInput("runner pool is disabled"));
        }
        if runner.tenant_id != pool_tenant {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }
        if pool_region
            .as_ref()
            .is_some_and(|region| runner.region.as_ref() != Some(region))
        {
            return Err(ControlPlaneError::CertificateIdentityMismatch);
        }

        transaction.execute(
            "INSERT INTO runners
             (id, pool_id, status, runner_json, created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                runner.id,
                runner.pool_id,
                runner_status_name(runner.status),
                serde_json::to_string(runner)?,
                to_i64(now_unix_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO runner_enrollment_postures
             (runner_id, inventory_digest, posture_digest, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                runner.id,
                inventory_digest.as_str(),
                posture_digest.as_str(),
                to_i64(now_unix_ms)?,
            ],
        )?;
        insert_runner_certificate_tx(&transaction, certificate)?;
        let changed = transaction.execute(
            "UPDATE enrollment_tokens SET consumed_unix_ms = ?2
             WHERE id = ?1 AND consumed_unix_ms IS NULL",
            params![record.id, to_i64(now_unix_ms)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::EnrollmentTokenConsumed);
        }
        let launch_claim: Option<String> = transaction
            .query_row(
                "SELECT fleet_request_id FROM runner_launch_claims
                 WHERE enrollment_token_id = ?1",
                [&record.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(fleet_request_id) = launch_claim {
            let claim_changed = transaction.execute(
                "UPDATE runner_launch_claims
                 SET consumed_unix_ms = ?2, runner_id = ?3
                 WHERE enrollment_token_id = ?1 AND consumed_unix_ms IS NULL
                   AND runner_id IS NULL",
                params![record.id, to_i64(now_unix_ms)?, runner.id],
            )?;
            let request_changed = transaction.execute(
                "UPDATE runner_fleet_requests
                 SET state = 'enrolled', runner_id = ?2, updated_unix_ms = ?3
                 WHERE id = ?1 AND state = 'bootstrapping'",
                params![fleet_request_id, runner.id, to_i64(now_unix_ms)?],
            )?;
            if claim_changed != 1 || request_changed != 1 {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "runner launch claim",
                    from: "bootstrapping",
                    to: "enrolled",
                });
            }
        }
        if let Some((replacement_id, _, _, generation)) = software_replacement {
            let claim_changed=transaction.execute(
                "UPDATE runner_software_update_claims SET consumed_unix_ms=?2,runner_id=?3
                 WHERE enrollment_token_id=?1 AND consumed_unix_ms IS NULL AND canceled_unix_ms IS NULL",
                params![record.id,to_i64(now_unix_ms)?,runner.id])?;
            let replacement_changed = transaction.execute(
                "UPDATE runner_replacements SET target_runner_id=?2,target_posture_digest=?3,
                    state='probationary',updated_unix_ms=?4
                 WHERE id=?1 AND generation=?5 AND state='claim-issued'",
                params![
                    replacement_id,
                    runner.id,
                    posture_digest.as_str(),
                    to_i64(now_unix_ms)?,
                    to_i64(generation)?
                ],
            )?;
            if claim_changed != 1 || replacement_changed != 1 {
                return Err(ControlPlaneError::InvalidTransition {
                    entity: "software update claim",
                    from: "claim-issued",
                    to: "probationary",
                });
            }
        }
        if let Some((request_digest, certificate_chain_pem, selected_protocol_version)) = replay {
            transaction.execute(
                "INSERT INTO runner_enrollment_replays(enrollment_token_id,request_digest,runner_id,pool_id,certificate_chain_pem,certificate_expires_unix_ms,authoritative_posture_digest,selected_protocol_version,created_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![record.id,request_digest.as_str(),runner.id,runner.pool_id,certificate_chain_pem,to_i64(certificate.not_after_unix_ms)?,posture_digest.as_str(),i64::from(selected_protocol_version),to_i64(now_unix_ms)?],
            )?;
        }
        transaction.commit()?;
        Ok(EnrollmentTokenRecord {
            consumed_unix_ms: Some(now_unix_ms),
            ..record
        })
    }

    /// Validate an Open-session inventory against the immutable enrollment
    /// binding and return the posture derived from the current durable record.
    pub fn validate_runner_inventory_binding(
        &self,
        runner_id: &str,
        inventory_digest: &ContentDigest,
    ) -> Result<ContentDigest, ControlPlaneError> {
        validate_text("runner id", runner_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted = persisted_runner_tx(&transaction, runner_id)?;
        let binding: Option<(String, String)> = transaction
            .query_row(
                "SELECT inventory_digest, posture_digest
                 FROM runner_enrollment_postures WHERE runner_id = ?1",
                [runner_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match binding {
            Some((expected_inventory, expected_posture)) => {
                let expected_inventory = ContentDigest::parse(expected_inventory)?;
                let authoritative =
                    authoritative_runner_posture_digest(&persisted.runner, &expected_inventory)?;
                if expected_inventory != *inventory_digest
                    || ContentDigest::parse(expected_posture)? != authoritative
                {
                    return Err(ControlPlaneError::RunnerInventoryMismatch);
                }
                transaction.commit()?;
                Ok(authoritative)
            }
            None => {
                // A schema-7 runner has no full binary/version/capability
                // binding. Never let reconnect input establish that identity.
                let mut runner = persisted.runner;
                runner.status = RunnerStatus::Quarantined;
                transaction.execute(
                    "UPDATE runners SET status = 'quarantined', runner_json = ?2
                     WHERE id = ?1",
                    params![runner_id, serde_json::to_string(&runner)?,],
                )?;
                transaction.commit()?;
                Err(ControlPlaneError::RunnerReenrollmentRequired)
            }
        }
    }
}
