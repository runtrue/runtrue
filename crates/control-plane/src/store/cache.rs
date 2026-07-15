use super::*;

impl ControlPlane {
    pub fn record_cache_trust_generation(
        &self,
        record: &CacheTrustGenerationRecord,
        expected_store_generation: Option<u64>,
    ) -> Result<bool, ControlPlaneError> {
        validate_cache_generation(record)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let replayed =
            record_cache_generation_tx(&transaction, record, expected_store_generation, None)?;
        transaction.commit()?;
        Ok(replayed)
    }

    /// Persist an evidence-bearing promotion intent after resolving the source
    /// through tenant predicates. A cross-tenant source is indistinguishable
    /// from an unknown source.
    pub fn create_cache_promotion_idempotent(
        &self,
        record: &CachePromotionRecord,
    ) -> Result<bool, ControlPlaneError> {
        validate_cache_promotion(record)?;
        if record.state != CachePromotionState::Pending
            || record.promoted_cache_entry_id.is_some()
            || record.completed_unix_ms.is_some()
            || record.last_error.is_some()
        {
            return Err(ControlPlaneError::InvalidInput(
                "new cache promotion must be pending",
            ));
        }
        let expected_subject = cache_promotion_subject_digest(record)?;
        if expected_subject != record.subject_digest {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source: Option<(String, String)> = transaction
            .query_row(
                "SELECT key_material_digest, trust_domain_json
                 FROM cache_trust_generations
                 WHERE cache_entry_id = ?1 AND tenant_id = ?2 AND repository_id = ?3",
                params![
                    record.source_cache_entry_id,
                    record.tenant_id,
                    record.repository_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if source.is_none() {
            return Err(not_found(
                "cache promotion source",
                &record.source_cache_entry_id,
            ));
        }
        let existing = transaction
            .query_row(
                "SELECT id, subject_digest, tenant_id, repository_id, source_cache_entry_id,
                        target_identity_digest, target_trust_domain_json,
                        expected_target_cache_entry_id, evidence_digest, evidence_json, state,
                        promoted_cache_entry_id, created_unix_ms, completed_unix_ms, last_error
                 FROM cache_promotion_journal WHERE id = ?1",
                [&record.id],
                cache_promotion_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == *record {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO cache_promotion_journal
             (id, subject_digest, tenant_id, repository_id, source_cache_entry_id,
              target_identity_digest, target_trust_domain_json,
              expected_target_cache_entry_id, evidence_digest, evidence_json, state,
              created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11)",
            params![
                record.id,
                record.subject_digest.as_str(),
                record.tenant_id,
                record.repository_id,
                record.source_cache_entry_id,
                record.target_identity_digest.as_str(),
                serde_json::to_string(&canonicalize_json(record.target_trust_domain.clone()))?,
                record.expected_target_cache_entry_id,
                record.evidence_digest.as_str(),
                serde_json::to_string(&canonicalize_json(record.evidence.clone()))?,
                to_i64(record.created_unix_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(false)
    }

    /// Finish an exact promotion after the cache store has published it. This
    /// transaction records the generation, head, journal result, and audit
    /// event together. A lost response replays the same completed record.
    pub fn complete_cache_promotion(
        &self,
        tenant_id: &str,
        promotion_id: &str,
        promoted: &CacheTrustGenerationRecord,
        now_unix_ms: u64,
    ) -> Result<bool, ControlPlaneError> {
        validate_text("cache promotion tenant", tenant_id)?;
        validate_text("cache promotion id", promotion_id)?;
        validate_cache_generation(promoted)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let journal = transaction
            .query_row(
                "SELECT id, subject_digest, tenant_id, repository_id, source_cache_entry_id,
                        target_identity_digest, target_trust_domain_json,
                        expected_target_cache_entry_id, evidence_digest, evidence_json, state,
                        promoted_cache_entry_id, created_unix_ms, completed_unix_ms, last_error
                 FROM cache_promotion_journal WHERE id = ?1 AND tenant_id = ?2",
                params![promotion_id, tenant_id],
                cache_promotion_row,
            )
            .optional()?
            .ok_or_else(|| not_found("cache promotion", promotion_id))?;
        if journal.state == CachePromotionState::Completed {
            if journal.promoted_cache_entry_id.as_deref() == Some(&promoted.cache_entry_id)
                && cache_generation_tx(&transaction, tenant_id, &promoted.cache_entry_id)?.as_ref()
                    == Some(promoted)
            {
                transaction.commit()?;
                return Ok(true);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if journal.state != CachePromotionState::Pending
            || promoted.tenant_id != journal.tenant_id
            || promoted.repository_id != journal.repository_id
            || promoted.identity_digest != journal.target_identity_digest
            || promoted.source_cache_entry_id.as_deref()
                != Some(journal.source_cache_entry_id.as_str())
            || promoted.promotion_evidence_digest.as_ref() != Some(&journal.evidence_digest)
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let replayed = record_cache_generation_tx(
            &transaction,
            promoted,
            journal
                .expected_target_cache_entry_id
                .as_ref()
                .map(|_| promoted.generation.saturating_sub(1)),
            journal.expected_target_cache_entry_id.as_deref(),
        )?;
        transaction.execute(
            "UPDATE cache_promotion_journal
             SET state = 'completed', promoted_cache_entry_id = ?2, completed_unix_ms = ?3
             WHERE id = ?1 AND state = 'pending'",
            params![promotion_id, promoted.cache_entry_id, to_i64(now_unix_ms)?],
        )?;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "source_cache_entry_id".to_owned(),
            AuditValue::String(journal.source_cache_entry_id),
        );
        metadata.insert(
            "promoted_cache_entry_id".to_owned(),
            AuditValue::String(promoted.cache_entry_id.clone()),
        );
        metadata.insert(
            "evidence_digest".to_owned(),
            AuditValue::Digest(journal.evidence_digest),
        );
        append_audit_event_tx(
            &transaction,
            &self.installation_id,
            AuditEventData {
                observed_unix_ms: now_unix_ms,
                tenant_id: tenant_id.to_owned(),
                actor: AuditPrincipal {
                    kind: "worker".to_owned(),
                    id: "cache-promotion".to_owned(),
                },
                action: "cache.promote".to_owned(),
                resource: AuditResource {
                    kind: "cache-promotion".to_owned(),
                    id: promotion_id.to_owned(),
                },
                result: "completed".to_owned(),
                request_id: promotion_id.to_owned(),
                decision_id: Some(journal.subject_digest.to_string()),
                metadata,
            },
        )?;
        transaction.commit()?;
        Ok(replayed)
    }

    pub fn cache_promotion(
        &self,
        tenant_id: &str,
        promotion_id: &str,
    ) -> Result<CachePromotionRecord, ControlPlaneError> {
        validate_text("cache promotion tenant", tenant_id)?;
        validate_text("cache promotion id", promotion_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, subject_digest, tenant_id, repository_id, source_cache_entry_id,
                        target_identity_digest, target_trust_domain_json,
                        expected_target_cache_entry_id, evidence_digest, evidence_json, state,
                        promoted_cache_entry_id, created_unix_ms, completed_unix_ms, last_error
                 FROM cache_promotion_journal WHERE id = ?1 AND tenant_id = ?2",
                params![promotion_id, tenant_id],
                cache_promotion_row,
            )
            .optional()?
            .ok_or_else(|| not_found("cache promotion", promotion_id))
    }

    pub fn cache_trust_generation(
        &self,
        tenant_id: &str,
        cache_entry_id: &str,
    ) -> Result<CacheTrustGenerationRecord, ControlPlaneError> {
        validate_text("cache generation tenant", tenant_id)?;
        validate_text("cache entry id", cache_entry_id)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT cache_entry_id, tenant_id, repository_id, identity_digest,
                        key_material_digest, key_material_json, trust_domain_json, generation,
                        manifest_digest, tree_manifest_digest, fencing_generation,
                        source_cache_entry_id, promotion_evidence_digest, created_unix_ms
                 FROM cache_trust_generations
                 WHERE cache_entry_id = ?1 AND tenant_id = ?2",
                params![cache_entry_id, tenant_id],
                cache_generation_row,
            )
            .optional()?
            .ok_or_else(|| not_found("cache generation", cache_entry_id))
    }

    /// Record a bounded cache decision. Changed replay conflicts, preventing a
    /// caller from rewriting a prior hit/miss or trust-scope observation.
    pub fn record_cache_access_observation(
        &self,
        observation: &CacheAccessObservation,
    ) -> Result<bool, ControlPlaneError> {
        validate_cache_observation(observation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM jobs j
                JOIN runs r ON r.id = j.run_id
                JOIN repositories p ON p.id = r.repository_id
                WHERE j.id = ?1 AND j.run_id = ?2 AND r.repository_id = ?3
                  AND p.tenant_id = ?4
             )",
            params![
                observation.job_id,
                observation.run_id,
                observation.repository_id,
                observation.tenant_id,
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let encoded_candidates = serde_json::to_string(&observation.candidates)?;
        let encoded_scope = observation
            .selected_trust_domain
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO cache_access_observations
             (id, tenant_id, repository_id, run_id, job_id, job_attempt, step_id,
              operation, key_material_digest, candidates_json, outcome,
              selected_trust_domain_json, selected_generation, transferred_bytes,
              latency_ms, breaker_state, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17)",
            params![
                observation.id,
                observation.tenant_id,
                observation.repository_id,
                observation.run_id,
                observation.job_id,
                i64::from(observation.job_attempt),
                observation.step_id,
                observation.operation,
                observation.key_material_digest.as_str(),
                encoded_candidates,
                observation.outcome,
                encoded_scope,
                observation.selected_generation.map(to_i64).transpose()?,
                to_i64(observation.transferred_bytes)?,
                to_i64(observation.latency_ms)?,
                observation.breaker_state,
                to_i64(observation.created_unix_ms)?,
            ],
        )?;
        let stored: CacheAccessObservation = transaction.query_row(
            "SELECT id, tenant_id, repository_id, run_id, job_id, job_attempt, step_id,
                    operation, key_material_digest, candidates_json, outcome,
                    selected_trust_domain_json, selected_generation, transferred_bytes,
                    latency_ms, breaker_state, created_unix_ms
             FROM cache_access_observations WHERE id = ?1",
            [&observation.id],
            cache_observation_row,
        )?;
        if stored != *observation {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.commit()?;
        Ok(inserted == 0)
    }

    pub fn cache_trust_metrics(
        &self,
        tenant_id: &str,
    ) -> Result<CacheTrustMetrics, ControlPlaneError> {
        validate_text("cache metrics tenant", tenant_id)?;
        let connection = self.connection()?;
        let count = |sql: &str, value: &str| -> Result<u64, ControlPlaneError> {
            let count: i64 =
                connection.query_row(sql, params![tenant_id, value], |row| row.get(0))?;
            from_i64("cache metric", count)
        };
        let observations = "SELECT COUNT(*) FROM cache_access_observations
                            WHERE tenant_id = ?1 AND outcome = ?2";
        let promotions = "SELECT COUNT(*) FROM cache_promotion_journal
                          WHERE tenant_id = ?1 AND state = ?2";
        Ok(CacheTrustMetrics {
            hits: count(observations, "hit")?,
            misses: count(observations, "miss")?,
            bypassed_health: count(observations, "bypassed-health")?,
            saves: count(observations, "saved")?,
            save_failures: count(observations, "save-failed")?,
            denied: count(observations, "denied")?,
            promotions_pending: count(promotions, "pending")?,
            promotions_completed: count(promotions, "completed")?,
            promotions_failed: count(promotions, "failed")?,
        })
    }
}

fn validate_cache_generation(record: &CacheTrustGenerationRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("cache entry id", record.cache_entry_id.as_str()),
        ("cache tenant", record.tenant_id.as_str()),
        ("cache repository", record.repository_id.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if record.generation == 0
        || record.fencing_generation == 0
        || !record.key_material.is_object()
        || !record.trust_domain.is_object()
        || record.source_cache_entry_id.is_some() != record.promotion_evidence_digest.is_some()
    {
        return Err(ControlPlaneError::InvalidInput(
            "cache generation metadata is invalid",
        ));
    }
    if let Some(source) = &record.source_cache_entry_id {
        validate_text("cache promotion source", source)?;
    }
    Ok(())
}

fn record_cache_generation_tx(
    transaction: &Transaction<'_>,
    record: &CacheTrustGenerationRecord,
    expected_store_generation: Option<u64>,
    expected_head_cache_entry_id: Option<&str>,
) -> Result<bool, ControlPlaneError> {
    let repository: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM repositories WHERE id = ?1 AND tenant_id = ?2)",
        params![record.repository_id, record.tenant_id],
        |row| row.get(0),
    )?;
    if !repository {
        return Err(not_found("cache repository", &record.repository_id));
    }
    if let Some(existing) =
        cache_generation_tx(transaction, &record.tenant_id, &record.cache_entry_id)?
    {
        if existing == *record {
            return Ok(true);
        }
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    let current: Option<(String, u64)> = transaction
        .query_row(
            "SELECT cache_entry_id, generation FROM cache_trust_current_heads
             WHERE identity_digest = ?1",
            [record.identity_digest.as_str()],
            |row| Ok((row.get(0)?, u64_column(row, 1, "cache head generation")?)),
        )
        .optional()?;
    let current_generation = current.as_ref().map(|value| value.1);
    let expected_next = expected_store_generation.map_or(1, |value| value.saturating_add(1));
    if current_generation.is_some() && current_generation != expected_store_generation
        || expected_head_cache_entry_id.is_some()
            && current.as_ref().map(|value| value.0.as_str()) != expected_head_cache_entry_id
        || record.generation != expected_next
    {
        return Err(ControlPlaneError::IdempotencyConflict);
    }
    if let Some(source_id) = &record.source_cache_entry_id {
        let source = cache_generation_tx(transaction, &record.tenant_id, source_id)?
            .ok_or_else(|| not_found("cache promotion source", source_id))?;
        if source.repository_id != record.repository_id
            || source.key_material_digest != record.key_material_digest
            || source.tree_manifest_digest != record.tree_manifest_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    transaction.execute(
        "INSERT INTO cache_trust_generations
         (cache_entry_id, tenant_id, repository_id, identity_digest, key_material_digest,
          key_material_json, trust_domain_json, generation, manifest_digest, tree_manifest_digest,
          fencing_generation, source_cache_entry_id, promotion_evidence_digest,
          created_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            record.cache_entry_id,
            record.tenant_id,
            record.repository_id,
            record.identity_digest.as_str(),
            record.key_material_digest.as_str(),
            serde_json::to_string(&canonicalize_json(record.key_material.clone()))?,
            serde_json::to_string(&canonicalize_json(record.trust_domain.clone()))?,
            to_i64(record.generation)?,
            record.manifest_digest.as_str(),
            record.tree_manifest_digest.as_str(),
            to_i64(record.fencing_generation)?,
            record.source_cache_entry_id,
            record
                .promotion_evidence_digest
                .as_ref()
                .map(ContentDigest::as_str),
            to_i64(record.created_unix_ms)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO cache_trust_current_heads
         (identity_digest, cache_entry_id, generation, updated_unix_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(identity_digest) DO UPDATE SET
           cache_entry_id = excluded.cache_entry_id,
           generation = excluded.generation,
           updated_unix_ms = excluded.updated_unix_ms",
        params![
            record.identity_digest.as_str(),
            record.cache_entry_id,
            to_i64(record.generation)?,
            to_i64(record.created_unix_ms)?,
        ],
    )?;
    Ok(false)
}

fn cache_generation_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    cache_entry_id: &str,
) -> Result<Option<CacheTrustGenerationRecord>, ControlPlaneError> {
    Ok(transaction
        .query_row(
            "SELECT cache_entry_id, tenant_id, repository_id, identity_digest,
                    key_material_digest, key_material_json, trust_domain_json, generation, manifest_digest,
                    tree_manifest_digest, fencing_generation, source_cache_entry_id,
                    promotion_evidence_digest, created_unix_ms
             FROM cache_trust_generations
             WHERE cache_entry_id = ?1 AND tenant_id = ?2",
            params![cache_entry_id, tenant_id],
            cache_generation_row,
        )
        .optional()?)
}

fn cache_generation_row(row: &Row<'_>) -> rusqlite::Result<CacheTrustGenerationRecord> {
    Ok(CacheTrustGenerationRecord {
        cache_entry_id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        identity_digest: digest_column(row, 3)?,
        key_material_digest: digest_column(row, 4)?,
        key_material: json_column(row, 5)?,
        trust_domain: json_column(row, 6)?,
        generation: u64_column(row, 7, "cache generation")?,
        manifest_digest: digest_column(row, 8)?,
        tree_manifest_digest: digest_column(row, 9)?,
        fencing_generation: u64_column(row, 10, "cache fencing generation")?,
        source_cache_entry_id: row.get(11)?,
        promotion_evidence_digest: optional_digest_column(row, 12)?,
        created_unix_ms: u64_column(row, 13, "cache generation creation")?,
    })
}

fn validate_cache_promotion(record: &CachePromotionRecord) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("cache promotion id", record.id.as_str()),
        ("cache promotion tenant", record.tenant_id.as_str()),
        ("cache promotion repository", record.repository_id.as_str()),
        (
            "cache promotion source",
            record.source_cache_entry_id.as_str(),
        ),
    ] {
        validate_text(field, value)?;
    }
    if !record.target_trust_domain.is_object() || !record.evidence.is_object() {
        return Err(ControlPlaneError::InvalidInput(
            "cache promotion evidence and trust domain must be objects",
        ));
    }
    if let Some(expected) = &record.expected_target_cache_entry_id {
        validate_text("expected cache promotion head", expected)?;
    }
    Ok(())
}

pub fn cache_promotion_subject_digest(
    record: &CachePromotionRecord,
) -> Result<ContentDigest, ControlPlaneError> {
    let bytes = serde_json::to_vec(&(
        "runtrue.cache-promotion.v1",
        &record.tenant_id,
        &record.repository_id,
        &record.source_cache_entry_id,
        &record.target_identity_digest,
        canonicalize_json(record.target_trust_domain.clone()),
        &record.expected_target_cache_entry_id,
        &record.evidence_digest,
        canonicalize_json(record.evidence.clone()),
    ))?;
    Ok(ContentDigest::sha256(bytes))
}

fn cache_promotion_row(row: &Row<'_>) -> rusqlite::Result<CachePromotionRecord> {
    let state: String = row.get(10)?;
    let state = match state.as_str() {
        "pending" => CachePromotionState::Pending,
        "completed" => CachePromotionState::Completed,
        "failed" => CachePromotionState::Failed,
        _ => {
            return Err(conversion(
                10,
                DecodeError("invalid cache promotion state".to_owned()),
            ))
        }
    };
    Ok(CachePromotionRecord {
        id: row.get(0)?,
        subject_digest: digest_column(row, 1)?,
        tenant_id: row.get(2)?,
        repository_id: row.get(3)?,
        source_cache_entry_id: row.get(4)?,
        target_identity_digest: digest_column(row, 5)?,
        target_trust_domain: json_column(row, 6)?,
        expected_target_cache_entry_id: row.get(7)?,
        evidence_digest: digest_column(row, 8)?,
        evidence: json_column(row, 9)?,
        state,
        promoted_cache_entry_id: row.get(11)?,
        created_unix_ms: u64_column(row, 12, "cache promotion creation")?,
        completed_unix_ms: optional_u64_column(row, 13, "cache promotion completion")?,
        last_error: row.get(14)?,
    })
}

fn validate_cache_observation(value: &CacheAccessObservation) -> Result<(), ControlPlaneError> {
    for (field, text) in [
        ("cache observation id", value.id.as_str()),
        ("cache observation tenant", value.tenant_id.as_str()),
        ("cache observation repository", value.repository_id.as_str()),
        ("cache observation run", value.run_id.as_str()),
        ("cache observation job", value.job_id.as_str()),
        ("cache observation step", value.step_id.as_str()),
    ] {
        validate_text(field, text)?;
    }
    if value.job_attempt == 0
        || !matches!(value.operation.as_str(), "restore" | "save")
        || !matches!(
            value.outcome.as_str(),
            "hit" | "miss" | "bypassed-health" | "saved" | "save-failed" | "denied"
        )
        || !matches!(
            value.breaker_state.as_str(),
            "closed" | "open" | "half-open"
        )
        || value.candidates.len() > 16
        || value
            .candidates
            .iter()
            .any(|candidate| !candidate.is_object())
        || value
            .selected_trust_domain
            .as_ref()
            .is_some_and(|scope| !scope.is_object())
    {
        return Err(ControlPlaneError::InvalidInput(
            "cache observation metadata is invalid",
        ));
    }
    Ok(())
}

fn cache_observation_row(row: &Row<'_>) -> rusqlite::Result<CacheAccessObservation> {
    Ok(CacheAccessObservation {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        repository_id: row.get(2)?,
        run_id: row.get(3)?,
        job_id: row.get(4)?,
        job_attempt: u32::try_from(row.get::<_, i64>(5)?)
            .map_err(|error| conversion(5, DecodeError(error.to_string())))?,
        step_id: row.get(6)?,
        operation: row.get(7)?,
        key_material_digest: digest_column(row, 8)?,
        candidates: json_column(row, 9)?,
        outcome: row.get(10)?,
        selected_trust_domain: row
            .get::<_, Option<String>>(11)?
            .map(|value| serde_json::from_str(&value).map_err(|error| conversion(11, error)))
            .transpose()?,
        selected_generation: optional_u64_column(row, 12, "cache selected generation")?,
        transferred_bytes: u64_column(row, 13, "cache transferred bytes")?,
        latency_ms: u64_column(row, 14, "cache latency")?,
        breaker_state: row.get(15)?,
        created_unix_ms: u64_column(row, 16, "cache observation creation")?,
    })
}
