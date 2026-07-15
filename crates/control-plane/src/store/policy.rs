use super::*;
// ---- Migration 23: canonical policy evidence and active-state CAS. ----

pub(in crate::store) fn load_policy_draft_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    draft_id: &str,
) -> Result<Option<PolicyBundleDraft>, ControlPlaneError> {
    type DurablePolicyDraft = (String, String, Vec<u8>, String, Option<String>, Option<i64>);
    let durable: Option<DurablePolicyDraft> = transaction
        .query_row(
            "SELECT author_id, policy_digest, draft_json, status,
                    simulation_digest, activated_policy_epoch
             FROM policy_bundle_drafts
             WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id, draft_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    durable
        .map(
            |(author_id, policy_digest, bytes, status, simulation_digest, activated_epoch)| {
                if bytes.len() > MAX_R9_POLICY_RECORD_BYTES {
                    return Err(ControlPlaneError::CorruptState(
                        "policy draft exceeds its durable bound".to_owned(),
                    ));
                }
                let draft: PolicyBundleDraft = serde_json::from_slice(&bytes)?;
                draft.verify()?;
                if draft.tenant_id != tenant_id
                    || draft.id != draft_id
                    || draft.author_id != author_id
                    || draft.digest.as_str() != policy_digest
                    || policy_draft_status_name(draft.status) != status
                    || draft.simulation_digest.as_ref().map(ContentDigest::as_str)
                        != simulation_digest.as_deref()
                    || draft.activated_policy_epoch
                        != activated_epoch
                            .map(|value| from_i64("activated policy epoch", value))
                            .transpose()?
                {
                    return Err(ControlPlaneError::CorruptState(
                        "policy draft durable binding changed".to_owned(),
                    ));
                }
                Ok(draft)
            },
        )
        .transpose()
}

pub(in crate::store) fn load_policy_state_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
) -> Result<(ActivePolicyBundleState, u64), ControlPlaneError> {
    type DurablePolicyState = (
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
        Vec<u8>,
        i64,
    );
    let row: Option<DurablePolicyState> = transaction
        .query_row(
            "SELECT policy_epoch, decision_cache_generation, active_draft_id,
                    active_policy_digest, state_digest, state_json, version
             FROM tenant_policy_states WHERE tenant_id = ?1",
            [tenant_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        policy_epoch,
        cache_generation,
        active_draft_id,
        active_digest,
        stored_digest,
        bytes,
        version,
    )) = row
    else {
        return Ok((ActivePolicyBundleState::new(tenant_id.to_owned())?, 0));
    };
    if bytes.len() > MAX_R9_POLICY_RECORD_BYTES {
        return Err(ControlPlaneError::CorruptState(
            "active policy state exceeds its durable bound".to_owned(),
        ));
    }
    let state: ActivePolicyBundleState = serde_json::from_slice(&bytes)?;
    if state.tenant_id != tenant_id {
        return Err(ControlPlaneError::CorruptState(
            "active policy state tenant changed".to_owned(),
        ));
    }
    let digest = r9_record_digest(b"runtrue.active-policy-state.v1\0", &bytes);
    if state.policy_epoch != from_i64("policy epoch", policy_epoch)?
        || state.decision_cache_generation
            != from_i64("policy decision cache generation", cache_generation)?
        || state.active.as_ref().map(|active| active.draft_id.as_str())
            != active_draft_id.as_deref()
        || state.active.as_ref().map(|active| active.digest.as_str()) != active_digest.as_deref()
        || digest.as_str() != stored_digest
    {
        return Err(ControlPlaneError::CorruptState(
            "active policy state durable binding changed".to_owned(),
        ));
    }
    drop(state.snapshot()?);
    Ok((state, from_i64("policy state version", version)?))
}

pub(in crate::store) fn policy_draft_status_name(status: PolicyBundleDraftStatus) -> &'static str {
    match status {
        PolicyBundleDraftStatus::Draft => "draft",
        PolicyBundleDraftStatus::Simulated => "simulated",
        PolicyBundleDraftStatus::Shadow => "shadow",
        PolicyBundleDraftStatus::Activated => "activated",
        PolicyBundleDraftStatus::Retired => "retired",
    }
}

pub(in crate::store) fn require_active_policy_actor_tx(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    actor_id: &str,
) -> Result<(), ControlPlaneError> {
    let active: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM tenant_memberships m
         JOIN human_users u ON u.id = m.user_id
         WHERE m.tenant_id = ?1 AND m.user_id = ?2
           AND m.status = 'active' AND u.status = 'active')",
        params![tenant_id, actor_id],
        |row| row.get(0),
    )?;
    if !active {
        return Err(not_found("active policy actor membership", actor_id));
    }
    Ok(())
}

pub(in crate::store) fn validate_r9_audit_metadata(
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    validate_r9_audit_text(&audit.actor_id)?;
    validate_r9_audit_text(&audit.correlation_id)
}

pub(in crate::store) fn store_policy_state_tx(
    transaction: &Transaction<'_>,
    state: &ActivePolicyBundleState,
    previous_version: u64,
    audit: &R9AuditMetadata,
) -> Result<(), ControlPlaneError> {
    drop(state.snapshot()?);
    let state_bytes = r9_json_bytes(state, MAX_R9_POLICY_RECORD_BYTES)?;
    let state_digest = r9_record_digest(b"runtrue.active-policy-state.v1\0", &state_bytes);
    let next_version = previous_version
        .checked_add(1)
        .ok_or(ControlPlaneError::IntegerRange {
            field: "policy state version",
        })?;
    let active_draft_id = state.active.as_ref().map(|active| active.draft_id.as_str());
    let active_digest = state.active.as_ref().map(|active| active.digest.as_str());
    if previous_version == 0 {
        transaction.execute(
            "INSERT INTO tenant_policy_states
             (tenant_id, policy_epoch, decision_cache_generation, active_draft_id,
              active_policy_digest, state_digest, state_json, version, actor_id,
              audit_correlation_id, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)",
            params![
                state.tenant_id,
                to_i64(state.policy_epoch)?,
                to_i64(state.decision_cache_generation)?,
                active_draft_id,
                active_digest,
                state_digest.as_str(),
                state_bytes,
                audit.actor_id,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
    } else {
        let changed = transaction.execute(
            "UPDATE tenant_policy_states SET policy_epoch = ?2,
                decision_cache_generation = ?3, active_draft_id = ?4,
                active_policy_digest = ?5, state_digest = ?6, state_json = ?7,
                version = ?8, actor_id = ?9, audit_correlation_id = ?10,
                updated_unix_ms = ?11 WHERE tenant_id = ?1 AND version = ?12",
            params![
                state.tenant_id,
                to_i64(state.policy_epoch)?,
                to_i64(state.decision_cache_generation)?,
                active_draft_id,
                active_digest,
                state_digest.as_str(),
                state_bytes,
                to_i64(next_version)?,
                audit.actor_id,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?,
                to_i64(previous_version)?
            ],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
    }
    Ok(())
}

impl ControlPlane {
    pub fn persist_policy_draft(
        &self,
        draft: &PolicyBundleDraft,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        draft.verify()?;
        validate_r9_audit_metadata(audit)?;
        if draft.status != PolicyBundleDraftStatus::Draft
            || draft.author_id != audit.actor_id
            || audit.occurred_unix_ms < draft.created_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "new policy draft lacks exact author or draft state",
            ));
        }
        let bytes = r9_json_bytes(draft, MAX_R9_POLICY_RECORD_BYTES)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &draft.tenant_id)?;
        require_active_policy_actor_tx(&transaction, &draft.tenant_id, &draft.author_id)?;
        if let Some(existing) = load_policy_draft_tx(&transaction, &draft.tenant_id, &draft.id)? {
            if existing == *draft {
                transaction.commit()?;
                return Ok(false);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO policy_bundle_drafts
             (id, tenant_id, author_id, policy_digest, draft_json, status,
              simulation_digest, activated_policy_epoch, audit_correlation_id,
              created_unix_ms, updated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'draft', NULL, NULL, ?6, ?7, ?8)",
            params![
                draft.id,
                draft.tenant_id,
                draft.author_id,
                draft.digest.as_str(),
                bytes,
                audit.correlation_id,
                to_i64(draft.created_unix_ms)?,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn persist_policy_simulation(
        &self,
        draft: &PolicyBundleDraft,
        report: &PolicySimulationReport,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        draft.verify()?;
        report.verify()?;
        validate_r9_audit_metadata(audit)?;
        if draft.status != PolicyBundleDraftStatus::Simulated
            || draft.simulation_digest.as_ref() != Some(&report.report_digest)
            || draft.digest != report.policy_digest
            || report.results.len()
                != report
                    .stored_case_count
                    .saturating_add(report.caller_case_count)
            || report.stored_case_count > 1024
            || report.caller_case_count > 128
        {
            return Err(ControlPlaneError::InvalidInput(
                "policy simulation does not bind the stored draft",
            ));
        }
        let draft_bytes = r9_json_bytes(draft, MAX_R9_POLICY_RECORD_BYTES)?;
        let report_bytes = r9_json_bytes(report, MAX_R9_POLICY_RECORD_BYTES)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &draft.tenant_id)?;
        require_active_policy_actor_tx(&transaction, &draft.tenant_id, &audit.actor_id)?;
        let existing = load_policy_draft_tx(&transaction, &draft.tenant_id, &draft.id)?
            .ok_or_else(|| not_found("policy draft", &draft.id))?;
        if existing.digest != draft.digest
            || existing.author_id != draft.author_id
            || !matches!(
                existing.status,
                PolicyBundleDraftStatus::Draft | PolicyBundleDraftStatus::Simulated
            )
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let existing_report: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT report_json FROM policy_simulation_reports
                 WHERE tenant_id = ?1 AND draft_id = ?2 AND report_digest = ?3",
                params![draft.tenant_id, draft.id, report.report_digest.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_report) = existing_report {
            if existing_report == report_bytes && existing == *draft {
                transaction.commit()?;
                return Ok(false);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO policy_simulation_reports
             (tenant_id, draft_id, report_digest, corpus_digest, report_json,
              stored_case_count, caller_case_count, evaluation_error_count,
              expectation_mismatch_count, actor_id, audit_correlation_id, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                draft.tenant_id,
                draft.id,
                report.report_digest.as_str(),
                report.corpus_digest.as_str(),
                report_bytes,
                to_i64(u64::try_from(report.stored_case_count).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "stored simulation count",
                    }
                })?)?,
                to_i64(u64::try_from(report.caller_case_count).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "caller simulation count",
                    }
                })?)?,
                to_i64(u64::try_from(report.evaluation_error_count).map_err(|_| {
                    ControlPlaneError::IntegerRange {
                        field: "simulation error count",
                    }
                })?)?,
                to_i64(
                    u64::try_from(report.expectation_mismatch_count).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "simulation mismatch count",
                        }
                    })?
                )?,
                audit.actor_id,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.execute(
            "UPDATE policy_bundle_drafts SET draft_json = ?3, status = 'simulated',
                simulation_digest = ?4, audit_correlation_id = ?5,
                updated_unix_ms = ?6 WHERE tenant_id = ?1 AND id = ?2",
            params![
                draft.tenant_id,
                draft.id,
                draft_bytes,
                report.report_digest.as_str(),
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn persist_policy_shadow(
        &self,
        draft: &PolicyBundleDraft,
        report: Option<&PolicyShadowReport>,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        draft.verify()?;
        validate_r9_audit_metadata(audit)?;
        if draft.status != PolicyBundleDraftStatus::Shadow {
            return Err(ControlPlaneError::InvalidInput(
                "policy shadow record requires shadow draft state",
            ));
        }
        let draft_bytes = r9_json_bytes(draft, MAX_R9_POLICY_RECORD_BYTES)?;
        let report_bytes = report
            .map(|report| r9_json_bytes(report, MAX_R9_POLICY_RECORD_BYTES))
            .transpose()?;
        let report_digest = report_bytes
            .as_ref()
            .map(|bytes| r9_record_digest(b"runtrue.policy-shadow-report.v1\0", bytes));
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &draft.tenant_id)?;
        require_active_policy_actor_tx(&transaction, &draft.tenant_id, &audit.actor_id)?;
        let existing = load_policy_draft_tx(&transaction, &draft.tenant_id, &draft.id)?
            .ok_or_else(|| not_found("policy draft", &draft.id))?;
        if existing.digest != draft.digest
            || existing.author_id != draft.author_id
            || !matches!(
                existing.status,
                PolicyBundleDraftStatus::Simulated | PolicyBundleDraftStatus::Shadow
            )
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if let Some(report) = report {
            if report.shadow_policy_digest != draft.digest
                || report.results.is_empty()
                || report.results.len() > 512
            {
                return Err(ControlPlaneError::InvalidInput(
                    "policy shadow report does not bind the draft",
                ));
            }
            let (state, _) = load_policy_state_tx(&transaction, &draft.tenant_id)?;
            if report.policy_epoch != state.policy_epoch
                || report.active_policy_digest
                    != state.active.as_ref().map(|active| active.digest.clone())
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let report_bytes = report_bytes.as_ref().expect("report bytes exist");
            let report_digest = report_digest.as_ref().expect("report digest exists");
            let existing_report: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT report_json FROM policy_shadow_reports
                     WHERE tenant_id = ?1 AND draft_id = ?2 AND report_digest = ?3",
                    params![draft.tenant_id, draft.id, report_digest.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_report) = existing_report {
                if existing_report == *report_bytes && existing == *draft {
                    transaction.commit()?;
                    return Ok(false);
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.execute(
                "INSERT INTO policy_shadow_reports
                 (tenant_id, draft_id, report_digest, policy_epoch, report_json,
                  case_count, actor_id, audit_correlation_id, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    draft.tenant_id,
                    draft.id,
                    report_digest.as_str(),
                    to_i64(report.policy_epoch)?,
                    report_bytes,
                    to_i64(u64::try_from(report.results.len()).map_err(|_| {
                        ControlPlaneError::IntegerRange {
                            field: "shadow case count",
                        }
                    })?)?,
                    audit.actor_id,
                    audit.correlation_id,
                    to_i64(audit.occurred_unix_ms)?
                ],
            )?;
        } else if existing == *draft {
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute(
            "UPDATE policy_bundle_drafts SET draft_json = ?3, status = 'shadow',
                audit_correlation_id = ?4, updated_unix_ms = ?5
             WHERE tenant_id = ?1 AND id = ?2",
            params![
                draft.tenant_id,
                draft.id,
                draft_bytes,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn activate_policy_bundle(
        &self,
        draft: &PolicyBundleDraft,
        state: &ActivePolicyBundleState,
        activation: &ActivatePolicyBundle,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        draft.verify()?;
        drop(state.snapshot()?);
        validate_r9_audit_metadata(audit)?;
        let Some(active) = &state.active else {
            return Err(ControlPlaneError::InvalidInput(
                "activated policy state has no active bundle",
            ));
        };
        if draft.status != PolicyBundleDraftStatus::Activated
            || state.tenant_id != draft.tenant_id
            || active.draft_id != draft.id
            || active.digest != draft.digest
            || active.simulation_digest != activation.simulation_digest
            || activation.draft_digest != draft.digest
            || active.approved_by != audit.actor_id
            || activation.approved_by != audit.actor_id
            || draft.author_id == audit.actor_id
            || audit.occurred_unix_ms != activation.approved_unix_ms
        {
            return Err(ControlPlaneError::InvalidInput(
                "policy activation evidence does not bind state, draft, and actor",
            ));
        }
        let draft_bytes = r9_json_bytes(draft, MAX_R9_POLICY_RECORD_BYTES)?;
        let activation_bytes = r9_json_bytes(activation, 256 * 1024)?;
        let activation_digest =
            r9_record_digest(b"runtrue.policy-activation.v1\0", &activation_bytes);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &draft.tenant_id)?;
        require_active_policy_actor_tx(&transaction, &draft.tenant_id, &audit.actor_id)?;
        let stored_draft = load_policy_draft_tx(&transaction, &draft.tenant_id, &draft.id)?
            .ok_or_else(|| not_found("policy draft", &draft.id))?;
        let existing_activation: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT activation_digest, activation_json FROM policy_activations
                 WHERE tenant_id = ?1 AND draft_id = ?2",
                params![draft.tenant_id, draft.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_digest, stored_bytes)) = existing_activation {
            let (stored_state, _) = load_policy_state_tx(&transaction, &draft.tenant_id)?;
            if stored_digest == activation_digest.as_str()
                && stored_bytes == activation_bytes
                && stored_draft == *draft
                && stored_state == *state
            {
                transaction.commit()?;
                return Ok(false);
            }
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        if stored_draft.status != PolicyBundleDraftStatus::Shadow
            || stored_draft.digest != draft.digest
            || stored_draft.simulation_digest != draft.simulation_digest
            || stored_draft.author_id == audit.actor_id
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let simulation_bytes: Vec<u8> = transaction
            .query_row(
                "SELECT report_json FROM policy_simulation_reports
                 WHERE tenant_id = ?1 AND draft_id = ?2 AND report_digest = ?3",
                params![
                    draft.tenant_id,
                    draft.id,
                    activation.simulation_digest.as_str()
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| not_found("eligible policy simulation", &draft.id))?;
        if simulation_bytes.len() > MAX_R9_POLICY_RECORD_BYTES {
            return Err(ControlPlaneError::CorruptState(
                "policy simulation exceeds its durable bound".to_owned(),
            ));
        }
        let simulation: PolicySimulationReport = serde_json::from_slice(&simulation_bytes)?;
        simulation.verify()?;
        if !simulation.activation_eligible()
            || simulation.policy_digest != draft.digest
            || simulation.report_digest != activation.simulation_digest
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        let (current, version) = load_policy_state_tx(&transaction, &draft.tenant_id)?;
        let next_epoch =
            current
                .policy_epoch
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "policy epoch",
                })?;
        let next_cache_generation = current.decision_cache_generation.checked_add(1).ok_or(
            ControlPlaneError::IntegerRange {
                field: "policy decision cache generation",
            },
        )?;
        if activation.expected_policy_epoch != current.policy_epoch
            || state.policy_epoch != next_epoch
            || state.decision_cache_generation != next_cache_generation
            || active.policy_epoch != next_epoch
            || state.emergency_denies != current.emergency_denies
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE policy_bundle_drafts SET draft_json = ?3, status = 'activated',
                activated_policy_epoch = ?4, audit_correlation_id = ?5,
                updated_unix_ms = ?6 WHERE tenant_id = ?1 AND id = ?2
                  AND status = 'shadow'",
            params![
                draft.tenant_id,
                draft.id,
                draft_bytes,
                to_i64(next_epoch)?,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        transaction.execute(
            "INSERT INTO policy_activations
             (tenant_id, draft_id, previous_policy_epoch, policy_epoch,
              activation_digest, policy_digest, simulation_digest, approval_id,
              approved_by, activation_json, audit_correlation_id, activated_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                draft.tenant_id,
                draft.id,
                to_i64(current.policy_epoch)?,
                to_i64(next_epoch)?,
                activation_digest.as_str(),
                draft.digest.as_str(),
                activation.simulation_digest.as_str(),
                activation.approval_id,
                activation.approved_by,
                activation_bytes,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        store_policy_state_tx(&transaction, state, version, audit)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn replace_emergency_denies(
        &self,
        state: &ActivePolicyBundleState,
        expected_cache_generation: u64,
        audit: &R9AuditMetadata,
    ) -> Result<bool, ControlPlaneError> {
        drop(state.snapshot()?);
        validate_r9_audit_metadata(audit)?;
        let denies_bytes = r9_json_bytes(&state.emergency_denies, MAX_R9_POLICY_RECORD_BYTES)?;
        let deny_digest = r9_record_digest(b"runtrue.emergency-denies.v1\0", &denies_bytes);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_r9_tenant_tx(&transaction, &state.tenant_id)?;
        require_active_policy_actor_tx(&transaction, &state.tenant_id, &audit.actor_id)?;
        let (current, version) = load_policy_state_tx(&transaction, &state.tenant_id)?;
        if current == *state {
            if expected_cache_generation != state.decision_cache_generation {
                let journal: Option<(i64, String, Vec<u8>)> = transaction
                    .query_row(
                        "SELECT previous_cache_generation, deny_digest, denies_json
                         FROM emergency_deny_replacements
                         WHERE tenant_id = ?1 AND cache_generation = ?2",
                        params![state.tenant_id, to_i64(state.decision_cache_generation)?],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((previous, stored_digest, stored_bytes)) = journal else {
                    return Err(ControlPlaneError::IdempotencyConflict);
                };
                if from_i64("previous cache generation", previous)? != expected_cache_generation
                    || stored_digest != deny_digest.as_str()
                    || stored_bytes != denies_bytes
                {
                    return Err(ControlPlaneError::IdempotencyConflict);
                }
            } else if state.decision_cache_generation != 0
                || state.emergency_denies != DenyFirstPolicy::default()
            {
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(false);
        }
        let next_generation = current.decision_cache_generation.checked_add(1).ok_or(
            ControlPlaneError::IntegerRange {
                field: "policy decision cache generation",
            },
        )?;
        if expected_cache_generation != current.decision_cache_generation
            || state.decision_cache_generation != next_generation
            || state.policy_epoch != current.policy_epoch
            || state.active != current.active
            || state.emergency_denies == current.emergency_denies
        {
            return Err(ControlPlaneError::IdempotencyConflict);
        }
        transaction.execute(
            "INSERT INTO emergency_deny_replacements
             (tenant_id, previous_cache_generation, cache_generation, deny_digest,
              denies_json, actor_id, audit_correlation_id, replaced_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                state.tenant_id,
                to_i64(current.decision_cache_generation)?,
                to_i64(next_generation)?,
                deny_digest.as_str(),
                denies_bytes,
                audit.actor_id,
                audit.correlation_id,
                to_i64(audit.occurred_unix_ms)?
            ],
        )?;
        store_policy_state_tx(&transaction, state, version, audit)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn active_policy_state(
        &self,
        tenant_id: &str,
    ) -> Result<ActivePolicyBundleState, ControlPlaneError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_r9_tenant_tx(&transaction, tenant_id)?;
        let (state, _) = load_policy_state_tx(&transaction, tenant_id)?;
        transaction.commit()?;
        Ok(state)
    }
}
