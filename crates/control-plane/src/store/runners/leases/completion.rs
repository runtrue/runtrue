// Lease completion and durable object-claim dependencies are explicit.
use super::super::{
    append_runner_broker_audit_tx, conclude_run_if_terminal_tx, expire_lease_with_state_tx,
    job_state_name, lease_conn, lease_hard_deadline_conn, lease_hard_deadline_tx, lease_state_name,
    lease_tx, params, revoke_runner_broker_state_tx, to_i64, transition_job_tx,
    validate_lease_fence_tx, validate_text, AuditValue, BTreeMap, BTreeSet, ContentDigest,
    ControlPlane, ControlPlaneError, CredentialTaintState, JobState, Lease, LeaseState,
    RunnerDataCommitKind, TransactionBehavior, MAX_RUNNER_COMPLETION_ARTIFACT_CLAIMS,
};
use rusqlite::OptionalExtension as _;

impl ControlPlane {
    /// Conservative aggregate used to gate Replay Bundle and Checkpoint
    /// publication. Runs without an explicit completion taint record are
    /// unknown and therefore fail closed.
    pub fn run_credential_taint(
        &self,
        run_id: &str,
    ) -> Result<CredentialTaintState, ControlPlaneError> {
        validate_text("run id", run_id)?;
        self.run(run_id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT l.terminal_credential_taint
             FROM leases l JOIN jobs j ON j.id = l.job_id
             WHERE j.run_id = ?1",
        )?;
        let values = statement.query_map([run_id], |row| row.get::<_, String>(0))?;
        let mut found = false;
        let mut aggregate = CredentialTaintState::None;
        for value in values {
            found = true;
            let value = value?;
            if value == "unobserved" {
                aggregate = CredentialTaintState::Unknown;
                continue;
            }
            match CredentialTaintState::parse(&value).map_err(|_| {
                ControlPlaneError::CorruptState(
                    "invalid terminal credential taint state".to_owned(),
                )
            })? {
                CredentialTaintState::CredentialReleased => {
                    return Ok(CredentialTaintState::CredentialReleased)
                }
                CredentialTaintState::Unknown => aggregate = CredentialTaintState::Unknown,
                CredentialTaintState::None => {}
            }
        }
        Ok(if found {
            aggregate
        } else {
            CredentialTaintState::Unknown
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_lease(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        result_digest: &ContentDigest,
        final_job_state: JobState,
        completed_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        self.complete_lease_with_objects(
            lease_id,
            runner_id,
            generation,
            epoch,
            result_digest,
            final_job_state,
            CredentialTaintState::Unknown,
            0,
            &[],
            &[],
            &[],
            completed_unix_ms,
        )
    }

    /// Verify typed artifact completion claims without changing lease, job, or
    /// completion state. Completed leases accept only the exact durable replay.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_runner_completion_artifact_claims(
        &self,
        lease_id: &str,
        runner_id: &str,
        fencing_generation: u64,
        installation_fencing_epoch: u64,
        job_attempt: u32,
        claims: &[(String, String)],
    ) -> Result<(), ControlPlaneError> {
        if validate_text("lease id", lease_id).is_err()
            || validate_text("runner id", runner_id).is_err()
            || fencing_generation == 0
            || installation_fencing_epoch == 0
            || claims.len() > MAX_RUNNER_COMPLETION_ARTIFACT_CLAIMS
            || (!claims.is_empty() && job_attempt == 0)
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let fence = i64::try_from(fencing_generation)
            .map_err(|_| ControlPlaneError::RunnerBrokerBindingMismatch)?;
        let epoch = i64::try_from(installation_fencing_epoch)
            .map_err(|_| ControlPlaneError::RunnerBrokerBindingMismatch)?;
        let mut object_ids = BTreeSet::new();
        let mut declaration_names = BTreeSet::new();
        for (object_id, declaration_name) in claims {
            if validate_text("artifact object id", object_id).is_err()
                || validate_text("artifact declaration name", declaration_name).is_err()
                || !object_ids.insert(object_id.as_str())
                || !declaration_names.insert(declaration_name.as_str())
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
        }

        type CompletionScope = (String, String, String, String, i64, String);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let scope: Option<CompletionScope> = transaction
            .query_row(
                "SELECT l.tenant_id, j.run_id, r.repository_id, l.job_id, j.attempt, l.state
                 FROM leases l JOIN jobs j ON j.id = l.job_id
                 JOIN runs r ON r.id = j.run_id
                 JOIN repositories repo ON repo.id = r.repository_id
                 JOIN job_fencing f ON f.job_id = j.id
                 CROSS JOIN installation_state i
                 WHERE l.id = ?1 AND l.runner_id = ?2
                   AND l.fencing_generation = ?3
                   AND l.installation_fencing_epoch = ?4
                   AND f.last_generation = ?3 AND i.singleton = 1
                   AND i.fencing_epoch = ?4 AND i.safe_mode = 0
                   AND repo.tenant_id = l.tenant_id
                   AND l.state IN ('active', 'cancel_requested', 'completed')",
                params![lease_id, runner_id, fence, epoch],
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
        let Some((tenant_id, run_id, repository_id, job_id, durable_attempt, lease_state)) = scope
        else {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        };
        if (job_attempt != 0 && i64::from(job_attempt) != durable_attempt)
            || (!claims.is_empty() && i64::from(job_attempt) != durable_attempt)
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }

        for (object_id, declaration_name) in claims {
            let exact: bool = transaction.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM runner_data_commits c
                   WHERE c.kind = 'artifact' AND c.object_id = ?1
                     AND c.output_name = ?2 AND c.tenant_id = ?3
                     AND c.repository_id = ?4 AND c.run_id = ?5
                     AND c.job_id = ?6 AND c.job_attempt = ?7
                     AND c.lease_id = ?8 AND c.fencing_generation = ?9
                 )",
                params![
                    object_id,
                    declaration_name,
                    tenant_id,
                    repository_id,
                    run_id,
                    job_id,
                    durable_attempt,
                    lease_id,
                    fence,
                ],
                |row| row.get(0),
            )?;
            if !exact {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
        }

        if lease_state == "completed" {
            let mut statement = transaction.prepare(
                "SELECT o.object_id, c.output_name FROM job_result_objects o
                 JOIN runner_data_commits c
                   ON c.kind = o.kind AND c.object_id = o.object_id
                 WHERE o.job_id = ?1 AND o.job_attempt = ?2 AND o.kind = 'artifact'
                   AND c.tenant_id = ?3 AND c.repository_id = ?4 AND c.run_id = ?5
                   AND c.job_id = ?1 AND c.job_attempt = ?2
                   AND c.lease_id = ?6 AND c.fencing_generation = ?7
                 ORDER BY o.ordinal",
            )?;
            let stored = statement
                .query_map(
                    params![
                        job_id,
                        durable_attempt,
                        tenant_id,
                        repository_id,
                        run_id,
                        lease_id,
                        fence,
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if stored.len() != claims.len()
                || stored.iter().zip(claims).any(
                    |((stored_id, stored_name), (object_id, declaration_name))| {
                        stored_id != object_id
                            || stored_name.as_deref() != Some(declaration_name.as_str())
                    },
                )
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
        }
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_lease_with_objects(
        &self,
        lease_id: &str,
        runner_id: &str,
        generation: u64,
        epoch: u64,
        result_digest: &ContentDigest,
        final_job_state: JobState,
        credential_taint: CredentialTaintState,
        job_attempt: u32,
        artifact_ids: &[String],
        cache_entry_ids: &[String],
        required_artifact_names: &[String],
        completed_unix_ms: u64,
    ) -> Result<Lease, ControlPlaneError> {
        if !final_job_state.is_terminal() {
            return Err(ControlPlaneError::InvalidInput(
                "lease completion requires a terminal job state",
            ));
        }
        let effective_taint = {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let lease =
                validate_lease_fence_tx(&transaction, lease_id, runner_id, generation, epoch)?;
            let stored_taint: String = transaction.query_row(
                "SELECT terminal_credential_taint FROM leases WHERE id = ?1",
                [lease_id],
                |row| row.get(0),
            )?;
            let (effective, downgrade) = match (stored_taint.as_str(), credential_taint) {
                ("unobserved", incoming) => (incoming, false),
                ("none", CredentialTaintState::None) => (CredentialTaintState::None, false),
                ("none", incoming) => (incoming, false),
                ("unknown", CredentialTaintState::CredentialReleased) => {
                    (CredentialTaintState::CredentialReleased, false)
                }
                ("unknown", CredentialTaintState::Unknown) => {
                    (CredentialTaintState::Unknown, false)
                }
                ("unknown", CredentialTaintState::None) => (CredentialTaintState::Unknown, true),
                ("credential_released", CredentialTaintState::CredentialReleased) => {
                    (CredentialTaintState::CredentialReleased, false)
                }
                ("credential_released", _) => (CredentialTaintState::CredentialReleased, true),
                _ => {
                    return Err(ControlPlaneError::CorruptState(
                        "invalid terminal credential taint state".to_owned(),
                    ))
                }
            };
            if downgrade {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            transaction.execute(
                "UPDATE leases SET terminal_credential_taint = ?2 WHERE id = ?1",
                params![lease_id, effective.as_str()],
            )?;
            if !effective.permits_replay_or_checkpoint() {
                transaction.execute(
                    "DELETE FROM runner_log_frames
                     WHERE execution_lease_id = ?1
                       AND redaction_state <> 'credential_taint_unredacted_operator_opt_in'",
                    [lease_id],
                )?;
                transaction.execute(
                    "DELETE FROM artifact_download_tickets
                     WHERE artifact_id IN (
                       SELECT artifact_id FROM artifacts_catalog WHERE job_id = ?1
                     )",
                    [&lease.job_id],
                )?;
                transaction.execute(
                    "UPDATE artifacts_catalog SET state = 'quarantined' WHERE job_id = ?1",
                    [&lease.job_id],
                )?;
                transaction.execute(
                    "DELETE FROM cache_trust_current_heads
                     WHERE cache_entry_id IN (
                       SELECT object_id FROM job_result_objects
                       WHERE job_id = ?1 AND kind = 'cache'
                     )",
                    [&lease.job_id],
                )?;
            }
            transaction.commit()?;
            effective
        };
        if !effective_taint.permits_replay_or_checkpoint()
            && (!artifact_ids.is_empty() || !cache_entry_ids.is_empty())
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = validate_lease_fence_tx(&transaction, lease_id, runner_id, generation, epoch)?;
        let current_taint: String = transaction.query_row(
            "SELECT terminal_credential_taint FROM leases WHERE id = ?1",
            [lease_id],
            |row| row.get(0),
        )?;
        if current_taint != effective_taint.as_str() {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let durable_job_attempt: u32 = transaction.query_row(
            "SELECT attempt FROM jobs WHERE id = ?1",
            [&lease.job_id],
            |row| row.get(0),
        )?;
        if job_attempt != 0 && job_attempt != durable_job_attempt {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let cancellation_requested: bool = transaction.query_row(
            "SELECT r.cancel_reason IS NOT NULL FROM jobs j
             JOIN runs r ON r.id = j.run_id WHERE j.id = ?1",
            [&lease.job_id],
            |row| row.get(0),
        )?;
        let final_job_state = if cancellation_requested {
            JobState::Canceled
        } else {
            final_job_state
        };
        let submitted_objects = [
            (RunnerDataCommitKind::Artifact, artifact_ids),
            (RunnerDataCommitKind::Cache, cache_entry_ids),
        ];
        let stored_objects =
            |kind: RunnerDataCommitKind| -> Result<Vec<String>, ControlPlaneError> {
                let mut statement = transaction.prepare(
                    "SELECT object_id FROM job_result_objects
                 WHERE job_id = ?1 AND job_attempt = ?2 AND kind = ?3 ORDER BY ordinal",
                )?;
                let rows = statement.query_map(
                    params![lease.job_id, i64::from(job_attempt), kind.as_str()],
                    |row| row.get(0),
                )?;
                rows.collect::<rusqlite::Result<_>>().map_err(Into::into)
            };
        if lease.state == LeaseState::Completed {
            let (stored_state, stored_taint): (Option<String>, String) = transaction.query_row(
                "SELECT terminal_job_state, terminal_credential_taint FROM leases WHERE id = ?1",
                [lease_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let objects_match = submitted_objects.iter().all(|(kind, submitted)| {
                stored_objects(*kind).is_ok_and(|stored| stored == **submitted)
            });
            if lease.terminal_result_digest.as_ref() == Some(result_digest)
                && stored_state.as_deref() == Some(job_state_name(final_job_state))
                && stored_taint == effective_taint.as_str()
                && objects_match
            {
                transaction.commit()?;
                return Ok(lease);
            }
            return Err(ControlPlaneError::ConflictingCompletion);
        }
        let hard_deadline = lease_hard_deadline_tx(&transaction, lease_id)?;
        if completed_unix_ms >= hard_deadline {
            expire_lease_with_state_tx(
                &transaction,
                &lease,
                if cancellation_requested {
                    JobState::Canceled
                } else {
                    JobState::TimedOut
                },
                completed_unix_ms,
            )?;
            conclude_run_if_terminal_tx(&transaction, &lease.job_id, completed_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseExpired);
        }
        if completed_unix_ms >= lease.expires_unix_ms {
            expire_lease_with_state_tx(
                &transaction,
                &lease,
                if cancellation_requested {
                    JobState::Canceled
                } else {
                    JobState::Lost
                },
                completed_unix_ms,
            )?;
            conclude_run_if_terminal_tx(&transaction, &lease.job_id, completed_unix_ms)?;
            transaction.commit()?;
            return Err(ControlPlaneError::LeaseExpired);
        }
        if !matches!(
            lease.state,
            LeaseState::Active | LeaseState::CancelRequested
        ) {
            return Err(ControlPlaneError::InvalidLeaseState {
                expected: "active or cancel_requested",
                actual: lease_state_name(lease.state),
            });
        }
        if (!artifact_ids.is_empty()
            || !cache_entry_ids.is_empty()
            || !required_artifact_names.is_empty())
            && job_attempt == 0
        {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        let mut artifact_names = BTreeSet::new();
        for (kind, object_ids) in submitted_objects {
            let mut seen = BTreeSet::new();
            for (ordinal, object_id) in object_ids.iter().enumerate() {
                validate_text("completion object id", object_id)?;
                if !seen.insert(object_id) {
                    return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                }
                let output_name: Option<String> = transaction
                    .query_row(
                        "SELECT output_name FROM runner_data_commits
                         WHERE kind = ?1 AND object_id = ?2
                           AND tenant_id = ?3 AND run_id = (SELECT run_id FROM jobs WHERE id = ?4)
                           AND job_id = ?4 AND job_attempt = ?5 AND lease_id = ?6
                           AND fencing_generation = ?7",
                        params![
                            kind.as_str(),
                            object_id,
                            lease.tenant_id,
                            lease.job_id,
                            i64::from(job_attempt),
                            lease.id,
                            to_i64(generation)?
                        ],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
                if kind == RunnerDataCommitKind::Artifact {
                    let name = output_name.ok_or(ControlPlaneError::RunnerBrokerBindingMismatch)?;
                    if !artifact_names.insert(name) {
                        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
                    }
                }
                transaction.execute(
                    "INSERT INTO job_result_objects(job_id, job_attempt, kind, object_id, ordinal)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        lease.job_id,
                        i64::from(job_attempt),
                        kind.as_str(),
                        object_id,
                        i64::try_from(ordinal).map_err(|_| ControlPlaneError::IntegerRange {
                            field: "completion object ordinal"
                        })?
                    ],
                )?;
            }
        }
        let required: BTreeSet<_> = required_artifact_names.iter().cloned().collect();
        if final_job_state == JobState::Succeeded && artifact_names != required {
            return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
        }
        transition_job_tx(
            &transaction,
            &lease.job_id,
            final_job_state,
            completed_unix_ms,
        )?;
        transaction.execute(
            "UPDATE leases SET state = 'completed', terminal_result_digest = ?2,
             terminal_job_state = ?3, completed_unix_ms = ?4 WHERE id = ?1",
            params![
                lease_id,
                result_digest.as_str(),
                job_state_name(final_job_state),
                to_i64(completed_unix_ms)?,
            ],
        )?;
        let (secret_revocations, oidc_revocations) = revoke_runner_broker_state_tx(
            &transaction,
            lease_id,
            generation,
            completed_unix_ms,
            "revoked",
        )?;
        if secret_revocations != 0 || oidc_revocations != 0 {
            append_runner_broker_audit_tx(
                &transaction,
                &self.installation_id,
                &lease.tenant_id,
                runner_id,
                "runner.broker.revoke_on_completion",
                "execution_lease",
                lease_id,
                completed_unix_ms,
                BTreeMap::from([
                    (
                        "secret_lease_count".to_owned(),
                        AuditValue::Integer(i64::try_from(secret_revocations).map_err(|_| {
                            ControlPlaneError::IntegerRange {
                                field: "secret broker revocation count",
                            }
                        })?),
                    ),
                    (
                        "oidc_issuance_count".to_owned(),
                        AuditValue::Integer(i64::try_from(oidc_revocations).map_err(|_| {
                            ControlPlaneError::IntegerRange {
                                field: "OIDC broker revocation count",
                            }
                        })?),
                    ),
                ]),
            )?;
        }
        conclude_run_if_terminal_tx(&transaction, &lease.job_id, completed_unix_ms)?;
        let completed = lease_tx(&transaction, lease_id)?;
        transaction.commit()?;
        Ok(completed)
    }

    pub fn lease(&self, id: &str) -> Result<Lease, ControlPlaneError> {
        let connection = self.connection()?;
        lease_conn(&connection, id)
    }

    pub fn lease_hard_deadline_unix_ms(&self, id: &str) -> Result<u64, ControlPlaneError> {
        validate_text("lease id", id)?;
        let connection = self.connection()?;
        lease_hard_deadline_conn(&connection, id)
    }
}
