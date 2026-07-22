// Explicit imports are local to external secret release authorization and journaling.
use super::super::{
    conversion, digest_column, environment_row, from_i64, installation_epoch_tx,
    lease_hard_deadline_tx, not_found, optional_u64_column, params, provider_configuration_tx,
    r10_json_bytes, require_active_policy_epoch_tx, require_environment_version_tx,
    require_provider_configuration_version_tx, require_r9_tenant_tx, runner_approval_subject_tx,
    runner_execution_subject_tx, secret_metadata_row, to_i64, u64_column,
    validate_provider_configuration, validate_r10_identifier, AuthorizedExternalSecretRelease,
    ContentDigest, ControlPlane, ControlPlaneError, DecodeError, ExternalSecretBrokerError,
    ExternalSecretLeaseMetadata, ExternalSecretReleaseAuthority, ExternalSecretReleaseJournal,
    ExternalSecretReleaseJournalEntry, ExternalSecretReleaseReservation,
    ExternalSecretReleaseState, ExternalSecretReserveOutcome, ExternalSecretRevokeOutcome, Row,
    RunnerExternalSecretRequest, Sha256, TenantProviderConfiguration, Transaction,
    TransactionBehavior,
};
use rusqlite::OptionalExtension as _;
use sha2::Digest as _;

impl ExternalSecretReleaseAuthority for ControlPlane {
    fn authorize(
        &self,
        request: &RunnerExternalSecretRequest,
        now_unix_ms: u64,
    ) -> Result<AuthorizedExternalSecretRelease, ExternalSecretBrokerError> {
        for value in [
            &request.runner_id,
            &request.execution_lease_id,
            &request.job_id,
            &request.step_id,
            &request.secret_metadata_id,
            &request.purpose,
        ] {
            validate_r10_identifier(value)
                .map_err(|_| ExternalSecretBrokerError::InvalidRequest)?;
        }
        if request.fencing_generation == 0
            || request.installation_fencing_epoch == 0
            || request.job_attempt == 0
            || request.expires_unix_ms <= now_unix_ms
            || request.expires_unix_ms - now_unix_ms > 15 * 60 * 1_000
        {
            return Err(ExternalSecretBrokerError::InvalidRequest);
        }
        let result = (|| -> Result<AuthorizedExternalSecretRelease, ControlPlaneError> {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let subject = runner_execution_subject_tx(
                &transaction,
                &request.execution_lease_id,
                &request.runner_id,
                request.fencing_generation,
                &request.job_id,
                now_unix_ms,
            )?;
            if subject.lease.installation_fencing_epoch != request.installation_fencing_epoch
                || request.expires_unix_ms > subject.lease.expires_unix_ms
                || request.expires_unix_ms
                    > lease_hard_deadline_tx(&transaction, &request.execution_lease_id)?
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            let durable_attempt: i64 = transaction.query_row(
                "SELECT attempt FROM jobs WHERE id = ?1 AND run_id = ?2",
                params![request.job_id, subject.run_id],
                |row| row.get(0),
            )?;
            if from_i64("external secret job attempt", durable_attempt)?
                != u64::from(request.job_attempt)
            {
                return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
            }
            if !subject.capsule.approval.privileged_execution
                || runner_approval_subject_tx(
                    &transaction,
                    &subject.capsule_id,
                    &subject.run_id,
                    &subject.capsule,
                )?
                .is_none()
            {
                return Err(ControlPlaneError::ApprovalRequired);
            }
            let step = subject
                .planned_job
                .steps
                .iter()
                .find(|step| step.id == request.step_id)
                .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
            let metadata = transaction
                .query_row(
                    "SELECT id, tenant_id, scope, name, provider, provider_reference,
                            secret_type, status, current_version, created_unix_ms,
                            updated_unix_ms FROM secret_metadata
                     WHERE tenant_id = ?1 AND id = ?2",
                    params![subject.tenant_id, request.secret_metadata_id],
                    secret_metadata_row,
                )
                .optional()?
                .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
            let declared = step.capabilities.secrets.iter().find(|secret| {
                secret.metadata_id == metadata.id
                    && secret.name == metadata.name
                    && secret.purpose.as_deref().unwrap_or_default() == request.purpose
            });
            let binding = declared.and_then(|secret| secret.resolution.as_ref());
            let provider_reference = metadata
                .provider_reference
                .clone()
                .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
            if declared.is_none()
                || binding.is_none_or(|binding| {
                    binding.scope != metadata.scope
                        || binding.metadata_version != metadata.current_version
                })
                || metadata.tenant_id != subject.tenant_id
                || metadata.provider == "built-in"
                || metadata.status != "active"
            {
                return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
            }
            let provider =
                provider_configuration_tx(&transaction, &subject.tenant_id, &metadata.provider)?
                    .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
            require_provider_configuration_version_tx(&transaction, &provider)?;
            if provider.capability != "external-secret" || provider.status != "active" {
                return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
            }
            if let Some(environment_name) = &subject.planned_job.environment {
                let environment = transaction
                    .query_row(
                        "SELECT id, tenant_id, repository_id, name,
                                deployment_target_reference, deployment_target_digest,
                                status, protection_rules_json, protection_rules_digest,
                                wait_timer_ms, concurrency_limit,
                                secret_provider_configuration_id,
                                signing_provider_configuration_id, required_policy_epoch,
                                last_concurrency_fence, created_unix_ms, updated_unix_ms,
                                version FROM environments
                         WHERE tenant_id = ?1 AND repository_id = ?2 AND name = ?3",
                        params![subject.tenant_id, subject.repository_id, environment_name],
                        environment_row,
                    )
                    .optional()?
                    .ok_or(ControlPlaneError::RunnerBrokerCapabilityDenied)?;
                require_environment_version_tx(&transaction, &environment)?;
                require_active_policy_epoch_tx(
                    &transaction,
                    &subject.tenant_id,
                    environment.required_policy_epoch,
                )?;
                let deployment_binding_is_current: bool = transaction.query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM deployment_requests r
                       JOIN environment_concurrency_leases g
                         ON g.tenant_id = r.tenant_id
                        AND g.environment_id = r.environment_id
                        AND g.deployment_request_id = r.id
                        AND g.concurrency_fence = r.concurrency_fence
                       WHERE r.tenant_id = ?1 AND r.job_id = ?2 AND r.job_attempt = ?3
                         AND r.environment_id = ?4 AND r.environment_version = ?5
                         AND r.policy_epoch = ?6 AND r.status = 'in-progress'
                         AND r.execution_lease_id = ?7 AND r.lease_fencing_generation = ?8
                         AND r.installation_fencing_epoch = ?9
                         AND g.state = 'active' AND g.execution_lease_id = ?7
                         AND g.lease_fencing_generation = ?8
                         AND g.installation_fencing_epoch = ?9
                         AND g.expires_unix_ms > ?10
                     )",
                    params![
                        subject.tenant_id,
                        request.job_id,
                        i64::from(request.job_attempt),
                        environment.id,
                        to_i64(environment.version)?,
                        to_i64(environment.required_policy_epoch)?,
                        request.execution_lease_id,
                        to_i64(request.fencing_generation)?,
                        to_i64(request.installation_fencing_epoch)?,
                        to_i64(now_unix_ms)?,
                    ],
                    |row| row.get(0),
                )?;
                if environment.status != "active"
                    || environment.secret_provider_configuration_id.as_deref()
                        != Some(provider.id.as_str())
                    || !deployment_binding_is_current
                {
                    return Err(ControlPlaneError::RunnerBrokerCapabilityDenied);
                }
            }
            let mut identity = Sha256::new();
            identity.update(b"runtrue.external-secret-release.v1\0");
            for value in [
                request.execution_lease_id.as_bytes(),
                request.job_id.as_bytes(),
                request.step_id.as_bytes(),
                request.secret_metadata_id.as_bytes(),
                request.purpose.as_bytes(),
                provider.id.as_bytes(),
                provider.configuration_digest.as_str().as_bytes(),
            ] {
                identity.update((value.len() as u64).to_be_bytes());
                identity.update(value);
            }
            identity.update(request.fencing_generation.to_be_bytes());
            identity.update(request.installation_fencing_epoch.to_be_bytes());
            identity.update(request.job_attempt.to_be_bytes());
            identity.update(provider.version.to_be_bytes());
            let release_id = format!("external-release-{}", hex::encode(identity.finalize()));
            let authorized = AuthorizedExternalSecretRelease {
                release_id,
                tenant_id: subject.tenant_id,
                repository_id: subject.repository_id,
                run_id: subject.run_id,
                runner_id: request.runner_id.clone(),
                execution_lease_id: request.execution_lease_id.clone(),
                fencing_generation: request.fencing_generation,
                installation_fencing_epoch: request.installation_fencing_epoch,
                job_id: request.job_id.clone(),
                job_attempt: request.job_attempt,
                step_id: request.step_id.clone(),
                secret_metadata_id: request.secret_metadata_id.clone(),
                purpose: request.purpose.clone(),
                provider_id: provider.id,
                provider_reference,
                expires_unix_ms: request.expires_unix_ms,
            };
            transaction.commit()?;
            Ok(authorized)
        })();
        result.map_err(|error| match error {
            ControlPlaneError::RunnerBrokerBindingMismatch
            | ControlPlaneError::StaleInstallationEpoch { .. }
            | ControlPlaneError::InstallationSafeMode => {
                ExternalSecretBrokerError::AuthorizationBindingMismatch
            }
            _ => ExternalSecretBrokerError::AuthorizationDenied,
        })
    }
}

fn external_release_row(row: &Row<'_>) -> rusqlite::Result<ExternalSecretReleaseJournalEntry> {
    let reservation_bytes: Vec<u8> = row.get(18)?;
    if reservation_bytes.len() > 256 * 1024 {
        return Err(conversion(
            18,
            DecodeError("external release reservation exceeds its bound".to_owned()),
        ));
    }
    let reservation: ExternalSecretReleaseReservation =
        serde_json::from_slice(&reservation_bytes).map_err(|error| conversion(18, error))?;
    let canonical_reservation =
        r10_json_bytes(&reservation, 256 * 1024).map_err(|error| conversion(18, error))?;
    let mut reservation_material = b"runtrue.external-release-reservation.v1\0".to_vec();
    reservation_material.extend_from_slice(&canonical_reservation);
    let reservation_digest = ContentDigest::sha256(reservation_material);
    let stored_reservation_digest = digest_column(row, 27)?;
    if reservation_bytes != canonical_reservation || reservation_digest != stored_reservation_digest
    {
        return Err(conversion(
            18,
            DecodeError("external release reservation digest changed".to_owned()),
        ));
    }
    let state_name: String = row.get(19)?;
    let state_bytes: Option<Vec<u8>> = row.get(20)?;
    let state = match (state_name.as_str(), state_bytes) {
        ("reserved", None) => ExternalSecretReleaseState::Reserved,
        (name, Some(bytes)) if bytes.len() <= 256 * 1024 => {
            let state: ExternalSecretReleaseState =
                serde_json::from_slice(&bytes).map_err(|error| conversion(20, error))?;
            let canonical =
                r10_json_bytes(&state, 256 * 1024).map_err(|error| conversion(20, error))?;
            let stored_digest = digest_column(row, 21)?;
            if canonical != bytes || ContentDigest::sha256(&canonical) != stored_digest {
                return Err(conversion(
                    20,
                    DecodeError("external release state digest changed".to_owned()),
                ));
            }
            let exact = matches!(
                (name, &state),
                ("delivered", ExternalSecretReleaseState::Delivered { .. })
                    | ("revoking", ExternalSecretReleaseState::Revoking { .. })
                    | ("revoked", ExternalSecretReleaseState::Revoked { .. })
                    | (
                        "indeterminate",
                        ExternalSecretReleaseState::Indeterminate { .. }
                    )
            );
            if !exact {
                return Err(conversion(
                    20,
                    DecodeError("external secret release state changed".to_owned()),
                ));
            }
            state
        }
        _ => {
            return Err(conversion(
                20,
                DecodeError("invalid external secret release state".to_owned()),
            ));
        }
    };
    let durable_release_id: String = row.get(0)?;
    let durable_subject = digest_column(row, 1)?;
    let provider_id: String = row.get(2)?;
    let provider_reference_digest = digest_column(row, 5)?;
    let tenant_id: String = row.get(6)?;
    let repository_id: String = row.get(7)?;
    let run_id: String = row.get(8)?;
    let runner_id: String = row.get(9)?;
    let execution_lease_id: String = row.get(10)?;
    let fencing_generation = u64_column(row, 11, "external release fence")?;
    let installation_fencing_epoch = u64_column(row, 12, "external release epoch")?;
    let job_id: String = row.get(13)?;
    let job_attempt = u32::try_from(u64_column(row, 14, "external release attempt")?)
        .map_err(|error| conversion(14, error))?;
    let step_id: String = row.get(15)?;
    let secret_metadata_id: String = row.get(16)?;
    let purpose: String = row.get(17)?;
    let expires_unix_ms = u64_column(row, 23, "external release expiry")?;
    let created_unix_ms = u64_column(row, 24, "external release creation")?;
    let updated_unix_ms = u64_column(row, 25, "external release update")?;
    let revoked_unix_ms = optional_u64_column(row, 26, "external release revocation")?;
    let _provider_configuration_digest = digest_column(row, 3)?;
    let provider_configuration_version = u64_column(row, 4, "external provider version")?;
    let transition_attempts = u64_column(row, 22, "external release transition attempts")?;
    if reservation.release_id != durable_release_id
        || reservation.release_subject_digest != durable_subject
        || reservation.provider_id != provider_id
        || reservation.provider_reference_digest != provider_reference_digest
        || reservation.tenant_id != tenant_id
        || reservation.repository_id != repository_id
        || reservation.run_id != run_id
        || reservation.runner_id != runner_id
        || reservation.execution_lease_id != execution_lease_id
        || reservation.fencing_generation != fencing_generation
        || reservation.installation_fencing_epoch != installation_fencing_epoch
        || reservation.job_id != job_id
        || reservation.job_attempt != job_attempt
        || reservation.step_id != step_id
        || reservation.secret_metadata_id != secret_metadata_id
        || reservation.purpose != purpose
        || reservation.expires_unix_ms != expires_unix_ms
        || provider_configuration_version == 0
        || transition_attempts > 8
        || updated_unix_ms < created_unix_ms
        || expires_unix_ms <= created_unix_ms
        || match &state {
            ExternalSecretReleaseState::Revoked {
                revoked_unix_ms: state_revoked,
                ..
            } => Some(*state_revoked) != revoked_unix_ms,
            _ => revoked_unix_ms.is_some(),
        }
    {
        return Err(conversion(
            18,
            DecodeError("external release reservation columns changed".to_owned()),
        ));
    }
    Ok(ExternalSecretReleaseJournalEntry { reservation, state })
}

const EXTERNAL_RELEASE_COLUMNS: &str =
    "release_id, release_subject_digest, provider_configuration_id,
     provider_configuration_digest, provider_configuration_version,
     provider_reference_digest, tenant_id, repository_id, run_id, runner_id,
     execution_lease_id, fencing_generation, installation_fencing_epoch,
     job_id, job_attempt, step_id, secret_metadata_id, purpose, reservation_json,
     state, provider_metadata_json, provider_metadata_digest, transition_attempts,
     expires_unix_ms, created_unix_ms, updated_unix_ms, revoked_unix_ms,
     reservation_digest";

fn external_release_tx(
    transaction: &Transaction<'_>,
    release_id: &str,
) -> Result<Option<ExternalSecretReleaseJournalEntry>, ControlPlaneError> {
    let sql = format!(
        "SELECT {EXTERNAL_RELEASE_COLUMNS} FROM external_secret_release_journal
         WHERE release_id = ?1"
    );
    let entry = transaction
        .query_row(&sql, [release_id], external_release_row)
        .optional()?;
    if let Some(entry) = &entry {
        let snapshot: Option<(String, i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT j.provider_configuration_digest,
                        j.provider_configuration_version, v.snapshot_json
                 FROM external_secret_release_journal j
                 JOIN tenant_provider_configuration_versions v
                   ON v.tenant_id = j.tenant_id
                  AND v.provider_configuration_id = j.provider_configuration_id
                  AND v.version = j.provider_configuration_version
                 WHERE j.release_id = ?1",
                [release_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((stored_digest, stored_version, bytes)) = snapshot else {
            return Err(ControlPlaneError::CorruptState(
                "external release provider version is missing".to_owned(),
            ));
        };
        if bytes.len() > 256 * 1024 {
            return Err(ControlPlaneError::CorruptState(
                "external release provider version is oversized".to_owned(),
            ));
        }
        let provider: TenantProviderConfiguration = serde_json::from_slice(&bytes)?;
        validate_provider_configuration(&provider)?;
        if provider.tenant_id != entry.reservation.tenant_id
            || provider.id != entry.reservation.provider_id
            || provider.configuration_digest.as_str() != stored_digest
            || to_i64(provider.version)? != stored_version
        {
            return Err(ControlPlaneError::CorruptState(
                "external release provider version binding changed".to_owned(),
            ));
        }
        require_provider_configuration_version_tx(transaction, &provider)?;
    }
    Ok(entry)
}

fn validate_external_release_lineage_tx(
    transaction: &Transaction<'_>,
    reservation: &ExternalSecretReleaseReservation,
) -> Result<(TenantProviderConfiguration, u64), ControlPlaneError> {
    require_r9_tenant_tx(transaction, &reservation.tenant_id)?;
    let provider = provider_configuration_tx(
        transaction,
        &reservation.tenant_id,
        &reservation.provider_id,
    )?
    .ok_or_else(|| not_found("provider configuration", &reservation.provider_id))?;
    if provider.capability != "external-secret" || provider.status != "active" {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    let secret: Option<(String, String, Option<String>, String)> = transaction
        .query_row(
            "SELECT tenant_id, provider, provider_reference, status
             FROM secret_metadata WHERE tenant_id = ?1 AND id = ?2",
            params![reservation.tenant_id, reservation.secret_metadata_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((secret_tenant, secret_provider, provider_reference, secret_status)) = secret else {
        return Err(not_found(
            "secret metadata",
            &reservation.secret_metadata_id,
        ));
    };
    let provider_reference =
        provider_reference.ok_or(ControlPlaneError::EnvironmentGateNotReady)?;
    if secret_tenant != reservation.tenant_id
        || secret_provider != reservation.provider_id
        || secret_status != "active"
        || ContentDigest::sha256(provider_reference.as_bytes())
            != reservation.provider_reference_digest
    {
        return Err(ControlPlaneError::EnvironmentGateNotReady);
    }
    type Lineage = (
        String,
        String,
        i64,
        i64,
        String,
        i64,
        i64,
        i64,
        String,
        String,
        String,
    );
    let lineage: Option<Lineage> = transaction
        .query_row(
            "SELECT l.tenant_id, l.runner_id, l.fencing_generation,
                    l.installation_fencing_epoch, l.state, l.issued_unix_ms,
                    l.expires_unix_ms, l.hard_deadline_unix_ms,
                    j.id, j.run_id, r.repository_id
             FROM leases l JOIN jobs j ON j.id = l.job_id
             JOIN runs r ON r.id = j.run_id
             JOIN repositories repo ON repo.id = r.repository_id
             JOIN runners runner ON runner.id = l.runner_id
             JOIN runner_pools pool ON pool.id = runner.pool_id
             WHERE l.tenant_id = ?1 AND l.id = ?2 AND repo.tenant_id = ?1
               AND pool.tenant_id = ?1 AND j.attempt = ?3",
            params![
                reservation.tenant_id,
                reservation.execution_lease_id,
                i64::from(reservation.job_attempt)
            ],
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()?;
    let Some((
        tenant,
        runner,
        fence,
        epoch,
        state,
        issued,
        expires,
        hard_deadline,
        job,
        run,
        repository,
    )) = lineage
    else {
        return Err(not_found(
            "execution lease",
            &reservation.execution_lease_id,
        ));
    };
    let current_epoch = installation_epoch_tx(transaction)?;
    let safe_mode: bool = transaction.query_row(
        "SELECT safe_mode FROM installation_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if safe_mode {
        return Err(ControlPlaneError::InstallationSafeMode);
    }
    if tenant != reservation.tenant_id
        || runner != reservation.runner_id
        || from_i64("external release fence", fence)? != reservation.fencing_generation
        || from_i64("external release epoch", epoch)? != reservation.installation_fencing_epoch
        || current_epoch != reservation.installation_fencing_epoch
        || state != "active"
        || job != reservation.job_id
        || run != reservation.run_id
        || repository != reservation.repository_id
        || reservation.expires_unix_ms <= from_i64("external release issued", issued)?
        || reservation.expires_unix_ms > from_i64("external release lease expiry", expires)?
        || reservation.expires_unix_ms > from_i64("external release hard deadline", hard_deadline)?
    {
        return Err(ControlPlaneError::RunnerBrokerBindingMismatch);
    }
    Ok((provider, from_i64("external release creation", issued)?))
}

type ExternalReleaseStateParts = (&'static str, Option<Vec<u8>>, Option<ContentDigest>);

fn external_release_state_parts(
    state: &ExternalSecretReleaseState,
) -> Result<ExternalReleaseStateParts, ControlPlaneError> {
    if matches!(state, ExternalSecretReleaseState::Reserved) {
        return Ok(("reserved", None, None));
    }
    let name = match state {
        ExternalSecretReleaseState::Delivered { .. } => "delivered",
        ExternalSecretReleaseState::Revoking { .. } => "revoking",
        ExternalSecretReleaseState::Revoked { .. } => "revoked",
        ExternalSecretReleaseState::Indeterminate { .. } => "indeterminate",
        ExternalSecretReleaseState::Reserved => unreachable!(),
    };
    let bytes = r10_json_bytes(state, 256 * 1024)?;
    let digest = ContentDigest::sha256(&bytes);
    Ok((name, Some(bytes), Some(digest)))
}

fn provider_metadata_matches_reservation(
    metadata: &ExternalSecretLeaseMetadata,
    reservation: &ExternalSecretReleaseReservation,
) -> bool {
    metadata.release_id == reservation.release_id
        && metadata.release_subject_digest == reservation.release_subject_digest
        && metadata.provider == reservation.provider_id
        && metadata.tenant_id == reservation.tenant_id
        && metadata.repository_id == reservation.repository_id
        && metadata.run_id == reservation.run_id
        && metadata.runner_id == reservation.runner_id
        && metadata.secret_metadata_id == reservation.secret_metadata_id
        && metadata.execution_lease_id == reservation.execution_lease_id
        && metadata.fencing_generation == reservation.fencing_generation
        && metadata.installation_fencing_epoch == reservation.installation_fencing_epoch
        && metadata.job_id == reservation.job_id
        && metadata.job_attempt == reservation.job_attempt
        && metadata.step_id == reservation.step_id
        && metadata.purpose == reservation.purpose
        && metadata.expires_unix_ms <= reservation.expires_unix_ms
}

impl ExternalSecretReleaseJournal for ControlPlane {
    fn reserve(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretReserveOutcome, ExternalSecretBrokerError> {
        let result = (|| -> Result<ExternalSecretReserveOutcome, ControlPlaneError> {
            let reservation_bytes = r10_json_bytes(reservation, 256 * 1024)?;
            let mut reservation_material = b"runtrue.external-release-reservation.v1\0".to_vec();
            reservation_material.extend_from_slice(&reservation_bytes);
            let reservation_digest = ContentDigest::sha256(reservation_material);
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(existing) = external_release_tx(&transaction, &reservation.release_id)? {
                if existing.reservation == *reservation {
                    transaction.commit()?;
                    return Ok(ExternalSecretReserveOutcome {
                        created: false,
                        entry: existing,
                    });
                }
                return Err(ControlPlaneError::IdempotencyConflict);
            }
            let (provider, created_unix_ms) =
                validate_external_release_lineage_tx(&transaction, reservation)?;
            transaction.execute(
                "INSERT INTO external_secret_release_journal
                 (release_id, release_subject_digest, provider_configuration_id,
                  provider_configuration_digest, provider_configuration_version,
                  provider_reference_digest, tenant_id, repository_id, run_id,
                  runner_id, execution_lease_id, fencing_generation,
                  installation_fencing_epoch, job_id, job_attempt, step_id,
                  secret_metadata_id, purpose, reservation_json, state,
                  provider_metadata_json, provider_metadata_digest,
                  transition_attempts, expires_unix_ms, created_unix_ms,
                  updated_unix_ms, revoked_unix_ms, reservation_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, 'reserved',
                         NULL, NULL, 0, ?20, ?21, ?21, NULL, ?22)",
                params![
                    reservation.release_id,
                    reservation.release_subject_digest.as_str(),
                    reservation.provider_id,
                    provider.configuration_digest.as_str(),
                    to_i64(provider.version)?,
                    reservation.provider_reference_digest.as_str(),
                    reservation.tenant_id,
                    reservation.repository_id,
                    reservation.run_id,
                    reservation.runner_id,
                    reservation.execution_lease_id,
                    to_i64(reservation.fencing_generation)?,
                    to_i64(reservation.installation_fencing_epoch)?,
                    reservation.job_id,
                    i64::from(reservation.job_attempt),
                    reservation.step_id,
                    reservation.secret_metadata_id,
                    reservation.purpose,
                    reservation_bytes,
                    to_i64(reservation.expires_unix_ms)?,
                    to_i64(created_unix_ms)?,
                    reservation_digest.as_str()
                ],
            )?;
            transaction.commit()?;
            Ok(ExternalSecretReserveOutcome {
                created: true,
                entry: ExternalSecretReleaseJournalEntry {
                    reservation: reservation.clone(),
                    state: ExternalSecretReleaseState::Reserved,
                },
            })
        })();
        match result {
            Ok(value) => Ok(value),
            Err(ControlPlaneError::IdempotencyConflict) => {
                Err(ExternalSecretBrokerError::SubjectConflict)
            }
            Err(_) => Err(ExternalSecretBrokerError::Journal),
        }
    }

    fn mark_delivered(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: &ExternalSecretLeaseMetadata,
    ) -> Result<(), ExternalSecretBrokerError> {
        if !provider_metadata_matches_reservation(provider_metadata, reservation) {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        let next = ExternalSecretReleaseState::Delivered {
            provider_metadata: provider_metadata.clone(),
        };
        transition_external_release(self, reservation, &next, "reserved", None)
    }

    fn mark_indeterminate(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        provider_metadata: Option<&ExternalSecretLeaseMetadata>,
        observed_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError> {
        if provider_metadata
            .is_some_and(|metadata| !provider_metadata_matches_reservation(metadata, reservation))
        {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        let next = ExternalSecretReleaseState::Indeterminate {
            provider_metadata: provider_metadata.cloned(),
            observed_unix_ms,
        };
        transition_external_release(self, reservation, &next, "reserved", Some(observed_unix_ms))
    }

    fn load(
        &self,
        release_id: &str,
    ) -> Result<ExternalSecretReleaseJournalEntry, ExternalSecretBrokerError> {
        validate_r10_identifier(release_id).map_err(|_| ExternalSecretBrokerError::Journal)?;
        let mut connection = self
            .connection()
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        let entry = external_release_tx(&transaction, release_id)
            .map_err(|_| ExternalSecretBrokerError::Journal)?
            .ok_or(ExternalSecretBrokerError::Journal)?;
        transaction
            .commit()
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        Ok(entry)
    }

    fn begin_revoke(
        &self,
        reservation: &ExternalSecretReleaseReservation,
    ) -> Result<ExternalSecretRevokeOutcome, ExternalSecretBrokerError> {
        let mut connection = self
            .connection()
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        let entry = external_release_tx(&transaction, &reservation.release_id)
            .map_err(|_| ExternalSecretBrokerError::Journal)?
            .ok_or(ExternalSecretBrokerError::Journal)?;
        if entry.reservation != *reservation {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        match entry.state {
            ExternalSecretReleaseState::Revoking { .. } => {
                transaction
                    .commit()
                    .map_err(|_| ExternalSecretBrokerError::Journal)?;
                Ok(ExternalSecretRevokeOutcome {
                    started: false,
                    entry,
                })
            }
            ExternalSecretReleaseState::Delivered { provider_metadata } => {
                let next = ExternalSecretReleaseState::Revoking { provider_metadata };
                let (state, bytes, digest) = external_release_state_parts(&next)
                    .map_err(|_| ExternalSecretBrokerError::Journal)?;
                let changed = transaction
                    .execute(
                        "UPDATE external_secret_release_journal
                         SET state = ?2, provider_metadata_json = ?3,
                             provider_metadata_digest = ?4,
                             transition_attempts = transition_attempts + 1
                         WHERE release_id = ?1 AND state = 'delivered'
                           AND transition_attempts < 8",
                        params![
                            reservation.release_id,
                            state,
                            bytes,
                            digest.as_ref().map(ContentDigest::as_str)
                        ],
                    )
                    .map_err(|_| ExternalSecretBrokerError::Journal)?;
                if changed != 1 {
                    return Err(ExternalSecretBrokerError::Journal);
                }
                transaction
                    .commit()
                    .map_err(|_| ExternalSecretBrokerError::Journal)?;
                Ok(ExternalSecretRevokeOutcome {
                    started: true,
                    entry: ExternalSecretReleaseJournalEntry {
                        reservation: reservation.clone(),
                        state: next,
                    },
                })
            }
            _ => Err(ExternalSecretBrokerError::IndeterminateRecoveryRequired),
        }
    }

    fn mark_revoked(
        &self,
        reservation: &ExternalSecretReleaseReservation,
        revoked_unix_ms: u64,
    ) -> Result<(), ExternalSecretBrokerError> {
        let current = self.load(&reservation.release_id)?;
        if current.reservation != *reservation {
            return Err(ExternalSecretBrokerError::SubjectConflict);
        }
        let provider_metadata = match current.state {
            ExternalSecretReleaseState::Revoking { provider_metadata } => provider_metadata,
            ExternalSecretReleaseState::Revoked {
                revoked_unix_ms: stored,
                ..
            } if stored == revoked_unix_ms => return Ok(()),
            _ => return Err(ExternalSecretBrokerError::Journal),
        };
        let next = ExternalSecretReleaseState::Revoked {
            provider_metadata,
            revoked_unix_ms,
        };
        transition_external_release(self, reservation, &next, "revoking", Some(revoked_unix_ms))
    }
}

fn transition_external_release(
    control: &ControlPlane,
    reservation: &ExternalSecretReleaseReservation,
    next: &ExternalSecretReleaseState,
    expected_state: &str,
    observed_unix_ms: Option<u64>,
) -> Result<(), ExternalSecretBrokerError> {
    let (state, bytes, digest) =
        external_release_state_parts(next).map_err(|_| ExternalSecretBrokerError::Journal)?;
    let mut connection = control
        .connection()
        .map_err(|_| ExternalSecretBrokerError::Journal)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ExternalSecretBrokerError::Journal)?;
    let existing = external_release_tx(&transaction, &reservation.release_id)
        .map_err(|_| ExternalSecretBrokerError::Journal)?
        .ok_or(ExternalSecretBrokerError::Journal)?;
    if existing.reservation != *reservation {
        return Err(ExternalSecretBrokerError::SubjectConflict);
    }
    if existing.state == *next {
        transaction
            .commit()
            .map_err(|_| ExternalSecretBrokerError::Journal)?;
        return Ok(());
    }
    let changed = transaction
        .execute(
            "UPDATE external_secret_release_journal
             SET state = ?2, provider_metadata_json = ?3,
                 provider_metadata_digest = ?4,
                 transition_attempts = transition_attempts + 1,
                 updated_unix_ms = MAX(updated_unix_ms, ?5),
                 revoked_unix_ms = CASE WHEN ?2 = 'revoked' THEN ?5 ELSE revoked_unix_ms END
             WHERE release_id = ?1 AND state = ?6 AND transition_attempts < 8",
            params![
                reservation.release_id,
                state,
                bytes,
                digest.as_ref().map(ContentDigest::as_str),
                to_i64(observed_unix_ms.unwrap_or(0))
                    .map_err(|_| { ExternalSecretBrokerError::Journal })?,
                expected_state
            ],
        )
        .map_err(|_| ExternalSecretBrokerError::Journal)?;
    if changed != 1 {
        return Err(ExternalSecretBrokerError::Journal);
    }
    transaction
        .commit()
        .map_err(|_| ExternalSecretBrokerError::Journal)?;
    Ok(())
}
