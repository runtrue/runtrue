use super::fleet::{fleet_request_row, require_autoscaler_lease_tx};
use super::*;

fn replacement_state_name(state: RunnerReplacementState) -> &'static str {
    match state {
        RunnerReplacementState::Requested => "requested",
        RunnerReplacementState::ClaimIssued => "claim-issued",
        RunnerReplacementState::Enrolled => "enrolled",
        RunnerReplacementState::Probationary => "probationary",
        RunnerReplacementState::Active => "active",
        RunnerReplacementState::DrainingSource => "draining-source",
        RunnerReplacementState::Completed => "completed",
        RunnerReplacementState::Failed => "failed",
        RunnerReplacementState::Canceled => "canceled",
    }
}

fn parse_replacement_mode(value: &str) -> Result<RunnerReplacementMode, ControlPlaneError> {
    match value {
        "autoscaled" => Ok(RunnerReplacementMode::Autoscaled),
        "fixed-host" => Ok(RunnerReplacementMode::FixedHost),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown runner replacement mode".to_owned(),
        )),
    }
}

fn parse_replacement_state(value: &str) -> Result<RunnerReplacementState, ControlPlaneError> {
    match value {
        "requested" => Ok(RunnerReplacementState::Requested),
        "claim-issued" => Ok(RunnerReplacementState::ClaimIssued),
        "enrolled" => Ok(RunnerReplacementState::Enrolled),
        "probationary" => Ok(RunnerReplacementState::Probationary),
        "active" => Ok(RunnerReplacementState::Active),
        "draining-source" => Ok(RunnerReplacementState::DrainingSource),
        "completed" => Ok(RunnerReplacementState::Completed),
        "failed" => Ok(RunnerReplacementState::Failed),
        "canceled" => Ok(RunnerReplacementState::Canceled),
        _ => Err(ControlPlaneError::CorruptState(
            "unknown runner replacement state".to_owned(),
        )),
    }
}

fn replacement_row(row: &Row<'_>) -> rusqlite::Result<RunnerReplacementRecord> {
    let mode: String = row.get(2)?;
    let state: String = row.get(15)?;
    Ok(RunnerReplacementRecord {
        id: row.get(0)?,
        pool_id: row.get(1)?,
        mode: parse_replacement_mode(&mode).map_err(|error| conversion(2, error))?,
        source_runner_id: row.get(3)?,
        source_posture_digest: digest_column(row, 4)?,
        target_runner_id: row.get(5)?,
        target_posture_digest: optional_digest_column(row, 6)?,
        runner_slot_id: row.get(7)?,
        source_fleet_request_id: row.get(8)?,
        target_fleet_request_id: row.get(9)?,
        generation: u64_column(row, 10, "replacement generation")?,
        policy_version: u64_column(row, 11, "replacement policy version")?,
        release_id: row.get(12)?,
        channel: row.get(13)?,
        rollout_ring: row.get(14)?,
        state: parse_replacement_state(&state).map_err(|error| conversion(15, error))?,
        failure_code: row.get(16)?,
        created_unix_ms: u64_column(row, 17, "replacement creation")?,
        updated_unix_ms: u64_column(row, 18, "replacement update")?,
    })
}

const REPLACEMENT_COLUMNS: &str = "id,pool_id,mode,source_runner_id,source_posture_digest,target_runner_id,target_posture_digest,runner_slot_id,source_fleet_request_id,target_fleet_request_id,generation,policy_version,release_id,channel,rollout_ring,state,failure_code,created_unix_ms,updated_unix_ms";
const SOFTWARE_CLAIM_COLUMNS: &str = "id,replacement_id,enrollment_token_id,pool_id,mode,source_runner_id,source_posture_digest,runner_slot_id,fleet_request_id,provider,provider_instance_id,updater_identity_digest,runner_template_digest,identity_proof_digest,generation,artifact_digest,installed_digest,release_id,component_profile_digest,update_root_digest,targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,policy_version,channel,rollout_ring,protocol_min,protocol_max,required_attestation_grade,attestation_nonce_digest,created_unix_ms,expires_unix_ms,canceled_unix_ms,consumed_unix_ms,runner_id";

fn software_claim_row(row: &Row<'_>) -> rusqlite::Result<RunnerSoftwareUpdateClaim> {
    let mode: String = row.get(4)?;
    Ok(RunnerSoftwareUpdateClaim {
        id: row.get(0)?,
        replacement_id: row.get(1)?,
        enrollment_token_id: row.get(2)?,
        pool_id: row.get(3)?,
        mode: parse_replacement_mode(&mode).map_err(|error| conversion(4, error))?,
        source_runner_id: row.get(5)?,
        source_posture_digest: digest_column(row, 6)?,
        runner_slot_id: row.get(7)?,
        fleet_request_id: row.get(8)?,
        provider: row.get(9)?,
        provider_instance_id: row.get(10)?,
        updater_identity_digest: optional_digest_column(row, 11)?,
        runner_template_digest: digest_column(row, 12)?,
        identity_proof_digest: digest_column(row, 13)?,
        generation: u64_column(row, 14, "update generation")?,
        artifact_digest: digest_column(row, 15)?,
        installed_digest: digest_column(row, 16)?,
        release_id: row.get(17)?,
        component_profile_digest: digest_column(row, 18)?,
        update_root_digest: digest_column(row, 19)?,
        targets_metadata_digest: digest_column(row, 20)?,
        snapshot_metadata_digest: digest_column(row, 21)?,
        timestamp_metadata_digest: digest_column(row, 22)?,
        policy_version: u64_column(row, 23, "update policy version")?,
        channel: row.get(24)?,
        rollout_ring: row.get(25)?,
        protocol_min: row.get(26)?,
        protocol_max: row.get(27)?,
        required_attestation_grade: row.get(28)?,
        attestation_nonce_digest: digest_column(row, 29)?,
        created_unix_ms: u64_column(row, 30, "update claim creation")?,
        expires_unix_ms: u64_column(row, 31, "update claim expiry")?,
        canceled_unix_ms: optional_u64_column(row, 32, "update claim cancellation")?,
        consumed_unix_ms: optional_u64_column(row, 33, "update claim consumption")?,
        runner_id: row.get(34)?,
    })
}

fn validate_update_release(release: &RunnerUpdateRelease) -> Result<(), ControlPlaneError> {
    for (field, value) in [
        ("release id", release.id.as_str()),
        ("release channel", release.channel.as_str()),
        ("component name", release.profile.component_name.as_str()),
        ("release version", release.profile.release_version.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if release
        .revoked_unix_ms
        .is_some_and(|value| value < release.created_unix_ms)
        || release.profile.digest().map_err(|_| {
            ControlPlaneError::InvalidInput("runner update release profile is malformed")
        })? != release.component_profile_digest
    {
        return Err(ControlPlaneError::InvalidInput(
            "runner update release profile is malformed or its digest does not match",
        ));
    }
    Ok(())
}

fn insert_update_release(
    connection: &Connection,
    release: &RunnerUpdateRelease,
) -> Result<(), ControlPlaneError> {
    connection.execute(
        "INSERT INTO runner_update_releases(id,component_name,release_version,channel,artifact_name,artifact_length,artifact_digest,artifact_media_type,platform,architecture,installed_digest,runner_version,engine_version,protocol_min,protocol_max,package_format,component_profile_json,component_profile_digest,update_root_digest,targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,created_unix_ms,revoked_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
        params![release.id,release.profile.component_name,release.profile.release_version,release.channel,release.profile.artifact_name,to_i64(release.profile.artifact_length)?,release.profile.artifact_digest.as_str(),release.profile.artifact_media_type,release.profile.platform,release.profile.architecture,release.profile.installed_digest.as_str(),release.profile.runner_version,release.profile.engine_version,i64::from(release.profile.protocol_min),i64::from(release.profile.protocol_max),release.profile.package_format,serde_json::to_string(&release.profile)?,release.component_profile_digest.as_str(),release.update_root_digest.as_str(),release.targets_metadata_digest.as_str(),release.snapshot_metadata_digest.as_str(),release.timestamp_metadata_digest.as_str(),to_i64(release.created_unix_ms)?,release.revoked_unix_ms.map(to_i64).transpose()?],
    )?;
    Ok(())
}

impl ControlPlane {
    pub fn runner_slot(&self, slot_id: &str) -> Result<RunnerSlotRecord, ControlPlaneError> {
        self.connection()?
            .query_row(
                "SELECT id,pool_id,updater_identity_digest,active_generation,active_runner_id,created_unix_ms,updated_unix_ms FROM runner_slots WHERE id=?1",
                [slot_id],
                |row| Ok(RunnerSlotRecord {
                    id: row.get(0)?,
                    pool_id: row.get(1)?,
                    updater_identity_digest: digest_column(row, 2)?,
                    active_generation: u64_column(row, 3, "slot generation")?,
                    active_runner_id: row.get(4)?,
                    created_unix_ms: u64_column(row, 5, "slot creation")?,
                    updated_unix_ms: u64_column(row, 6, "slot update")?,
                }),
            )
            .optional()?
            .ok_or_else(|| not_found("runner slot", slot_id))
    }

    pub fn put_runner_slot(&self, slot: &RunnerSlotRecord) -> Result<(), ControlPlaneError> {
        validate_text("runner slot id", &slot.id)?;
        validate_text("runner slot pool", &slot.pool_id)?;
        if slot.updated_unix_ms < slot.created_unix_ms {
            return Err(ControlPlaneError::InvalidInput(
                "runner slot timestamps are invalid",
            ));
        }
        if slot.active_runner_id.is_some() != (slot.active_generation > 0) {
            return Err(ControlPlaneError::InvalidInput(
                "runner slot active identity and generation are inconsistent",
            ));
        }
        let changed = self.connection()?.execute(
            "INSERT INTO runner_slots(id,pool_id,updater_identity_digest,active_generation,active_runner_id,created_unix_ms,updated_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE ?5 IS NULL OR EXISTS(SELECT 1 FROM runners WHERE id=?5 AND pool_id=?2 AND status NOT IN('revoked','quarantined'))",
            params![slot.id,slot.pool_id,slot.updater_identity_digest.as_str(),to_i64(slot.active_generation)?,slot.active_runner_id,to_i64(slot.created_unix_ms)?,to_i64(slot.updated_unix_ms)?],
        )?;
        if changed != 1 {
            return Err(ControlPlaneError::InvalidInput(
                "runner slot active identity is not an eligible member of the pool",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_fixed_host_update_claim(
        &self,
        slot_id: &str,
        identity_proof_digest: &ContentDigest,
        now_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<IssuedRunnerSoftwareUpdateClaim, ControlPlaneError> {
        if expires_unix_ms <= now_unix_ms || expires_unix_ms.saturating_sub(now_unix_ms) > 900_000 {
            return Err(ControlPlaneError::InvalidInput(
                "software update claim lifetime must be at most fifteen minutes",
            ));
        }
        let mut raw = [0_u8; ENROLLMENT_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut raw)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let token = RunnerLaunchClaimToken::new(hex::encode(raw));
        raw.zeroize();
        let mut id = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| ControlPlaneError::RandomnessUnavailable)?;
        let suffix = hex::encode(id);
        let enrollment_id = format!("enroll-{suffix}");
        let replacement_id = format!("replace-{suffix}");
        let claim_id = format!("update-{suffix}");
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let slot=tx.query_row("SELECT pool_id,updater_identity_digest,active_generation,active_runner_id FROM runner_slots WHERE id=?1",[slot_id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,u64_column(row,2,"slot generation")?,row.get::<_,Option<String>>(3)?))).optional()?.ok_or_else(||not_found("runner slot",slot_id))?;
        let source_id = slot.3.ok_or(ControlPlaneError::InvalidInput(
            "runner slot has no active source",
        ))?;
        let source = persisted_runner_tx(&tx, &source_id)?;
        let open:u64=tx.query_row("SELECT COUNT(*) FROM leases WHERE runner_id=?1 AND state IN('offered','active','cancel_requested')",[&source_id],|row|u64_column(row,0,"open leases"))?;
        if source.runner.status != RunnerStatus::Draining
            || source.runner.active_jobs != 0
            || open != 0
        {
            return Err(ControlPlaneError::InvalidInput(
                "fixed-host source is not completely drained",
            ));
        }
        let source_posture: String = tx.query_row(
            "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=?1",
            [&source_id],
            |row| row.get(0),
        )?;
        let policy=tx.query_row("SELECT p.version,p.release_id,p.runner_template_digest,p.channel,p.protocol_min,p.protocol_max,p.required_attestation_grade,u.artifact_digest,u.installed_digest,u.component_profile_digest,u.update_root_digest,u.targets_metadata_digest,u.snapshot_metadata_digest,u.timestamp_metadata_digest,p.maintenance_window_json FROM runner_pool_update_policies p JOIN runner_update_releases u ON u.id=p.release_id AND u.revoked_unix_ms IS NULL WHERE p.pool_id=?1 AND p.enabled=1 AND p.paused=0 ORDER BY p.version DESC LIMIT 1",[&slot.0],|row|Ok((u64_column(row,0,"policy version")?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,u32>(4)?,row.get::<_,u32>(5)?,row.get::<_,String>(6)?,row.get::<_,String>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,String>(10)?,row.get::<_,String>(11)?,row.get::<_,String>(12)?,row.get::<_,String>(13)?,row.get::<_,String>(14)?))).optional()?.ok_or(ControlPlaneError::InvalidInput("automatic runner updates are disabled or paused"))?;
        let windows: Vec<String> = serde_json::from_str(&policy.14)?;
        if !crate::types::update_window_allows(&windows, now_unix_ms) {
            return Err(ControlPlaneError::InvalidInput(
                "runner update is outside its UTC maintenance window",
            ));
        }
        let latest_generation: u64 = tx.query_row(
            "SELECT COALESCE(MAX(generation),?2) FROM runner_replacements WHERE runner_slot_id=?1",
            params![slot_id, to_i64(slot.2)?],
            |row| u64_column(row, 0, "latest slot replacement generation"),
        )?;
        let generation =
            latest_generation
                .checked_add(1)
                .ok_or(ControlPlaneError::IntegerRange {
                    field: "runner slot generation",
                })?;
        tx.execute("UPDATE runner_software_update_claims SET canceled_unix_ms=?2 WHERE runner_slot_id=?1 AND consumed_unix_ms IS NULL AND canceled_unix_ms IS NULL",params![slot_id,to_i64(now_unix_ms)?])?;
        tx.execute("UPDATE runner_replacements SET state='canceled',failure_code='superseded',updated_unix_ms=?2 WHERE runner_slot_id=?1 AND state IN('requested','claim-issued')",params![slot_id,to_i64(now_unix_ms)?])?;
        tx.execute("INSERT INTO enrollment_tokens(id,pool_id,token_hash,created_unix_ms,expires_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![enrollment_id,slot.0,enrollment_token_hash(token.expose()).as_str(),to_i64(now_unix_ms)?,to_i64(expires_unix_ms)?])?;
        tx.execute("INSERT INTO runner_replacements(id,pool_id,mode,source_runner_id,source_posture_digest,runner_slot_id,generation,policy_version,release_id,channel,rollout_ring,state,created_unix_ms,updated_unix_ms) VALUES(?1,?2,'fixed-host',?3,?4,?5,?6,?7,?8,?9,0,'claim-issued',?10,?10)",params![replacement_id,slot.0,source_id,source_posture,slot_id,to_i64(generation)?,to_i64(policy.0)?,policy.1,policy.3,to_i64(now_unix_ms)?])?;
        tx.execute("INSERT INTO runner_software_update_claims(id,replacement_id,enrollment_token_id,pool_id,mode,source_runner_id,source_posture_digest,runner_slot_id,updater_identity_digest,runner_template_digest,identity_proof_digest,generation,artifact_digest,installed_digest,release_id,component_profile_digest,update_root_digest,targets_metadata_digest,snapshot_metadata_digest,timestamp_metadata_digest,policy_version,channel,rollout_ring,protocol_min,protocol_max,required_attestation_grade,attestation_nonce_digest,created_unix_ms,expires_unix_ms) VALUES(?1,?2,?3,?4,'fixed-host',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,0,?22,?23,?24,?10,?25,?26)",params![claim_id,replacement_id,enrollment_id,slot.0,source_id,source_posture,slot_id,slot.1,policy.2,identity_proof_digest.as_str(),to_i64(generation)?,policy.7,policy.8,policy.1,policy.9,policy.10,policy.11,policy.12,policy.13,to_i64(policy.0)?,policy.3,i64::from(policy.4),i64::from(policy.5),policy.6,to_i64(now_unix_ms)?,to_i64(expires_unix_ms)?])?;
        let sql = format!(
            "SELECT {SOFTWARE_CLAIM_COLUMNS} FROM runner_software_update_claims WHERE id=?1"
        );
        let metadata = tx.query_row(&sql, [claim_id], software_claim_row)?;
        tx.commit()?;
        Ok(IssuedRunnerSoftwareUpdateClaim { metadata, token })
    }
    pub fn runner_software_update_claim_for_enrollment_token(
        &self,
        enrollment_token_id: &str,
    ) -> Result<Option<RunnerSoftwareUpdateClaim>, ControlPlaneError> {
        let connection = self.connection()?;
        let sql=format!("SELECT {SOFTWARE_CLAIM_COLUMNS} FROM runner_software_update_claims WHERE enrollment_token_id=?1");
        connection
            .query_row(&sql, [enrollment_token_id], software_claim_row)
            .optional()
            .map_err(Into::into)
    }
    #[cfg(test)]
    pub(crate) fn put_runner_update_release(
        &self,
        release: &RunnerUpdateRelease,
    ) -> Result<(), ControlPlaneError> {
        validate_update_release(release)?;
        let connection = self.connection()?;
        insert_update_release(&connection, release)
    }

    pub fn put_verified_runner_update_release(
        &self,
        registration: &VerifiedRunnerUpdateReleaseRegistration,
        now_unix_ms: u64,
    ) -> Result<(), ControlPlaneError> {
        let release = &registration.release;
        validate_update_release(release)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT trusted_state_json FROM runner_update_trust_states WHERE channel=?1",
                [&release.channel],
                |row| row.get(0),
            )
            .optional()?;
        let trusted = match (existing, &registration.bootstrap_trusted_state) {
            (Some(bytes), None) => runtrue_update::TrustedState::decode(bytes.as_bytes()),
            (None, Some(state)) => Ok(state.clone()),
            (Some(_), Some(_)) => {
                return Err(ControlPlaneError::InvalidInput(
                    "update trust is already initialized for this channel",
                ))
            }
            (None, None) => {
                return Err(ControlPlaneError::InvalidInput(
                    "first release for a channel requires a pinned bootstrap trust state",
                ))
            }
        }
        .map_err(|_| ControlPlaneError::InvalidInput("stored update trust state is invalid"))?;
        let verified = trusted
            .verify_release_metadata(
                &registration.bundle,
                &registration.target_path,
                now_unix_ms / 1_000,
            )
            .map_err(|_| ControlPlaneError::InvalidInput("signed update metadata was rejected"))?;
        release
            .profile
            .verify_signed_target(&verified.target)
            .map_err(|_| {
                ControlPlaneError::InvalidInput(
                    "signed component profile does not match the selected target",
                )
            })?;
        let root_digest =
            runtrue_update::root_envelope_digest(&verified.next_state.trusted_root)
                .map_err(|_| ControlPlaneError::InvalidInput("verified update root is invalid"))?;
        let targets_digest = ContentDigest::sha256(
            runtrue_update::canonical_bytes(&registration.bundle.targets).map_err(|_| {
                ControlPlaneError::InvalidInput("verified targets metadata is invalid")
            })?,
        );
        let snapshot_digest = ContentDigest::sha256(
            runtrue_update::canonical_bytes(&registration.bundle.snapshot).map_err(|_| {
                ControlPlaneError::InvalidInput("verified snapshot metadata is invalid")
            })?,
        );
        let timestamp_digest = ContentDigest::sha256(
            runtrue_update::canonical_bytes(&registration.bundle.timestamp).map_err(|_| {
                ControlPlaneError::InvalidInput("verified timestamp metadata is invalid")
            })?,
        );
        if release.update_root_digest != root_digest
            || release.targets_metadata_digest != targets_digest
            || release.snapshot_metadata_digest != snapshot_digest
            || release.timestamp_metadata_digest != timestamp_digest
        {
            return Err(ControlPlaneError::InvalidInput(
                "release metadata identities do not match the independently verified chain",
            ));
        }
        let state = String::from_utf8(verified.next_state.canonical_bytes().map_err(|_| {
            ControlPlaneError::InvalidInput("verified update trust state is invalid")
        })?)
        .map_err(|_| ControlPlaneError::InvalidInput("verified update trust state is not JSON"))?;
        tx.execute("INSERT INTO runner_update_trust_states(channel,update_root_digest,trusted_state_json,created_unix_ms,updated_unix_ms) VALUES(?1,?2,?3,?4,?4) ON CONFLICT(channel) DO UPDATE SET update_root_digest=excluded.update_root_digest,trusted_state_json=excluded.trusted_state_json,updated_unix_ms=excluded.updated_unix_ms",params![release.channel,root_digest.as_str(),state,to_i64(now_unix_ms)?])?;
        insert_update_release(&tx, release)?;
        tx.commit()?;
        Ok(())
    }

    pub fn put_runner_pool_update_policy(
        &self,
        policy: &RunnerPoolUpdatePolicy,
    ) -> Result<(), ControlPlaneError> {
        if policy.version == 0
            || policy.failure_threshold == 0
            || policy.protocol_min == 0
            || policy.protocol_max < policy.protocol_min
            || policy.rings.is_empty()
            || !crate::types::valid_update_windows(&policy.maintenance_windows)
        {
            return Err(ControlPlaneError::InvalidInput(
                "runner update policy bounds are invalid",
            ));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exact: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM runner_update_releases r JOIN runner_pool_templates t ON t.pool_id=?1 WHERE r.id=?2 AND r.revoked_unix_ms IS NULL AND r.channel=?3 AND r.protocol_min<=?4 AND r.protocol_max>=?5 AND t.runtime_compatibility_digest=?6 AND t.provider=?7 AND t.provider_template_id=?8 AND t.runner_template_digest=?9)",
            params![policy.pool_id,policy.release_id,policy.channel,i64::from(policy.protocol_max),i64::from(policy.protocol_min),policy.runtime_compatibility_digest.as_str(),policy.provider,policy.provider_template_id,policy.runner_template_digest.as_str()], |row| row.get(0))?;
        if !exact {
            return Err(ControlPlaneError::InvalidInput(
                "runner update policy has no exact signed release and pool template mapping",
            ));
        }
        let latest: u64 = tx.query_row(
            "SELECT COALESCE(MAX(version),0) FROM runner_pool_update_policies WHERE pool_id=?1",
            [&policy.pool_id],
            |row| u64_column(row, 0, "update policy version"),
        )?;
        if policy.version != latest.saturating_add(1) {
            return Err(ControlPlaneError::InvalidInput(
                "runner update policy version is not the next version",
            ));
        }
        tx.execute(
            "UPDATE runner_pool_update_policies SET enabled=0 WHERE pool_id=?1 AND enabled=1",
            [&policy.pool_id],
        )?;
        tx.execute("INSERT INTO runner_pool_update_policies(pool_id,version,enabled,release_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,channel,maintenance_window_json,rings_json,minimum_healthy,maximum_surge,maximum_unavailable,failure_threshold,required_attestation_grade,protocol_min,protocol_max,paused,created_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)", params![policy.pool_id,to_i64(policy.version)?,policy.enabled,policy.release_id,policy.runtime_compatibility_digest.as_str(),policy.provider,policy.provider_template_id,policy.runner_template_digest.as_str(),policy.channel,serde_json::to_string(&policy.maintenance_windows)?,serde_json::to_string(&policy.rings)?,i64::from(policy.minimum_healthy),i64::from(policy.maximum_surge),i64::from(policy.maximum_unavailable),i64::from(policy.failure_threshold),policy.required_attestation_grade,i64::from(policy.protocol_min),i64::from(policy.protocol_max),policy.paused,to_i64(policy.created_unix_ms)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn runner_replacements(
        &self,
        pool_id: &str,
    ) -> Result<Vec<RunnerReplacementRecord>, ControlPlaneError> {
        validate_text("runner replacement pool", pool_id)?;
        let connection = self.connection()?;
        let sql = format!("SELECT {REPLACEMENT_COLUMNS} FROM runner_replacements WHERE pool_id=?1 ORDER BY generation,id LIMIT 10000");
        let mut statement = connection.prepare(&sql)?;
        let values = statement
            .query_map([pool_id], replacement_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_autoscaled_runner_replacement(
        &self,
        pool_id: &str,
        source_runner_id: &str,
        replacement_id: &str,
        fleet_request_id: &str,
        owner_id: &str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> Result<PlannedRunnerReplacement, ControlPlaneError> {
        for (field, value) in [
            ("runner update pool", pool_id),
            ("source runner", source_runner_id),
            ("replacement id", replacement_id),
            ("replacement fleet request", fleet_request_id),
        ] {
            validate_text(field, value)?;
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_autoscaler_lease_tx(&tx, pool_id, owner_id, fencing_generation, now_unix_ms)?;
        let policy = tx.query_row(
            "SELECT version,release_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,channel,maximum_surge,maximum_unavailable,failure_threshold,protocol_min,protocol_max,json_array_length(rings_json),maintenance_window_json,minimum_healthy FROM runner_pool_update_policies WHERE pool_id=?1 AND enabled=1 AND paused=0 ORDER BY version DESC LIMIT 1",
            [pool_id], |row| Ok((u64_column(row,0,"policy version")?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,u64_column(row,7,"maximum surge")?,u64_column(row,8,"maximum unavailable")?,u64_column(row,9,"failure threshold")?,row.get::<_,u32>(10)?,row.get::<_,u32>(11)?,row.get::<_,u32>(12)?,row.get::<_,String>(13)?,u64_column(row,14,"minimum healthy")?)))
            .optional()?.ok_or(ControlPlaneError::InvalidInput("automatic runner updates are disabled or paused"))?;
        let windows: Vec<String> = serde_json::from_str(&policy.13)?;
        if !crate::types::update_window_allows(&windows, now_unix_ms) {
            return Err(ControlPlaneError::InvalidInput(
                "runner update is outside its UTC maintenance window",
            ));
        }
        let source = persisted_runner_tx(&tx, source_runner_id)?;
        if source.runner.pool_id != pool_id || source.runner.status != RunnerStatus::Online {
            return Err(ControlPlaneError::InvalidInput(
                "runner update source is not an online member of the pool",
            ));
        }
        let source_posture: String = tx.query_row(
            "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=?1",
            [source_runner_id],
            |row| row.get(0),
        )?;
        let source_fleet: Option<String> = tx
            .query_row(
                "SELECT id FROM runner_fleet_requests WHERE runner_id=?1 AND state='online'",
                [source_runner_id],
                |row| row.get(0),
            )
            .optional()?;
        let inflight:u64=tx.query_row("SELECT COUNT(*) FROM runner_replacements WHERE pool_id=?1 AND state IN('requested','claim-issued','enrolled','probationary','active','draining-source')",[pool_id],|row|u64_column(row,0,"inflight replacements"))?;
        let healthy: u64 = tx.query_row(
            "SELECT COUNT(*) FROM runners WHERE pool_id=?1 AND status='online'",
            [pool_id],
            |row| u64_column(row, 0, "healthy runners"),
        )?;
        let unavailable:u64=tx.query_row("SELECT COUNT(*) FROM runners WHERE pool_id=?1 AND status IN('offline','draining','quarantined','revoked')",[pool_id],|row|u64_column(row,0,"unavailable runners"))?;
        let completed_ring:i64=tx.query_row("SELECT COALESCE(MAX(rollout_ring),-1) FROM runner_replacements WHERE pool_id=?1 AND policy_version=?2 AND state='completed'",params![pool_id,to_i64(policy.0)?],|row|row.get(0))?;
        let rollout_ring =
            u32::try_from((completed_ring + 1).min(i64::from(policy.12.saturating_sub(1))))
                .unwrap_or(0);
        let failures:u64=tx.query_row("SELECT COUNT(*) FROM runner_replacements WHERE pool_id=?1 AND policy_version=?2 AND rollout_ring=?3 AND state='failed'",params![pool_id,to_i64(policy.0)?,i64::from(rollout_ring)],|row|u64_column(row,0,"replacement failures"))?;
        if failures >= policy.9 {
            tx.execute(
                "UPDATE runner_pool_update_policies SET paused=1 WHERE pool_id=?1 AND version=?2",
                params![pool_id, to_i64(policy.0)?],
            )?;
            tx.commit()?;
            return Err(ControlPlaneError::InvalidInput(
                "runner update rollout paused after reaching its ring failure threshold",
            ));
        }
        if inflight >= policy.7 || unavailable > policy.8 || healthy < policy.14 {
            return Err(ControlPlaneError::InvalidInput(
                "runner update rollout capacity bounds do not permit another replacement",
            ));
        }
        let release_ok:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM runner_update_releases WHERE id=?1 AND revoked_unix_ms IS NULL AND protocol_min<=?2 AND protocol_max>=?3)",params![policy.1,i64::from(policy.11),i64::from(policy.10)],|row|row.get(0))?;
        if !release_ok {
            return Err(ControlPlaneError::InvalidInput(
                "runner update release is revoked or protocol-incompatible",
            ));
        }
        let generation: u64 = tx.query_row(
            "SELECT COALESCE(MAX(generation),0)+1 FROM runner_replacements WHERE pool_id=?1",
            [pool_id],
            |row| u64_column(row, 0, "replacement generation"),
        )?;
        tx.execute("INSERT INTO runner_fleet_requests(id,pool_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,state,created_unix_ms,updated_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,'requested',?7,?7 WHERE EXISTS(SELECT 1 FROM runner_pool_templates WHERE pool_id=?2 AND runtime_compatibility_digest=?3 AND provider=?4 AND provider_template_id=?5 AND runner_template_digest=?6)",params![fleet_request_id,pool_id,policy.2,policy.3,policy.4,policy.5,to_i64(now_unix_ms)?])?;
        tx.execute("INSERT INTO runner_replacements(id,pool_id,mode,source_runner_id,source_posture_digest,source_fleet_request_id,target_fleet_request_id,generation,policy_version,release_id,channel,rollout_ring,state,created_unix_ms,updated_unix_ms) VALUES(?1,?2,'autoscaled',?3,?4,?5,?6,?7,?8,?9,?10,?11,'requested',?12,?12)",params![replacement_id,pool_id,source_runner_id,source_posture,source_fleet,fleet_request_id,to_i64(generation)?,to_i64(policy.0)?,policy.1,policy.6,i64::from(rollout_ring),to_i64(now_unix_ms)?])?;
        let request=tx.query_row("SELECT id,pool_id,runtime_compatibility_digest,provider,provider_template_id,runner_template_digest,state,provider_request_id,provider_instance_id,runner_id,failure_code,created_unix_ms,updated_unix_ms FROM runner_fleet_requests WHERE id=?1",[fleet_request_id],fleet_request_row)?;
        let sql = format!("SELECT {REPLACEMENT_COLUMNS} FROM runner_replacements WHERE id=?1");
        let replacement = tx.query_row(&sql, [replacement_id], replacement_row)?;
        tx.commit()?;
        Ok(PlannedRunnerReplacement {
            replacement,
            fleet_request: request,
        })
    }

    pub fn activate_runner_replacement(
        &self,
        replacement_id: &str,
        owner_id: &str,
        fencing_generation: u64,
        now_unix_ms: u64,
    ) -> Result<RunnerReplacementRecord, ControlPlaneError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sql = format!("SELECT {REPLACEMENT_COLUMNS} FROM runner_replacements WHERE id=?1");
        let replacement = tx
            .query_row(&sql, [replacement_id], replacement_row)
            .optional()?
            .ok_or_else(|| not_found("runner replacement", replacement_id))?;
        if replacement.mode == RunnerReplacementMode::Autoscaled {
            require_autoscaler_lease_tx(
                &tx,
                &replacement.pool_id,
                owner_id,
                fencing_generation,
                now_unix_ms,
            )?;
        }
        if replacement.state != RunnerReplacementState::Probationary {
            return Err(ControlPlaneError::InvalidTransition {
                entity: "runner replacement",
                from: replacement_state_name(replacement.state),
                to: "active",
            });
        }
        let target =
            replacement
                .target_runner_id
                .as_deref()
                .ok_or(ControlPlaneError::CorruptState(
                    "probationary replacement has no target runner".to_owned(),
                ))?;
        let posture =
            replacement
                .target_posture_digest
                .as_ref()
                .ok_or(ControlPlaneError::CorruptState(
                    "probationary replacement has no target posture".to_owned(),
                ))?;
        let persisted = persisted_runner_tx(&tx, target)?;
        let durable_posture: String = tx.query_row(
            "SELECT posture_digest FROM runner_enrollment_postures WHERE runner_id=?1",
            [target],
            |row| row.get(0),
        )?;
        if persisted.runner.status != RunnerStatus::Probationary
            || ContentDigest::parse(durable_posture)? != *posture
            || now_unix_ms.saturating_sub(persisted.runner.last_heartbeat_unix_ms) > 120_000
        {
            return Err(ControlPlaneError::InvalidInput(
                "replacement candidate has not passed current health and posture checks",
            ));
        }
        let mut target_runner = persisted.runner;
        target_runner.status = RunnerStatus::Online;
        if tx.execute("UPDATE runners SET status='online',runner_json=?2,updated_unix_ms=?3 WHERE id=?1 AND status='probationary'",params![target,serde_json::to_string(&target_runner)?,to_i64(now_unix_ms)?])? != 1 {
            return Err(ControlPlaneError::InvalidTransition { entity: "replacement candidate", from: "probationary", to: "online" });
        }
        let mut source = persisted_runner_tx(&tx, &replacement.source_runner_id)?;
        let final_state = if replacement.mode == RunnerReplacementMode::FixedHost {
            let open:u64=tx.query_row("SELECT COUNT(*) FROM leases WHERE runner_id=?1 AND state IN('offered','active','cancel_requested')",[&replacement.source_runner_id],|row|u64_column(row,0,"open leases"))?;
            if source.runner.status != RunnerStatus::Draining
                || source.runner.active_jobs != 0
                || open != 0
            {
                return Err(ControlPlaneError::InvalidInput(
                    "fixed-host source is not completely drained at activation",
                ));
            }
            source.runner.status = RunnerStatus::Revoked;
            if tx.execute("UPDATE runners SET status='revoked',runner_json=?2,updated_unix_ms=?3 WHERE id=?1 AND status='draining'",params![replacement.source_runner_id,serde_json::to_string(&source.runner)?,to_i64(now_unix_ms)?])? != 1 {
                return Err(ControlPlaneError::InvalidTransition { entity: "fixed-host source", from: "draining", to: "revoked" });
            }
            tx.execute("UPDATE runner_certificates SET status='revoked',revoked_unix_ms=?2 WHERE runner_id=?1 AND status IN('active','overlap')",params![replacement.source_runner_id,to_i64(now_unix_ms)?])?;
            let slot =
                replacement
                    .runner_slot_id
                    .as_deref()
                    .ok_or(ControlPlaneError::CorruptState(
                        "fixed replacement slot is missing".to_owned(),
                    ))?;
            if tx.execute("UPDATE runner_slots SET active_generation=?2,active_runner_id=?3,updated_unix_ms=?4 WHERE id=?1 AND active_generation<?2 AND active_runner_id=?5",params![slot,to_i64(replacement.generation)?,target,to_i64(now_unix_ms)?,replacement.source_runner_id])? != 1 {
                return Err(ControlPlaneError::InvalidInput("fixed-host slot generation or source changed before activation"));
            }
            RunnerReplacementState::Completed
        } else {
            source.runner.status = RunnerStatus::Draining;
            tx.execute("UPDATE runners SET status='draining',runner_json=?2,updated_unix_ms=?3 WHERE id=?1 AND status IN('online','offline')",params![replacement.source_runner_id,serde_json::to_string(&source.runner)?,to_i64(now_unix_ms)?])?;
            if let Some(request_id) = replacement.source_fleet_request_id.as_deref() {
                tx.execute("UPDATE runner_fleet_requests SET state='draining',updated_unix_ms=?2 WHERE id=?1 AND state='online'",params![request_id,to_i64(now_unix_ms)?])?;
            }
            RunnerReplacementState::DrainingSource
        };
        if tx.execute("UPDATE runner_replacements SET state=?2,updated_unix_ms=?3 WHERE id=?1 AND state='probationary'",params![replacement_id,replacement_state_name(final_state),to_i64(now_unix_ms)?])? != 1 {
            return Err(ControlPlaneError::InvalidTransition { entity: "runner replacement", from: "probationary", to: replacement_state_name(final_state) });
        }
        tx.commit()?;
        Ok(RunnerReplacementRecord {
            state: final_state,
            updated_unix_ms: now_unix_ms,
            ..replacement
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RunnerComponentProfile;
    use runtrue_workflow_ir::{Architecture, Isolation, OperatingSystem};
    use std::collections::BTreeSet;

    #[test]
    fn signed_policy_plans_one_fenced_exact_replacement_and_enriches_its_claim() {
        let control = ControlPlane::open_in_memory("runner-update-test", 1).unwrap();
        control
            .create_runner_pool(&RunnerPoolRecord {
                id: "pool-update".into(),
                tenant_id: "tenant-update".into(),
                name: "update".into(),
                region: None,
                status: RunnerPoolStatus::Active,
                created_unix_ms: 1,
            })
            .unwrap();
        let installed = ContentDigest::sha256(b"runner-v2");
        let compatibility = ContentDigest::sha256(b"compat-v2");
        control
            .upsert_runner_pool_template(&RunnerPoolTemplateRecord {
                pool_id: "pool-update".into(),
                runtime_compatibility_digest: compatibility.clone(),
                provider: "fake".into(),
                provider_template_id: "template-v2".into(),
                runner_template_digest: installed.clone(),
                created_unix_ms: 2,
                updated_unix_ms: 2,
            })
            .unwrap();
        let source = RunnerRecord {
            id: "runner-v1".into(),
            tenant_id: "tenant-update".into(),
            pool_id: "pool-update".into(),
            ephemeral: false,
            retired: false,
            os: OperatingSystem::Linux,
            arch: Architecture::Amd64,
            isolation_backends: BTreeSet::from([Isolation::Oci]),
            logical_cpus: 2,
            memory_bytes: 1024,
            storage_bytes: 2048,
            max_concurrent_wasm_jobs: 1,
            region: None,
            verified_capabilities: BTreeSet::new(),
            self_reported_capabilities: BTreeSet::new(),
            status: RunnerStatus::Online,
            active_jobs: 0,
            active_wasm_jobs: 0,
            used_cpus: 0,
            used_memory_bytes: 0,
            used_storage_bytes: 0,
            locality: BTreeSet::new(),
            package_tiers: Default::default(),
            last_heartbeat_unix_ms: 2,
        };
        control
            .register_runner_with_inventory(&source, &ContentDigest::sha256(b"inventory-v1"), 2)
            .unwrap();
        let profile = RunnerComponentProfile {
            component_name: "runtrue-runner".into(),
            release_version: "2.0.0".into(),
            artifact_name: "runtrue-runner".into(),
            artifact_length: 9,
            artifact_digest: installed.clone(),
            artifact_media_type: "application/octet-stream".into(),
            platform: "linux".into(),
            architecture: "amd64".into(),
            installed_digest: installed.clone(),
            runner_version: "2.0.0".into(),
            engine_version: "2.0.0".into(),
            protocol_min: 1,
            protocol_max: 1,
            package_format: "raw".into(),
            allowed_installation_paths: vec!["bin/runtrue-runner".into()],
            allowed_modes: vec![0o555],
        };
        let release = RunnerUpdateRelease {
            id: "release-v2".into(),
            channel: "stable".into(),
            component_profile_digest: profile.digest().unwrap(),
            update_root_digest: ContentDigest::sha256(b"root"),
            targets_metadata_digest: ContentDigest::sha256(b"targets"),
            snapshot_metadata_digest: ContentDigest::sha256(b"snapshot"),
            timestamp_metadata_digest: ContentDigest::sha256(b"timestamp"),
            profile,
            created_unix_ms: 3,
            revoked_unix_ms: None,
        };
        control.put_runner_update_release(&release).unwrap();
        control
            .put_runner_pool_update_policy(&RunnerPoolUpdatePolicy {
                pool_id: "pool-update".into(),
                version: 1,
                enabled: true,
                release_id: release.id.clone(),
                runtime_compatibility_digest: compatibility,
                provider: "fake".into(),
                provider_template_id: "template-v2".into(),
                runner_template_digest: installed,
                channel: "stable".into(),
                maintenance_windows: vec!["always".into()],
                rings: vec!["canary".into()],
                minimum_healthy: 1,
                maximum_surge: 1,
                maximum_unavailable: 0,
                failure_threshold: 1,
                required_attestation_grade: "provider-native".into(),
                protocol_min: 1,
                protocol_max: 1,
                paused: false,
                created_unix_ms: 4,
            })
            .unwrap();
        control
            .acquire_runner_autoscaler_lease("pool-update", "owner", 5, 1000)
            .unwrap();
        let planned = control
            .plan_autoscaled_runner_replacement(
                "pool-update",
                "runner-v1",
                "replace-v2",
                "fleet-v2",
                "owner",
                1,
                6,
            )
            .unwrap();
        assert_eq!(planned.replacement.generation, 1);
        control
            .transition_runner_fleet_request(
                "fleet-v2",
                RunnerFleetRequestState::Requested,
                RunnerFleetRequestState::Provisioning,
                Some("provider-request"),
                None,
                None,
                None,
                "owner",
                1,
                7,
            )
            .unwrap();
        let issued = control
            .create_runner_launch_claim(
                "fleet-v2",
                "instance-v2",
                &ContentDigest::sha256(b"identity"),
                "owner",
                1,
                8,
                608,
            )
            .unwrap();
        let bound = control
            .runner_software_update_claim_for_enrollment_token(&issued.metadata.enrollment_token_id)
            .unwrap()
            .unwrap();
        assert_eq!(bound.replacement_id, "replace-v2");
        assert_eq!(bound.installed_digest, release.profile.installed_digest);
        assert_eq!(
            control.runner_replacements("pool-update").unwrap()[0].state,
            RunnerReplacementState::ClaimIssued
        );
    }
}
