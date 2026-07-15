#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMetadata {
    pub version: u64,
    pub sha256: ContentDigest,
}

impl TrustedMetadata {
    fn from_envelope<T: Serialize>(
        version: u64,
        envelope: &SignedEnvelope<T>,
    ) -> Result<Self, UpdateError> {
        let bytes = canonical_bytes(envelope)?;
        Ok(Self {
            version,
            sha256: ContentDigest::sha256(bytes),
        })
    }

    fn check_no_rollback<T: Serialize>(
        &self,
        version: u64,
        envelope: &SignedEnvelope<T>,
        role: RoleType,
    ) -> Result<(), UpdateError> {
        if version < self.version {
            return Err(UpdateError::MetadataRollback(role));
        }
        if version == self.version {
            let candidate = Self::from_envelope(version, envelope)?;
            if candidate.sha256 != self.sha256 {
                return Err(UpdateError::SameVersionMetadataChanged(role));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedState {
    pub schema_version: u32,
    pub trusted_root: SignedEnvelope<RootMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<TrustedMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<TrustedMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TrustedMetadata>,
}

impl TrustedState {
    pub fn bootstrap(
        root: SignedEnvelope<RootMetadata>,
        expected_root_digest: &ContentDigest,
        now_unix_seconds: u64,
    ) -> Result<Self, UpdateError> {
        if &root_envelope_digest(&root)? != expected_root_digest {
            return Err(UpdateError::UnpinnedBootstrapRoot);
        }
        root.signed.validate_at(now_unix_seconds)?;
        verify_role_threshold(&root, &root.signed, RoleType::Root, false)?;
        Ok(Self {
            schema_version: UPDATE_SCHEMA_VERSION,
            trusted_root: root,
            targets: None,
            snapshot: None,
            timestamp: None,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UpdateError> {
        self.validate_structure()?;
        canonical_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, UpdateError> {
        let state: Self = decode_canonical(bytes, MAX_TRUST_STATE_BYTES)?;
        state.validate_structure()?;
        Ok(state)
    }

    pub fn verify_release(
        &self,
        bundle: &ReleaseBundle,
        target_path: &str,
        target_bytes: &[u8],
        now_unix_seconds: u64,
    ) -> Result<VerifiedRelease, UpdateError> {
        self.validate_structure()?;
        if bundle.root_rotations.len() > MAX_ROOT_ROTATIONS {
            return Err(UpdateError::TooManyRootRotations);
        }
        let mut next = self.clone();
        for root in &bundle.root_rotations {
            next.rotate_root(root.clone(), now_unix_seconds)?;
        }
        next.trusted_root.signed.validate_at(now_unix_seconds)?;

        bundle.timestamp.signed.validate_at(now_unix_seconds)?;
        verify_role_threshold(
            &bundle.timestamp,
            &next.trusted_root.signed,
            RoleType::Timestamp,
            false,
        )?;
        if let Some(trusted) = &next.timestamp {
            trusted.check_no_rollback(
                bundle.timestamp.signed.header.version,
                &bundle.timestamp,
                RoleType::Timestamp,
            )?;
        }

        bundle.snapshot.signed.validate_at(now_unix_seconds)?;
        verify_role_threshold(
            &bundle.snapshot,
            &next.trusted_root.signed,
            RoleType::Snapshot,
            false,
        )?;
        bundle
            .timestamp
            .signed
            .snapshot
            .verify(bundle.snapshot.signed.header.version, &bundle.snapshot)?;
        if let Some(trusted) = &next.snapshot {
            trusted.check_no_rollback(
                bundle.snapshot.signed.header.version,
                &bundle.snapshot,
                RoleType::Snapshot,
            )?;
        }

        bundle.targets.signed.validate_at(now_unix_seconds)?;
        verify_role_threshold(
            &bundle.targets,
            &next.trusted_root.signed,
            RoleType::Targets,
            false,
        )?;
        bundle
            .snapshot
            .signed
            .targets
            .verify(bundle.targets.signed.header.version, &bundle.targets)?;
        if let Some(trusted) = &next.targets {
            trusted.check_no_rollback(
                bundle.targets.signed.header.version,
                &bundle.targets,
                RoleType::Targets,
            )?;
        }

        validate_chain_times(
            &next.trusted_root.signed.header,
            &bundle.targets.signed.header,
            &bundle.snapshot.signed.header,
            &bundle.timestamp.signed.header,
        )?;
        let normalized = normalize_relative_path(target_path)
            .map_err(|_| UpdateError::UnsafeTargetPath(target_path.to_owned()))?;
        if normalized != target_path || target_path.len() > MAX_STRING_BYTES {
            return Err(UpdateError::UnsafeTargetPath(target_path.to_owned()));
        }
        let target = bundle
            .targets
            .signed
            .targets
            .get(target_path)
            .ok_or_else(|| UpdateError::TargetNotFound(target_path.to_owned()))?;
        target.verify_bytes(target_bytes)?;

        next.timestamp = Some(TrustedMetadata::from_envelope(
            bundle.timestamp.signed.header.version,
            &bundle.timestamp,
        )?);
        next.snapshot = Some(TrustedMetadata::from_envelope(
            bundle.snapshot.signed.header.version,
            &bundle.snapshot,
        )?);
        next.targets = Some(TrustedMetadata::from_envelope(
            bundle.targets.signed.header.version,
            &bundle.targets,
        )?);
        Ok(VerifiedRelease {
            next_state: next,
            target_path: target_path.to_owned(),
            target: target.clone(),
        })
    }

    fn rotate_root(
        &mut self,
        candidate: SignedEnvelope<RootMetadata>,
        now_unix_seconds: u64,
    ) -> Result<(), UpdateError> {
        candidate.signed.validate_at(now_unix_seconds)?;
        let expected = self
            .trusted_root
            .signed
            .header
            .version
            .checked_add(1)
            .ok_or(UpdateError::VersionOverflow)?;
        if candidate.signed.header.version != expected {
            return Err(UpdateError::NonSequentialRootRotation {
                expected,
                actual: candidate.signed.header.version,
            });
        }
        verify_role_threshold(&candidate, &self.trusted_root.signed, RoleType::Root, true)?;
        verify_role_threshold(&candidate, &candidate.signed, RoleType::Root, true)?;
        let authorized = self
            .trusted_root
            .signed
            .roles
            .get(&RoleType::Root)
            .ok_or(UpdateError::MissingRoleAssignment(RoleType::Root))?
            .key_ids
            .union(
                &candidate
                    .signed
                    .roles
                    .get(&RoleType::Root)
                    .ok_or(UpdateError::MissingRoleAssignment(RoleType::Root))?
                    .key_ids,
            )
            .cloned()
            .collect::<BTreeSet<_>>();
        if candidate
            .signatures
            .iter()
            .any(|signature| !authorized.contains(&signature.key_id))
        {
            return Err(UpdateError::SignatureKeyNotAuthorized);
        }
        self.trusted_root = candidate;
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), UpdateError> {
        if self.schema_version != UPDATE_SCHEMA_VERSION {
            return Err(UpdateError::InvalidTrustedState);
        }
        self.trusted_root.signed.validate_structure()?;
        verify_role_threshold(
            &self.trusted_root,
            &self.trusted_root.signed,
            RoleType::Root,
            true,
        )?;
        for metadata in [&self.targets, &self.snapshot, &self.timestamp]
            .into_iter()
            .flatten()
        {
            if metadata.version == 0 {
                return Err(UpdateError::InvalidTrustedState);
            }
        }
        Ok(())
    }
}

use crate::{
    canonical_bytes, decode_canonical, root_envelope_digest, validate_chain_times,
    verify_role_threshold, ReleaseBundle, RoleType, RootMetadata, SignedEnvelope, UpdateError,
    VerifiedRelease, MAX_ROOT_ROTATIONS, MAX_STRING_BYTES, MAX_TRUST_STATE_BYTES,
    UPDATE_SCHEMA_VERSION,
};
use runtrue_model::{normalize_relative_path, ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
