use super::*;
use crate::{sensitive::KEY_BYTES, MasterKey, SecretPlaintext};

const NOW: u64 = 1_000_000;

fn identity() -> SecretIdentity {
    SecretIdentity::new("tenant-a", "repository:repo-a", "release-token").unwrap()
}

fn vault() -> SecretVault {
    SecretVault::new("local-kek-v1", MasterKey::from_bytes([7_u8; KEY_BYTES])).unwrap()
}

fn request(identity: SecretIdentity, suffix: &str) -> SecretLeaseRequest {
    SecretLeaseRequest {
        identity,
        version: None,
        execution_lease_id: "execution-lease-a".to_owned(),
        fencing_generation: 1,
        step_id: format!("step-{suffix}"),
        purpose: format!("purpose-{suffix}"),
        expires_at_unix_ms: NOW + 10_000,
    }
}

#[test]
fn tampering_payload_or_wrapped_dek_fails_authentication() {
    let identity = identity();
    let plaintext = SecretPlaintext::new(b"correct horse battery staple".to_vec());
    let master_key = MasterKey::from_bytes([1_u8; KEY_BYTES]);
    let encrypted =
        EncryptedSecretVersion::encrypt(identity, 1, &plaintext, "kek-1", &master_key).unwrap();

    let mut payload_tamper = encrypted.clone();
    payload_tamper.payload.ciphertext[0] ^= 0x80;
    assert!(matches!(
        payload_tamper.decrypt(&master_key),
        Err(SecretsError::AuthenticationFailed)
    ));

    let mut dek_tamper = encrypted;
    dek_tamper.wrapped_dek.ciphertext[0] ^= 0x01;
    assert!(matches!(
        dek_tamper.decrypt(&master_key),
        Err(SecretsError::AuthenticationFailed)
    ));
}

#[test]
fn tenant_scope_name_and_version_are_all_authenticated() {
    let plaintext = SecretPlaintext::new(b"aad-bound-value".to_vec());
    let master_key = MasterKey::from_bytes([2_u8; KEY_BYTES]);
    let encrypted =
        EncryptedSecretVersion::encrypt(identity(), 1, &plaintext, "kek-1", &master_key).unwrap();

    let mut wrong_tenant = encrypted.clone();
    wrong_tenant.identity.tenant_id = "tenant-b".to_owned();
    let mut wrong_scope = encrypted.clone();
    wrong_scope.identity.scope = "repository:repo-b".to_owned();
    let mut wrong_name = encrypted.clone();
    wrong_name.identity.name = "different-secret".to_owned();
    let mut wrong_version = encrypted;
    wrong_version.version = 2;

    for changed in [wrong_tenant, wrong_scope, wrong_name, wrong_version] {
        assert!(matches!(
            changed.decrypt(&master_key),
            Err(SecretsError::AuthenticationFailed)
        ));
    }
}

#[test]
fn wrong_master_key_cannot_unwrap_the_dek() {
    let plaintext = SecretPlaintext::new(b"master-key-bound".to_vec());
    let encrypted = EncryptedSecretVersion::encrypt(
        identity(),
        1,
        &plaintext,
        "kek-1",
        &MasterKey::from_bytes([3_u8; KEY_BYTES]),
    )
    .unwrap();

    assert!(matches!(
        encrypted.decrypt(&MasterKey::from_bytes([4_u8; KEY_BYTES])),
        Err(SecretsError::AuthenticationFailed)
    ));
}

#[test]
fn encrypted_snapshot_round_trips_and_authenticates_before_restore() {
    let identity = identity();
    let key = MasterKey::from_bytes([5_u8; KEY_BYTES]);
    let mut vault = SecretVault::new("local-kek-v1", key).unwrap();
    vault
        .create_secret(
            identity.clone(),
            &SecretPlaintext::new(b"snapshot-value".to_vec()),
        )
        .unwrap();
    vault
        .add_version(
            &identity,
            &SecretPlaintext::new(b"snapshot-value-v2".to_vec()),
        )
        .unwrap();
    let snapshot = vault.snapshot();
    assert!(!format!("{snapshot:?}").contains("snapshot-value"));
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    assert!(!bytes
        .windows(b"snapshot-value".len())
        .any(|window| window == b"snapshot-value"));

    let restored = SecretVault::from_snapshot(
        serde_json::from_slice(&bytes).unwrap(),
        MasterKey::from_bytes([5_u8; KEY_BYTES]),
    )
    .unwrap();
    assert_eq!(restored.metadata(&identity).unwrap().current_version, 2);
    assert_eq!(
        restored
            .reveal_for_administration(&identity, None)
            .unwrap()
            .as_bytes(),
        b"snapshot-value-v2"
    );
    assert!(matches!(
        SecretVault::from_snapshot(
            serde_json::from_slice(&bytes).unwrap(),
            MasterKey::from_bytes([6_u8; KEY_BYTES]),
        ),
        Err(SecretsError::AuthenticationFailed)
    ));
}

#[test]
fn kek_rotation_rewraps_deks_without_rewriting_payloads() {
    let identity = identity();
    let plaintext = SecretPlaintext::new(b"rotate-without-reencrypt".to_vec());
    let mut vault = vault();
    vault.create_secret(identity.clone(), &plaintext).unwrap();
    vault
        .add_version(&identity, &SecretPlaintext::new(b"version-two".to_vec()))
        .unwrap();
    let before = (1..=2)
        .map(|version| {
            let encrypted = vault.encrypted_version(&identity, version).unwrap();
            (encrypted.payload.clone(), encrypted.wrapped_dek.clone())
        })
        .collect::<Vec<_>>();

    vault
        .rotate_kek("local-kek-v2", MasterKey::from_bytes([8_u8; KEY_BYTES]))
        .unwrap();
    assert_eq!(vault.kek_id(), "local-kek-v2");
    for (index, version) in (1..=2).enumerate() {
        let encrypted = vault.encrypted_version(&identity, version).unwrap();
        assert_eq!(encrypted.payload.nonce, before[index].0.nonce);
        assert_eq!(encrypted.payload.ciphertext, before[index].0.ciphertext);
        assert_ne!(encrypted.wrapped_dek.nonce, before[index].1.nonce);
        assert_ne!(encrypted.wrapped_dek.ciphertext, before[index].1.ciphertext);
        assert_eq!(encrypted.kek_id(), "local-kek-v2");
        assert!(matches!(
            encrypted.decrypt(&MasterKey::from_bytes([7_u8; KEY_BYTES])),
            Err(SecretsError::AuthenticationFailed)
        ));
    }

    vault
        .set_active_fencing_generation("execution-lease-a", 1)
        .unwrap();
    let lease = vault.issue_lease(request(identity, "rotate"), NOW).unwrap();
    let released = vault
        .redeem_lease(
            &lease.id,
            "execution-lease-a",
            1,
            "step-rotate",
            "purpose-rotate",
            NOW,
        )
        .unwrap();
    assert_eq!(released.as_bytes(), b"version-two");
}

#[test]
fn versions_are_randomized_immutable_and_tombstones_are_final() {
    let identity = identity();
    let plaintext = SecretPlaintext::new(b"same-plaintext".to_vec());
    let mut vault = vault();
    vault.create_secret(identity.clone(), &plaintext).unwrap();
    let version_one = vault.encrypted_version(&identity, 1).unwrap().clone();
    vault.add_version(&identity, &plaintext).unwrap();
    let version_two = vault.encrypted_version(&identity, 2).unwrap().clone();

    assert_ne!(version_one.payload.nonce, version_two.payload.nonce);
    assert_ne!(
        version_one.payload.ciphertext,
        version_two.payload.ciphertext
    );
    assert_ne!(
        version_one.wrapped_dek.ciphertext,
        version_two.wrapped_dek.ciphertext
    );
    assert_eq!(vault.encrypted_version(&identity, 1).unwrap(), &version_one);

    vault
        .set_active_fencing_generation("execution-lease-a", 1)
        .unwrap();
    let lease = vault
        .issue_lease(request(identity.clone(), "tombstone"), NOW)
        .unwrap();
    let metadata = vault.tombstone(&identity).unwrap();
    assert_eq!(metadata.status, SecretStatus::Tombstoned);
    assert_eq!(metadata.current_version, 2);
    assert!(matches!(
        vault.add_version(&identity, &plaintext),
        Err(SecretsError::SecretTombstoned(_))
    ));
    assert_eq!(
        vault.lease_metadata(&lease.id).unwrap().state,
        LeaseState::Revoked
    );
    assert!(matches!(
        vault.issue_lease(request(identity, "after-tombstone"), NOW),
        Err(SecretsError::SecretTombstoned(_))
    ));
}

#[test]
fn leases_are_one_use_and_exactly_step_and_purpose_bound() {
    let identity = identity();
    let marker = b"lease-only-plaintext".to_vec();
    let mut vault = vault();
    vault
        .create_secret(identity.clone(), &SecretPlaintext::new(marker.clone()))
        .unwrap();
    vault
        .set_active_fencing_generation("execution-lease-a", 1)
        .unwrap();
    let lease = vault
        .issue_lease(request(identity, "release"), NOW)
        .unwrap();

    assert!(matches!(
        vault.redeem_lease(
            &lease.id,
            "execution-lease-a",
            1,
            "wrong-step",
            "purpose-release",
            NOW,
        ),
        Err(SecretsError::LeaseBindingMismatch { field: "step_id" })
    ));
    assert!(matches!(
        vault.redeem_lease(
            &lease.id,
            "execution-lease-a",
            1,
            "step-release",
            "wrong-purpose",
            NOW,
        ),
        Err(SecretsError::LeaseBindingMismatch { field: "purpose" })
    ));
    let released = vault
        .redeem_lease(
            &lease.id,
            "execution-lease-a",
            1,
            "step-release",
            "purpose-release",
            NOW,
        )
        .unwrap();
    assert_eq!(released.as_bytes(), marker);
    assert_eq!(
        vault.lease_metadata(&lease.id).unwrap().state,
        LeaseState::Consumed
    );
    assert!(matches!(
        vault.redeem_lease(
            &lease.id,
            "execution-lease-a",
            1,
            "step-release",
            "purpose-release",
            NOW,
        ),
        Err(SecretsError::LeaseAlreadyConsumed(_))
    ));
}

#[test]
fn expiry_revocation_and_fencing_fail_closed() {
    let identity = identity();
    let mut vault = vault();
    vault
        .create_secret(identity.clone(), &SecretPlaintext::new(b"fenced".to_vec()))
        .unwrap();
    vault
        .set_active_fencing_generation("execution-lease-a", 1)
        .unwrap();

    let mut expiry_request = request(identity.clone(), "expiry");
    expiry_request.expires_at_unix_ms = NOW + 1;
    let expired = vault.issue_lease(expiry_request, NOW).unwrap();
    assert!(matches!(
        vault.redeem_lease(
            &expired.id,
            "execution-lease-a",
            1,
            "step-expiry",
            "purpose-expiry",
            NOW + 1,
        ),
        Err(SecretsError::LeaseExpired(_))
    ));
    assert_eq!(
        vault.lease_metadata(&expired.id).unwrap().state,
        LeaseState::Expired
    );

    let revoked = vault
        .issue_lease(request(identity.clone(), "revoked"), NOW)
        .unwrap();
    vault.revoke_lease(&revoked.id).unwrap();
    vault.revoke_lease(&revoked.id).unwrap();
    assert!(matches!(
        vault.redeem_lease(
            &revoked.id,
            "execution-lease-a",
            1,
            "step-revoked",
            "purpose-revoked",
            NOW,
        ),
        Err(SecretsError::LeaseRevoked(_))
    ));

    let fenced = vault
        .issue_lease(request(identity.clone(), "fenced"), NOW)
        .unwrap();
    vault
        .set_active_fencing_generation("execution-lease-a", 2)
        .unwrap();
    assert!(matches!(
        vault.redeem_lease(
            &fenced.id,
            "execution-lease-a",
            1,
            "step-fenced",
            "purpose-fenced",
            NOW,
        ),
        Err(SecretsError::StaleFencingGeneration {
            active: 2,
            provided: 1
        })
    ));
    let old_generation = request(identity, "old-generation");
    assert!(matches!(
        vault.issue_lease(old_generation, NOW),
        Err(SecretsError::StaleFencingGeneration {
            active: 2,
            provided: 1
        })
    ));
    assert_eq!(
        vault.set_active_fencing_generation("execution-lease-a", 1),
        Err(SecretsError::FencingGenerationRegression {
            current: 2,
            proposed: 1
        })
    );
}

#[test]
fn serializable_and_debuggable_surfaces_never_contain_plaintext_or_keys() {
    let marker = "PLAINTEXT-MUST-NEVER-APPEAR";
    let identity = identity();
    let plaintext = SecretPlaintext::new(marker.as_bytes().to_vec());
    let mut vault = vault();
    let metadata = vault.create_secret(identity.clone(), &plaintext).unwrap();
    let encrypted = vault.encrypted_version(&identity, 1).unwrap();

    for rendered in [
        serde_json::to_string(&metadata).unwrap(),
        serde_json::to_string(encrypted).unwrap(),
        format!("{metadata:?}"),
        format!("{encrypted:?}"),
        format!("{plaintext:?}"),
        format!("{:?}", MasterKey::from_bytes([9_u8; KEY_BYTES])),
        format!("{vault:?}"),
    ] {
        assert!(!rendered.contains(marker), "plaintext leaked in {rendered}");
        assert!(!rendered.contains(&"09".repeat(KEY_BYTES)));
    }
    assert_eq!(format!("{plaintext:?}"), "SecretPlaintext([REDACTED])");
}
