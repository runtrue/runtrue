use super::*;

fn grant() -> OidcGrant {
    OidcGrant {
        grant_id: "grant-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        repository_id: "repo-1".to_owned(),
        run_id: "run-1".to_owned(),
        job_id: "build".to_owned(),
        step_id: "publish".to_owned(),
        capsule_digest: ContentDigest::sha256(b"capsule"),
        execution_lease_id: "lease-1".to_owned(),
        fencing_generation: 4,
        trust: "protected_branch".to_owned(),
        runner_pool_id: Some("pool-1".to_owned()),
        environment: Some("production".to_owned()),
        ref_name: Some("refs/heads/main".to_owned()),
        source_commit: "a".repeat(40),
        approval_subject_digest: Some(ContentDigest::sha256(b"approval")),
        runner_posture_digest: Some(ContentDigest::sha256(b"posture")),
        allowed_audiences: BTreeSet::from([
            "https://cloud.example".to_owned(),
            "https://vault.example".to_owned(),
        ]),
        expires_unix_seconds: 1000,
    }
}

fn issuer() -> OidcIssuer {
    OidcIssuer::new(
        "https://runtrue.example".to_owned(),
        OidcSigningKey::from_seed([9; 32]),
    )
    .expect("issuer")
}

fn request() -> MintTokenRequest {
    MintTokenRequest {
        audience: "https://cloud.example".to_owned(),
        ttl_seconds: 300,
    }
}

fn indexed_signing_key(index: u16) -> OidcSigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&index.to_le_bytes());
    OidcSigningKey::from_seed(seed)
}

fn sign_claims(key: &OidcSigningKey, claims: &JwtClaims) -> String {
    let header = JwtHeader {
        algorithm: JWT_ALGORITHM.to_owned(),
        token_type: JWT_TYPE.to_owned(),
        key_id: key.verifying_key().key_id().to_string(),
    };
    let header =
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).expect("serialize header"));
    let claims =
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(claims).expect("serialize claims"));
    let signing_input = format!("{header}.{claims}");
    let signature = Base64UrlUnpadded::encode_string(&key.sign(signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

#[test]
fn mints_and_verifies_exact_step_and_lease_bound_claims() {
    let issuer = issuer();
    let token = issuer.mint(&grant(), &request(), 100).expect("mint");
    let claims = verify_token(
        &token.token,
        &issuer.signing_key.verifying_key(),
        issuer.issuer(),
        &grant(),
        "https://cloud.example",
        200,
    )
    .expect("verify");
    assert_eq!(
        claims.runtrue_capsule_digest,
        ContentDigest::sha256(b"capsule")
    );
    assert_eq!(claims.runtrue_execution_lease_id, "lease-1");
    assert_eq!(claims.runtrue_fencing_generation, 4);
    assert_eq!(claims.runtrue_step_id, "publish");
    assert_eq!(claims.expires_unix_seconds, 400);
    assert_eq!(
        claims.subject,
        "repo:repo-1:run:run-1:job:build:step:publish"
    );
}

#[test]
fn audience_and_ttl_cannot_exceed_the_authorized_grant() {
    let issuer = issuer();
    let mut denied = request();
    "https://other.example".clone_into(&mut denied.audience);
    assert!(matches!(
        issuer.mint(&grant(), &denied, 100),
        Err(OidcError::AudienceNotGranted)
    ));
    let mut oversized = request();
    oversized.ttl_seconds = MAX_TOKEN_TTL_SECONDS + 1;
    assert!(matches!(
        issuer.mint(&grant(), &oversized, 100),
        Err(OidcError::InvalidTtl)
    ));
}

#[test]
fn signature_tampering_is_rejected() {
    let issuer = issuer();
    let minted = issuer.mint(&grant(), &request(), 100).expect("mint");
    let mut parts = minted
        .token
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut signature = Base64UrlUnpadded::decode_vec(&parts[2]).expect("decode");
    signature[0] ^= 1;
    parts[2] = Base64UrlUnpadded::encode_string(&signature);
    let tampered = parts.join(".");
    assert!(matches!(
        verify_token(
            &tampered,
            &issuer.signing_key.verifying_key(),
            issuer.issuer(),
            &grant(),
            "https://cloud.example",
            200
        ),
        Err(OidcError::InvalidSignature(_))
    ));
}

#[test]
fn time_window_and_grant_expiry_are_enforced() {
    let issuer = issuer();
    let minted = issuer.mint(&grant(), &request(), 100).expect("mint");
    for now in [99, minted.expires_unix_seconds] {
        assert!(matches!(
            verify_token(
                &minted.token,
                &issuer.signing_key.verifying_key(),
                issuer.issuer(),
                &grant(),
                "https://cloud.example",
                now
            ),
            Err(OidcError::TokenExpiredOrNotYetValid)
        ));
    }
    let mut expired = grant();
    expired.expires_unix_seconds = 100;
    assert!(matches!(
        issuer.mint(&expired, &request(), 100),
        Err(OidcError::GrantExpired)
    ));
}

#[test]
fn changed_fence_or_step_invalidates_an_otherwise_valid_token() {
    let issuer = issuer();
    let minted = issuer.mint(&grant(), &request(), 100).expect("mint");
    let mut changed = grant();
    changed.fencing_generation = 5;
    assert!(matches!(
        verify_token(
            &minted.token,
            &issuer.signing_key.verifying_key(),
            issuer.issuer(),
            &changed,
            "https://cloud.example",
            200
        ),
        Err(OidcError::ClaimMismatch)
    ));
    changed = grant();
    "other".clone_into(&mut changed.step_id);
    assert!(matches!(
        verify_token(
            &minted.token,
            &issuer.signing_key.verifying_key(),
            issuer.issuer(),
            &changed,
            "https://cloud.example",
            200
        ),
        Err(OidcError::ClaimMismatch)
    ));
}

#[test]
fn signing_material_and_compact_token_are_redacted_from_debug() {
    let issuer = issuer();
    let minted = issuer.mint(&grant(), &request(), 100).expect("mint");
    assert_eq!(
        format!("{:?}", issuer.signing_key),
        "OidcSigningKey([REDACTED])"
    );
    assert!(!format!("{issuer:?}").contains(&minted.token));
    assert!(!format!("{minted:?}").contains(&minted.token));
    assert_eq!(format!("{minted}"), "MintedOidcToken([REDACTED])");
}

#[test]
fn jwks_exposes_only_the_public_ed25519_key() {
    let issuer = issuer();
    let jwks = issuer.jwks();
    assert_eq!(jwks.keys.len(), 1);
    let jwk = &jwks.keys[0];
    assert_eq!(jwk.algorithm, "EdDSA");
    assert_eq!(jwk.curve, "Ed25519");
    let public = Base64UrlUnpadded::decode_vec(&jwk.x).expect("public key");
    assert_eq!(public, issuer.signing_key.verifying_key().to_bytes());
    assert!(!serde_json::to_string(&jwks).expect("json").contains("seed"));
}

#[test]
fn issuer_requires_https_except_for_explicit_loopback_development() {
    assert!(OidcIssuer::new(
        "http://runtrue.example".to_owned(),
        OidcSigningKey::from_seed([1; 32])
    )
    .is_err());
    assert!(OidcIssuer::new(
        "http://localhost.evil.example".to_owned(),
        OidcSigningKey::from_seed([1; 32])
    )
    .is_err());
    assert!(OidcIssuer::new(
        "http://127.0.0.1:8080".to_owned(),
        OidcSigningKey::from_seed([1; 32])
    )
    .is_ok());
    assert!(OidcIssuer::new(
        "https://runtrue.example/?x=1".to_owned(),
        OidcSigningKey::from_seed([1; 32])
    )
    .is_err());
}

#[test]
fn normal_rotation_publishes_both_keys_only_for_the_bounded_overlap() {
    let mut issuer = issuer();
    let old_token = issuer.mint(&grant(), &request(), 100).expect("old token");
    let old_key_id = old_token.key_id.clone();

    let rotation = issuer
        .rotate_signing_key(
            OidcSigningKey::from_seed([10; 32]),
            150,
            DEFAULT_SIGNING_KEY_OVERLAP_SECONDS,
        )
        .expect("rotate");
    let new_token = issuer.mint(&grant(), &request(), 150).expect("new token");
    assert_eq!(rotation.generation, 2);
    assert_eq!(rotation.previous_key_id, old_key_id);
    assert_eq!(rotation.active_key_id, new_token.key_id);
    assert_eq!(rotation.previous_key_publish_until_unix_seconds, Some(1050));
    assert!(!rotation.emergency);

    let overlap_jwks = issuer.jwks_at(200).expect("overlap JWKS");
    assert_eq!(overlap_jwks.keys.len(), 2);
    assert_eq!(overlap_jwks.keys[0].key_id, new_token.key_id.to_string());
    assert_eq!(overlap_jwks.keys[1].key_id, old_key_id.to_string());
    issuer
        .verify(&old_token.token, &grant(), "https://cloud.example", 200)
        .expect("old token remains valid during overlap");
    issuer
        .verify(&new_token.token, &grant(), "https://cloud.example", 200)
        .expect("new token valid");
    verify_token_with_jwks(
        &old_token.token,
        &overlap_jwks,
        issuer.issuer(),
        &grant(),
        "https://cloud.example",
        200,
    )
    .expect("JWKS verifier selects retired key by kid");

    let expired_jwks = issuer.jwks_at(1050).expect("post-overlap JWKS");
    assert_eq!(expired_jwks.keys.len(), 1);
    assert!(matches!(
        issuer.verify(&old_token.token, &grant(), "https://cloud.example", 1050),
        Err(OidcError::SigningKeyOutsideValidityWindow)
    ));
    assert_eq!(
        issuer
            .prune_expired_signing_keys(1050)
            .expect("prune expired key"),
        1
    );
    assert_eq!(issuer.key_ring_generation(), 3);
    assert!(issuer.key_ring_snapshot().retired.is_empty());
}

#[test]
fn emergency_rotation_revokes_the_previous_key_immediately() {
    let mut issuer = issuer();
    let old_token = issuer.mint(&grant(), &request(), 100).expect("old token");
    let rotation = issuer
        .emergency_rotate_signing_key(OidcSigningKey::from_seed([10; 32]), 150)
        .expect("emergency rotation");
    assert!(rotation.emergency);
    assert_eq!(rotation.previous_key_publish_until_unix_seconds, None);
    assert_eq!(issuer.jwks_at(150).expect("JWKS").keys.len(), 1);
    assert!(matches!(
        issuer.verify(&old_token.token, &grant(), "https://cloud.example", 151),
        Err(OidcError::SigningKeyRevoked)
    ));
    let snapshot = issuer.key_ring_snapshot();
    assert_eq!(snapshot.revoked.len(), 1);
    assert_eq!(snapshot.revoked[0].key_id, old_token.key_id);
    assert!(snapshot.retired.is_empty());
}

#[test]
fn explicit_revocation_removes_a_retired_key_and_is_durable() {
    let mut issuer = issuer();
    let old_token = issuer.mint(&grant(), &request(), 100).expect("old token");
    issuer
        .rotate_signing_key(
            OidcSigningKey::from_seed([10; 32]),
            150,
            DEFAULT_SIGNING_KEY_OVERLAP_SECONDS,
        )
        .expect("rotate");
    let revocation = issuer
        .revoke_retired_signing_key(&old_token.key_id, 160)
        .expect("revoke retired key");
    assert_eq!(revocation.generation, 3);
    assert_eq!(issuer.jwks_at(160).expect("JWKS").keys.len(), 1);
    assert!(matches!(
        issuer.verify(&old_token.token, &grant(), "https://cloud.example", 161),
        Err(OidcError::SigningKeyRevoked)
    ));
    assert!(matches!(
        issuer.revoke_retired_signing_key(&old_token.key_id, 161),
        Err(OidcError::SigningKeyRevoked)
    ));
    assert!(matches!(
        issuer.revoke_retired_signing_key(&issuer.active_key_id(), 161),
        Err(OidcError::CannotRevokeActiveSigningKey)
    ));

    let snapshot =
        OidcKeyRingSnapshot::from_json(&issuer.key_ring_snapshot_json().expect("snapshot JSON"))
            .expect("parse snapshot");
    let restored =
        OidcIssuer::from_key_ring_snapshot(OidcSigningKey::from_seed([10; 32]), snapshot)
            .expect("restore");
    assert!(matches!(
        restored.verify(&old_token.token, &grant(), "https://cloud.example", 162),
        Err(OidcError::SigningKeyRevoked)
    ));
}

#[test]
fn live_key_history_is_bounded_without_silent_eviction() {
    let mut issuer = OidcIssuer::new_at(
        "https://runtrue.example".to_owned(),
        indexed_signing_key(0),
        100,
    )
    .expect("issuer");
    for index in 1..=MAX_RETAINED_SIGNING_KEYS {
        issuer
            .rotate_signing_key(
                indexed_signing_key(u16::try_from(index).expect("small index")),
                100,
                DEFAULT_SIGNING_KEY_OVERLAP_SECONDS,
            )
            .expect("rotation within history bound");
    }
    assert_eq!(issuer.jwks_at(100).expect("JWKS").keys.len(), 9);
    let before = issuer.key_ring_snapshot();
    assert!(matches!(
        issuer.rotate_signing_key(indexed_signing_key(100), 100, 900),
        Err(OidcError::SigningKeyHistoryFull)
    ));
    assert_eq!(issuer.key_ring_snapshot(), before);

    issuer
        .rotate_signing_key(indexed_signing_key(100), 1000, 900)
        .expect("expired history can be atomically replaced");
    assert_eq!(issuer.key_ring_snapshot().retired.len(), 1);
}

#[test]
fn revocation_tombstones_are_bounded_without_mutating_on_failure() {
    let mut issuer = OidcIssuer::new("https://runtrue.example".to_owned(), indexed_signing_key(0))
        .expect("issuer");
    for index in 1..=MAX_REVOKED_SIGNING_KEY_IDS {
        issuer
            .emergency_rotate_signing_key(
                indexed_signing_key(u16::try_from(index).expect("small index")),
                u64::try_from(index).expect("small timestamp"),
            )
            .expect("rotation within revocation bound");
    }
    let before = issuer.key_ring_snapshot();
    assert_eq!(before.revoked.len(), MAX_REVOKED_SIGNING_KEY_IDS);
    assert!(matches!(
        issuer.emergency_rotate_signing_key(indexed_signing_key(100), 100),
        Err(OidcError::SigningKeyRevocationHistoryFull)
    ));
    assert_eq!(issuer.key_ring_snapshot(), before);
}

#[test]
fn key_ring_snapshot_round_trips_and_checks_private_key_continuity() {
    let mut issuer = OidcIssuer::new_at(
        "https://runtrue.example".to_owned(),
        indexed_signing_key(1),
        50,
    )
    .expect("issuer");
    issuer.set_maximum_ttl_seconds(300).expect("configure TTL");
    let old_token = issuer.mint(&grant(), &request(), 100).expect("old token");
    issuer
        .rotate_signing_key(indexed_signing_key(2), 150, 600)
        .expect("rotate");
    let json = issuer.key_ring_snapshot_json().expect("snapshot JSON");
    assert!(!String::from_utf8_lossy(&json).contains("seed"));
    let parsed = OidcKeyRingSnapshot::from_json(&json).expect("parse snapshot");
    assert_eq!(parsed, issuer.key_ring_snapshot());

    let restored = OidcIssuer::from_key_ring_snapshot(indexed_signing_key(2), parsed.clone())
        .expect("restore matching private key");
    assert_eq!(
        restored.jwks_at(200).expect("restored JWKS"),
        issuer.jwks_at(200).expect("original JWKS")
    );
    restored
        .verify(&old_token.token, &grant(), "https://cloud.example", 200)
        .expect("restored retired key verifies overlap token");
    assert!(matches!(
        OidcIssuer::from_key_ring_snapshot(indexed_signing_key(3), parsed.clone()),
        Err(OidcError::SigningKeyContinuityMismatch)
    ));

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&json);
    assert!(matches!(
        OidcKeyRingSnapshot::from_json(&noncanonical),
        Err(OidcError::NonCanonicalKeyRingSnapshot)
    ));
    let mut tampered = parsed.clone();
    tampered.active.public_key =
        Base64UrlUnpadded::encode_string(&indexed_signing_key(3).verifying_key().to_bytes());
    assert!(matches!(
        tampered.to_json(),
        Err(OidcError::SigningKeyContinuityMismatch)
    ));
    let mut unsupported = parsed;
    unsupported.schema_version = KEY_RING_SNAPSHOT_VERSION + 1;
    assert!(matches!(
        unsupported.to_json(),
        Err(OidcError::UnsupportedKeyRingSnapshotVersion)
    ));
}

#[test]
fn strict_jwks_parsing_and_selection_fail_closed() {
    let issuer = issuer();
    let token = issuer.mint(&grant(), &request(), 100).expect("token");
    let json = issuer.jwks().to_json().expect("JWKS JSON");
    let jwks = JwkSet::from_json(&json).expect("parse JWKS");
    verify_token_with_jwks(
        &token.token,
        &jwks,
        issuer.issuer(),
        &grant(),
        "https://cloud.example",
        200,
    )
    .expect("verify with exact kid");

    let mut malformed_unrelated = jwks.clone();
    let mut invalid = indexed_signing_key(1).verifying_key().jwk();
    "RS256".clone_into(&mut invalid.algorithm);
    malformed_unrelated.keys.push(invalid);
    assert!(matches!(
        verify_token_with_jwks(
            &token.token,
            &malformed_unrelated,
            issuer.issuer(),
            &grant(),
            "https://cloud.example",
            200
        ),
        Err(OidcError::InvalidJwk)
    ));

    let mut duplicate = jwks.clone();
    duplicate.keys.push(jwks.keys[0].clone());
    assert!(matches!(
        duplicate.to_json(),
        Err(OidcError::DuplicateSigningKey)
    ));
    let other_issuer =
        OidcIssuer::new("https://runtrue.example".to_owned(), indexed_signing_key(2))
            .expect("other issuer");
    let other_token = other_issuer
        .mint(&grant(), &request(), 100)
        .expect("other token");
    assert!(matches!(
        verify_token_with_jwks(
            &other_token.token,
            &jwks,
            issuer.issuer(),
            &grant(),
            "https://cloud.example",
            200
        ),
        Err(OidcError::UnknownSigningKey)
    ));
    assert!(matches!(
        JwkSet::from_json(&vec![b' '; MAX_JWKS_BYTES + 1]),
        Err(OidcError::JwksTooLarge)
    ));
    assert!(matches!(
        JwkSet::from_json(br#"{"keys":[],"unexpected":true}"#),
        Err(OidcError::Json(_))
    ));
}

#[test]
fn discovery_document_is_exact_and_size_bounded() {
    let issuer = issuer();
    let document = issuer.discovery_document();
    let json = document.to_json().expect("discovery JSON");
    assert_eq!(
        OidcDiscoveryDocument::from_json(&json, issuer.issuer()).expect("parse discovery"),
        document
    );
    assert_eq!(document.jwks_uri, "https://runtrue.example/jwks.json");
    assert_eq!(document.token_endpoint, "https://runtrue.example/token");

    let mut wrong_endpoint = document.clone();
    "https://attacker.example/jwks.json".clone_into(&mut wrong_endpoint.jwks_uri);
    assert!(matches!(
        wrong_endpoint.validate(issuer.issuer()),
        Err(OidcError::InvalidDiscoveryDocument)
    ));
    let mut wrong_algorithm = document;
    wrong_algorithm.id_token_signing_alg_values_supported = vec!["RS256".to_owned()];
    assert!(matches!(
        wrong_algorithm.validate(issuer.issuer()),
        Err(OidcError::InvalidDiscoveryDocument)
    ));
    assert!(matches!(
        OidcDiscoveryDocument::from_json(
            &vec![b' '; MAX_DISCOVERY_DOCUMENT_BYTES + 1],
            issuer.issuer()
        ),
        Err(OidcError::DiscoveryDocumentTooLarge)
    ));
    assert!(matches!(
        OidcDiscoveryDocument::from_json(
            br#"{"issuer":"https://runtrue.example","unexpected":true}"#,
            issuer.issuer()
        ),
        Err(OidcError::Json(_))
    ));
}

#[test]
fn lifecycle_windows_and_global_token_lifetime_fail_closed() {
    let active_key = OidcSigningKey::from_seed([9; 32]);
    let mut issuer = OidcIssuer::new_at(
        "https://runtrue.example".to_owned(),
        OidcSigningKey::from_seed([9; 32]),
        100,
    )
    .expect("issuer");
    assert!(matches!(
        issuer.mint(&grant(), &request(), 99),
        Err(OidcError::SigningKeyClockRollback)
    ));
    let before_activation_claims = JwtClaims::from_grant(
        issuer.issuer(),
        &grant(),
        "https://cloud.example".to_owned(),
        99,
        200,
        "before-activation".to_owned(),
    );
    let before_activation = sign_claims(&active_key, &before_activation_claims);
    assert!(matches!(
        issuer.verify(&before_activation, &grant(), "https://cloud.example", 150),
        Err(OidcError::SigningKeyOutsideValidityWindow)
    ));

    issuer
        .rotate_signing_key(
            OidcSigningKey::from_seed([10; 32]),
            200,
            DEFAULT_SIGNING_KEY_OVERLAP_SECONDS,
        )
        .expect("rotate");
    let after_retirement_claims = JwtClaims::from_grant(
        issuer.issuer(),
        &grant(),
        "https://cloud.example".to_owned(),
        201,
        300,
        "after-retirement".to_owned(),
    );
    let after_retirement = sign_claims(&active_key, &after_retirement_claims);
    assert!(matches!(
        issuer.verify(&after_retirement, &grant(), "https://cloud.example", 250),
        Err(OidcError::SigningKeyOutsideValidityWindow)
    ));

    let mut long_grant = grant();
    long_grant.expires_unix_seconds = 5000;
    let excessive_lifetime_claims = JwtClaims::from_grant(
        "https://runtrue.example",
        &long_grant,
        "https://cloud.example".to_owned(),
        100,
        100 + MAX_TOKEN_TTL_SECONDS + 1,
        "excessive-lifetime".to_owned(),
    );
    let excessive_lifetime = sign_claims(&active_key, &excessive_lifetime_claims);
    assert!(matches!(
        verify_token(
            &excessive_lifetime,
            &active_key.verifying_key(),
            "https://runtrue.example",
            &long_grant,
            "https://cloud.example",
            200
        ),
        Err(OidcError::InvalidTokenLifetime)
    ));
}

#[test]
fn rejected_rotation_and_exhausted_prune_are_atomic() {
    let mut issuer = issuer();
    let initial = issuer.key_ring_snapshot();
    assert!(matches!(
        issuer.rotate_signing_key(
            OidcSigningKey::from_seed([10; 32]),
            100,
            MAX_TOKEN_TTL_SECONDS - 1
        ),
        Err(OidcError::InvalidSigningKeyOverlap)
    ));
    assert_eq!(issuer.key_ring_snapshot(), initial);
    assert!(matches!(
        issuer.rotate_signing_key(OidcSigningKey::from_seed([9; 32]), 100, 900),
        Err(OidcError::DuplicateSigningKey)
    ));
    assert_eq!(issuer.key_ring_snapshot(), initial);

    issuer
        .rotate_signing_key(OidcSigningKey::from_seed([10; 32]), 100, 900)
        .expect("valid rotation");
    let after_rotation = issuer.key_ring_snapshot();
    assert!(matches!(
        issuer.rotate_signing_key(OidcSigningKey::from_seed([11; 32]), 99, 900),
        Err(OidcError::SigningKeyClockRollback)
    ));
    assert_eq!(issuer.key_ring_snapshot(), after_rotation);

    let mut exhausted_snapshot = after_rotation;
    exhausted_snapshot.generation = u64::MAX;
    let mut exhausted =
        OidcIssuer::from_key_ring_snapshot(OidcSigningKey::from_seed([10; 32]), exhausted_snapshot)
            .expect("restore exhausted generation");
    let before_prune = exhausted.key_ring_snapshot();
    assert!(matches!(
        exhausted.prune_expired_signing_keys(1000),
        Err(OidcError::SigningKeyGenerationExhausted)
    ));
    assert_eq!(exhausted.key_ring_snapshot(), before_prune);
}
