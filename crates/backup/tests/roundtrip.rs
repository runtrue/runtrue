use runtrue_attest::CapsuleSigningKey;
use runtrue_audit::{AuditEventData, AuditPrincipal, AuditResource};
use runtrue_backup::{
    activate_restore, create_backup, restore_backup, verify_backup, ActivateRestoreRequest,
    BackupError, BackupLimits, BackupSourcePaths, CreateBackupRequest, LocalSecuritySeed,
    RestoreBackupRequest, VerifyBackupRequest,
};
use runtrue_control_plane::{
    BackupPinRecord, ControlPlane, CreateRunRequest, NewJob, RepositoryRecord, RunnerPoolRecord,
    RunnerPoolStatus, SecretMetadataReference, SignedCapsuleRecord,
};
use runtrue_git::{GitTreeEntry, GitTreeEntryKind, GitTreeManifest, GIT_TREE_MANIFEST_VERSION};
use runtrue_model::ContentDigest;
use runtrue_scheduler::{RunnerRecord, RunnerStatus, SchedulingRequirements};
use runtrue_secrets::{MasterKey, SecretPlaintext};
use runtrue_storage::{CasLimits, FsCas};
use runtrue_workflow_ir::{
    ApprovalRequirements, Architecture, CapsuleContext, ExecutionCapsule, Isolation,
    OperatingSystem, ParityGrade, PermissionSet, PlannedJob, RunnerRequirements, Trust,
    WorkflowIdentity, CAPSULE_SCHEMA_VERSION, ENGINE_COMPATIBILITY_VERSION,
};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;
use zeroize::Zeroize as _;

const NOW: u64 = 10_000;

#[test]
fn authoritative_backup_pin_must_exist_in_archived_cas() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let blobs = directory.path().join("blobs");
    let missing_backup = directory.path().join("missing-backup");
    let complete_backup = directory.path().join("complete-backup");
    let control = ControlPlane::open(&database, "backup-roots", NOW).unwrap();
    let digest = ContentDigest::sha256(b"authoritative backup root");
    control
        .create_backup_pin(&BackupPinRecord {
            id: "pin-1".to_owned(),
            tenant_id: None,
            root_kind: "object".to_owned(),
            root_id: "backup-epoch".to_owned(),
            object_digest: digest.clone(),
            created_unix_ms: NOW,
            expires_unix_ms: None,
            released_unix_ms: None,
        })
        .unwrap();
    drop(control);
    let cas = FsCas::open(blobs.join("cas"), CasLimits::default()).unwrap();
    let missing = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: database.clone(),
            blobs: Some(blobs.clone()),
            config: None,
            key_ciphertext: None,
        },
        destination: missing_backup.clone(),
        local_security_seed: None,
        created_unix_ms: NOW + 1,
        limits: BackupLimits::default(),
    });
    assert!(
        matches!(missing, Err(BackupError::InvalidManifest(_))),
        "{missing:?}"
    );
    assert!(!missing_backup.exists());

    let stored = cas.put_bytes(b"authoritative backup root").unwrap();
    assert_eq!(stored.digest, digest);
    create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database,
            blobs: Some(blobs),
            config: None,
            key_ciphertext: None,
        },
        destination: complete_backup.clone(),
        local_security_seed: None,
        created_unix_ms: NOW + 2,
        limits: BackupLimits::default(),
    })
    .unwrap();
    verify_backup(VerifyBackupRequest {
        backup: complete_backup,
        local_security_seed: None,
        limits: BackupLimits::default(),
    })
    .unwrap();
}

#[test]
fn authoritative_source_graph_requires_every_reachable_blob() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let blobs = directory.path().join("blobs");
    let incomplete_backup = directory.path().join("incomplete-backup");
    let complete_backup = directory.path().join("complete-backup");
    let cas = FsCas::open(blobs.join("cas"), CasLimits::default()).unwrap();
    let file_bytes = b"exact source file";
    let file_digest = ContentDigest::sha256(file_bytes);
    let manifest = GitTreeManifest {
        version: GIT_TREE_MANIFEST_VERSION,
        repository_id: "repo-graph".to_owned(),
        commit: "a".repeat(40),
        entries: vec![GitTreeEntry {
            path: "src/lib.rs".to_owned(),
            kind: GitTreeEntryKind::File {
                digest: file_digest.clone(),
                size_bytes: file_bytes.len() as u64,
                executable: false,
            },
        }],
    };
    let manifest_object = cas.put_bytes(&manifest.canonical_bytes().unwrap()).unwrap();
    let control = ControlPlane::open(&database, "backup-source-graph", NOW).unwrap();
    control
        .create_backup_pin(&BackupPinRecord {
            id: "source-pin".to_owned(),
            tenant_id: None,
            root_kind: "source".to_owned(),
            root_id: "replay-source".to_owned(),
            object_digest: manifest_object.digest,
            created_unix_ms: NOW,
            expires_unix_ms: None,
            released_unix_ms: None,
        })
        .unwrap();
    drop(control);

    let incomplete = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: database.clone(),
            blobs: Some(blobs.clone()),
            config: None,
            key_ciphertext: None,
        },
        destination: incomplete_backup.clone(),
        local_security_seed: None,
        created_unix_ms: NOW + 1,
        limits: BackupLimits::default(),
    });
    assert!(matches!(incomplete, Err(BackupError::Lifecycle(_))));
    assert!(!incomplete_backup.exists());

    assert_eq!(cas.put_bytes(file_bytes).unwrap().digest, file_digest);
    create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database,
            blobs: Some(blobs),
            config: None,
            key_ciphertext: None,
        },
        destination: complete_backup.clone(),
        local_security_seed: None,
        created_unix_ms: NOW + 2,
        limits: BackupLimits::default(),
    })
    .unwrap();
    verify_backup(VerifyBackupRequest {
        backup: complete_backup,
        local_security_seed: None,
        limits: BackupLimits::default(),
    })
    .unwrap();
}

#[test]
fn artifact_root_must_be_a_verified_artifact_record_not_just_present_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("control.sqlite");
    let blobs = directory.path().join("blobs");
    let backup = directory.path().join("backup");
    let cas = FsCas::open(blobs.join("cas"), CasLimits::default()).unwrap();
    let invalid_record = cas
        .put_bytes(br#"{"content":"not-an-artifact-record"}"#)
        .unwrap();
    let control = ControlPlane::open(&database, "backup-artifact-record", NOW).unwrap();
    control
        .create_backup_pin(&BackupPinRecord {
            id: "artifact-pin".to_owned(),
            tenant_id: None,
            root_kind: "artifact".to_owned(),
            root_id: "release-artifact".to_owned(),
            object_digest: invalid_record.digest,
            created_unix_ms: NOW,
            expires_unix_ms: None,
            released_unix_ms: None,
        })
        .unwrap();
    drop(control);

    let result = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database,
            blobs: Some(blobs),
            config: None,
            key_ciphertext: None,
        },
        destination: backup.clone(),
        local_security_seed: None,
        created_unix_ms: NOW + 1,
        limits: BackupLimits::default(),
    });
    assert!(matches!(result, Err(BackupError::Lifecycle(_))));
    assert!(!backup.exists());
}

struct Fixture {
    _directory: TempDir,
    database: std::path::PathBuf,
    blobs: std::path::PathBuf,
    config: std::path::PathBuf,
    keys: std::path::PathBuf,
    backup: std::path::PathBuf,
    restore: std::path::PathBuf,
    seed: LocalSecuritySeed,
    lease_id: String,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("source.sqlite");
    let blobs = directory.path().join("source-blobs");
    let config = directory.path().join("source-config");
    let keys = directory.path().join("source-keys");
    fs::create_dir(&blobs).unwrap();
    fs::create_dir(&config).unwrap();
    fs::create_dir(&keys).unwrap();
    fs::write(blobs.join("blob-one"), b"durable blob").unwrap();
    fs::write(config.join("server.toml"), b"listen = '127.0.0.1:8080'\n").unwrap();
    fs::write(keys.join("wrapped-key.bin"), b"ciphertext only").unwrap();

    let raw_seed = [7_u8; 32];
    let lease_id = populate_database(&database, &raw_seed);
    Fixture {
        backup: directory.path().join("backup"),
        restore: directory.path().join("restore"),
        _directory: directory,
        database,
        blobs,
        config,
        keys,
        seed: LocalSecuritySeed::from_bytes(raw_seed),
        lease_id,
    }
}

fn populate_database(path: &Path, security_seed: &[u8; 32]) -> String {
    let control = ControlPlane::open(path, "installation-backup", NOW).unwrap();
    control
        .create_repository(&RepositoryRecord {
            id: "repo-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            owner: "octo".to_owned(),
            name: "backup".to_owned(),
            default_branch: "main".to_owned(),
            visibility: "private".to_owned(),
            created_unix_ms: NOW,
        })
        .unwrap();
    let capsule = execution_capsule();
    let mut capsule_seed = derive_security_seed(security_seed, b"capsule-signing");
    let signing_key = CapsuleSigningKey::from_seed(capsule_seed);
    capsule_seed.zeroize();
    let signature = signing_key.sign_capsule(&capsule).unwrap();
    control
        .store_signed_capsule(
            &SignedCapsuleRecord {
                id: "capsule-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                digest: signature.capsule_digest.clone(),
                canonical_capsule: capsule.canonical_bytes().unwrap(),
                signature,
                created_unix_ms: NOW,
            },
            &signing_key.verifying_key(),
        )
        .unwrap();
    control
        .create_runner_pool(&RunnerPoolRecord {
            id: "pool-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            name: "backup".to_owned(),
            region: None,
            status: RunnerPoolStatus::Active,
            created_unix_ms: NOW,
        })
        .unwrap();
    control
        .register_runner_with_inventory(
            &runner(),
            &ContentDigest::sha256(b"backup runner inventory"),
            NOW,
        )
        .unwrap();
    control
        .create_run_idempotent(
            "run-key",
            &CreateRunRequest {
                id: "run-1".to_owned(),
                repository_id: "repo-1".to_owned(),
                capsule_id: "capsule-1".to_owned(),
                priority: 0,
                remote: true,
                created_unix_ms: NOW,
                jobs: vec![NewJob {
                    id: "job-1".to_owned(),
                    job_key: "build".to_owned(),
                    attempt: 1,
                    requirements: requirements(),
                }],
            },
        )
        .unwrap();
    let lease = control
        .offer_next_lease_for_runner("runner-1", NOW + 2)
        .unwrap();
    let lease = lease.unwrap();
    control
        .accept_lease(
            &lease.id,
            "runner-1",
            lease.fencing_generation,
            lease.installation_fencing_epoch,
            NOW + 3,
        )
        .unwrap();

    let mut secret_seed = derive_security_seed(security_seed, b"secret-vault");
    let master_key = MasterKey::from_bytes(secret_seed);
    secret_seed.zeroize();
    control
        .create_secret_idempotent(
            "secret-key",
            &SecretMetadataReference {
                id: "secret-1".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                scope: "repository:repo-1".to_owned(),
                name: "token".to_owned(),
                provider: "built-in".to_owned(),
                provider_reference: None,
                secret_type: "opaque".to_owned(),
                status: "active".to_owned(),
                current_version: Some(1),
                created_unix_ms: NOW,
                updated_unix_ms: NOW,
            },
            Some(&SecretPlaintext::new(b"backup secret".to_vec())),
            &master_key,
        )
        .unwrap();
    control
        .append_audit_event(AuditEventData {
            observed_unix_ms: NOW,
            tenant_id: "tenant-1".to_owned(),
            actor: AuditPrincipal {
                kind: "operator".to_owned(),
                id: "backup-test".to_owned(),
            },
            action: "backup.test".to_owned(),
            resource: AuditResource {
                kind: "installation".to_owned(),
                id: "installation-backup".to_owned(),
            },
            result: "success".to_owned(),
            request_id: "request-1".to_owned(),
            decision_id: None,
            metadata: BTreeMap::new(),
        })
        .unwrap();
    lease.id
}

#[test]
fn online_backup_restore_fences_stale_leases_and_requires_explicit_activation() {
    let fixture = fixture();
    let created = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: fixture.database.clone(),
            blobs: Some(fixture.blobs.clone()),
            config: Some(fixture.config.clone()),
            key_ciphertext: Some(fixture.keys.clone()),
        },
        destination: fixture.backup.clone(),
        local_security_seed: Some(&fixture.seed),
        created_unix_ms: NOW + 10,
        limits: BackupLimits::default(),
    })
    .unwrap();
    assert!(created.local_key_continuity_verified);
    assert_eq!(created.fencing_epoch, 1);
    assert!(created.entry_count >= 4);
    let verified = verify_backup(VerifyBackupRequest {
        backup: fixture.backup.clone(),
        local_security_seed: Some(&fixture.seed),
        limits: BackupLimits::default(),
    })
    .unwrap();
    assert_eq!(verified.manifest_digest, created.manifest_digest);

    let restored = restore_backup(RestoreBackupRequest {
        backup: fixture.backup.clone(),
        target: fixture.restore.clone(),
        local_security_seed: Some(&fixture.seed),
        restored_unix_ms: NOW + 20,
        limits: BackupLimits::default(),
    })
    .unwrap();
    assert!(restored.safe_mode);
    assert_eq!(restored.source_fencing_epoch, 1);
    assert_eq!(restored.restored_fencing_epoch, 2);
    assert_eq!(
        fs::read(fixture.restore.join("blobs/blob-one")).unwrap(),
        b"durable blob"
    );
    let control = ControlPlane::open(
        fixture.restore.join("control-plane.sqlite"),
        "installation-backup",
        NOW + 21,
    )
    .unwrap();
    assert!(control.recovery_state().unwrap().safe_mode);
    assert_eq!(
        control.lease(&fixture.lease_id).unwrap().state,
        runtrue_scheduler::LeaseState::Expired
    );
    assert_eq!(
        control.jobs_for_run("run-1").unwrap()[0].status,
        runtrue_lifecycle::JobState::Lost
    );
    drop(control);

    assert!(matches!(
        activate_restore(ActivateRestoreRequest {
            target: fixture.restore.clone(),
            local_security_seed: Some(&fixture.seed),
            expected_fencing_epoch: 2,
            verification_acknowledged: false,
            limits: BackupLimits::default(),
        }),
        Err(BackupError::ActivationAcknowledgementRequired)
    ));
    let activated = activate_restore(ActivateRestoreRequest {
        target: fixture.restore.clone(),
        local_security_seed: Some(&fixture.seed),
        expected_fencing_epoch: 2,
        verification_acknowledged: true,
        limits: BackupLimits::default(),
    })
    .unwrap();
    assert!(!activated.safe_mode);
    assert_eq!(activated.fencing_epoch, 2);
}

#[test]
fn tampering_wrong_keys_and_nonempty_restore_targets_fail_closed() {
    let fixture = fixture();
    create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: fixture.database.clone(),
            blobs: Some(fixture.blobs.clone()),
            config: None,
            key_ciphertext: None,
        },
        destination: fixture.backup.clone(),
        local_security_seed: Some(&fixture.seed),
        created_unix_ms: NOW,
        limits: BackupLimits::default(),
    })
    .unwrap();
    let wrong_seed = LocalSecuritySeed::from_bytes([8_u8; 32]);
    assert!(matches!(
        verify_backup(VerifyBackupRequest {
            backup: fixture.backup.clone(),
            local_security_seed: Some(&wrong_seed),
            limits: BackupLimits::default(),
        }),
        Err(BackupError::KeyContinuityMismatch)
    ));

    fs::create_dir(&fixture.restore).unwrap();
    fs::write(fixture.restore.join("occupied"), b"do not overwrite").unwrap();
    assert!(matches!(
        restore_backup(RestoreBackupRequest {
            backup: fixture.backup.clone(),
            target: fixture.restore.clone(),
            local_security_seed: Some(&fixture.seed),
            restored_unix_ms: NOW,
            limits: BackupLimits::default(),
        }),
        Err(BackupError::DestinationNotEmpty(_))
    ));
    assert_eq!(
        fs::read(fixture.restore.join("occupied")).unwrap(),
        b"do not overwrite"
    );

    fs::write(fixture.backup.join("blobs/blob-one"), b"tampered").unwrap();
    assert!(matches!(
        verify_backup(VerifyBackupRequest {
            backup: fixture.backup,
            local_security_seed: Some(&fixture.seed),
            limits: BackupLimits::default(),
        }),
        Err(BackupError::DigestMismatch(_))
    ));
}

#[cfg(unix)]
#[test]
fn symlinks_and_special_files_are_rejected_without_leaving_a_backup() {
    use std::os::unix::{fs::symlink, net::UnixListener};

    let fixture = fixture();
    symlink(fixture.blobs.join("blob-one"), fixture.blobs.join("link")).unwrap();
    let error = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: fixture.database.clone(),
            blobs: Some(fixture.blobs.clone()),
            config: None,
            key_ciphertext: None,
        },
        destination: fixture.backup.clone(),
        local_security_seed: Some(&fixture.seed),
        created_unix_ms: NOW,
        limits: BackupLimits::default(),
    })
    .unwrap_err();
    assert!(matches!(error, BackupError::UnsupportedFileType(_)));
    assert!(!fixture.backup.exists());

    fs::remove_file(fixture.blobs.join("link")).unwrap();
    let _socket = UnixListener::bind(fixture.blobs.join("socket")).unwrap();
    let error = create_backup(CreateBackupRequest {
        source: BackupSourcePaths {
            database: fixture.database,
            blobs: Some(fixture.blobs),
            config: None,
            key_ciphertext: None,
        },
        destination: fixture.backup.clone(),
        local_security_seed: Some(&fixture.seed),
        created_unix_ms: NOW,
        limits: BackupLimits::default(),
    })
    .unwrap_err();
    assert!(matches!(error, BackupError::UnsupportedFileType(_)));
    assert!(!fixture.backup.exists());
}

fn execution_capsule() -> ExecutionCapsule {
    ExecutionCapsule {
        schema_version: CAPSULE_SCHEMA_VERSION,
        engine_compatibility_version: ENGINE_COMPATIBILITY_VERSION.to_owned(),
        compiler_version: "backup-test".to_owned(),
        workflow: WorkflowIdentity {
            name: "backup".to_owned(),
            digest: ContentDigest::sha256(b"workflow"),
            source_path: ".runtrue/workflows/ci.yaml".to_owned(),
        },
        context: CapsuleContext {
            source_commit: "a".repeat(40),
            source_tree_digest: None,
            base_commit: None,
            source_trust: Default::default(),
            normalized_event_digest: ContentDigest::sha256(b"event"),
            normalized_event_json: None,
            scm: None,
            event_context: BTreeMap::new(),
            lockfile_digest: None,
            workflow_frontend: None,
            policy_version_ids: Vec::new(),
        },
        variables: BTreeMap::new(),
        permissions: PermissionSet::default(),
        jobs: vec![PlannedJob {
            id: "build".to_owned(),
            base_id: "build".to_owned(),
            name: "build".to_owned(),
            needs: Vec::new(),
            matrix: BTreeMap::new(),
            condition: None,
            trust: Trust::UntrustedOk,
            environment: None,
            runner: RunnerRequirements {
                os: OperatingSystem::Linux,
                arch: Architecture::Amd64,
                isolation: Isolation::Microvm,
                image: None,
                cpu: 1,
                memory_bytes: 1_024,
                storage_bytes: Some(1_024),
                region: None,
                capabilities: Vec::new(),
            },
            permissions: PermissionSet::default(),
            timeout_ms: 60_000,
            retries: 0,
            concurrency: None,
            variables: BTreeMap::new(),
            services: Vec::new(),
            steps: Vec::new(),
            finalizers: Vec::new(),
            finalizer_timeout_ms: 120_000,
            value_outputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }],
        dynamic_jobs: Vec::new(),
        approval: ApprovalRequirements {
            workflow_definition: false,
            privileged_execution: false,
            reasons: Vec::new(),
        },
        expected_parity: ParityGrade::AExact,
    }
}

fn requirements() -> SchedulingRequirements {
    SchedulingRequirements {
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation: Isolation::Microvm,
        cpu: 1,
        memory_bytes: 1_024,
        storage_bytes: 1_024,
        region: None,
        required_capabilities: Default::default(),
        allowed_pools: Default::default(),
    }
}

fn runner() -> RunnerRecord {
    RunnerRecord {
        id: "runner-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        ephemeral: false,
        retired: false,
        os: OperatingSystem::Linux,
        arch: Architecture::Amd64,
        isolation_backends: [Isolation::Microvm].into_iter().collect(),
        logical_cpus: 2,
        memory_bytes: 4_096,
        storage_bytes: 4_096,
        region: None,
        verified_capabilities: Default::default(),
        self_reported_capabilities: Default::default(),
        status: RunnerStatus::Online,
        active_jobs: 0,
        used_cpus: 0,
        used_memory_bytes: 0,
        used_storage_bytes: 0,
        locality: Default::default(),
        last_heartbeat_unix_ms: NOW,
    }
}

fn derive_security_seed(seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runtrue.server.security-key.v1\0");
    hash.update(domain);
    hash.update(seed);
    hash.finalize().into()
}
