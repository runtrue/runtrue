use super::*;
use super::{credentials::read_bounded_private_file_with_credentials, model::timestamp};
use runtrue_git::{GitTreeEntry, GitTreeEntryKind, GitTreeManifest, GIT_TREE_MANIFEST_VERSION};
use runtrue_model::ContentDigest;
use runtrue_protocol::{v1, v2};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{collections::BTreeSet, fs, io::Cursor};

#[test]
fn epoch_is_monotonic_and_stale_active_work_is_not_resumed() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = RunnerStateStore::open(directory.path().join("state")).unwrap();
    store.accept_installation_epoch(7).unwrap();
    store
        .mark_active(ActiveLeaseMarker {
            lease_id: "lease".to_owned(),
            fencing_generation: 2,
            installation_fencing_epoch: 7,
            workspace_name: "workspace".to_owned(),
        })
        .unwrap();
    drop(store);

    let mut reopened = RunnerStateStore::open(directory.path().join("state")).unwrap();
    assert!(reopened.clear_stale_active_marker().unwrap());
    assert!(reopened.state().active_lease.is_none());
    assert!(matches!(
        reopened.accept_installation_epoch(6),
        Err(StateError::EpochRollback { .. })
    ));
}

#[test]
fn source_materialization_is_verified_bounded_and_create_new() {
    let directory = tempfile::tempdir().unwrap();
    let manager = WorkspaceManager::open(directory.path().join("work")).unwrap();
    let workspace = manager.create("lease", 1).unwrap();
    let bytes = b"exact source\n".to_vec();
    let digest = ContentDigest::sha256(&bytes);
    let manifest = GitTreeManifest {
        version: GIT_TREE_MANIFEST_VERSION,
        repository_id: "repo".to_owned(),
        commit: "a".repeat(40),
        entries: vec![
            GitTreeEntry {
                path: "src".to_owned(),
                kind: GitTreeEntryKind::Directory,
            },
            GitTreeEntry {
                path: "src/main.txt".to_owned(),
                kind: GitTreeEntryKind::File {
                    digest: digest.clone(),
                    size_bytes: bytes.len() as u64,
                    executable: false,
                },
            },
        ],
    };
    let count = manager
        .materialize_source(&workspace, &manifest, 1024, |requested| {
            assert_eq!(requested, &digest);
            Ok(Box::new(Cursor::new(bytes.clone())))
        })
        .unwrap();
    assert_eq!(count, bytes.len() as u64);
    assert_eq!(fs::read(workspace.join("src/main.txt")).unwrap(), bytes);
    assert!(manager
        .materialize_source(&workspace, &manifest, 1024, |_| unreachable!())
        .is_err());
}

#[test]
fn source_cache_survives_restart_and_advertises_only_complete_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("source-cache");
    let bytes = b"cached source\n".to_vec();
    let file_digest = ContentDigest::sha256(&bytes);
    let manifest = GitTreeManifest {
        version: GIT_TREE_MANIFEST_VERSION,
        repository_id: "repo".to_owned(),
        commit: "b".repeat(40),
        entries: vec![GitTreeEntry {
            path: "cached.txt".to_owned(),
            kind: GitTreeEntryKind::File {
                digest: file_digest.clone(),
                size_bytes: bytes.len() as u64,
                executable: false,
            },
        }],
    };
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    let manifest_digest = manifest.digest().unwrap();

    let cache = SourceCache::open(&root, 1024 * 1024, 100).unwrap();
    cache
        .store(
            Cursor::new(manifest_bytes.clone()),
            &manifest_digest,
            manifest_bytes.len() as u64,
            manifest_bytes.len() as u64,
        )
        .unwrap();
    assert!(cache.locality(256).unwrap().is_empty());
    cache
        .store(
            Cursor::new(bytes.clone()),
            &file_digest,
            bytes.len() as u64,
            bytes.len() as u64,
        )
        .unwrap();
    assert!(cache
        .complete_snapshot(&manifest_digest, &manifest)
        .unwrap());
    assert_eq!(
        cache.locality(256).unwrap(),
        BTreeSet::from([manifest_digest.clone()])
    );
    drop(cache);

    let reopened = SourceCache::open(&root, 1024 * 1024, 100).unwrap();
    assert_eq!(
        reopened.locality(256).unwrap(),
        BTreeSet::from([manifest_digest.clone()])
    );
    assert_eq!(
        std::io::read_to_string(reopened.reader(&file_digest, 1024).unwrap().unwrap()).unwrap(),
        "cached source\n"
    );
    assert!(reopened.locality(0).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn state_and_private_inputs_reject_symlinks_and_permissive_modes() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let secret = directory.path().join("secret");
    fs::write(&secret, b"secret").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        read_bounded_private_file(&secret, 100),
        Err(StateError::InsecurePermissions(_))
    ));
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("link");
    symlink(&secret, &link).unwrap();
    assert!(matches!(
        read_bounded_private_file(&link, 100),
        Err(StateError::UnsafePath(_))
    ));
}

#[cfg(unix)]
#[test]
fn only_direct_systemd_credentials_accept_read_only_modes() {
    let directory = tempfile::tempdir().unwrap();
    let credentials_directory = directory.path().join("credentials");
    fs::create_dir(&credentials_directory).unwrap();
    fs::set_permissions(&credentials_directory, fs::Permissions::from_mode(0o500)).unwrap();

    let ordinary = directory.path().join("ordinary-token");
    fs::write(&ordinary, b"ordinary").unwrap();
    for mode in [0o400, 0o440] {
        fs::set_permissions(&ordinary, fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            read_bounded_private_file_with_credentials(
                &ordinary,
                100,
                Some(&credentials_directory),
            ),
            Err(StateError::InsecurePermissions(_))
        ));
    }

    let credential = credentials_directory.join("token");
    fs::write(&credential, b"credential").unwrap();
    for mode in [0o400, 0o440] {
        fs::set_permissions(&credential, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_bounded_private_file_with_credentials(
                &credential,
                100,
                Some(&credentials_directory),
            )
            .unwrap(),
            b"credential"
        );
    }

    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        read_bounded_private_file_with_credentials(&credential, 100, Some(&credentials_directory),),
        Err(StateError::InsecurePermissions(_))
    ));

    fs::set_permissions(&credential, fs::Permissions::from_mode(0o400)).unwrap();
    let extra_link = directory.path().join("credential-hard-link");
    fs::hard_link(&credential, &extra_link).unwrap();
    assert!(matches!(
        read_bounded_private_file_with_credentials(&credential, 100, Some(&credentials_directory),),
        Err(StateError::InsecurePermissions(_))
    ));
}

#[test]
fn workspace_open_removes_stale_directories_and_never_resumes_them() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("workspaces");
    let manager = WorkspaceManager::open(&root).unwrap();
    let stale = manager.create("lease", 1).unwrap();
    fs::write(stale.join("partial-output"), b"data").unwrap();
    drop(manager);
    let manager = WorkspaceManager::open(&root).unwrap();
    assert!(!stale.exists());
    let fresh = manager.create("lease", 1).unwrap();
    assert!(fresh.exists());
    manager.cleanup(&fresh).unwrap();
}

#[test]
fn exact_completion_survives_restart_and_new_epoch_invalidates_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("state");
    let digest = ContentDigest::sha256(b"terminal result");
    let completion = v1::CompleteLeaseRequest {
        lease_id: "lease-1".to_owned(),
        fencing_generation: 3,
        installation_fencing_epoch: 8,
        final_state: "succeeded".to_owned(),
        exit_code: Some(0),
        error_code: String::new(),
        result_digest: Some(v1::Digest::try_from(digest).unwrap()),
        artifact_ids: Vec::new(),
        cache_entry_ids: Vec::new(),
        completed_at: Some(timestamp(123_456)),
        final_job_attempt: 2,
        expected_log_frames: 7,
    };
    let mut store = RunnerStateStore::open(&root).unwrap();
    store.accept_installation_epoch(8).unwrap();
    store.set_pending_completion(&completion).unwrap();
    drop(store);

    let mut reopened = RunnerStateStore::open(&root).unwrap();
    assert_eq!(reopened.pending_completion().unwrap(), Some(completion));
    reopened.accept_installation_epoch(9).unwrap();
    assert!(reopened.pending_completion().unwrap().is_none());
}

#[test]
fn concurrent_active_leases_and_completions_survive_restart_independently() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("concurrent-state");
    let mut store = RunnerStateStore::open(&root).unwrap();
    store.accept_installation_epoch(8).unwrap();
    for lease_id in ["lease-a", "lease-b"] {
        store
            .mark_active(ActiveLeaseMarker {
                lease_id: lease_id.to_owned(),
                fencing_generation: 1,
                installation_fencing_epoch: 8,
                workspace_name: format!("workspace-{lease_id}"),
            })
            .unwrap();
        let completion = v1::CompleteLeaseRequest {
            lease_id: lease_id.to_owned(),
            fencing_generation: 1,
            installation_fencing_epoch: 8,
            final_state: "succeeded".to_owned(),
            exit_code: Some(0),
            error_code: String::new(),
            result_digest: Some(
                v1::Digest::try_from(ContentDigest::sha256(lease_id.as_bytes())).unwrap(),
            ),
            artifact_ids: Vec::new(),
            cache_entry_ids: Vec::new(),
            completed_at: Some(timestamp(123_456)),
            final_job_attempt: 1,
            expected_log_frames: 0,
        };
        store
            .set_pending_completion_with_objects(
                &completion,
                Vec::new(),
                runtrue_engine::CredentialTaint::CredentialReleased,
            )
            .unwrap();
    }
    drop(store);

    let mut reopened = RunnerStateStore::open(&root).unwrap();
    let records = reopened.pending_completion_records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].lease_id, "lease-a");
    assert_eq!(records[1].lease_id, "lease-b");
    reopened.clear_pending_completion_lease("lease-a").unwrap();
    assert_eq!(reopened.pending_completion_records()[0].lease_id, "lease-b");
}

#[test]
fn typed_completion_claims_survive_restart_and_legacy_records_stay_v1() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("typed-state");
    let completion = v1::CompleteLeaseRequest {
        lease_id: "lease-typed".to_owned(),
        fencing_generation: 4,
        installation_fencing_epoch: 9,
        final_state: "succeeded".to_owned(),
        exit_code: Some(0),
        error_code: String::new(),
        result_digest: Some(v1::Digest::try_from(ContentDigest::sha256(b"typed result")).unwrap()),
        artifact_ids: vec!["artifact-1".to_owned()],
        cache_entry_ids: vec!["cache-1".to_owned()],
        completed_at: Some(timestamp(321_000)),
        final_job_attempt: 2,
        expected_log_frames: 5,
    };
    let objects = vec![
        PersistedCommittedObject {
            kind: PersistedCommittedObjectKind::Artifact,
            object_id: "artifact-1".to_owned(),
            declaration_name: Some("package".to_owned()),
            job_attempt: 2,
        },
        PersistedCommittedObject {
            kind: PersistedCommittedObjectKind::Cache,
            object_id: "cache-1".to_owned(),
            declaration_name: None,
            job_attempt: 2,
        },
    ];
    let mut store = RunnerStateStore::open(&root).unwrap();
    store
        .set_pending_completion_with_objects(
            &completion,
            objects,
            runtrue_engine::CredentialTaint::CredentialReleased,
        )
        .unwrap();
    drop(store);

    let reopened = RunnerStateStore::open(&root).unwrap();
    let persisted = reopened.pending_completion_record().unwrap();
    let typed = persisted.to_wire_v2().unwrap().unwrap();
    assert_eq!(typed.final_state, v2::LeaseFinalState::Succeeded as i32);
    assert_eq!(typed.committed_objects.len(), 2);
    assert_eq!(
        typed.credential_taint,
        v2::CredentialTaintState::CredentialReleased as i32
    );
    assert_eq!(persisted.to_wire().unwrap(), completion);

    let legacy_root = directory.path().join("legacy-state");
    let mut legacy = RunnerStateStore::open(&legacy_root).unwrap();
    legacy.set_pending_completion(&completion).unwrap();
    assert!(legacy
        .pending_completion_record()
        .unwrap()
        .to_wire_v2()
        .unwrap()
        .is_none());
}
