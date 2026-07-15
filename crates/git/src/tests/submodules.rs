use super::*;

#[test]
fn exact_locked_submodule_is_flattened_deterministically_without_network() {
    let origin = "https://git.example.com/acme/nested.git";
    let (nested_directory, nested_commit) =
        create_submodule_repository(origin, b"nested exact bytes\n");
    let fixture = Fixture::create();
    let root_commit = add_gitlink(
        fixture.directory.path(),
        "vendor/nested",
        origin,
        &nested_commit,
    );
    let root = fixture.repository();
    let nested =
        GitRepository::open(nested_directory.path(), GitLimits::default()).expect("nested");
    let source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/nested",
            normalized_origin(origin),
            nested_commit.clone(),
        )
        .expect("lock"),
        &nested,
        Vec::new(),
    )
    .expect("source");
    let sources = LockedSubmoduleSources::new(vec![source]).expect("sources");
    let mut published = Vec::new();
    let first = root
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &root_commit,
            LockedSourceSnapshotLimits::default(),
            &sources,
            |digest, bytes| {
                published.push((digest.clone(), bytes.to_vec()));
                Ok(())
            },
        )
        .expect("locked manifest");
    let second = root
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &root_commit,
            LockedSourceSnapshotLimits::default(),
            &sources,
            |_, _| Ok(()),
        )
        .expect("locked replay");

    assert_eq!(first, second);
    assert_eq!(first.manifest().commit, root_commit);
    assert!(first
        .manifest()
        .entries
        .windows(2)
        .all(|entries| { entries[0].path < entries[1].path }));
    assert!(first.manifest().entries.iter().any(|entry| {
        entry.path == "vendor/nested" && matches!(&entry.kind, GitTreeEntryKind::Directory)
    }));
    assert!(first.manifest().entries.iter().any(|entry| {
        entry.path == "vendor/nested/nested.txt"
            && matches!(
                &entry.kind,
                GitTreeEntryKind::File { digest, .. }
                    if digest == &ContentDigest::sha256(b"nested exact bytes\n")
            )
    }));
    assert_eq!(first.submodule_locks().len(), 1);
    assert_eq!(first.submodule_locks()[0].path(), "vendor/nested");
    assert_eq!(
        first.submodule_lock_digest().unwrap(),
        second.submodule_lock_digest().unwrap()
    );
    assert!(published
        .iter()
        .any(|(_, bytes)| { bytes.as_slice() == b"nested exact bytes\n" }));

    let old_error = root
        .build_source_manifest(
            "repository-1",
            &root_commit,
            SourceSnapshotLimits::default(),
            |_, _| Ok(()),
        )
        .expect_err("legacy path stays fail closed");
    assert!(matches!(
        old_error,
        GitError::UnlockedSubmodule(path) if path == "vendor/nested"
    ));
}

#[test]
fn locked_submodule_commit_path_origin_and_missing_object_fail_before_publication() {
    let origin = "https://git.example.com/acme/nested.git";
    let changed_origin = "https://git.example.com/acme/changed.git";
    let (nested_directory, nested_commit) =
        create_submodule_repository(changed_origin, b"nested\n");
    fs::write(nested_directory.path().join("nested.txt"), b"second\n").unwrap();
    git(nested_directory.path(), &["add", "nested.txt"]);
    git(
        nested_directory.path(),
        &["commit", "--quiet", "-m", "second"],
    );
    let second_commit = git_output(nested_directory.path(), &["rev-parse", "HEAD"]);
    let nested =
        GitRepository::open(nested_directory.path(), GitLimits::default()).expect("nested");

    let origin_fixture = Fixture::create();
    let origin_root_commit = add_gitlink(
        origin_fixture.directory.path(),
        "vendor/nested",
        origin,
        &nested_commit,
    );
    let origin_root = origin_fixture.repository();
    let origin_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/nested",
            normalized_origin(origin),
            nested_commit.clone(),
        )
        .unwrap(),
        &nested,
        Vec::new(),
    )
    .unwrap();
    let origin_sources = LockedSubmoduleSources::new(vec![origin_source]).unwrap();
    let mut published = 0;
    let error = origin_root
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &origin_root_commit,
            LockedSourceSnapshotLimits::default(),
            &origin_sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("changed local origin");
    assert!(matches!(error, GitError::SubmoduleOriginMismatch(_)));
    assert_eq!(published, 0);

    let commit_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/nested",
            normalized_origin(changed_origin),
            second_commit,
        )
        .unwrap(),
        &nested,
        Vec::new(),
    )
    .unwrap();
    let commit_sources = LockedSubmoduleSources::new(vec![commit_source]).unwrap();
    let commit_fixture = Fixture::create();
    let commit_root = add_gitlink(
        commit_fixture.directory.path(),
        "vendor/nested",
        changed_origin,
        &nested_commit,
    );
    let mut published = 0;
    let error = commit_fixture
        .repository()
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &commit_root,
            LockedSourceSnapshotLimits::default(),
            &commit_sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("changed commit");
    assert!(matches!(error, GitError::SubmoduleCommitMismatch(_)));
    assert_eq!(published, 0);

    let path_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/other",
            normalized_origin(changed_origin),
            nested_commit.clone(),
        )
        .unwrap(),
        &nested,
        Vec::new(),
    )
    .unwrap();
    let path_sources = LockedSubmoduleSources::new(vec![path_source]).unwrap();
    let mut published = 0;
    let error = commit_fixture
        .repository()
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &commit_root,
            LockedSourceSnapshotLimits::default(),
            &path_sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("changed path");
    assert!(matches!(error, GitError::UnlockedSubmodule(_)));
    assert_eq!(published, 0);

    let absent_commit = "1111111111111111111111111111111111111111";
    let missing_fixture = Fixture::create();
    let missing_root = add_gitlink(
        missing_fixture.directory.path(),
        "vendor/nested",
        changed_origin,
        absent_commit,
    );
    let missing_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/nested",
            normalized_origin(changed_origin),
            absent_commit,
        )
        .unwrap(),
        &nested,
        Vec::new(),
    )
    .unwrap();
    let missing_sources = LockedSubmoduleSources::new(vec![missing_source]).unwrap();
    let mut published = 0;
    let error = missing_fixture
        .repository()
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &missing_root,
            LockedSourceSnapshotLimits::default(),
            &missing_sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("absent local object");
    assert!(matches!(error, GitError::SubmoduleObjectUnavailable(_)));
    assert_eq!(published, 0);
}

#[test]
fn locked_submodule_depth_cycle_and_duplicate_mounts_fail_closed() {
    let leaf_origin = "https://git.example.com/acme/leaf.git";
    let middle_origin = "https://git.example.com/acme/middle.git";
    let (leaf_directory, leaf_commit) = create_submodule_repository(leaf_origin, b"leaf\n");
    let (middle_directory, _) = create_submodule_repository(middle_origin, b"middle\n");
    let middle_commit = add_gitlink(
        middle_directory.path(),
        "deps/leaf",
        leaf_origin,
        &leaf_commit,
    );
    let root_fixture = Fixture::create();
    let root_commit = add_gitlink(
        root_fixture.directory.path(),
        "vendor/middle",
        middle_origin,
        &middle_commit,
    );
    let leaf = GitRepository::open(leaf_directory.path(), GitLimits::default()).expect("leaf");
    let middle =
        GitRepository::open(middle_directory.path(), GitLimits::default()).expect("middle");
    let leaf_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new("deps/leaf", normalized_origin(leaf_origin), leaf_commit).unwrap(),
        &leaf,
        Vec::new(),
    )
    .unwrap();
    let middle_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/middle",
            normalized_origin(middle_origin),
            middle_commit,
        )
        .unwrap(),
        &middle,
        vec![leaf_source],
    )
    .unwrap();
    let sources = LockedSubmoduleSources::new(vec![middle_source]).unwrap();
    let mut published = 0;
    let error = root_fixture
        .repository()
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &root_commit,
            LockedSourceSnapshotLimits {
                maximum_submodule_depth: 1,
                ..LockedSourceSnapshotLimits::default()
            },
            &sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("depth bound");
    assert!(matches!(
        error,
        GitError::SourceSnapshotLimit {
            kind: "submodule depth",
            limit: 1
        }
    ));
    assert_eq!(published, 0);

    let cycle_origin = "https://git.example.com/acme/cycle.git";
    let cycle_fixture = Fixture::create();
    git(
        cycle_fixture.directory.path(),
        &["remote", "add", "origin", cycle_origin],
    );
    let (cycle_nested_directory, cycle_nested_commit) =
        create_submodule_repository(cycle_origin, b"cycle\n");
    let cycle_root = add_gitlink(
        cycle_fixture.directory.path(),
        "vendor/cycle",
        cycle_origin,
        &cycle_nested_commit,
    );
    let cycle_nested =
        GitRepository::open(cycle_nested_directory.path(), GitLimits::default()).unwrap();
    let cycle_source = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/cycle",
            normalized_origin(cycle_origin),
            cycle_nested_commit.clone(),
        )
        .unwrap(),
        &cycle_nested,
        Vec::new(),
    )
    .unwrap();
    let cycle_sources = LockedSubmoduleSources::new(vec![cycle_source]).unwrap();
    let mut published = 0;
    let error = cycle_fixture
        .repository()
        .build_source_manifest_with_locked_submodules(
            "repository-1",
            &cycle_root,
            LockedSourceSnapshotLimits::default(),
            &cycle_sources,
            |_, _| {
                published += 1;
                Ok(())
            },
        )
        .expect_err("origin cycle");
    assert!(matches!(error, GitError::SubmoduleCycle(_)));
    assert_eq!(published, 0);

    let first = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/duplicate",
            normalized_origin(cycle_origin),
            cycle_nested_commit.clone(),
        )
        .unwrap(),
        &cycle_nested,
        Vec::new(),
    )
    .unwrap();
    let second = LockedSubmoduleSource::new(
        GitSubmoduleLock::new(
            "vendor/duplicate",
            normalized_origin(cycle_origin),
            cycle_nested_commit,
        )
        .unwrap(),
        &cycle_nested,
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        LockedSubmoduleSources::new(vec![second, first]),
        Err(GitError::DuplicateSubmoduleMount(path)) if path == "vendor/duplicate"
    ));
}
