use super::*;

#[test]
fn source_manifest_is_deterministic_and_binds_modes_and_bytes() {
    let fixture = Fixture::create();
    let repository = fixture.repository();
    let mut first_blobs = Vec::new();
    let first = repository
        .build_source_manifest(
            "repository-1",
            &fixture.source,
            SourceSnapshotLimits::default(),
            |digest, bytes| {
                first_blobs.push((digest.clone(), bytes.to_vec()));
                Ok(())
            },
        )
        .expect("manifest");
    let second = repository
        .build_source_manifest(
            "repository-1",
            &fixture.source,
            SourceSnapshotLimits::default(),
            |_, _| Ok(()),
        )
        .expect("manifest replay");
    assert_eq!(first, second);
    assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    assert!(first
        .entries
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path));
    assert!(first.entries.iter().any(|entry| matches!(
        &entry.kind,
        GitTreeEntryKind::Symlink { target } if entry.path == "linked" && target == "src/a.txt"
    )));
    assert!(!first_blobs.is_empty());
    assert!(first_blobs
        .iter()
        .all(|(digest, bytes)| digest == &ContentDigest::sha256(bytes)));
}

#[cfg(unix)]
#[test]
fn source_manifest_rejects_symlink_escape_and_unlocked_submodule() {
    let fixture = Fixture::create();
    std::os::unix::fs::symlink("../../outside", fixture.directory.path().join("escape"))
        .expect("escape symlink");
    git(fixture.directory.path(), &["add", "escape"]);
    git(
        fixture.directory.path(),
        &["commit", "--quiet", "-m", "escape"],
    );
    let commit = git_output(fixture.directory.path(), &["rev-parse", "HEAD"]);
    let error = fixture
        .repository()
        .build_source_manifest(
            "repository-1",
            &commit,
            SourceSnapshotLimits::default(),
            |_, _| Ok(()),
        )
        .expect_err("escape denied");
    assert!(matches!(error, GitError::UnsafeSymlink(path) if path == "escape"));
}

#[test]
fn source_manifest_enforces_aggregate_bounds_before_publication() {
    let fixture = Fixture::create();
    let mut emitted = 0_usize;
    let error = fixture
        .repository()
        .build_source_manifest(
            "repository-1",
            &fixture.source,
            SourceSnapshotLimits {
                maximum_total_bytes: 1,
                ..SourceSnapshotLimits::default()
            },
            |_, _| {
                emitted += 1;
                Ok(())
            },
        )
        .expect_err("aggregate limit");
    assert!(matches!(
        error,
        GitError::SourceSnapshotLimit {
            kind: "total bytes",
            limit: 1
        }
    ));
    assert_eq!(emitted, 0);
}

#[test]
fn source_manifest_enforces_individual_blob_bound_before_publication() {
    let fixture = Fixture::create();
    let repository = GitRepository::open(
        fixture.directory.path(),
        GitLimits {
            max_blob_bytes: 1,
            ..GitLimits::default()
        },
    )
    .unwrap();
    let mut emitted = 0_usize;
    let error = repository
        .build_source_manifest(
            "repository-1",
            &fixture.source,
            SourceSnapshotLimits::default(),
            |_, _| {
                emitted += 1;
                Ok(())
            },
        )
        .expect_err("individual blob limit");
    assert!(matches!(
        error,
        GitError::SourceSnapshotLimit {
            kind: "blob bytes",
            limit: 1
        }
    ));
    assert_eq!(emitted, 0);
}
