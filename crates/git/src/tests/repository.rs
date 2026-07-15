use super::*;

#[test]
fn reads_only_exact_regular_blobs_and_preserves_mode_identity() {
    let fixture = Fixture::create();
    let repository = fixture.repository();
    let blob = repository
        .read_blob(&fixture.base, ".runtrue/workflows/ci.yaml")
        .expect("blob");
    assert_eq!(blob.commit, fixture.base);
    assert_eq!(blob.path, ".runtrue/workflows/ci.yaml");
    assert_eq!(blob.bytes, b"version: 1\nname: trusted-base\n");
    assert_eq!(blob.digest, ContentDigest::sha256(&blob.bytes));
    assert!(!blob.executable);
}

#[test]
fn bare_repositories_support_the_same_exact_object_reads() {
    let fixture = Fixture::create();
    let parent = tempfile::tempdir().expect("bare parent");
    let bare = parent.path().join("repository.git");
    let status = Command::new("git")
        .args(["clone", "--quiet", "--bare"])
        .arg(fixture.directory.path())
        .arg(&bare)
        .status()
        .expect("bare clone");
    assert!(status.success());
    let repository = GitRepository::open(&bare, GitLimits::default()).expect("bare repo");
    assert_eq!(repository.kind(), GitRepositoryKind::Bare);
    assert_eq!(repository.git_dir(), repository.root());
    let blob = repository
        .read_blob(&fixture.base, ".runtrue/workflows/ci.yaml")
        .expect("bare blob");
    assert!(String::from_utf8_lossy(&blob.bytes).contains("trusted-base"));
    assert!(repository
        .changed_paths(&fixture.base, &fixture.source)
        .expect("bare diff")
        .contains(&"src/a.txt".to_owned()));
}

#[test]
fn mutable_revisions_and_object_expression_paths_are_rejected() {
    let fixture = Fixture::create();
    let repository = fixture.repository();
    for revision in ["HEAD", "main", "abc", &"A".repeat(40)] {
        assert!(matches!(
            repository.verify_commit(revision),
            Err(GitError::MutableOrInvalidRevision)
        ));
    }
    for path in ["../secret", "./src/a.txt", "src:a.txt", "/etc/passwd"] {
        assert!(matches!(
            repository.read_blob(&fixture.source, path),
            Err(GitError::UnsafePath(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn symlink_blob_is_never_returned_as_workflow_bytes() {
    let fixture = Fixture::create();
    let error = fixture
        .repository()
        .read_blob(&fixture.source, "linked")
        .expect_err("symlink");
    assert!(matches!(error, GitError::UnsupportedBlobMode(mode) if mode == "120000"));
}

#[test]
fn changed_paths_are_normalized_sorted_and_bounded() {
    let fixture = Fixture::create();
    let paths = fixture
        .repository()
        .changed_paths(&fixture.base, &fixture.source)
        .expect("changed paths");
    let mut sorted = paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(paths, sorted);
    assert!(paths.contains(&".runtrue/workflows/ci.yaml".to_owned()));
    assert!(paths.contains(&"src/a.txt".to_owned()));

    let limits = GitLimits {
        max_changed_paths: 1,
        ..GitLimits::default()
    };
    let repository = GitRepository::open(fixture.directory.path(), limits).expect("repo");
    assert!(matches!(
        repository.changed_paths(&fixture.base, &fixture.source),
        Err(GitError::OutputLimit {
            kind: "changed path count",
            ..
        })
    ));
}

#[test]
fn regular_file_discovery_is_exact_sorted_and_bounded() {
    let fixture = Fixture::create();
    let repository = fixture.repository();
    let files = repository
        .regular_files_under(&fixture.source, ".runtrue/workflows", 10)
        .expect("workflow files");
    assert_eq!(files, vec![".runtrue/workflows/ci.yaml".to_owned()]);
    assert!(matches!(
        repository.regular_files_under(&fixture.source, ".runtrue/workflows", 0),
        Err(GitError::InvalidConfiguration)
    ));
}

#[test]
fn target_branch_workflow_is_separate_from_proposed_risk_input() {
    let fixture = Fixture::create();
    let sources = fixture
        .repository()
        .trusted_workflow_sources(&fixture.base, &fixture.source, ".runtrue/workflows/ci.yaml")
        .expect("sources");
    assert!(String::from_utf8_lossy(&sources.execution().bytes).contains("trusted-base"));
    assert!(
        String::from_utf8_lossy(&sources.proposed_for_risk().expect("proposed").bytes)
            .contains("proposed-untrusted")
    );
    assert_ne!(
        sources.execution().digest,
        sources.proposed_for_risk().expect("proposed").digest
    );
}

#[test]
fn deleted_proposed_workflow_never_replaces_the_base_workflow() {
    let fixture = Fixture::create();
    fs::remove_file(fixture.directory.path().join(".runtrue/workflows/ci.yaml")).expect("delete");
    git(fixture.directory.path(), &["add", "-A"]);
    git(
        fixture.directory.path(),
        &["commit", "--quiet", "-m", "delete workflow"],
    );
    let deleted = git_output(fixture.directory.path(), &["rev-parse", "HEAD"]);
    let sources = fixture
        .repository()
        .trusted_workflow_sources(&fixture.source, &deleted, ".runtrue/workflows/ci.yaml")
        .expect("sources");
    assert!(String::from_utf8_lossy(&sources.execution().bytes).contains("proposed-untrusted"));
    assert!(sources.proposed_for_risk().is_none());
}

#[test]
fn blob_size_is_checked_before_blob_bytes_are_read() {
    let fixture = Fixture::create();
    let limits = GitLimits {
        max_blob_bytes: 128,
        ..GitLimits::default()
    };
    let repository = GitRepository::open(fixture.directory.path(), limits).expect("repo");
    assert!(matches!(
        repository.read_blob(&fixture.source, "large.bin"),
        Err(GitError::OutputLimit {
            kind: "blob bytes",
            limit: 128
        })
    ));
}

#[cfg(unix)]
#[test]
fn repository_root_may_not_be_a_symlink() {
    let fixture = Fixture::create();
    let parent = tempfile::tempdir().expect("parent");
    let link = parent.path().join("repository");
    std::os::unix::fs::symlink(fixture.directory.path(), &link).expect("symlink root");
    assert!(matches!(
        GitRepository::open(&link, GitLimits::default()),
        Err(GitError::UnsafeRepositoryRoot(_))
    ));
}
