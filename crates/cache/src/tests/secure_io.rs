use super::*;

#[cfg(unix)]
#[test]
fn symlinked_head_directory_is_rejected() {
    use std::os::unix::fs::symlink;
    let (directory, store) = test_store();
    let identity = identity(main_domain());
    let digest = identity.digest(CacheLimits::default()).unwrap();
    let encoded = digest_hex(&digest).unwrap();
    let prefix = store.root().join("heads/sha256").join(&encoded[..2]);
    fs::create_dir(&prefix).unwrap();
    let outside = directory.path().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, prefix.join(&encoded[2..])).unwrap();

    assert!(matches!(
        store.inspect(&identity),
        Err(CacheError::UnsafeMetadataPath(_))
    ));
}
