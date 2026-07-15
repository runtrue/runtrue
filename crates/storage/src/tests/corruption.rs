use super::*;

#[cfg(unix)]
#[test]
fn lifecycle_deletion_retains_corrupt_objects() {
    let (_directory, cas) = test_cas();
    let record = cas.put_bytes(b"authoritative bytes").unwrap();
    let path = object_path(&cas, &record.digest);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"corrupt bytes").unwrap();
    assert!(matches!(
        cas.remove_verified_object(&record.digest),
        Err(StorageError::CorruptBlob { .. })
    ));
    assert!(path.exists());
}

#[test]
fn corruption_is_detected_on_every_read() {
    let (_directory, cas) = test_cas();
    let record = cas.put_bytes(b"trusted bytes").unwrap();
    let path = object_path(&cas, &record.digest);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
    }
    fs::write(&path, b"tampered bytes").unwrap();
    assert!(matches!(
        cas.read_blob(&record.digest),
        Err(StorageError::CorruptBlob { .. })
    ));
}
