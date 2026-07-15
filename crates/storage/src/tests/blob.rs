use super::*;

#[test]
fn immutable_put_is_idempotent_and_verified() {
    let (_directory, cas) = test_cas();
    let first = cas.put_bytes(b"immutable").unwrap();
    let second = cas.put_bytes(b"immutable").unwrap();
    assert_eq!(first.digest, second.digest);
    assert!(!first.already_present);
    assert!(second.already_present);
    assert_eq!(cas.read_blob(&first.digest).unwrap(), b"immutable");
}

#[test]
fn lifecycle_inventory_is_bounded_and_verified_deletion_replays() {
    let (_directory, cas) = test_cas();
    let first = cas.put_bytes(b"first lifecycle object").unwrap();
    let second = cas.put_bytes(b"second lifecycle object").unwrap();
    assert!(matches!(
        cas.inventory_objects(1),
        Err(StorageError::LimitExceeded {
            resource: "CAS inventory objects",
            ..
        })
    ));
    let inventory = cas.inventory_objects(2).unwrap();
    assert_eq!(inventory.len(), 2);
    assert!(inventory.iter().any(|entry| entry.digest == first.digest));
    assert!(inventory.iter().any(|entry| entry.digest == second.digest));
    assert_eq!(
        cas.remove_verified_object(&first.digest).unwrap(),
        Some(first.size_bytes)
    );
    assert_eq!(cas.remove_verified_object(&first.digest).unwrap(), None);
    assert_eq!(cas.verify_blob(&second.digest).unwrap(), second.size_bytes);
}

#[test]
fn concurrent_writers_commit_one_immutable_object() {
    let (_directory, cas) = test_cas();
    let cas = Arc::new(cas);
    let handles = (0..12)
        .map(|_| {
            let cas = Arc::clone(&cas);
            thread::spawn(move || cas.put_bytes(b"same concurrent bytes").unwrap())
        })
        .collect::<Vec<_>>();
    let records = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        records
            .iter()
            .filter(|record| !record.already_present)
            .count(),
        1
    );
    assert!(records
        .windows(2)
        .all(|pair| pair[0].digest == pair[1].digest));
}

#[test]
fn size_limits_abort_streams() {
    let directory = tempdir().unwrap();
    let limits = CasLimits {
        max_blob_bytes: 3,
        ..CasLimits::default()
    };
    let cas = FsCas::open(directory.path().join("cas"), limits).unwrap();
    assert!(matches!(
        cas.put_bytes(b"four"),
        Err(StorageError::LimitExceeded { .. })
    ));
}

#[test]
fn verified_reader_streams_and_rewinds_without_a_blob_vec() {
    let (_directory, cas) = test_cas();
    let bytes = vec![0x5a; COPY_BUFFER_BYTES * 3 + 17];
    let record = cas.put_bytes(&bytes).unwrap();
    let mut reader = cas
        .verified_reader(&record.digest, record.size_bytes)
        .unwrap();
    assert_eq!(reader.size_bytes(), bytes.len() as u64);
    let mut observed = Vec::new();
    reader.read_to_end(&mut observed).unwrap();
    assert_eq!(observed, bytes);
}

#[test]
fn verified_staging_rejects_digest_size_and_byte_limits() {
    let (_directory, cas) = test_cas();
    let expected = ContentDigest::sha256(b"expected");
    assert!(matches!(
        cas.put_verified_reader(Cursor::new(b"substitute"), &expected, 10, 10),
        Err(StorageError::Manifest(_))
    ));
    assert!(matches!(
        cas.put_verified_reader(Cursor::new(b"expected"), &expected, 8, 7),
        Err(StorageError::LimitExceeded { .. })
    ));
}
