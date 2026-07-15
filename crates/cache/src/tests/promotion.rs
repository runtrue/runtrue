use super::*;

#[test]
fn explicit_promotion_reuses_bytes_and_requires_evidence() {
    let (directory, store) = test_store();
    let source = source_tree(directory.path(), "source", b"candidate");
    let quarantine_identity = identity(quarantine_domain());
    let quarantine = store
        .commit_tree(
            &quarantine_domain(),
            quarantine_identity.clone(),
            source,
            None,
            2,
            producer(),
        )
        .unwrap();
    let target = identity(main_domain());
    let promoted = store
        .promote(
            &quarantine_identity,
            target.clone(),
            PromotionEvidence {
                kind: PromotionKind::ManualSecurityApproval,
                evidence_digest: digest("review"),
                approval_id: Some("approval-1".to_owned()),
            },
            None,
            3,
        )
        .unwrap();
    assert_eq!(promoted.manifest.tree, quarantine.manifest.tree);
    assert!(promoted.manifest.promotion.is_some());
    assert!(matches!(
        store.promote(
            &target,
            quarantine_identity,
            PromotionEvidence {
                kind: PromotionKind::TrustedRebuild,
                evidence_digest: digest("bad-direction"),
                approval_id: None,
            },
            Some(&quarantine.head),
            4
        ),
        Err(CacheError::InvalidPromotion(_))
    ));
}
