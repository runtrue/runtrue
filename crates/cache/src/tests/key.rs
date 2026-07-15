use super::*;

#[test]
fn cache_key_material_is_trust_neutral_and_mutations_miss() {
    let limits = CacheLimits::default();
    let material = material();
    assert_eq!(
        material.digest(limits).unwrap(),
        CacheKeyMaterial::from(&material.with_trust_domain(quarantine_domain()))
            .digest(limits)
            .unwrap()
    );
    for mutate in [
        |value: &mut CacheKeyMaterial| value.definition = digest("changed-action"),
        |value: &mut CacheKeyMaterial| value.toolchain = Some(digest("changed-toolchain")),
        |value: &mut CacheKeyMaterial| value.platform.os = "windows".to_owned(),
        |value: &mut CacheKeyMaterial| value.policy_epoch += 1,
        |value: &mut CacheKeyMaterial| value.declared_inputs = digest("changed-inputs"),
    ] {
        let mut changed = material.clone();
        mutate(&mut changed);
        assert_ne!(
            material.digest(limits).unwrap(),
            changed.digest(limits).unwrap()
        );
    }
}

#[test]
fn structured_identity_digest_is_stable_and_scope_checked() {
    let limits = CacheLimits::default();
    let first = identity(main_domain());
    let second = identity(main_domain());
    assert_eq!(
        first.digest(limits).unwrap(),
        second.digest(limits).unwrap()
    );
    let mut invalid = first;
    invalid.repository_id = "different".to_owned();
    assert!(matches!(
        invalid.validate(limits),
        Err(CacheError::InvalidIdentity(_))
    ));
}
