use super::*;

#[test]
fn server_owned_scopes_allow_pr_to_read_main_but_never_reverse_trust_flow() {
    let limits = CacheLimits::default();
    let scopes = derive_cache_access(
        &material(),
        &access(
            CacheSourceTrust::UntrustedChange {
                change_id: "pr-7".to_owned(),
            },
            CacheReadPolicy::Branch,
            CacheWritePolicy::Branch,
        ),
        limits,
    )
    .unwrap();
    assert_eq!(scopes.read_candidates[0].trust_domain, main_domain());
    assert_eq!(scopes.read_candidates[1].trust_domain, quarantine_domain());
    assert_eq!(
        scopes.write_identity.unwrap().trust_domain,
        quarantine_domain()
    );
    assert!(quarantine_domain().can_read_from(&main_domain()));
    assert!(!main_domain().can_read_from(&quarantine_domain()));
}

#[test]
fn verified_head_writes_require_protected_source_and_server_approval() {
    let limits = CacheLimits::default();
    let mut context = access(
        CacheSourceTrust::UntrustedChange {
            change_id: "pr-7".to_owned(),
        },
        CacheReadPolicy::Verified,
        CacheWritePolicy::Verified,
    );
    assert!(derive_cache_access(&material(), &context, limits)
        .unwrap()
        .write_identity
        .is_none());
    context.source = CacheSourceTrust::ProtectedMain;
    context.verified_write_authorized = false;
    assert!(derive_cache_access(&material(), &context, limits)
        .unwrap()
        .write_identity
        .is_none());
    context.verified_write_authorized = true;
    assert_eq!(
        derive_cache_access(&material(), &context, limits)
            .unwrap()
            .write_identity
            .unwrap()
            .trust_domain,
        main_domain()
    );
}

#[test]
fn protected_branch_identity_hits_across_runs_with_identical_material() {
    let limits = CacheLimits::default();
    let mut first = access(
        CacheSourceTrust::ProtectedMain,
        CacheReadPolicy::Branch,
        CacheWritePolicy::Branch,
    );
    first.run_id = "run-one".to_owned();
    let mut second = first.clone();
    second.run_id = "run-two".to_owned();
    let first = derive_cache_access(&material(), &first, limits).unwrap();
    let second = derive_cache_access(&material(), &second, limits).unwrap();
    assert_eq!(first.write_identity, second.write_identity);
    assert_eq!(
        second.read_candidates.first(),
        second.write_identity.as_ref(),
        "a later protected run must resolve the same branch head first",
    );
}
