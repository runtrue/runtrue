# Lane 06: control-plane identity, policy, and deployments

## Goal

Complete the control-plane split and reduce `store/mod.rs` to the store type,
module declarations, and truly shared orchestration.

## Dependency

Lane 05.

## Target modules

```text
store/identity/{mod,tenants,users,memberships,oidc,sessions}.rs
store/policy.rs
store/deployment/{mod,providers,environments,requests,signing_results}.rs
store/tests/**
```

## Steps

1. Move tenant identity and OIDC-provider configuration.
2. Move human user, external identity, and tenant membership operations.
3. Move browser OIDC transaction and browser-session persistence.
4. Move policy drafts, simulations, shadow records, active bundle state, and
   emergency deny replacement into `policy.rs`.
5. Move tenant provider configuration and signer policy operations.
6. Move environment CRUD and protection rules.
7. Move deployment reservation, environment gate, concurrency lease binding,
   start/result recording, metrics, and signing result journals.
8. Split remaining tests by domain. Keep cross-domain tests as children of
   `store/tests/mod.rs` rather than forcing them into public integration tests.
9. Audit `store/mod.rs`: remove stale imports and helpers, and verify every
   remaining item is genuinely shared or foundational.

## Original source map

| Target | Original `store.rs` region |
|---|---|
| tenant/user identity | 20460-21315 |
| OIDC browser/session state | 21316-21979 |
| active policy state | 21980-22722 |
| providers/signer policy/environments | 22723-24281 |
| deployment requests/gates/start | 24282-25087 |
| deployment results/metrics | 25088-25631 |
| signing result journal | 25632 onward, before external-secret support |

After extracting the production code, split the original test module beginning
at line 26734 by test-name prefix and owning domain. Keep shared fixtures in
`store/tests/support.rs` with `pub(super)` visibility.

## Safety constraints

Preserve identity uniqueness, session secrecy, policy activation journaling,
environment concurrency fencing, deployment transitions, and signing
idempotency.

## Done when

- `store/mod.rs` is a small module root rather than an implementation catalog.
- `types/mod.rs` is a re-export façade.
- All control-plane and workspace checks pass.
