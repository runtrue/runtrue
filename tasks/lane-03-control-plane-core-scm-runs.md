# Lane 03: control-plane installation, SCM, and runs

## Goal

Extract installation, API token, repository, SCM, plan, run, job, approval, and
source-snapshot workflows from `store/mod.rs`.

## Dependency

Lane 02.

## Exclusive ownership

All control-plane store and test files. No other control-plane lane may run.

## Target modules

```text
store/installation.rs
store/api_tokens.rs
store/repositories.rs
store/scm/{mod,installations,github_setup,github_catalog,github_lifecycle,source_fetch,check_publication,continuations}.rs
store/runs/{mod,capsules,runs,jobs,approvals,source_snapshots}.rs
```

## Steps

1. Extract installation fencing, recovery state, restore safe mode, and lease
   fencing helpers into `installation.rs`.
2. Extract API token creation, delegation, authentication, listing, ancestry,
   revocation, row decoding, and validation into `api_tokens.rs`.
3. Extract repository CRUD and SCM installation/link operations.
4. Split GitHub setup transactions, installation reconciliation, repository
   catalog/linking, and lifecycle delivery into their named SCM modules.
5. Split source fetch and check publication journals into separate modules.
6. Move signed plan storage, plan metadata, run creation, job insertion, DAG
   validation, state transitions, and source snapshots into `store/runs`.
7. Keep approval authorization and SCM continuation transactions intact. Move
   them last because they bridge SCM, Capsules, audit, and durable tasks.
8. Move associated tests into `store/tests/{installation,scm,runs,approvals}.rs`.
9. After each module extraction, compile before extracting the next module.

## Original source map

These ranges refer to the pre-refactor `store.rs`; after earlier lanes, locate
items by symbol name:

| Target | Original public-method region |
|---|---|
| installation | 448-584 |
| API tokens | 585-889 |
| repositories/neutral SCM | 890-1104 |
| GitHub setup | 1105-1467 |
| GitHub installations/catalog | 1468-2015 |
| GitHub lifecycle | 2016-2433 |
| SCM source fetch | 2434-2614 |
| SCM checks | 2615-2909 |
| signed Capsules | 2910-3078 |
| run creation | 3079-3210 |
| SCM continuations | 3211-4141 |
| source snapshots/tickets | 4147-4580 |
| jobs/run transitions | 4581-4788 |
| approvals | 4789-5040 |

Helper groups are later in the original file. Find them by prefixes such as
`github_*`, `scm_*`, `insert_capsule_*`, `insert_run_*`, `*_snapshot_*`,
`approval_*`, and `validate_*`; move a helper only with its owning workflow.

## Safety constraints

- Preserve transaction boundaries, statement order, idempotency hashes, audit
  event ordering, and SCM validation.
- Do not split one transaction across module APIs merely to reduce file size.

## Done when

- The listed operations no longer live in `store/mod.rs`.
- Focused and full control-plane checks pass.
