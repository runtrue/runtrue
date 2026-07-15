# Lane 05: control-plane data, lifecycle, and workflow semantics

## Goal

Extract artifact, storage, cache, lifecycle, matrix expansion, trigger, and
schedule persistence.

## Dependency

Lane 04.

## Target modules

```text
store/artifacts/{mod,catalog,downloads,storage,scans,promotions}.rs
store/cache.rs
store/lifecycle.rs
store/workflow/{mod,expansions,triggers,schedules}.rs
```

## Steps

1. Move artifact catalog and download-ticket operations with their row decoders.
2. Move tenant quota, reservation, ticket binding, accounting, object usage,
   and related validation into `artifacts/storage.rs`.
3. Move scan journal enqueue/claim/finish operations and promotion reservation/
   completion operations into separate modules.
4. Move cache generation, promotion, observation, and metrics operations into
   `cache.rs`.
5. Move backup pins, GC lease/mark/inventory/sweep, artifact retirement,
   ledger pruning, and lifecycle metrics into `lifecycle.rs`.
6. Move expanded job set recording/materialization into `workflow/expansions.rs`.
7. Move normalized trigger persistence into `workflow/triggers.rs` and cron
   parsing/matching/reconciliation into `workflow/schedules.rs`.
8. Move tests into `store/tests/{artifacts,storage,cache,lifecycle,workflow}.rs`.

## Original source map

| Target | Original `store.rs` region |
|---|---|
| artifact catalog/downloads | 9576-9924 |
| cache | 9925-10279 |
| storage quotas/tickets | 10280-10738 |
| scans | 10739-10992 |
| promotions | 10993-11194 |
| backup pins and lifecycle | 11195-11926 |
| output helper cluster | 11927-12744 |
| workflow expansions | 19218-19564 |
| triggers/schedule methods | 19565-20040 |
| cron/trigger helpers | 20041-20345 |

Preserve crate-root re-exports for the artifact scan, artifact promotion, and
cache promotion digest functions when moving them to their owner modules.

## Safety constraints

Preserve quota accounting, ticket binding, GC fencing, cache trust digests,
cron semantics, and materialization authorization.

## Done when

- Data/lifecycle/workflow implementations are domain-owned.
- Their focused tests and all control-plane checks pass.
