# Lane 04: control-plane runners and durable state

## Goal

Extract runner lifecycle, scheduling, leases, broker operations, and durable
task/variable/secret/audit state.

## Dependency

Lane 03.

## Target modules

```text
store/runners/{mod,pools,enrollment,certificates,scheduler,leases,broker,oidc,logs,data_commits}.rs
store/durable/{mod,tasks,variables,secrets,audit,replay,policy_versions}.rs
```

## Steps

1. Move runner pool CRUD and persisted-runner inventory operations.
2. Move enrollment token creation, hashing, inspection, consumption, and final
   enrollment into `enrollment.rs`.
3. Move certificate authentication, rotation journals, expiration, and
   fingerprint lookup into `certificates.rs`.
4. Move scheduler candidate selection, quotas, maintenance, concurrency groups,
   and locality helpers into `scheduler.rs`.
5. Move lease creation, offer, acceptance, heartbeat, cancellation, rejection,
   completion, expiration, job transitions, and run conclusion together into
   `leases.rs`.
6. Move runner secret lease and broker audit/revocation logic into `broker.rs`.
7. Move runner OIDC authorization/issuance, log journals, blob uploads and
   downloads, and data commits into their named modules.
8. Extract durable task queueing, variables, secret metadata/vault operations,
   audit queries, replay bundles, and policy-version storage.
9. Split associated tests into `store/tests/{runners,scheduler,leases,durable,secrets}.rs`.

## Original source map

Ranges refer to the initial `store.rs`; use symbols after prior extraction:

| Target | Original public-method region |
|---|---|
| scheduler offers/maintenance | 5064-5477 |
| runner registry/pools | 5478-5809, plus `drain_runner` |
| enrollment | 5810-6220 |
| certificates | 6221-6495 |
| leases | 6496-7361 |
| tasks and snapshots | 7362-7624 |
| secret metadata/audit/query APIs | 7625-7949 |
| replay/variables/promotions/policy | 7950-8374 |
| durable secret operations | 8375-8609 |
| runner broker | 8610-8843 |
| runner OIDC | 8844-9153 |
| logs | 9154-9268 |
| blob transfers | 9269-9414 |
| data commits | 9415-9575 |

Find private helpers by the same domain prefix. Lease and scheduler helpers
cluster around the original 16939-18557 region; durable task/secret helpers
cluster around 18558-18820.

## Safety constraints

Preserve lease fences, certificate ancestry, secret plaintext boundaries,
scheduler ordering, resource accounting, and run/job state-machine behavior.

## Done when

- All listed implementation is removed from `store/mod.rs`.
- Runner, scheduler, secret, and durable-task tests pass.
