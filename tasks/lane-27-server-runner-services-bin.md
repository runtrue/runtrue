# Lane 27: server runner services

## Goal and ownership

Split `bins/server/src/runner_service.rs` after lane 26. No other server lane
may run concurrently.

## Target layout

```text
src/runner_service/mod.rs
src/runner_service/{config,metrics,session,identity,enrollment,control,leases,completion,validation,status}.rs
src/runner_service/data_plane/{mod,authorization,uploads,downloads,cache,artifacts,storage,wire}.rs
```

## Steps

1. Convert the source to `runner_service/mod.rs` unchanged and compile.
2. Extract public config/metrics and private session/identity models.
3. Separate enrollment service from authenticated control service.
4. Move connection/session negotiation, inventory, lease offer/acceptance,
   heartbeat/cancellation, plan fetch, and completion into named modules.
5. Move object-transfer service under `data_plane/`: source authorization,
   staging/drop cleanup, upload/download streams, storage reservations, cache
   tickets, artifact tickets, and wire digests.
6. Move bounded identifiers, timestamps/durations, protocol version checks,
   message identity, health/locality, isolation, and status mapping to narrowly
   owned modules.
7. Preserve `RunnerControlService` and `RunnerEnrollmentService` exports.
8. Split runner service and end-to-end tests by enrollment, control protocol,
   leases, completion, cache/artifacts, source download, and mTLS.

## Safety constraints

Preserve mTLS identity binding, protocol negotiation, session/lease fences,
stream limits, staging cleanup, quota accounting, ticket recovery, completion
state, and gRPC status classification.

Run all `runtrue-server` tests, especially `runner_e2e`, before lane 28.
