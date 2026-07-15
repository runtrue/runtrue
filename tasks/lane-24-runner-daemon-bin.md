# Lane 24: runner entrypoint and daemon

## Goal and ownership

Split `bins/runner/src/main.rs` and `daemon.rs` after lanes 09, 11, 12, 14, 15,
17, 19, and 21. This is the first runner lane; no other runner lane may run
concurrently.

## Target layout

```text
src/main.rs
src/startup/{mod,args,config,backends,doctor,error}.rs
src/daemon/{mod,executor,remote,loop,lifecycle,observations,source,clock,error}.rs
src/lib.rs
```

## Steps

1. Move runner Clap arguments, environment/config resolution, backend
   completion, command selection, and startup errors under `startup/`.
2. Leave `main.rs` as a thin async entrypoint calling `startup::run`.
3. Convert `daemon.rs` to `daemon/mod.rs` without changing behavior and compile.
4. Move execution traits, native executor, and remote executor separately.
5. Move the `RunnerDaemon` connection/event loop and active execution state.
6. Move lease lifecycle, observation publishing, server-clock/deadline handling,
   and completion conversion into named modules.
7. Move source hydration/download and digest decoding together, preserving
   source ticket authorization and bounds.
8. Keep `RunnerError` with its conversions in `daemon/error.rs`; preserve all
   existing re-exports from `lib.rs`.
9. Split main and daemon tests by config, loop, lease lifecycle, source, and
   cancellation.

## Safety constraints

Preserve offer acceptance/rejection, fences, clock calculations, cancellation,
step observations, reconnect behavior, completion ordering, and source digest
verification.

Run the standard checks for `runtrue-runner` and compile `runtrue-server`.
