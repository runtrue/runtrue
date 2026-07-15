# Lane 10: engine

## Goal and ownership

Split `crates/engine/src/lib.rs`. This lane exclusively owns
`crates/engine/**`. Start after lane 19.

## Target layout

```text
src/{lib,model,events,cancellation,executor,error,context,conditions,bindings,outputs}.rs
src/engine/{mod,job,attempt,step}.rs
src/validation/{mod,plan,dag,scalar}.rs
src/native/{mod,executor,process,capture}.rs
```

## Steps

1. Extract public execution/result/event/request types, cancellation token,
   executor trait, and errors. Preserve crate-root exports.
2. Move plan, DAG, scalar, environment, and condition syntax validation.
3. Move runtime context construction/update, condition evaluation, and binding
   resolution into their named modules.
4. Move structured output decoding, typed output validation, and job output
   projection into `outputs.rs`.
5. Break `Engine` execution into job, attempt, and step modules without
   changing event or cleanup order.
6. Move native process preparation, spawning, capture, termination, and process
   group cleanup under `native/`.
7. Split tests by validation, conditions, outputs, execution, cancellation,
   and native process behavior.

Preserve state conclusions, output semantics, event ordering, cancellation,
and process cleanup. Run standard checks for `runtrue-engine`.
