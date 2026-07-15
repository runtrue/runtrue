# Lane 17: Wasm and Firecracker executors

## Goal and ownership

Split oversized implementation files in `crates/executor-wasm/**` and
`crates/executor-firecracker/**`. One agent owns both crates for this lane; no
other executor agent may touch them concurrently. Start after lanes 10 and 21.

## Wasm target

```text
src/{lib,target,limits,authentication,component,config,executor,invocation,capabilities,watchdog,validation,error}.rs
src/host/{mod,state,filesystem,environment,outputs,bindings,limits}.rs
src/cache/{mod,model,authentication,read,write,metadata,secure_fs,validation,error}.rs
```

Steps:

1. Extract target, limits, authenticated handles, component artifact, config,
   output, and error types from `lib.rs`.
2. Move `WasmExecutor` orchestration, invocation grants, call classification,
   interruption/watchdog, output merging, and capability validation.
3. Convert `host.rs` and `cache.rs` to module directories and split them by the
   responsibilities above. Retain `rooted_fs.rs` unless it independently needs
   a cohesive sub-split.
4. Preserve epoch timeout/cancellation, handle authentication, scope
   normalization, host output bounds, cache trust, and resource limits.

## Firecracker target

Split only oversized existing modules:

```text
src/image/{mod,model,compatibility,verification,copy,secure_open}.rs
src/config_state/{mod,config,paths,manager,reflink,state,secure_fs}.rs
src/snapshot/{mod,plan,request,api,validation}.rs
```

Convert one source file to `mod.rs`, compile it unchanged, and then extract one
child at a time. Preserve image digest verification, private path checks,
reflink/copy fallback, snapshot ordering, and cleanup.

Split tests after production moves. Run standard checks for both executor
packages and compile `runtrue-executor-dispatch`.
