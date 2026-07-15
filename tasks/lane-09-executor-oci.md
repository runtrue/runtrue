# Lane 09: OCI executor

## Goal and ownership

Split `crates/executor-oci/src/lib.rs`; retain and reuse the existing
`process.rs`. This lane exclusively owns `crates/executor-oci/**`. Start after
lane 10.

## Target layout

```text
src/{lib,config,limits,image,admission,recovery,runtime,invocation,executor,services,mounts,environment,error}.rs
src/security/{mod,paths,seccomp,arguments,filesystem}.rs
```

## Steps

1. Move configuration, limits, platform, mount, invocation, result, and control
   types with their validation implementations.
2. Move locked/admitted image types and admission provider into `image.rs` and
   `admission.rs`.
3. Move abandoned-job recovery and runtime prefix construction together.
4. Move runtime command runner abstractions and result validation.
5. Move seccomp, safe path, private state root, no-follow filesystem, mount,
   environment, command argument, identifier, and socket checks into narrowly
   named security modules.
6. Move service setup/healthcheck/network lifecycle into `services.rs`.
7. Leave `OciExecutor` orchestration in `executor.rs` and preserve cleanup on
   every error/cancellation path.
8. Split tests into config, image, security, services, execution, recovery, and
   cleanup suites.

Do not change runtime argument ordering, isolation checks, path confinement,
cleanup sequencing, cancellation, or error classification. Run standard
checks for `runtrue-executor-oci`.
