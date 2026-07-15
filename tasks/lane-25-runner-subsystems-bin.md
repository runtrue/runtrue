# Lane 25: runner backends and subsystems

## Goal and ownership

Complete the `bins/runner/**` split after lane 24. No server lane may begin
until this lane passes because the server depends on the runner library.

## Target layout

```text
src/credentials/{mod,model,load,rotation,publish,validation,secure_fs,error}.rs
src/state/{mod,model,store,workspaces,credentials,secure_fs,error}.rs
src/transport/{mod,security,tonic,broker,conversion,error}.rs
src/data_plane/{mod,session,cache,artifacts,transfer,patterns,wire}.rs
src/broker/{mod,client,bindings,secrets,oidc,envelope}.rs
src/firecracker/{mod,config,driver,images,host,recovery,execution}.rs
src/oci/{mod,config,assignments,admission,execution,validation}.rs
src/wasm/{mod,config,components,adapters,execution,validation}.rs
src/inventory/{mod,model,probe,storage,trust,validation,error}.rs
src/enrollment.rs
```

## Steps

1. Process one original source file at a time; first convert it unchanged to a
   directory-form module, compile, then extract children.
2. Credentials: separate generation model/load, pending rotation, certificate
   validation, atomic publication, and private filesystem handling.
3. State: separate durable completion/fencing state from workspace lifecycle
   and systemd credential validation.
4. Transport: separate endpoint/TLS policy, tonic control transport, broker RPC,
   wire conversion, and errors.
5. Data plane: separate session observation, cache/artifact ticket workflows,
   upload/download, input pattern expansion, and canonical wire conversion.
6. Broker: separate client RPC, execution binding, secret/OIDC adapters, and
   authenticated envelope decryption.
7. Split Firecracker into runtime configuration/driver, trusted images, host
   probes/recovery, and execution reporting.
8. Split OCI into runtime config, assignment/admission loading, execution, and
   hardened validation; split Wasm into config/components, adapters, execution,
   and validation.
9. Split inventory into trusted-plan keys, platform/resource probes, bounded
   storage subprocess, posture, and validation. Keep enrollment cohesive.
10. Split runner tests by subsystem and audit `lib.rs` as a re-export façade.

## Safety constraints

Preserve key permissions and atomic rotation, state fences, TLS identity,
broker binding, upload authorization, backend isolation, image/component trust,
process cleanup, and authoritative inventory posture.

Run all `runtrue-runner` checks plus `cargo check -p runtrue-server --all-targets`.
