# Lane 13: local runtime

## Goal and ownership

Split `crates/runtime-local/src/lib.rs`. This lane exclusively owns
`crates/runtime-local/**`. Start after lanes 07, 10, 11, 12, and 14.

## Target layout

```text
src/lib.rs
src/cache/{mod,config,executor,inputs,restore,save,staging,paths}.rs
src/artifacts/{mod,config,executor,capture,signing_key}.rs
src/{secure_io,error}.rs
```

## Steps

1. Extract local cache configuration/warnings and executor wrapper.
2. Move plan preparation, cache declarations, identities, and input walking.
3. Separate staged restore/install/rollback from output save/copy behavior.
4. Move exact path, workspace, no-follow open, permissions, and destination
   checks into the cache path or shared secure-I/O module as appropriate.
5. Extract local artifact configuration, capture model/error, executor wrapper,
   artifact preparation, and single-artifact capture.
6. Move signing-key load/create and secret-file persistence together.
7. Split tests by cache preparation, input digest, restore rollback, save,
   artifact capture, signing keys, and path safety.

Preserve cache keys, executable bits, rollback semantics, artifact identity,
and signing-key secrecy. Run standard checks for `runtrue-runtime-local`.
