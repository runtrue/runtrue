# Lane 12: storage

## Goal and ownership

Split `crates/storage/src/lib.rs`. This lane exclusively owns
`crates/storage/**`.

## Target layout

```text
src/{lib,limits,blob,manifest,snapshot,error}.rs
src/cas/{mod,read,write,capture,materialize}.rs
src/secure_io/{mod,open,directories,files}.rs
```

## Steps

1. Extract limits, blob records/readers, tree manifest/entries, and snapshot
   types with their validation.
2. Keep `FsCas` in `cas/mod.rs`; move verified reads, blob/tree writes,
   filesystem capture, and materialization into separate modules.
3. Move hashing and pending-file lifecycle beside CAS writing/capture.
4. Move path anchoring, confined open, component validation, no-follow file
   creation, directory preparation, and permissions under `secure_io/`.
5. Preserve platform-specific implementations and cfg gates.
6. Split tests into blob, manifest, capture, materialization, traversal attack,
   symlink, corruption, and bounded-resource suites. Keep existing integration
   tests working.

Preserve content digests, manifest normalization, atomicity, confinement, and
read verification. Run standard checks for `runtrue-storage` and its integration
tests.
