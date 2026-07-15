# Lane 11: cache

## Goal and ownership

Split `crates/cache/src/lib.rs`. This lane exclusively owns `crates/cache/**`.
Start after lane 12.

## Target layout

```text
src/{lib,limits,identity,access,key,ticket,manifest,promotion,secure_io,error}.rs
src/store/{mod,commit,restore,metadata}.rs
```

## Steps

1. Extract limits/platform, trust identity, key material, access policies, and
   access derivation.
2. Move write-ticket model, subject digest, validation, and consumption rules.
3. Move manifest/head/entry and promotion evidence/record types.
4. Keep `CacheStore` in `store/mod.rs`; move commit and restore paths separately
   while retaining shared locking/fencing in the store layer.
5. Move append/read metadata, temporary file reservation, permissions, sync,
   and safe directory operations into `secure_io.rs`.
6. Move errors last and preserve crate-root exports.
7. Split tests into access, key, ticket, commit, restore, promotion, corruption,
   and secure I/O.

Preserve generation fences, expected-head checks, trust derivation, atomic
metadata writes, and corruption classification. Run standard checks for
`runtrue-cache`.
