# Lane 14: artifacts

## Goal and ownership

Split `crates/artifacts/src/lib.rs`. This lane exclusively owns
`crates/artifacts/**`. Start after lane 12.

## Target layout

```text
src/{lib,model,limits,ticket,provenance,promotion,metadata,secure_io,error}.rs
src/store/{mod,commit,read}.rs
```

## Steps

1. Move classification, scan state, producer, record, handle, and request
   models while retaining serialization.
2. Move ticket issue/claim/subject digest and validation into `ticket.rs`.
3. Move provenance verification and promotion evidence/retention checks.
4. Keep `ArtifactStore` in `store/mod.rs`; separate commit and lookup/read
   operations without splitting atomic commit flows.
5. Move metadata append/read, temporary files, read-only permissions, sync,
   and directory validation into `secure_io.rs`.
6. Split tests by ticket, provenance, commit, snapshot, promotion, corruption,
   and filesystem hardening.

Preserve immutable record verification, ticket one-use behavior, provenance
links, atomic metadata, and error classification. Run standard checks for
`runtrue-artifacts`.
