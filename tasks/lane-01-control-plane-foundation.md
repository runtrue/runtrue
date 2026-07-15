# Lane 01: control-plane foundation

## Goal

Turn the monolithic control-plane files into a module tree without moving
domain operations yet.

## Dependency

Lane 00.

## Exclusive ownership

- `crates/control-plane/src/**`
- No other control-plane lane may run concurrently.

## Target layout

```text
src/
  lib.rs
  error.rs
  types/mod.rs
  store/
    mod.rs
    database.rs
    decode.rs
    validation.rs
```

## Steps

1. Move `store.rs` to `store/mod.rs` and `types.rs` to `types/mod.rs` as pure
   path changes. Compile before further extraction.
2. Move `ControlPlaneError` and `DecodeError` plus their trait implementations
   into `error.rs`. Re-export `ControlPlaneError` from the crate root.
3. Move secure database open, database identity, sidecar validation,
   initialization, and migration application into `store/database.rs`.
4. Keep `ControlPlane` in `store/mod.rs` with private fields. Child store
   modules may define inherent `impl ControlPlane` blocks.
5. Move only broadly reused row conversions into `store/decode.rs`: bounded
   integer conversion, digest columns, token digests, JSON columns, and
   conversion error construction.
6. Move only validation used by three or more domains into
   `store/validation.rs`. Leave domain validation beside its domain.
7. Use `pub(super)` or `pub(crate)` only where required; do not expose the
   connection or weaken field privacy.
8. Preserve every crate-root export in `lib.rs`.

## Verification

```text
cargo fmt --check
cargo check -p runtrue-control-plane
cargo test -p runtrue-control-plane
cargo clippy -p runtrue-control-plane --all-targets
cargo check --workspace
```

## Done when

- The new foundation compiles and tests pass.
- Domain operations are behaviorally unchanged.
- `store/mod.rs` still contains the unsplit domain implementation, ready for
  later lanes.
