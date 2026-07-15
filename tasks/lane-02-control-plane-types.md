# Lane 02: control-plane public types

## Goal

Split the control-plane type catalog by domain while preserving all crate-root
imports and serialized representations.

## Dependency

Lane 01.

## Exclusive ownership

- `crates/control-plane/src/types/**`
- `crates/control-plane/src/lib.rs` only if re-exports need repair.

## Target modules

Create `installation`, `api_tokens`, `repositories`, `scm`, `capsules`, `runs`,
`approvals`, `runners`, `leases`, `tasks`, `variables`, `secrets`, `audit`,
`artifacts`, `storage`, `cache`, `lifecycle`, `workflow`, `identity`, `sessions`,
`policy`, `providers`, `environments`, `deployments`, and `signing` under
`src/types/`.

## Steps

1. Build a declaration-to-domain checklist before moving code. Move every
   associated inherent implementation with its type.
2. Move related request, record, state enum, metrics, and result types together.
3. Preserve declaration bodies exactly, including derive lists, `serde`
   attributes, custom `Debug`, zeroizing behavior, and documentation.
4. Use `crate::types::<domain>` imports for cross-domain references.
5. Re-export every previously public item from `types/mod.rs`, then keep
   `pub use types::*` at the crate root.
6. Search the workspace for all affected type names and confirm existing
   crate-root imports still compile.
7. Do not rename types, fields, enum variants, modules visible to consumers, or
   serialized values.

## Verification

Run the control-plane standard checks, `cargo check --workspace`, and any
serialization tests touching moved types.

## Done when

- `types/mod.rs` contains module declarations and re-exports only.
- Existing `runtrue_control_plane::<Type>` paths compile unchanged.
- No serialized representation changed.
