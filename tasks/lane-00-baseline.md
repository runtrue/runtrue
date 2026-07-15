# Lane 00: baseline and compatibility inventory

## Goal

Create a trustworthy pre-refactor baseline without changing implementation.

## Exclusive ownership

- Workspace-level diagnostic output and any new modularization-check script.
- Do not edit crate implementation files.

## Steps

1. Confirm the workspace root and inspect existing changes. Preserve them.
2. Run `cargo fmt --check`, `cargo check --workspace`,
   `cargo test --workspace`, and `cargo clippy --workspace --all-targets`.
3. Record failures exactly, distinguishing pre-existing failures from commands
   that pass.
4. Inventory every Rust file under `crates/` and `bins/` with total lines and the line at
   which its top-level `#[cfg(test)] mod tests` begins. Do not confuse a
   test-only helper attribute with the start of the test module.
5. Record public exports from every affected library and binary crate root. Pay special attention
   to glob re-exports such as `pub use types::*`.
6. Search the workspace for module-qualified imports into affected crates so
   the later lanes know which paths must remain stable.
7. Identify generated files, protocol fixtures, and files that need an
   explicit size exception.
8. Save the baseline in `tasks/baseline.md`. This is the only planned file
   addition for this lane.

## Done when

- Baseline commands and results are recorded.
- Public API and oversized-file inventories are present.
- No crate implementation changed.
