# Lane 30: final workspace audit

## Goal

Integrate all accepted lanes, validate behavior, and enforce the new layout.

## Dependency

All other lanes, including binary lanes 23-29, are complete, skipped with justification, or explicitly
blocked. No editing agents may still be active.

## Steps

1. Inspect all changed paths for scope violations, accidental manifest changes,
   public API loss, unrelated cleanup, and broad visibility escalation.
2. Run workspace-wide formatting and repair formatting only.
3. Run:

   ```text
   cargo check --workspace
   cargo test --workspace
   cargo clippy --workspace --all-targets
   ```

4. Compare failures with `tasks/baseline.md`. Fix only regressions introduced by
   modularization; document proven pre-existing failures.
5. Search downstream imports and verify crate-root public APIs remain intact.
6. Audit all SQL, migrations, serde attributes, protocol constants, canonical
   encoders, cryptographic message construction, and state enum values for
   accidental changes.
7. Inventory production module sizes under both `crates/` and `bins/`. Review files above 800 production lines;
   split those that still combine responsibilities and document cohesive
   exceptions. Require explicit justification above 1,200 production lines.
8. Add a lightweight CI size/layout check only after the final inventory is
   accepted. The check must distinguish a top-level test module from isolated
   `#[cfg(test)]` helpers and allow documented exceptions.
9. Confirm crate roots are façades and no `utils.rs`, `common.rs`, or new
   dumping-ground module was introduced.
10. Produce a final report listing completed lanes, validation results, public
    API checks, remaining exceptions, and any follow-up work.

## Done when

- No modularization regression remains.
- Full workspace validation passes or only documented pre-existing failures
  remain.
- Oversized cohesive exceptions are explicit and reviewable.
