# Lane 07: compiler

## Goal and ownership

Split `crates/compiler/src/lib.rs`. This lane exclusively owns
`crates/compiler/**`. Start after lane 19 so its language-model dependencies
are stable.

## Target layout

```text
src/lib.rs
src/{compiler,settings,context,error,matrix,jobs,steps,bindings,triggers}.rs
src/validation/{mod,workflow,dag,inputs,references}.rs
src/reusable/{mod,source,expansion,bindings,rewrite}.rs
src/risk/{mod,report,diff,collection}.rs
src/permissions/{mod,network,signing}.rs
```

## Steps

1. Move public settings, context, compilation result, approval subject, and
   error types first; re-export them from `lib.rs`.
2. Move risk report types and `semantic_risk_diff` with all comparison helpers.
3. Move reusable source bundles, recursive expansion state, input binding,
   context rewriting, output targeting, and permission intersection under
   `reusable/`.
4. Move shape, input, DAG, reference, identifier, and expression validation
   into `validation/` without changing error paths or messages.
5. Move static and dynamic matrix expansion into `matrix.rs`.
6. Move job, service, run, step, cache, output, binding, permission, trigger,
   and variable conversion into their named modules.
7. Leave `Compiler` in `compiler.rs` as orchestration over those modules.
8. Split tests by `compile`, `reusable`, `risk`, `validation`, and `matrix`.

Preserve plan digests, job ordering, approval subjects, error text, and public
exports. Run the standard checks for `runtrue-compiler`.
