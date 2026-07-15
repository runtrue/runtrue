# Lane 19: workflow language and lock files

## Goal and ownership

Split `crates/expression/**`, `crates/workflow-ast/**`,
`crates/workflow-ir/**`, and `crates/lock/**`.

## Target layouts

```text
expression/src/{lib,span,value,context,ast,lexer,parser,evaluation,error}.rs
workflow-ast/src/{lib,map,workflow,triggers,permissions,jobs,runners,services,steps,bindings,outputs,parse,error}.rs
workflow-ir/src/{lib,plan,context,permissions,jobs,steps,outputs,matrix,capabilities,artifacts,error}.rs
lock/src/{lib,model,raw,parse,requirements,resolution,diff,validation,error}.rs
```

## Steps

1. Process expression first: move value/provenance, resolver/context, private
   syntax tree, lexer, parser/serialization, evaluator, and errors. Preserve
   expression formatting and spans.
2. Process workflow AST: group serde models by feature; keep every serde
   rename/default/deny-unknown behavior unchanged. Move YAML expansion budget
   and parsing into `parse.rs`.
3. Process workflow IR: group plan/context, permissions, jobs/services, steps,
   outputs, matrix expansion, capability sets, and artifact models. Keep type
   validation beside its type where practical.
4. Process lock: separate raw deserialization from validated public models,
   requirements/resolution, change diffing, and validation.
5. Re-export all original public types and functions at each crate root.
6. Split tests by feature only after each production split passes.

Preserve serialized forms, canonical expression/lock output, matrix order,
taint/provenance, validation messages, and all public root paths. Run standard
checks for each package and then check `runtrue-compiler`.
