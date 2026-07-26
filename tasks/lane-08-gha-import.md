# Lane 08: GitHub Actions importer

## Goal and ownership

Split `frontends/github-actions/src/lib.rs`. This lane exclusively owns
`frontends/github-actions/**`. Start after lane 07.

## Target layout

```text
src/lib.rs
src/{report,error,strict_yaml,validation}.rs
src/github/{mod,schema,triggers,jobs,steps,permissions}.rs
src/native/{mod,schema,lockfile}.rs
src/analyzer/{mod,workflow,jobs,steps,actions,expressions,security}.rs
```

## Steps

1. Extract compatibility report/status/finding/count types and import errors.
2. Move strict YAML representation, deserialization budget, seed, and visitor
   into `strict_yaml.rs` with limits unchanged.
3. Separate input GitHub schema from generated native schema.
4. Keep `Analyzer` as coordinator; move its methods by workflow, job, step,
   action mapping, expression, and security responsibility.
5. Move generated lockfile/image-lock construction into `native/lockfile.rs`.
6. Move identifier, path, SHA, secret-name, runner-label, and scalar validation
   into `validation.rs` only when shared by several analyzer modules.
7. Preserve finding order, compatibility counts, emitted YAML, error messages,
   and fixture output. Split tests by supported, unsupported, security, and
   lockfile cases.

Run the adapter repository's standard checks plus every fixture-based test.
