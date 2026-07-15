# Lane 15: Git

## Goal and ownership

Split `crates/git/src/lib.rs` and `src/mirror.rs` while preserving existing
`origin.rs` and `benchmark.rs`. This lane exclusively owns `crates/git/**`.

## Target layout

```text
src/{lib,repository,tree,blob,snapshot,submodules,command,validation,error}.rs
src/mirror/{mod,manager,identity,credentials,fetch,hydrate,maintenance,metadata,secure_fs}.rs
```

## Steps

1. Extract tree/blob/snapshot/limits models and keep `GitRepository` in
   `repository.rs`.
2. Move bounded command execution, capture, timeout, and process-tree
   termination into `command.rs`.
3. Move locked submodule walking, declarations, source validation, and manifest
   construction into `submodules.rs`.
4. Convert `mirror.rs` to `mirror/mod.rs`; extract identity and credential
   models before manager methods.
5. Split mirror sync/fetch, workspace hydration, maintenance, metadata/config,
   and hardened filesystem operations.
6. Split tests by repository, tree, submodule, command, mirror identity, fetch,
   hydration, maintenance, credential redaction, and tree hardening.

Preserve Git hardening arguments, commit/object verification, SSRF checks,
credential redaction, no-follow deletion, and read-only mirror state. Run
standard checks for `runtrue-git`.
